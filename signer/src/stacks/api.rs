//! A module with structs that interact with the Stacks API.

use std::borrow::Cow;
use std::future::Future;
use std::time::Duration;

use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TokenTransferMemo;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::types::StandardPrincipalData;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::net::api::getaccount::AccountEntryResponse;
use blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo;
use blockstack_lib::net::api::postfeerate::FeeRateEstimateRequestBody;
use blockstack_lib::net::api::postfeerate::RPCFeeEstimateResponse;
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::types::chainstate::StacksBlockId;
use futures::TryFutureExt;
use reqwest::header::CONTENT_LENGTH;
use reqwest::header::CONTENT_TYPE;

use crate::config::StacksSettings;
use crate::error::Error;
use crate::storage::DbRead;

use super::contracts::AsTxPayload;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The default fee in microSTX for a stacks transaction if the stacks node
/// does not return any fee estimations for the transaction. This should
/// never happen, since it's hard coded to return three estimates in
/// stacks-core.
const DEFAULT_TX_FEE: u64 = 1_000_000;

/// The max fee in microSTX for a stacks transaction. Used as a backstop in
/// case the stacks node returns wonky values. This is 10 STX.
const MAX_TX_FEE: u64 = DEFAULT_TX_FEE * 10;

/// This is a dummy STX transfer payload used only for estimating STX
/// transfer costs.
const DUMMY_STX_TRANSFER_PAYLOAD: TransactionPayload = TransactionPayload::TokenTransfer(
    PrincipalData::Standard(StandardPrincipalData(0, [0; 20])),
    0,
    TokenTransferMemo([0; 34]),
);

/// An enum representing the types of estimates returns by the stacks node.
///
/// The when a stacks node returns an estimate for the transaction fee it
/// returns a Low, middle, and High fee. It has a few fee different
/// estimators for arriving at the returned estimates. One uses a weighted
/// percentile approach where "larger" transactions have move weight[1],
/// while another is uses the execution cost and takes the 5th, 50th, and
/// 95th percentile of fees[2].
///
/// [^1]: https://github.com/stacks-network/stacks-core/blob/47db1d0a8bf70eda1c93cb3e0731bdf5595f7baa/stackslib/src/cost_estimates/fee_medians.rs#L33-L51
/// [^2]: https://github.com/stacks-network/stacks-core/blob/47db1d0a8bf70eda1c93cb3e0731bdf5595f7baa/stackslib/src/cost_estimates/fee_scalar.rs#L30-L42
#[derive(Debug, Clone, Copy)]
pub enum FeePriority {
    /// Think of it as the 5th percentile of all fees by execution cost.
    Low,
    /// Think of it as the 50th percentile of all fees by execution cost.
    Medium,
    /// Think of it as the 95th percentile of all fees by execution cost.
    High,
}

/// A trait detailing the interface with the Stacks API and Stacks Nodes.
pub trait StacksInteract {
    /// Fetch the raw stacks nakamoto block from a Stacks node given the
    /// Stacks block ID.
    fn get_block(
        &self,
        block_id: StacksBlockId,
    ) -> impl Future<Output = Result<NakamotoBlock, Error>> + Send;
    /// Fetch all Nakamoto ancestor blocks within the same tenure as the
    /// given block ID from a Stacks node.
    ///
    /// The response includes the Nakamoto block for the given block id.
    ///
    /// This function is analogous to the GET /v3/tenures/<block-id>
    /// endpoint on stacks-core nodes, but responses from that endpoint are
    /// capped at ~16 MB. This function returns all blocks, regardless of
    /// the size of the blocks within the tenure.
    fn get_tenure(
        &self,
        block_id: StacksBlockId,
    ) -> impl Future<Output = Result<Vec<NakamotoBlock>, Error>> + Send;
    /// Get information about the current tenure.
    ///
    /// This function is analogous to the GET /v3/tenures/info stacks node
    /// endpoint for retrieving tenure information.
    fn get_tenure_info(&self) -> impl Future<Output = Result<RPCGetTenureInfo, Error>> + Send;
    /// Estimate the priority transaction fees for the input transaction
    /// for the current state of the mempool. The result should be and
    /// estimated total fee in microSTX.
    ///
    /// This function usually uses the POST /v2/fees/transaction endpoint
    /// of a stacks node.
    fn estimate_fees<T>(
        &self,
        payload: &T,
        priority: FeePriority,
    ) -> impl Future<Output = Result<u64, Error>> + Send
    where
        T: AsTxPayload + Send + Sync;
    /// Get the start height of the first EPOCH 3.0 block on the Stacks
    /// blockchain.
    fn nakamoto_start_height(&self) -> u64;
}

/// These are the rejection reason codes for submitting a transaction
///
/// The official documentation specifies what to expect when there is a
/// rejection, and that documentation can be found here:
/// https://github.com/stacks-network/stacks-core/blob/2.5.0.0.5/docs/rpc-endpoints.md
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(serde::Serialize))]
pub enum RejectionReason {
    /// From MemPoolRejection::SerializationFailure
    Serialization,
    /// From MemPoolRejection::DeserializationFailure
    Deserialization,
    /// From MemPoolRejection::FailedToValidate
    SignatureValidation,
    /// From MemPoolRejection::FeeTooLow
    FeeTooLow,
    /// From MemPoolRejection::BadNonces
    BadNonce,
    /// From MemPoolRejection::NotEnoughFunds
    NotEnoughFunds,
    /// From MemPoolRejection::NoSuchContract
    NoSuchContract,
    /// From MemPoolRejection::NoSuchPublicFunction
    NoSuchPublicFunction,
    /// From MemPoolRejection::BadFunctionArgument
    BadFunctionArgument,
    /// From MemPoolRejection::ContractAlreadyExists
    ContractAlreadyExists,
    /// From MemPoolRejection::PoisonMicroblocksDoNotConflict
    PoisonMicroblocksDoNotConflict,
    /// From MemPoolRejection::NoAnchorBlockWithPubkeyHash
    PoisonMicroblockHasUnknownPubKeyHash,
    /// From MemPoolRejection::InvalidMicroblocks
    PoisonMicroblockIsInvalid,
    /// From MemPoolRejection::BadAddressVersionByte
    BadAddressVersionByte,
    /// From MemPoolRejection::NoCoinbaseViaMempool
    NoCoinbaseViaMempool,
    /// From MemPoolRejection::NoTenureChangeViaMempool
    NoTenureChangeViaMempool,
    /// From MemPoolRejection::NoSuchChainTip
    ServerFailureNoSuchChainTip,
    /// From MemPoolRejection::ConflictingNonceInMempool
    ConflictingNonceInMempool,
    /// From MemPoolRejection::TooMuchChaining
    TooMuchChaining,
    /// From MemPoolRejection::BadTransactionVersion
    BadTransactionVersion,
    /// From MemPoolRejection::TransferRecipientIsSender
    TransferRecipientCannotEqualSender,
    /// From MemPoolRejection::TransferAmountMustBePositive
    TransferAmountMustBePositive,
    /// From MemPoolRejection::DBError or MemPoolRejection::Other
    ServerFailureDatabase,
    /// From MemPoolRejection::EstimatorError
    EstimatorError,
    /// From MemPoolRejection::TemporarilyBlacklisted
    TemporarilyBlacklisted,
}

/// A rejection response from the node.
///
/// The official documentation specifies what to expect when there is a
/// rejection, and that documentation can be found here:
/// https://github.com/stacks-network/stacks-core/blob/2.5.0.0.5/docs/rpc-endpoints.md
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(serde::Serialize))]
pub struct TxRejection {
    /// The error message. It should always be the string "transaction
    /// rejection".
    pub error: String,
    /// The reason code for the rejection.
    pub reason: RejectionReason,
    /// More details about the reason for the rejection.
    pub reason_data: Option<serde_json::Value>,
    /// The transaction ID of the rejected transaction.
    pub txid: Txid,
}

/// The response from a POST /v2/transactions request
///
/// The stacks node returns three types of responses, either:
/// 1. A 200 status hex encoded txid in the response body (on acceptance)
/// 2. A 400 status with a JSON object body (on rejection),
/// 3. A 400/500 status string message about some other error (such as
///    using an unsupported address mode).
///
/// All good with the first response type, but the second response type
/// could be due to the fee being too low or because of a bad nonce. These
/// are retryable "error", so we distinguish them from the third kinds of
/// errors, which are likely not retryable.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub enum SubmitTxResponse {
    /// The transaction ID for the submitted transaction.
    Acceptance(Txid),
    /// The response when the transaction is rejected from the node.
    Rejection(TxRejection),
}

/// The account info for a stacks address.
pub struct AccountInfo {
    /// The total balance of the account in micro-STX. This amount includes
    /// the amount locked.
    pub balance: u128,
    /// The amount locked (stacked) in micro-STX.
    pub locked: u128,
    /// The height of the stacks block where the above locked micro-STX
    /// will be unlocked.
    pub unlock_height: u64,
    /// The next nonce for the account.
    pub nonce: u64,
}

/// Helper function for converting a hexidecimal string into an integer.
fn parse_hex_u128(hex: &str) -> Result<u128, Error> {
    let hex_str = hex.trim_start_matches("0x");
    u128::from_str_radix(hex_str, 16).map_err(Error::ParseHexInt)
}

impl TryFrom<AccountEntryResponse> for AccountInfo {
    type Error = Error;

    fn try_from(value: AccountEntryResponse) -> Result<Self, Self::Error> {
        Ok(AccountInfo {
            balance: parse_hex_u128(&value.balance)?,
            locked: parse_hex_u128(&value.locked)?,
            nonce: value.nonce,
            unlock_height: value.unlock_height,
        })
    }
}

/// A client for interacting with Stacks nodes and the Stacks API
pub struct StacksClient {
    /// The base URL (with the port) that will be used when making requests
    /// for to a Stacks node.
    pub node_endpoint: url::Url,
    /// The client used to make the request.
    pub client: reqwest::Client,
    /// The start height of the first EPOCH 3.0 block on the Stacks
    /// blockchain.
    pub nakamoto_start_height: u64,
}

impl StacksClient {
    /// Create a new instance of the Stacks client using the given
    /// StacksSettings.
    pub fn new(settings: StacksSettings) -> Self {
        Self {
            node_endpoint: settings.node.endpoint,
            nakamoto_start_height: settings.node.nakamoto_start_height,
            client: reqwest::Client::new(),
        }
    }

    /// Get the latest account info for the given address.
    ///
    /// This is done by making a GET /v2/accounts/<principal> request. In
    /// the request we specify that the nonce and balance proofs should not
    /// be included in the response.
    #[tracing::instrument(skip_all)]
    pub async fn get_account(&self, address: &StacksAddress) -> Result<AccountInfo, Error> {
        let path = format!("/v2/accounts/{}?proof=0", address);
        let base = self.node_endpoint.clone();
        let url = base
            .join(&path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Owned(path)))?;

        tracing::debug!(%address, "Fetching the latest account information");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json::<AccountEntryResponse>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .and_then(AccountInfo::try_from)
    }

    /// Submit a transaction to a Stacks node.
    ///
    /// This is done by making a POST /v2/transactions request to a Stacks
    /// node. That endpoint supports two different content-types in the
    /// request body: JSON, and an octet-stream. This function always sends
    /// the raw transaction bytes as an octet-stream.
    #[tracing::instrument(skip_all)]
    pub async fn submit_tx(&self, tx: &StacksTransaction) -> Result<SubmitTxResponse, Error> {
        let path = "/v2/transactions";
        let base = self.node_endpoint.clone();
        let url = base
            .join(path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Borrowed(path)))?;

        tracing::debug!(txid = %tx.txid(), "Submitting transaction to the stacks node");
        let body = tx.serialize_to_vec();

        let response: reqwest::Response = self
            .client
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }

    /// Estimate the current mempool transaction fees.
    ///
    /// This is done by making a POST /v2/fees/transaction request to a
    /// Stacks node. The response provides 3 estimates by default, but
    /// sometimes the stacks node cannot estimate the fees. When the node
    /// cannot estimate the fees, it returns a 400 response with a simple
    /// string message. This function does not try to distinguish between
    /// the different error modes.
    ///
    /// The docs for this RPC can be found here:
    /// https://docs.stacks.co/stacks-101/api#v2-fees-transaction
    #[tracing::instrument(skip_all)]
    pub async fn get_fee_estimate<T>(&self, payload: &T) -> Result<RPCFeeEstimateResponse, Error>
    where
        T: AsTxPayload + Send,
    {
        let path = "/v2/fees/transaction";
        let base = self.node_endpoint.clone();
        let url = base
            .join(path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Borrowed(path)))?;

        let tx_payload = payload.tx_payload().serialize_to_vec();
        let request_body = FeeRateEstimateRequestBody {
            estimated_len: None,
            transaction_payload: blockstack_lib::util::hash::to_hex(&tx_payload),
        };
        let body = serde_json::to_string(&request_body).map_err(Error::JsonSerialize)?;

        tracing::debug!("Making request to the stacks-node for a tx fee estimate");
        let response: reqwest::Response = self
            .client
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        // Only parse the JSON if it's a success status, otherwise return
        // an error.
        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }

    /// Fetch the raw stacks nakamoto block from a Stacks node given the
    /// Stacks block ID.
    ///
    /// # Note
    ///
    /// If the given block ID does not exist or is an ID for a non-Nakamoto
    /// block then a Result::Err is returned.
    #[tracing::instrument(skip(self))]
    async fn get_block(&self, block_id: StacksBlockId) -> Result<NakamotoBlock, Error> {
        let path = format!("/v3/blocks/{}", block_id.to_hex());
        let base = self.node_endpoint.clone();
        let url = base
            .join(&path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Owned(path)))?;

        tracing::debug!("Making request to the stacks node for the raw nakamoto block");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        let resp = response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .bytes()
            .await
            .map_err(Error::UnexpectedStacksResponse)?;

        NakamotoBlock::consensus_deserialize(&mut &*resp)
            .map_err(|err| Error::DecodeNakamotoBlock(err, block_id))
    }

    /// Fetch all Nakamoto ancestor blocks within the same tenure as the
    /// given block ID from a Stacks node.
    ///
    /// The response includes the Nakamoto block for the given block id.
    ///
    /// # Note
    ///
    /// If the given block ID does not exist or is an ID for a non-Nakamoto
    /// block then a Result::Err is returned.
    #[tracing::instrument(skip(self))]
    async fn get_tenure(&self, block_id: StacksBlockId) -> Result<Vec<NakamotoBlock>, Error> {
        tracing::debug!("Making initial request for Nakamoto blocks within the tenure");
        let mut tenure_blocks = self.get_tenure_raw(block_id).await?;
        let mut prev_last_block_id = block_id;

        // Given the response size limit of GET /v3/tenures/<block-id>
        // requests, there could be more blocks that we need to fetch.
        while let Some(last_block_id) = tenure_blocks.last().map(NakamotoBlock::block_id) {
            // To determine whether all blocks within a tenure have been
            // retrieved, we check if we've seen the last block in the
            // previous GET /v3/tenures/<block-id> response. Note that the
            // response always starts with the block corresponding to
            // <block-id> and is followed by its ancestors from the same
            // tenure.
            if last_block_id == prev_last_block_id {
                break;
            }
            prev_last_block_id = last_block_id;

            tracing::debug!(%last_block_id, "Fetching more Nakamoto blocks within the tenure");
            let blocks = self.get_tenure_raw(last_block_id).await?;
            // The first block in the GET /v3/tenures/<block-id> response
            // is always the block related to the given <block-id>. But we
            // already have that block, so we can skip adding it again.
            debug_assert_eq!(blocks.first().map(|b| b.block_id()), Some(last_block_id));
            tenure_blocks.extend(blocks.into_iter().skip(1))
        }

        Ok(tenure_blocks)
    }

    /// Make a GET /v3/tenures/<block-id> request for Nakamoto ancestor
    /// blocks with the same tenure as the given block ID from a Stacks
    /// node.
    ///
    /// # Notes
    ///
    /// * The GET /v3/tenures/<block-id> response is capped at ~16 MB, so a
    ///   single request may not return all Nakamoto blocks.
    /// * The response includes the Nakamoto block for the given block id.
    /// * If the given block ID does not exist or is an ID for a
    ///   non-Nakamoto block then a Result::Err is returned.
    #[tracing::instrument(skip(self))]
    async fn get_tenure_raw(&self, block_id: StacksBlockId) -> Result<Vec<NakamotoBlock>, Error> {
        let base = self.node_endpoint.clone();
        let path = format!("/v3/tenures/{}", block_id.to_hex());
        let url = base
            .join(&path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Owned(path)))?;

        tracing::debug!("Making request to the stacks node for the raw nakamoto block");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        // The response here does not detail the number of blocks in the
        // response. So we essentially take the same implementation given
        // in [`StacksHttpResponse::decode_nakamoto_tenure`], which just
        // keeps decoding until there are no more bytes.
        let resp = response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .bytes()
            .await
            .map_err(Error::UnexpectedStacksResponse)?;

        let bytes: &mut &[u8] = &mut resp.as_ref();
        let mut blocks = Vec::new();

        while !bytes.is_empty() {
            let block = NakamotoBlock::consensus_deserialize(bytes)
                .map_err(|err| Error::DecodeNakamotoTenure(err, block_id))?;

            blocks.push(block);
        }

        Ok(blocks)
    }

    /// Get information about the current tenure.
    ///
    /// Uses the GET /v3/tenures/info stacks node endpoint for retrieving
    /// tenure information.
    #[tracing::instrument(skip(self))]
    pub async fn get_tenure_info(&self) -> Result<RPCGetTenureInfo, Error> {
        let base = self.node_endpoint.clone();
        let path = "/v3/tenures/info";
        let url = base
            .join(path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Borrowed(path)))?;

        tracing::debug!("Making request to the stacks node for the current tenure info");
        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }
}

impl StacksInteract for StacksClient {
    async fn get_block(&self, block_id: StacksBlockId) -> Result<NakamotoBlock, Error> {
        self.get_block(block_id).await
    }
    async fn get_tenure(&self, block_id: StacksBlockId) -> Result<Vec<NakamotoBlock>, Error> {
        self.get_tenure(block_id).await
    }
    async fn get_tenure_info(&self) -> Result<RPCGetTenureInfo, Error> {
        self.get_tenure_info().await
    }
    /// Estimate the high priority transaction fee for the input
    /// transaction call given the current state of the mempool.
    ///
    /// This function attempts to use the POST /v2/fees/transaction
    /// endpoint on a stacks node to estimate the current high priority
    /// transaction fee for a given transaction. If the node does not
    /// have enough information to provide an estimate, we then get the
    /// current high priority fee for an STX transfer and use that as an
    /// estimate for the transaction fee.
    async fn estimate_fees<T>(&self, payload: &T, priority: FeePriority) -> Result<u64, Error>
    where
        T: AsTxPayload + Send + Sync,
    {
        // If we cannot get an estimate for the transaction, try the
        // generic STX transfer since we should always be able to get the
        // STX transfer fee estimate. If that fails then we bail, maybe we
        // should try another node.
        let mut resp = self
            .get_fee_estimate(payload)
            .or_else(|err| async move {
                tracing::warn!("could not estimate contract call fees: {err}");
                // Estimating STX transfers is simple since the estimate
                // doesn't depend on the recipient, amount, or memo. So a
                // dummy transfer payload will do.
                self.get_fee_estimate(&DUMMY_STX_TRANSFER_PAYLOAD).await
            })
            .await?;
        // As of this writing the RPC response includes exactly 3 estimates
        // (the low, medium, and high priority estimates). It's note worthy
        // if this changes so we log it but the code here is robust to such
        // a change.
        let num_estimates = resp.estimations.len();
        if num_estimates != 3 {
            tracing::info!("Unexpected number of fee estimates: {num_estimates}");
        }
        // Now we sort them and take the low, middle, and high fees
        resp.estimations.sort_by_key(|estimate| estimate.fee);
        let fee_estimate = match priority {
            FeePriority::Low => resp.estimations.first().map(|est| est.fee),
            FeePriority::Medium => resp.estimations.get(num_estimates / 2).map(|est| est.fee),
            FeePriority::High => resp.estimations.last().map(|est| est.fee),
        };

        Ok(fee_estimate.unwrap_or(DEFAULT_TX_FEE).min(MAX_TX_FEE))
    }
    fn nakamoto_start_height(&self) -> u64 {
        self.nakamoto_start_height
    }
}

/// Fetch all Nakamoto blocks that are not already stored in the
/// datastore.
pub async fn fetch_unknown_ancestors<S, D>(
    stacks: &S,
    db: &D,
    block_id: StacksBlockId,
) -> Result<Vec<NakamotoBlock>, Error>
where
    S: StacksInteract,
    D: DbRead + Send + Sync,
    Error: From<<D as DbRead>::Error>,
{
    let mut blocks = vec![stacks.get_block(block_id).await?];

    while let Some(block) = blocks.last() {
        // We won't get anymore Nakamoto blocks before this point, so
        // time to stop.
        if block.header.chain_length <= stacks.nakamoto_start_height() {
            tracing::info!(
                nakamoto_start_height = %stacks.nakamoto_start_height(),
                last_chain_length = %block.header.chain_length,
                "Stopping, since we have fetched all Nakamoto blocks"
            );
            break;
        }
        // We've seen this parent already, so time to stop.
        if db.stacks_block_exists(block.header.parent_block_id).await? {
            tracing::info!("Parent block known in the database");
            break;
        }
        // There are more blocks to fetch.
        blocks.extend(stacks.get_tenure(block.header.parent_block_id).await?);
    }

    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use crate::config::StacksNodeSettings;
    use crate::storage::in_memory::Store;
    use crate::storage::postgres::PgStore;
    use crate::storage::DbWrite;

    use test_case::test_case;

    use super::*;
    use std::io::Read;

    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    #[sqlx::test]
    async fn fetch_unknown_ancestors_works(pool: sqlx::PgPool) {
        sbtc::logging::setup_logging("info,signer=debug", false);

        let settings = StacksSettings::new_from_config().unwrap();
        let client = StacksClient::new(settings);
        let db = PgStore::from(pool);

        let info = client.get_tenure_info().await.unwrap();
        let blocks = fetch_unknown_ancestors(&client, &db, info.tip_block_id).await;

        let blocks = blocks.unwrap();
        let headers = blocks
            .iter()
            .map(TryFrom::try_from)
            .collect::<Result<_, _>>()
            .unwrap();
        db.write_stacks_block_headers(headers).await.unwrap();
    }

    /// Test that get_blocks works as expected.
    ///
    /// The author took the following steps to set up this test:
    /// 1. Get Nakamoto running locally. This was done using
    ///    https://github.com/hirosystems/stacks-regtest-env/blob/feat/signer/docker-compose.yml
    ///    where the STACKS_BLOCKCHAIN_COMMIT was changed to
    ///    "3d96d53b35409859ca2baa2f0b6ddaa1fbd80265" and the
    ///    MINE_INTERVAL_EPOCH3 was set to "60s".
    /// 2. After Nakamoto is running, use a dummy test like
    ///    `fetching_last_tenure_blocks_works` to get the blocks for an
    ///    actual tenure. Note the block IDs for the first and last
    ///    `NakamotoBlock`s in the result.
    /// 3. Use the block IDs from step (2) to make two curl requests:
    ///     * The tenure starting with the end block:
    ///     ```bash
    ///     curl http://localhost:20443/v3/tenures/<tenure-end-block-id> \
    ///         --output tests/fixtures/tenure-blocks-0-<tenure-end-block-id>.bin \
    ///         -vvv
    ///     ```
    ///     * The tenure starting at the tenure start block:
    ///     ```bash
    ///     curl http://localhost:20443/v3/tenures/<tenure-start-block-id> \
    ///         --output tests/fixtures/tenure-blocks-1-<tenure-start-block-id>.bin \
    ///         -vvv
    ///     ```
    /// 4. Done
    #[tokio::test]
    async fn get_blocks_test() {
        // Here we test that out code will handle the response from a
        // stacks node in the expected way.
        const TENURE_START_BLOCK_ID: &str =
            "8ff4eb1ed4a2f83faada29f6012b7f86f476eafed9921dff8d2c14cdfa30da94";
        const TENURE_END_BLOCK_ID: &str =
            "1ed91e0720129bda5072540ee7283dd5345d0f6de0cf5b982c6de3943b6e3291";

        // Okay we need to set up the server to returned what a stacks node
        // would return. We load up a file that contains a response from an
        // actual stacks node in regtest mode.
        let path = format!("tests/fixtures/tenure-blocks-0-{TENURE_END_BLOCK_ID}.bin");
        let mut file = std::fs::File::open(path).unwrap();
        let mut buf1 = Vec::new();
        file.read_to_end(&mut buf1).unwrap();

        let mut stacks_node_server = mockito::Server::new_async().await;
        let endpoint_path_tenure_end = format!("/v3/tenures/{TENURE_END_BLOCK_ID}");
        let first_mock = stacks_node_server
            .mock("GET", endpoint_path_tenure_end.as_str())
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("transfer-encoding", "chunked")
            .with_chunked_body(move |w| w.write_all(&buf1))
            .expect(1)
            .create();

        // The StacksClient::get_blocks call should make at least two
        // requests to the stacks node if there are two or more Nakamoto
        // blocks within the same tenure. Our test setup has 23 blocks
        // within the tenure, so we need to tell the mock server what to
        // return in the second request.
        //
        // Also, worth noting is that the total size of the blocks within a
        // GET /v3/tenures/<block-id> is ~16 MB (via the MAX_MESSAGE_LEN
        // constant in stacks-core). The size of the blocks for this test
        // is well under 1 MB, so we get all the data during the first
        // request, which just don't know that until the second request.
        let path = format!("tests/fixtures/tenure-blocks-1-{TENURE_START_BLOCK_ID}.bin");
        let mut file = std::fs::File::open(path).unwrap();
        let mut buf2 = Vec::new();
        file.read_to_end(&mut buf2).unwrap();

        let endpoint_path_tenure_start = format!("/v3/tenures/{TENURE_START_BLOCK_ID}");
        let second_mock = stacks_node_server
            .mock("GET", endpoint_path_tenure_start.as_str())
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("transfer-encoding", "chunked")
            .with_chunked_body(move |w| w.write_all(&buf2))
            .expect(1)
            .create();

        let settings = StacksSettings {
            node: StacksNodeSettings {
                endpoint: url::Url::parse(stacks_node_server.url().as_str()).unwrap(),
                nakamoto_start_height: 20,
            },
        };

        let client = StacksClient::new(settings);
        let block_id = StacksBlockId::from_hex(TENURE_END_BLOCK_ID).unwrap();
        // The moment of truth, do the requests succeed?
        let blocks = client.get_tenure(block_id).await.unwrap();
        assert!(blocks.len() > 1);
        dbg!(blocks.len());

        // We know that the blocks are ordered as a chain, and we know the
        // first and last block IDs, let's check that.
        let last_block_id = StacksBlockId::from_hex(TENURE_START_BLOCK_ID).unwrap();
        let n = blocks.len() - 1;
        assert_eq!(blocks[0].block_id(), block_id);
        assert_eq!(blocks[n].block_id(), last_block_id);

        // Let's check that the returned blocks are distinct.
        let mut ans: Vec<StacksBlockId> = blocks.iter().map(|block| block.block_id()).collect();
        ans.sort();
        ans.dedup();
        assert_eq!(blocks.len(), ans.len());

        first_mock.assert();
        second_mock.assert();
    }

    #[tokio::test]
    async fn get_tenure_info_works() {
        let raw_json_response = r#"{
            "consensus_hash": "e42b3a9ffce62376e1f36cf76c33cc23d9305de1",
            "tenure_start_block_id": "e08c740242092eb0b5f74756ce203db048a5156e444df531a7c29e2d952cf628",
            "parent_consensus_hash": "d9693fbdf0a9bab9ee5ffd3c4f52fef6e1da1899",
            "parent_tenure_start_block_id": "8ff4eb1ed4a2f83faada29f6012b7f86f476eafed9921dff8d2c14cdfa30da94",
            "tip_block_id": "8f61dc41560560e8122609e82966740075929ed663543d9ad6733f8fc32876c5",
            "tip_height": 2037,
            "reward_cycle": 11
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let first_mock = stacks_node_server
            .mock("GET", "/v3/tenures/info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let settings = StacksSettings {
            node: StacksNodeSettings {
                endpoint: url::Url::parse(stacks_node_server.url().as_str()).unwrap(),
                nakamoto_start_height: 20,
            },
        };

        let client = StacksClient::new(settings);
        let resp = client.get_tenure_info().await.unwrap();
        let expected: RPCGetTenureInfo = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);
        first_mock.assert();
    }

    /// Check that everything works as expected in the happy path case.
    #[tokio::test]
    async fn get_fee_estimate_works() {
        // The following was taken from a locally running stacks node for
        // the cost of a contract deploy.
        let raw_json_response = r#"{
            "estimated_cost":{
                "write_length":3893,
                "write_count":3,
                "read_length":94,
                "read_count":3,
                "runtime":157792
            },
            "estimated_cost_scalar":44,
            "estimations":[
                {"fee_rate":156.45435901001113,"fee":7679},
                {"fee_rate":174.56585442157953,"fee":7680},
                {"fee_rate":579.6667045875889,"fee":25505}
            ],
            "cost_scalar_change_by_byte":0.00476837158203125
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let first_mock = stacks_node_server
            .mock("POST", "/v2/fees/transaction")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(4)
            .create();

        let settings = StacksSettings {
            node: StacksNodeSettings {
                endpoint: url::Url::parse(stacks_node_server.url().as_str()).unwrap(),
                nakamoto_start_height: 20,
            },
        };

        let client = StacksClient::new(settings);
        let resp = client
            .get_fee_estimate(&DUMMY_STX_TRANSFER_PAYLOAD)
            .await
            .unwrap();
        let expected: RPCFeeEstimateResponse = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);

        // Now lets check that the interface function returns the requested
        // priority fees.
        let fee = client
            .estimate_fees(&DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::Low)
            .await
            .unwrap();
        assert_eq!(fee, 7679);

        let fee = client
            .estimate_fees(&DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::Medium)
            .await
            .unwrap();
        assert_eq!(fee, 7680);

        let fee = client
            .estimate_fees(&DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::High)
            .await
            .unwrap();
        assert_eq!(fee, 25505);

        first_mock.assert();
    }

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn fetching_last_tenure_blocks_works() {
        let settings = StacksSettings::new_from_config().unwrap();
        let client = StacksClient::new(settings);

        let storage = Store::new_shared();

        let info = client.get_tenure_info().await.unwrap();
        let blocks = fetch_unknown_ancestors(&client, &storage, info.tenure_start_block_id)
            .await
            .unwrap();
        assert!(!blocks.is_empty());
    }

    #[test_case("0x1A3B5C7D9E", 112665066910; "uppercase-112665066910")]
    #[test_case("0x1a3b5c7d9e", 112665066910; "lowercase-112665066910")]
    #[test_case("1a3b5c7d9e", 112665066910; "no-prefix-lowercase-112665066910")]
    #[test_case("0xF0", 240; "uppercase-240")]
    #[test_case("f0", 240; "no-prefix-lowercase-240")]
    fn parsing_integers(hex: &str, expected: u128) {
        let actual = parse_hex_u128(hex).unwrap();
        assert_eq!(actual, expected);
    }

    #[test_case(""; "empty-string")]
    #[test_case("0x"; "almost-empty-string")]
    #[test_case("ZZZ"; "invalid hex")]
    fn parsing_integers_bad_input(hex: &str) {
        assert!(parse_hex_u128(hex).is_err());
    }

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn fetching_account_information_works() {
        let settings = StacksSettings::new_from_config().unwrap();
        let client = StacksClient::new(settings);

        let address = StacksAddress::burn_address(false);
        let account = client.get_account(&address).await.unwrap();
        assert_eq!(account.nonce, 0);
    }
}
