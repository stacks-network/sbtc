//! A module with structs that interact with the Stacks API.

use std::borrow::Cow;
use std::future::Future;
use std::time::Duration;

use bitcoin::Amount;
use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::burn::ConsensusHash;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TokenTransferMemo;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::types::StandardPrincipalData;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::net::api::getaccount::AccountEntryResponse;
use blockstack_lib::net::api::getcontractsrc::ContractSrcResponse;
use blockstack_lib::net::api::getinfo::RPCPeerInfoData;
use blockstack_lib::net::api::getpoxinfo::RPCPoxInfoData;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo;
use blockstack_lib::net::api::postfeerate::FeeRateEstimateRequestBody;
use blockstack_lib::net::api::postfeerate::RPCFeeEstimate;
use blockstack_lib::net::api::postfeerate::RPCFeeEstimateResponse;
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::types::chainstate::StacksBlockId;
use clarity::types::StacksEpochId;
use clarity::vm::types::{BuffData, ListData, SequenceData};
use clarity::vm::{ClarityName, ContractName, Value};
use reqwest::header::CONTENT_LENGTH;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Deserializer};
use url::Url;

use crate::config::Settings;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::StacksBlock;
use crate::storage::DbRead;
use crate::util::ApiFallbackClient;

use super::contracts::AsTxPayload;
use super::contracts::SmartContract;
use super::wallet::SignerWallet;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The multiplier to use when estimating the fee based on payload-size.
const TX_FEE_TX_SIZE_MULTIPLIER: u64 = 2 * MINIMUM_TX_FEE_RATE_PER_BYTE;

/// The max fee in microSTX for a stacks transaction. Used as a backstop in
/// case the stacks node returns wonky values. This is 10 STX.
const MAX_TX_FEE: u64 = 10_000_000;

/// This is a dummy STX transfer payload used only for estimating STX
/// transfer costs.
const DUMMY_STX_TRANSFER_PAYLOAD: TransactionPayload = TransactionPayload::TokenTransfer(
    PrincipalData::Standard(StandardPrincipalData(0, [0; 20])),
    0,
    TokenTransferMemo([0; 34]),
);

trait ExtractFee {
    fn extract_fee(&self, priority: FeePriority) -> Option<RPCFeeEstimate>;
}

impl ExtractFee for RPCFeeEstimateResponse {
    fn extract_fee(&self, priority: FeePriority) -> Option<RPCFeeEstimate> {
        // As of this writing the RPC response includes exactly 3 estimates
        // (the low, medium, and high priority estimates). It's noteworthy
        // if this changes so we log it but the code here is robust to such
        // a change.
        let num_estimates = self.estimations.len();
        if num_estimates != 3 {
            tracing::info!("Unexpected number of fee estimates: {num_estimates}");
        }

        // Use pattern matching to directly access the low, medium, and high estimates
        match priority {
            FeePriority::Low => self
                .estimations
                .iter()
                .min_by_key(|estimate| estimate.fee)
                .cloned(),
            FeePriority::Medium => {
                let mut sorted_estimations = self.estimations.clone();
                sorted_estimations.sort_by_key(|estimate| estimate.fee);
                sorted_estimations.get(num_estimates / 2).cloned()
            }
            FeePriority::High => self
                .estimations
                .iter()
                .max_by_key(|estimate| estimate.fee)
                .cloned(),
        }
    }
}

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
#[cfg_attr(any(test, feature = "testing"), mockall::automock)]
pub trait StacksInteract: Send + Sync {
    /// Retrieve the current signer set from the `sbtc-registry` contract.
    ///
    /// This is done by making a `GET /v2/data_var/<contract-principal>/sbtc-registry/current-signer-set`
    /// request.
    fn get_current_signer_set(
        &self,
        contract_principal: &StacksAddress,
    ) -> impl Future<Output = Result<Vec<PublicKey>, Error>> + Send;

    /// Retrieve the current signers' aggregate key from the `sbtc-registry` contract.
    ///
    /// This is done by making a `GET /v2/data_var/<contract-principal>/sbtc-registry/current-aggregate-pubkey`
    /// request.
    fn get_current_signers_aggregate_key(
        &self,
        contract_principal: &StacksAddress,
    ) -> impl Future<Output = Result<Option<PublicKey>, Error>> + Send;

    /// Get the latest account info for the given address.
    fn get_account(
        &self,
        address: &StacksAddress,
    ) -> impl Future<Output = Result<AccountInfo, Error>> + Send;

    /// Submit a transaction to a Stacks node.
    fn submit_tx(
        &self,
        tx: &StacksTransaction,
    ) -> impl Future<Output = Result<SubmitTxResponse, Error>> + Send;

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
    ) -> impl Future<Output = Result<TenureBlocks, Error>> + Send;
    /// Get information about the current tenure.
    ///
    /// This function is analogous to the GET /v3/tenures/info stacks node
    /// endpoint for retrieving tenure information.
    fn get_tenure_info(&self) -> impl Future<Output = Result<RPCGetTenureInfo, Error>> + Send;
    /// Get information about the sortition associated to a consensus hash
    fn get_sortition_info(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> impl Future<Output = Result<SortitionInfo, Error>> + Send;
    /// Estimate the priority transaction fees given the input transaction
    /// and the current state of the mempool. The result will be the
    /// estimated total transaction fee in microSTX.
    ///
    /// This function usually uses the POST /v2/fees/transaction endpoint
    /// of a stacks node.
    #[cfg_attr(any(test, feature = "testing"), mockall::concretize)]
    fn estimate_fees<T>(
        &self,
        wallet: &SignerWallet,
        payload: &T,
        priority: FeePriority,
    ) -> impl Future<Output = Result<u64, Error>> + Send
    where
        T: AsTxPayload + Send + Sync;

    /// Get information about the current PoX state.
    fn get_pox_info(&self) -> impl Future<Output = Result<RPCPoxInfoData, Error>> + Send;

    /// Get information about the current node.
    fn get_node_info(&self) -> impl Future<Output = Result<RPCPeerInfoData, Error>> + Send;

    /// Get the source of a deployed smart contract.
    ///
    /// # Notes
    ///
    /// This is useful just to know whether a contract has been deployed
    /// already or not. If the smart contract has not been deployed yet,
    /// the stacks node returns a 404 Not Found.
    fn get_contract_source(
        &self,
        address: &StacksAddress,
        contract_name: &str,
    ) -> impl Future<Output = Result<ContractSrcResponse, Error>> + Send;

    /// Get the total supply of sBTC from the `sbtc-token` smart contract.
    fn get_sbtc_total_supply(
        &self,
        sender: &StacksAddress,
    ) -> impl Future<Output = Result<Amount, Error>> + Send;
}

/// A trait for getting the start height of the first EPOCH 3.0 block on the
/// Stacks blockchain.
pub trait GetNakamotoStartHeight {
    /// Get the start height of the first EPOCH 3.0 block on the Stacks
    /// blockchain.
    fn nakamoto_start_height(&self) -> Option<u64>;
}

impl GetNakamotoStartHeight for RPCPoxInfoData {
    fn nakamoto_start_height(&self) -> Option<u64> {
        self.epochs.iter().find_map(|epoch| {
            if epoch.epoch_id == StacksEpochId::Epoch30 {
                Some(epoch.start_height)
            } else {
                None
            }
        })
    }
}

/// This struct represents a non-empty subset of the Stacks blocks that
/// were created during a tenure.
#[derive(Debug)]
pub struct TenureBlocks {
    /// The subset of Stacks blocks that were created during a tenure. This
    /// is always non-empty.
    blocks: Vec<NakamotoBlock>,
    /// The bitcoin block that this tenure builds off of.
    pub anchor_block_hash: BitcoinBlockHash,
    /// The height of the bitcoin block associated with the above block
    /// hash.
    pub anchor_block_height: u64,
}

impl TenureBlocks {
    /// Create a new one
    pub fn try_new(blocks: Vec<NakamotoBlock>, info: SortitionInfo) -> Result<Self, Error> {
        if blocks.is_empty() {
            return Err(Error::EmptyStacksTenure);
        }
        Ok(Self {
            blocks,
            anchor_block_hash: info.burn_block_hash.into(),
            anchor_block_height: info.burn_block_height,
        })
    }

    /// Get all the blocks contained in this object.
    ///
    /// # Note
    ///
    /// The struct doesn't need to contain all the blocks in a tenure.
    pub fn blocks(&self) -> &[NakamotoBlock] {
        &self.blocks
    }

    /// Return all the blocks contained in this object.
    ///
    /// # Note
    ///
    /// The struct doesn't need to contain all the blocks in a tenure.
    pub fn into_blocks(self) -> Vec<NakamotoBlock> {
        self.blocks
    }

    /// Return an iterator of Stacks blocks included in this object.
    pub fn as_stacks_blocks(&self) -> impl Iterator<Item = StacksBlock> + '_ {
        let bitcoin_anchor = &self.anchor_block_hash;
        self.blocks
            .iter()
            .map(|block| StacksBlock::from_nakamoto_block(block, bitcoin_anchor))
    }
}

/// These are the rejection reason codes for submitting a transaction
///
/// The official documentation specifies what to expect when there is a
/// rejection, and that documentation can be found here:
/// https://github.com/stacks-network/stacks-core/blob/2.5.0.0.5/docs/rpc-endpoints.md
#[derive(Debug, Clone, Copy, serde::Deserialize, strum::IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
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

impl std::fmt::Display for TxRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason_str: &'static str = self.reason.into();
        write!(f, "transaction rejected from stacks mempool: {reason_str}")
    }
}

impl std::error::Error for TxRejection {}

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

/// The response from a GET /v2/data_var/<contract-principal>/<contract-name>/<var-name> request.
#[derive(Debug, Deserialize)]
pub struct DataVarResponse {
    /// The value of the data variable.
    #[serde(deserialize_with = "clarity_value_deserializer")]
    pub data: Value,
}

/// The request body for a POST /v2/contracts/call-read/<contract-principal>/<contract-name>/<fn-name> request.
#[derive(Debug, serde::Serialize)]
pub struct CallReadRequest {
    /// The simulated address of the sender.
    pub sender: String,
    /// The arguments to the function in index-order.
    pub arguments: Vec<String>,
}

/// The response from a POST /v2/contracts/call-read/<contract-principal>/<contract-name>/<fn-name> request.
#[derive(Debug, Deserialize)]
pub struct CallReadResponse {
    /// The result of the function call.
    #[serde(deserialize_with = "clarity_value_deserializer")]
    pub result: Value,
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
#[derive(Debug, Clone)]
pub struct StacksClient {
    /// The base url for the Stacks node's RPC API.
    pub endpoint: Url,
    /// The client used to make the request.
    pub client: reqwest::Client,
}

impl StacksClient {
    /// Create a new instance of the Stacks client using the given
    /// StacksSettings.
    pub fn new(url: Url) -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()?;

        Ok(Self { endpoint: url, client })
    }

    /// Calls a read-only public function on a given smart contract.
    #[tracing::instrument(skip_all)]
    pub async fn call_read(
        &self,
        contract_principal: &StacksAddress,
        contract_name: &ContractName,
        fn_name: &ClarityName,
        sender: &StacksAddress,
    ) -> Result<Value, Error> {
        let path = format!(
            "/v2/contracts/call-read/{}/{}/{}?tip=latest",
            contract_principal, contract_name, fn_name
        );

        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        let body = CallReadRequest {
            sender: sender.to_string(),
            arguments: vec![], // TODO: Add when needed
        };

        tracing::debug!(
            %contract_principal,
            %contract_name,
            %fn_name,
            "Fetching contract data variable"
        );

        let response = self
            .client
            .post(url)
            .timeout(REQUEST_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .error_for_status()
            .map_err(Error::StacksNodeResponse)?
            .json::<CallReadResponse>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .map(|x| x.result)
    }

    /// Retrieve the latest value of a data variable from the specified contract.
    ///
    /// This is done by making a
    /// `GET /v2/data_var/<contract-principal>/<contract-name>/<var-name>`
    /// request. In the request we specify that the proof should not be included
    /// in the response.
    #[tracing::instrument(skip_all)]
    pub async fn get_data_var(
        &self,
        contract_principal: &StacksAddress,
        contract_name: &ContractName,
        var_name: &ClarityName,
    ) -> Result<Value, Error> {
        let path = format!(
            "/v2/data_var/{}/{}/{}?proof=0",
            contract_principal, contract_name, var_name
        );

        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!(
            %contract_principal,
            %contract_name,
            %var_name,
            "fetching contract data variable"
        );

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
            .json::<DataVarResponse>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .map(|x| x.data)
    }

    /// Get the latest account info for the given address.
    ///
    /// This is done by making a GET /v2/accounts/<principal> request. In
    /// the request we specify that the nonce and balance proofs should not
    /// be included in the response.
    #[tracing::instrument(skip_all)]
    pub async fn get_account(&self, address: &StacksAddress) -> Result<AccountInfo, Error> {
        let path = format!("/v2/accounts/{}?proof=0", address);
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!(%address, "fetching the latest account information");

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

    /// Get the source of a deployed smart contract.
    ///
    /// # Notes
    ///
    /// This is done by makes a `GET
    /// /v2/contracts/source/<deployer-address>/<contract-name>?proof=0`
    /// request to the stacks node. This is useful just to know whether a
    /// contract has been deployed already or not. If the smart contract
    /// has not been deployed yet, the stacks node returns a 404 Not Found.
    #[tracing::instrument(skip_all)]
    pub async fn get_contract_source(
        &self,
        address: &StacksAddress,
        contract_name: &str,
    ) -> Result<ContractSrcResponse, Error> {
        let path = format!("/v2/contracts/source/{}/{}?proof=0", address, contract_name);
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

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
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
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
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        tracing::debug!(txid = %tx.txid(), "submitting transaction to the stacks node");
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
    pub async fn get_fee_estimate<T>(
        &self,
        payload: &T,
        tx_size: Option<u64>,
    ) -> Result<RPCFeeEstimateResponse, Error>
    where
        T: AsTxPayload + Send,
    {
        let path = "/v2/fees/transaction";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        let tx_payload = payload.tx_payload().serialize_to_vec();
        let request_body = FeeRateEstimateRequestBody {
            estimated_len: tx_size,
            transaction_payload: blockstack_lib::util::hash::to_hex(&tx_payload),
        };
        let body = serde_json::to_string(&request_body).map_err(Error::JsonSerialize)?;

        tracing::debug!("making request to the stacks node for a tx fee estimate");
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
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!("making request to the stacks node for the raw nakamoto block");

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
    async fn get_tenure(&self, block_id: StacksBlockId) -> Result<TenureBlocks, Error> {
        tracing::debug!("making initial request for nakamoto blocks within the tenure");
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

            tracing::debug!(%last_block_id, "fetching more nakamoto blocks within the tenure");
            let blocks = self.get_tenure_raw(last_block_id).await?;
            // The first block in the GET /v3/tenures/<block-id> response
            // is always the block related to the given <block-id>. But we
            // already have that block, so we can skip adding it again.

            match blocks.first().map(|b| b.block_id()) {
                Some(received_id) if received_id == last_block_id => {}
                Some(received_id) => {
                    return Err(Error::GetTenureRawMismatch(received_id, last_block_id))
                }
                None => return Err(Error::EmptyStacksTenure),
            }

            tenure_blocks.extend(blocks.into_iter().skip(1))
        }

        // If Self::get_tenure_raw returns with Ok(_) then the Vec will
        // include at least 1 Nakamoto block. Since we bail if there is an
        // error, this vector has at least one element.
        let Some(block) = tenure_blocks.last() else {
            return Err(Error::EmptyStacksTenure);
        };

        let info = self
            .get_sortition_info(&block.header.consensus_hash)
            .await?;

        TenureBlocks::try_new(tenure_blocks, info)
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
        let path = format!("/v3/tenures/{}", block_id.to_hex());
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!("making request to the stacks node for the raw nakamoto block");

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
        let path = "/v3/tenures/info";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        tracing::debug!("making request to the stacks node for the current tenure info");
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

    /// Get information about the sortition related to a consensus hash.
    ///
    /// Uses the GET /v3/sortitions stacks node endpoint for retrieving
    /// sortition information.
    #[tracing::instrument(skip(self))]
    pub async fn get_sortition_info(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<SortitionInfo, Error> {
        let path = format!("/v3/sortitions/consensus/{}", consensus_hash);
        let url = self
            .endpoint
            .join(&path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Owned(path)))?;

        tracing::debug!("making request to the stacks node for sortition info");
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
            .json::<Vec<SortitionInfo>>()
            .await
            .map_err(Error::UnexpectedStacksResponse)
            .and_then(|result| {
                // For `consensus` lookups we expect to get a list with a single element
                // https://github.com/stacks-network/stacks-core/blob/40059a57cd27e740c5e9d91a833fb2c975b0bf0b/docs/rpc/openapi.yaml#L693
                result
                    .into_iter()
                    .next()
                    .ok_or(Error::InvalidStacksResponse("missing sortition info"))
            })
    }

    /// Get PoX information from the Stacks node.
    #[tracing::instrument(skip(self))]
    pub async fn get_pox_info(&self) -> Result<RPCPoxInfoData, Error> {
        let path = "/v2/pox";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        tracing::debug!("making request to the stacks node for the current PoX info");
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

    /// Get information about the current node.
    #[tracing::instrument(skip(self))]
    pub async fn get_node_info(&self) -> Result<RPCPeerInfoData, Error> {
        let path = "/v2/info";
        let url = self
            .endpoint
            .join(path)
            .map_err(|err| Error::PathJoin(err, self.endpoint.clone(), Cow::Borrowed(path)))?;

        tracing::debug!("making request to the stacks node for the current node info");
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

/// Fetch all Nakamoto blocks that are not already stored in the
/// datastore.
pub async fn fetch_unknown_ancestors<S, D>(
    stacks: &S,
    db: &D,
    block_id: StacksBlockId,
) -> Result<Vec<TenureBlocks>, Error>
where
    S: StacksInteract,
    D: DbRead + Send + Sync,
{
    let mut blocks = vec![stacks.get_tenure(block_id).await?];
    let pox_info = stacks.get_pox_info().await?;
    let nakamoto_start_height = pox_info
        .nakamoto_start_height()
        .ok_or(Error::MissingNakamotoStartHeight)?;

    while let Some(tenure) = blocks.last() {
        // We won't get anymore Nakamoto blocks before this point, so
        // time to stop.
        if tenure.anchor_block_height <= nakamoto_start_height {
            tracing::debug!(
                %nakamoto_start_height,
                last_chain_length = %tenure.anchor_block_height,
                "all Nakamoto blocks fetched; stopping"
            );
            break;
        }
        // Tenure blocks are always non-empty, and this invariant is upheld
        // by the type. So no need to worry about the early break.
        let Some(block) = tenure.blocks().last() else {
            break;
        };
        // We've seen this parent already, so time to stop.
        if db.stacks_block_exists(block.header.parent_block_id).await? {
            tracing::debug!("parent block known in the database");
            break;
        }
        // There are more blocks to fetch, so let's get them.
        let tenure_blocks = stacks.get_tenure(block.header.parent_block_id).await?;
        blocks.push(tenure_blocks);
    }

    Ok(blocks)
}

/// A deserializer for Clarity's [`Value`] type that deserializes a hex-encoded
/// string which was serialized using Clarity's consensus serialization format.
fn clarity_value_deserializer<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    Value::try_deserialize_hex_untyped(&String::deserialize(deserializer)?)
        .map_err(serde::de::Error::custom)
}

impl StacksInteract for StacksClient {
    async fn get_current_signer_set(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Vec<PublicKey>, Error> {
        // Make a request to the sbtc-registry contract to get the current
        // signer set.
        let result = self
            .get_data_var(
                contract_principal,
                &ContractName::from("sbtc-registry"),
                &ClarityName::from("current-signer-set"),
            )
            .await?;

        // Check the result and return the signer set. We're expecting a
        // list of buffers, where each buffer is a public key.
        match result {
            Value::Sequence(SequenceData::List(ListData { data, .. })) => {
                // Iterate through each record in the list and verify that it's a buffer.
                // If it is a buffer, then convert it to a public key.
                // Otherwise, return an error.
                data.into_iter()
                    .map(|item| match item {
                        // If the item is a buffer, then convert it to a public key.
                        Value::Sequence(SequenceData::Buffer(BuffData { data })) => {
                            PublicKey::from_slice(&data)
                        }
                        // Otherwise, return an error.
                        _ => Err(Error::InvalidStacksResponse(
                            "expected a buffer but got something else",
                        )),
                    })
                    .collect()
            }
            // We expected the top-level value to be a list of buffers,
            // but we got something else.
            _ => Err(Error::InvalidStacksResponse(
                "expected a sequence but got something else",
            )),
        }
    }

    async fn get_current_signers_aggregate_key(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Option<PublicKey>, Error> {
        let result = self
            .get_data_var(
                contract_principal,
                &ContractName::from("sbtc-registry"),
                &ClarityName::from("current-aggregate-pubkey"),
            )
            .await?;

        // Check the result and return the aggregate key.
        match result {
            Value::Sequence(SequenceData::Buffer(BuffData { data })) => {
                // The initial value of the data var is all zeros
                if data.iter().all(|v| *v == 0) {
                    Ok(None)
                } else {
                    PublicKey::from_slice(&data).map(Some)
                }
            }
            _ => Err(Error::InvalidStacksResponse(
                "expected a buffer but got something else",
            )),
        }
    }

    async fn get_account(&self, address: &StacksAddress) -> Result<AccountInfo, Error> {
        self.get_account(address).await
    }

    async fn submit_tx(&self, tx: &StacksTransaction) -> Result<SubmitTxResponse, Error> {
        self.submit_tx(tx).await
    }

    async fn get_block(&self, block_id: StacksBlockId) -> Result<NakamotoBlock, Error> {
        self.get_block(block_id).await
    }

    async fn get_tenure(&self, block_id: StacksBlockId) -> Result<TenureBlocks, Error> {
        self.get_tenure(block_id).await
    }

    async fn get_tenure_info(&self) -> Result<RPCGetTenureInfo, Error> {
        self.get_tenure_info().await
    }

    async fn get_sortition_info(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<SortitionInfo, Error> {
        self.get_sortition_info(consensus_hash).await
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
    async fn estimate_fees<T>(
        &self,
        wallet: &SignerWallet,
        payload: &T,
        priority: FeePriority,
    ) -> Result<u64, Error>
    where
        T: AsTxPayload + Send + Sync,
    {
        let transaction_size = super::wallet::get_full_tx_size(payload, wallet)?;

        // In Stacks core, the minimum fee is 1 mSTX per byte, so take the
        // transaction size and multiply it by the TX_FEE_TX_SIZE_MULTIPLIER
        // here to ensure that 1) we'll be accepted in the mempool, 2) that we
        // have a decent margin above the absolute minimum fee.
        let default_min_fee = (transaction_size * TX_FEE_TX_SIZE_MULTIPLIER).min(MAX_TX_FEE);

        // Estimate attempt #1 - actual payload
        //
        // First we attempt to estimate the fee using the actual transaction
        // payload.
        let tx_size = Some(transaction_size);
        let tx_fee_estimate_response = self.get_fee_estimate(payload, tx_size).await;

        // If we get a valid response, then we use the fee estimate we received,
        // just ensuring that it doesn't exceed our maximum fee.
        match tx_fee_estimate_response {
            Ok(resp) => {
                let estimate = resp.extract_fee(priority).map(|estimate| estimate.fee);

                // If we got a valid estimate, then we use it.
                if let Some(estimate) = estimate {
                    return Ok(estimate.min(MAX_TX_FEE));
                }

                tracing::warn!(
                    "received a fee estimate response, but it did not contain a fee for the specified priority, falling back to STX transfer fee estimation"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "could not estimate contract call fees using the transaction, falling back to STX transfer fee estimation");
            }
        }

        // Estimate attempt #2 - STX transfer
        //
        // Estimating STX transfers is simple since the estimate
        // doesn't depend on the recipient, amount, or memo. So a
        // dummy transfer payload will do.
        let stx_transfer_estimate_response = self
            .get_fee_estimate(&DUMMY_STX_TRANSFER_PAYLOAD, None)
            .await;

        // If we get a valid response, then we use the fee estimate we received,
        // falling back to our calculated default minimum fee if for some reason
        // either we received an error or the estimate was malformed/didn't
        // contain a fee for the specified priority.
        match stx_transfer_estimate_response {
            Ok(resp) => {
                let rate = resp.extract_fee(priority).map(|estimate| estimate.fee_rate);

                // If for some reason we couldn't get the rate for the specified
                // priority, then we fall back to the default minimum fee.
                let Some(rate) = rate else {
                    return Ok(default_min_fee);
                };

                let estimate = ((rate * transaction_size as f64) as u64)
                    .min(MAX_TX_FEE) // Ensure we don't exceed our maximum fee
                    .max(transaction_size * MINIMUM_TX_FEE_RATE_PER_BYTE); // Ensure we don't go below the absolute minimum fee

                Ok(estimate)
            }
            Err(error) => {
                tracing::warn!(%error, "could not estimate STX fees using the Stacks node, falling back to transaction-size-based estimation");
                // Fallback to our calculated minimum fee if we couldn't get an estimate
                // from a Stacks node.
                Ok(default_min_fee)
            }
        }
    }

    async fn get_pox_info(&self) -> Result<RPCPoxInfoData, Error> {
        self.get_pox_info().await
    }

    async fn get_node_info(&self) -> Result<RPCPeerInfoData, Error> {
        self.get_node_info().await
    }

    /// Get the source of a deployed smart contract.
    ///
    /// # Notes
    ///
    /// This is useful just to know whether a contract has been deployed
    /// already or not. If the smart contract has not been deployed yet,
    /// the stacks node returns a 404 Not Found.
    async fn get_contract_source(
        &self,
        address: &StacksAddress,
        contract_name: &str,
    ) -> Result<ContractSrcResponse, Error> {
        self.get_contract_source(address, contract_name).await
    }

    async fn get_sbtc_total_supply(&self, deployer: &StacksAddress) -> Result<Amount, Error> {
        let result = self
            .call_read(
                deployer,
                &ContractName::from(SmartContract::SbtcToken.contract_name()),
                &ClarityName::from("get-total-supply"),
                deployer,
            )
            .await?;

        match result {
            Value::Response(response) => match *response.data {
                Value::UInt(total_supply) => Ok(Amount::from_sat(
                    u64::try_from(total_supply)
                        .map_err(|_| Error::InvalidStacksResponse("total supply is too large"))?,
                )),
                _ => Err(Error::InvalidStacksResponse(
                    "expected a uint but got something else",
                )),
            },
            _ => Err(Error::InvalidStacksResponse(
                "expected a response but got something else",
            )),
        }
    }
}

impl StacksInteract for ApiFallbackClient<StacksClient> {
    async fn get_current_signer_set(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Vec<PublicKey>, Error> {
        self.exec(|client, retry| async move {
            let result = client.get_current_signer_set(contract_principal).await;
            retry.abort_if(|| matches!(result, Err(Error::InvalidStacksResponse(_))));
            result
        })
        .await
    }

    async fn get_current_signers_aggregate_key(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Option<PublicKey>, Error> {
        self.exec(|client, retry| async move {
            let result = client
                .get_current_signers_aggregate_key(contract_principal)
                .await;
            retry.abort_if(|| matches!(result, Err(Error::InvalidStacksResponse(_))));
            result
        })
        .await
    }

    async fn get_account(&self, address: &StacksAddress) -> Result<AccountInfo, Error> {
        self.exec(|client, _| client.get_account(address)).await
    }

    async fn submit_tx(&self, tx: &StacksTransaction) -> Result<SubmitTxResponse, Error> {
        self.exec(|client, _| client.submit_tx(tx)).await
    }

    async fn get_block(&self, block_id: StacksBlockId) -> Result<NakamotoBlock, Error> {
        self.exec(|client, _| client.get_block(block_id)).await
    }

    async fn get_tenure(&self, block_id: StacksBlockId) -> Result<TenureBlocks, Error> {
        self.exec(|client, _| client.get_tenure(block_id)).await
    }

    async fn get_tenure_info(&self) -> Result<RPCGetTenureInfo, Error> {
        self.exec(|client, _| client.get_tenure_info()).await
    }

    async fn get_sortition_info(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<SortitionInfo, Error> {
        self.exec(|client, _| client.get_sortition_info(consensus_hash))
            .await
    }

    async fn estimate_fees<T>(
        &self,
        wallet: &SignerWallet,
        payload: &T,
        priority: FeePriority,
    ) -> Result<u64, Error>
    where
        T: AsTxPayload + Send + Sync,
    {
        self.exec(|client, _| StacksClient::estimate_fees(client, wallet, payload, priority))
            .await
    }

    async fn get_pox_info(&self) -> Result<RPCPoxInfoData, Error> {
        self.exec(|client, _| client.get_pox_info()).await
    }

    async fn get_node_info(&self) -> Result<RPCPeerInfoData, Error> {
        self.exec(|client, _| client.get_node_info()).await
    }

    async fn get_contract_source(
        &self,
        address: &StacksAddress,
        contract_name: &str,
    ) -> Result<ContractSrcResponse, Error> {
        // TODO: We need to properly catch catch certain errors and let
        // them pass. In particular, this error is fine:
        // ```rust
        // Error::StacksNodeResponse(error)
        //      if error.status() == Some(reqwest::StatusCode::NOT_FOUND)
        // ```
        self.get_client()
            .get_contract_source(address, contract_name)
            .await
    }

    async fn get_sbtc_total_supply(&self, deployer: &StacksAddress) -> Result<Amount, Error> {
        self.exec(|client, _| client.get_sbtc_total_supply(deployer))
            .await
    }
}

impl TryFrom<&Settings> for ApiFallbackClient<StacksClient> {
    type Error = Error;

    fn try_from(settings: &Settings) -> Result<Self, Self::Error> {
        let clients = settings
            .stacks
            .endpoints
            .iter()
            .map(|url| StacksClient::new(url.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        ApiFallbackClient::new(clients).map_err(Error::FallbackClient)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::NetworkKind;
    use crate::keys::{PrivateKey, PublicKey};
    use crate::stacks::wallet::get_full_tx_size;
    use crate::storage::in_memory::Store;
    use crate::storage::DbWrite;

    use clarity::types::Address;
    use clarity::vm::types::{
        BuffData, BufferLength, ListData, ListTypeData, SequenceData, SequenceSubtype,
        TypeSignature,
    };
    use rand::rngs::OsRng;
    use secp256k1::Keypair;
    use test_case::test_case;
    use test_log::test;

    use super::*;
    use std::io::Read;

    fn generate_wallet(num_keys: u16, signatures_required: u16) -> SignerWallet {
        let network_kind = NetworkKind::Regtest;

        let public_keys = std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
            .map(|kp| kp.public_key().into())
            .take(num_keys as usize)
            .collect::<Vec<_>>();

        SignerWallet::new(&public_keys, signatures_required, network_kind, 0).unwrap()
    }

    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    #[test(tokio::test)]
    async fn fetch_unknown_ancestors_works() {
        let db = crate::testing::storage::new_test_database().await;

        let settings = Settings::new_from_default_config().unwrap();
        // This is an integration test that will read from the config, which provides
        // a list of endpoints, so we use the fallback client.
        let client: ApiFallbackClient<StacksClient> = TryFrom::try_from(&settings).unwrap();

        let info = client.get_tenure_info().await.unwrap();
        let tenures = fetch_unknown_ancestors(&client, &db, info.tip_block_id).await;

        let blocks = tenures.unwrap();
        let headers = blocks
            .iter()
            .flat_map(TenureBlocks::as_stacks_blocks)
            .collect::<Vec<_>>();
        db.write_stacks_block_headers(headers).await.unwrap();

        crate::testing::storage::drop_db(db).await;
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
    ///    `NakamotoBlock`s in the result. Note that the tenure info only
    ///    gives you the start block ids, you'll need to get the actual
    ///    block to get the last block in a tenure.
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
    #[test_case(|url| StacksClient::new(url).unwrap(); "stacks-client")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client")]
    #[tokio::test]
    async fn get_blocks_test<F, C>(client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        // Here we test that out code will handle the response from a
        // stacks node in the expected way.
        const TENURE_START_BLOCK_ID: &str =
            "5addaf4477a60a9bab28608aa2ec9ea9eb7d68aa038274ecac7a41fdca58e650";
        const TENURE_END_BLOCK_ID: &str =
            "e5fdeb1a51ba6eb297797a1c473e715c27dc81a58ba82c698f6a32eeccee9a5b";

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

        let path = format!("tests/fixtures/stacksapi-v3-sortitions.json");
        let mut file = std::fs::File::open(path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let called_endpoint = "/v3/sortitions/consensus/f9fff2c4c5e5f55788bbd62f6b41aeba99d982fd";
        stacks_node_server
            .mock("GET", called_endpoint)
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("transfer-encoding", "chunked")
            .with_chunked_body(move |w| w.write_all(&buf))
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

        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());

        let block_id = StacksBlockId::from_hex(TENURE_END_BLOCK_ID).unwrap();
        // The moment of truth, do the requests succeed?
        let blocks = client.get_tenure(block_id).await.unwrap().blocks;
        assert!(blocks.len() > 1);

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
    async fn get_sbtc_total_supply_works() {
        let raw_json_response = r#"{
            "okay": true,
            "result": "0x070100000000000000000000000000000539"
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("POST", "/v2/contracts/call-read/SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS/sbtc-token/get-total-supply?tip=latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let client = StacksClient::new(stacks_node_server.url().parse().unwrap()).unwrap();
        let result = client
            .get_sbtc_total_supply(
                &StacksAddress::from_string("SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS").unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(result, Amount::from_sat(1337));
        mock.assert();
    }

    #[test_case(|url| StacksClient::new(url).unwrap(); "stacks-client")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client")]
    #[tokio::test]
    async fn get_tenure_info_works<F, C>(client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
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

        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());
        let resp = client.get_tenure_info().await.unwrap();
        let expected: RPCGetTenureInfo = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);
        first_mock.assert();
    }

    /// Helper method for generating a list of public keys.
    fn generate_pubkeys(count: u16) -> Vec<PublicKey> {
        (0..count)
            .map(|_| PublicKey::from_private_key(&PrivateKey::new(&mut rand::thread_rng())))
            .collect()
    }

    /// Helper method for creating a list of public keys as a Clarity [`Value::Sequence`].
    fn create_clarity_pubkey_list(public_keys: &[PublicKey]) -> Vec<Value> {
        public_keys
            .iter()
            .map(|pk| {
                Value::Sequence(SequenceData::Buffer(BuffData {
                    data: pk.serialize().to_vec(),
                }))
            })
            .collect()
    }

    #[test_case(|url| StacksClient::new(url).unwrap(); "stacks-client")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client")]
    #[tokio::test]
    async fn get_current_signer_set_fails_when_value_not_a_sequence<F, C>(client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        let clarity_value = Value::Int(1234);
        let raw_json_response = format!(
            r#"{{"data":"0x{}"}}"#,
            Value::serialize_to_hex(&clarity_value).expect("failed to serialize value")
        );

        // Setup our mock server
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/data_var/ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM/sbtc-registry/current-signer-set?proof=0")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());

        // Make the request to the mock server
        let resp = client
            .get_current_signer_set(
                &StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
                    .expect("failed to parse stacks address"),
            )
            .await;

        let err = resp.unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidStacksResponse(s) if s == "expected a sequence but got something else"
        ));
        mock.assert();
    }

    #[test_case(0, |url| StacksClient::new(url).unwrap(); "stacks-client-empty-list")]
    #[test_case(128, |url| StacksClient::new(url).unwrap(); "stacks-client-list-128")]
    #[test_case(0, |url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client-empty-list")]
    #[test_case(128, |url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(); "fallback-client-list-128")]
    #[tokio::test]
    async fn get_current_signer_set_works<F, C>(list_size: u16, client: F)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        // Create our simulated response JSON. This uses the same method to generate
        // the serialized list of public keys as the actual Stacks node does.
        let public_keys = generate_pubkeys(list_size);
        let signer_set = Value::Sequence(SequenceData::List(ListData {
            data: create_clarity_pubkey_list(&public_keys),
            type_signature: ListTypeData::new_list(
                TypeSignature::list_of(
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(
                        BufferLength::try_from(33_usize).unwrap(),
                    )),
                    33,
                )
                .expect("failed to create sequence type signature"),
                128,
            )
            .expect("failed to create list type signature"),
        }));
        // The format of the response JSON is `{"data": "0x<serialized-value>"}` (excluding the proof).
        let raw_json_response = format!(
            r#"{{"data":"0x{}"}}"#,
            Value::serialize_to_hex(&signer_set).expect("failed to serialize value")
        );

        // Setup our mock server
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/data_var/ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM/sbtc-registry/current-signer-set?proof=0")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client
        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());

        // Make the request to the mock server
        let resp = client
            .get_current_signer_set(
                &StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
                    .expect("failed to parse stacks address"),
            )
            .await
            .unwrap();

        // Assert that the response is what we expect
        assert_eq!(&resp, &public_keys);
        mock.assert();
    }

    #[test_case(|url| StacksClient::new(url).unwrap(), false; "stacks-client-some")]
    #[test_case(|url| StacksClient::new(url).unwrap(), true; "stacks-client-none")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(), false; "fallback-client-some")]
    #[test_case(|url| ApiFallbackClient::new(vec![StacksClient::new(url).unwrap()]).unwrap(), true; "fallback-client-none")]
    #[tokio::test]
    async fn get_current_signers_aggregate_key_works<F, C>(client: F, return_none: bool)
    where
        C: StacksInteract,
        F: Fn(Url) -> C,
    {
        let aggregate_key = generate_pubkeys(1).into_iter().next().unwrap();

        let data;
        let expected;
        if return_none {
            data = [0; 33].to_vec();
            expected = None;
        } else {
            data = aggregate_key.serialize().to_vec();
            expected = Some(aggregate_key);
        }
        let aggregate_key_clarity = Value::Sequence(SequenceData::Buffer(BuffData { data }));

        // The format of the response JSON is `{"data": "0x<serialized-value>"}` (excluding the proof).
        let raw_json_response = format!(
            r#"{{"data":"0x{}"}}"#,
            Value::serialize_to_hex(&aggregate_key_clarity).expect("failed to serialize value")
        );

        // Setup our mock server
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/data_var/ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM/sbtc-registry/current-aggregate-pubkey?proof=0")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client
        let client = client(url::Url::parse(stacks_node_server.url().as_str()).unwrap());

        // Make the request to the mock server
        let resp = client
            .get_current_signers_aggregate_key(
                &StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
                    .expect("failed to parse stacks address"),
            )
            .await
            .unwrap();

        // Assert that the response is what we expect
        assert_eq!(resp, expected);
        mock.assert();
    }

    #[test_case(0; "empty-list")]
    #[test_case(128; "list-128")]
    #[tokio::test]
    async fn get_data_var_works(list_size: u16) {
        // Create our simulated response JSON. This uses the same method to generate
        // the serialized list of public keys as the actual Stacks node does.
        let signer_set = Value::Sequence(SequenceData::List(ListData {
            data: create_clarity_pubkey_list(&generate_pubkeys(list_size)),
            type_signature: ListTypeData::new_list(
                TypeSignature::list_of(
                    TypeSignature::SequenceType(SequenceSubtype::BufferType(
                        BufferLength::try_from(33_usize).unwrap(),
                    )),
                    33,
                )
                .expect("failed to create sequence type signature"),
                128,
            )
            .expect("failed to create list type signature"),
        }));
        // The format of the response JSON is `{"data": "0x<serialized-value>"}` (excluding the proof).
        let raw_json_response = format!(
            r#"{{"data":"0x{}"}}"#,
            Value::serialize_to_hex(&signer_set).expect("failed to serialize value")
        );

        // Setup our mock server
        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/data_var/ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM/sbtc-registry/current-signer-set?proof=0")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_data_var` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

        // Make the request to the mock server
        let resp = client
            .get_data_var(
                &StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
                    .expect("failed to parse stacks address"),
                &ContractName::from("sbtc-registry"),
                &ClarityName::from("current-signer-set"),
            )
            .await
            .unwrap();

        // Assert that the response is what we expect
        let expected: DataVarResponse = serde_json::from_str(&raw_json_response).unwrap();
        assert_eq!(&resp, &expected.data);
        mock.assert();
    }

    // Check that if we don't get valid responses from the Stacks node for both
    // the transaction and STX transfer fee estimation requests, we fallback to
    // estimating the fee based on the size of the transaction payload.
    #[test_case(15, 11)]
    #[tokio::test]
    async fn estimate_fees_fallback_works(num_keys: u16, signatures_required: u16) {
        let wallet = generate_wallet(num_keys, signatures_required);
        let mut stacks_node_server = mockito::Server::new_async().await;

        // Setup a mock which will fail both the transaction and STX transfer
        // estimation request attempts.
        let mock = stacks_node_server
            .mock("POST", "/v2/fees/transaction")
            .with_status(400)
            .expect(2)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_fee_estimate` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

        let expected_fee = get_full_tx_size(&DUMMY_STX_TRANSFER_PAYLOAD, &wallet).unwrap()
            * TX_FEE_TX_SIZE_MULTIPLIER;

        let resp = client
            .estimate_fees(&wallet, &DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::High)
            .await
            .unwrap();

        assert_eq!(resp, expected_fee);

        mock.assert();
    }

    /// Check that everything works as expected in the happy path case.
    #[tokio::test]
    async fn get_fee_estimate_works() {
        let wallet = generate_wallet(1, 1);
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

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_fee_estimate` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();
        let resp = client
            .get_fee_estimate(&DUMMY_STX_TRANSFER_PAYLOAD, None)
            .await
            .unwrap();
        let expected: RPCFeeEstimateResponse = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);

        // Now lets check that the interface function returns the requested
        // priority fees.
        let fee = client
            .estimate_fees(&wallet, &DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::Low)
            .await
            .unwrap();
        assert_eq!(fee, 7679);

        let fee = client
            .estimate_fees(&wallet, &DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::Medium)
            .await
            .unwrap();
        assert_eq!(fee, 7680);

        let fee = client
            .estimate_fees(&wallet, &DUMMY_STX_TRANSFER_PAYLOAD, FeePriority::High)
            .await
            .unwrap();
        assert_eq!(fee, 25505);

        first_mock.assert();
    }

    #[tokio::test]
    async fn get_pox_info_and_get_nakamoto_start_height_works() {
        let raw_json_response =
            include_str!("../../tests/fixtures/stacksapi-get-pox-info-test-data.json");

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/pox")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_pox_info` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();
        let resp = client.get_pox_info().await.unwrap();
        let expected: RPCPoxInfoData = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);
        mock.assert();

        let nakamoto_start_height = resp.nakamoto_start_height();
        assert!(nakamoto_start_height.is_some());
        assert_eq!(nakamoto_start_height.unwrap(), 232);
    }

    #[tokio::test]
    async fn get_node_info_works() {
        let raw_json_response =
            include_str!("../../tests/fixtures/stacksapi-get-node-info-test-data.json");

        let mut stacks_node_server = mockito::Server::new_async().await;
        let mock = stacks_node_server
            .mock("GET", "/v2/info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        // Setup our Stacks client. We use a regular client here because we're
        // testing the `get_node_info` method.
        let client =
            StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();
        let resp = client.get_node_info().await.unwrap();
        let expected: RPCPeerInfoData = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);
        mock.assert();
    }

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn fetching_last_tenure_blocks_works() {
        let settings = Settings::new_from_default_config().unwrap();
        // We use the fallback client here because the CI test reads from the config
        // which provides a list of endpoints.
        let client: ApiFallbackClient<StacksClient> = TryFrom::try_from(&settings).unwrap();
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
        let settings = Settings::new_from_default_config().unwrap();
        // We use the fallback client here because the CI test reads from the config
        // which provides a list of endpoints.
        let client: ApiFallbackClient<StacksClient> = TryFrom::try_from(&settings).unwrap();

        let address = StacksAddress::burn_address(false);
        let account = client.get_account(&address).await.unwrap();
        assert_eq!(account.nonce, 0);
    }
}
