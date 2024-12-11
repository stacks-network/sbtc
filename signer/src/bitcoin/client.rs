//! Bitcoin Core RPC client implementations
//!
//! Here's some info about the Bitcoin Core RPC client errors:
//!
//! - Example when the node is not running/unreachable:
//!   JsonRpc(Transport(SocketError(Os { code: 111, kind: ConnectionRefused, message: "Connection refused" })))
//!
//! - Example when authentication fails:
//!   JsonRpc(Transport(HttpErrorCode(401)))
//!
//! - Example when trying to estimate fees but the node doesn't have enough data:
//!   EstimateSmartFeeResponse(Some(["Insufficient data or no feerate found"]), 1)
//!
//! - Example when trying to get a block that doesn't exist:
//!   JsonRpc(Rpc(RpcError { code: -5, message: "Block not found", data: None }))

use bitcoin::BlockHash;
use bitcoin::Txid;
use bitcoincore_rpc_json::GetTxOutResult;
use url::Url;

use crate::{error::Error, util::ApiFallbackClient};

use super::rpc::BitcoinBlockHeader;
use super::rpc::BitcoinCoreClient;
use super::rpc::BitcoinTxInfo;
use super::rpc::GetTxResponse;
use super::BitcoinInteract;
use super::TransactionLookupHint;

/// Implement the [`TryFrom`] trait for a slice of [`Url`]s to allow for a
/// [`ApiFallbackClient`] to be implicitly created from a list of URLs.
impl TryFrom<&[Url]> for ApiFallbackClient<BitcoinCoreClient> {
    type Error = Error;
    fn try_from(urls: &[Url]) -> Result<Self, Self::Error> {
        let clients = urls
            .iter()
            .map(BitcoinCoreClient::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(clients).map_err(Into::into)
    }
}

impl BitcoinInteract for ApiFallbackClient<BitcoinCoreClient> {
    async fn get_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<Option<bitcoin::Block>, Error> {
        self.exec(|client, _| async { client.get_block(block_hash) })
            .await
    }

    async fn get_block_header(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Option<BitcoinBlockHeader>, Error> {
        self.exec(|client, _| BitcoinInteract::get_block_header(client, block_hash))
            .await
    }

    async fn get_tx(&self, txid: &Txid) -> Result<Option<GetTxResponse>, Error> {
        self.exec(|client, _| BitcoinInteract::get_tx(client, txid))
            .await
    }

    async fn get_tx_info(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
    ) -> Result<Option<BitcoinTxInfo>, Error> {
        self.exec(|client, _| BitcoinInteract::get_tx_info(client, txid, block_hash))
            .await
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        // TODO(542)
        self.exec(|client, _| BitcoinInteract::estimate_fee_rate(client))
            .await
    }

    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), Error> {
        self.exec(|client, _| client.broadcast_transaction(tx))
            .await
    }

    async fn find_mempool_transactions_spending_output(
        &self,
        outpoint: &bitcoin::OutPoint,
    ) -> Result<Vec<Txid>, Error> {
        self.exec(|client, _| client.find_mempool_transactions_spending_output(outpoint))
            .await
    }

    async fn find_mempool_descendants(&self, txid: &Txid) -> Result<Vec<Txid>, Error> {
        self.exec(|client, _| client.find_mempool_descendants(txid))
            .await
    }

    async fn get_transaction_output(
        &self,
        outpoint: &bitcoin::OutPoint,
        include_mempool: bool,
    ) -> Result<Option<GetTxOutResult>, Error> {
        self.exec(|client, _| client.get_transaction_output(outpoint, include_mempool))
            .await
    }

    async fn get_transaction_fee(
        &self,
        txid: &bitcoin::Txid,
        lookup_hint: Option<TransactionLookupHint>,
    ) -> Result<super::GetTransactionFeeResult, Error> {
        self.exec(|client, _| client.get_transaction_fee(txid, lookup_hint))
            .await
    }

    async fn get_mempool_entry(
        &self,
        txid: &Txid,
    ) -> Result<Option<bitcoincore_rpc_json::GetMempoolEntryResult>, Error> {
        self.exec(|client, _| async { client.get_mempool_entry(txid) })
            .await
    }
}
