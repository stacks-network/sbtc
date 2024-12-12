//! Contains functionality for interacting with the Bitcoin blockchain

use std::future::Future;

use bitcoin::BlockHash;
use bitcoin::Txid;

use bitcoincore_rpc_json::GetMempoolEntryResult;
use bitcoincore_rpc_json::GetTxOutResult;
use rpc::BitcoinBlockHeader;
use rpc::BitcoinTxInfo;
use rpc::GetTxResponse;

use crate::error::Error;

pub mod client;
pub mod fees;
pub mod packaging;
pub mod rpc;
pub mod utxo;
pub mod validation;
pub mod zmq;

/// Result of a call to `get_transaction_fee`.
#[derive(Debug, Clone)]
pub struct GetTransactionFeeResult {
    /// The fee paid by the transaction.
    pub fee: u64,
    /// The fee rate of the transaction in satoshi per vbyte.
    pub fee_rate: f64,
    /// The virtual size of the transaction.
    pub vsize: u64,
}

/// An enum representing the possible locations of a transaction, used to
/// optimize certain lookups. It is assumed that an
/// `Option<TransactionLookupHint>` is used to indicate that the caller is
/// unsure of the location of the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionLookupHint {
    /// The transaction is in the mempool.
    Mempool,
    /// The transaction is in a (known) block.
    Confirmed,
}

/// Represents the ability to interact with the bitcoin blockchain
#[cfg_attr(any(test, feature = "testing"), mockall::automock())]
pub trait BitcoinInteract: Sync + Send {
    /// Get block
    fn get_block(
        &self,
        block_hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<bitcoin::Block>, Error>> + Send;

    /// Get the header of the block identified by the given block hash.
    fn get_block_header(
        &self,
        block_hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<BitcoinBlockHeader>, Error>> + Send;

    /// get tx
    fn get_tx(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<Option<GetTxResponse>, Error>> + Send;

    /// Get a transaction with additional information about it.
    fn get_tx_info(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<BitcoinTxInfo>, Error>> + Send;

    /// Estimate fee rate
    // This should be implemented with the help of the `fees::EstimateFees` trait
    fn estimate_fee_rate(&self) -> impl std::future::Future<Output = Result<f64, Error>> + Send;

    /// Broadcast transaction
    fn broadcast_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Find transactions in the mempool which spend the given output. `txid`
    /// must be a known confirmed transaction.
    ///
    /// This method returns an (unordered) list of transaction IDs which are in
    /// the mempool and spend the given (confirmed) output.
    ///
    /// If there are no transactions in the mempool which spend the given
    /// output, an empty list is returned.
    fn find_mempool_transactions_spending_output(
        &self,
        outpoint: &bitcoin::OutPoint,
    ) -> impl Future<Output = Result<Vec<Txid>, Error>> + Send;

    /// Finds all transactions in the mempool which are descendants of the given
    /// mempool transaction. `txid` must be a transaction in the mempool.
    ///
    /// This method returns an (unordered) list of transaction IDs which are
    /// both direct and indirect descendants of the given transaction, meaning
    /// that they either directly spend an output of the given transaction or
    /// spend an output of a transaction which is itself a descendant of the
    /// given transaction.
    ///
    /// If there are no descendants of the given transaction in the mempool, an
    /// empty list is returned.
    ///
    /// Use [`Self::find_mempool_transactions_spending_output`] to find
    /// transactions in the mempool which spend an output of a confirmed
    /// transaction if needed prior to calling this method.
    fn find_mempool_descendants(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<Vec<Txid>, Error>> + Send;

    /// Gets the output of the specified transaction, optionally including
    /// transactions from the mempool.
    fn get_transaction_output(
        &self,
        outpoint: &bitcoin::OutPoint,
        include_mempool: bool,
    ) -> impl Future<Output = Result<Option<GetTxOutResult>, Error>> + Send;

    /// Gets the associated fees for the given transaction. It is expected that
    /// the provided transaction is known to the Bitcoin core node, either
    /// confirmed or in the mempool, otherwise an error will be returned.
    fn get_transaction_fee(
        &self,
        tx: &Txid,
        lookup_hint: Option<TransactionLookupHint>,
    ) -> impl Future<Output = Result<GetTransactionFeeResult, Error>> + Send;

    /// Attempts to get the mempool entry for the given transaction ID.
    fn get_mempool_entry(
        &self,
        txid: &Txid,
    ) -> impl Future<Output = Result<Option<GetMempoolEntryResult>, Error>> + Send;
}
