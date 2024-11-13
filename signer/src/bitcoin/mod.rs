//! Contains functionality for interacting with the Bitcoin blockchain

use std::future::Future;

use bitcoin::BlockHash;
use bitcoin::Txid;

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

/// Represents the ability to interact with the bitcoin blockchain
#[cfg_attr(any(test, feature = "testing"), mockall::automock())]
pub trait BitcoinInteract: Sync + Send {
    /// Get block
    fn get_block(
        &self,
        block_hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<bitcoin::Block>, Error>> + Send;

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
}
