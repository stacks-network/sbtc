//! Contains functionality for interacting with the Bitcoin blockchain

use std::future::Future;

use bitcoin::BlockHash;
use bitcoin::Txid;

use rpc::BitcoinTxInfo;
use rpc::GetTxResponse;

use crate::error::Error;
use crate::keys::PublicKey;

pub mod client;
pub mod fees;
pub mod packaging;
pub mod rpc;
pub mod utxo;
pub mod zmq;

/// Represents the ability to interact with the bitcoin blockchain
#[cfg_attr(any(test, feature = "testing"), mockall::automock())]
pub trait BitcoinInteract {
    /// Get block
    fn get_block(
        &self,
        block_hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<bitcoin::Block>, Error>> + Send;

    /// get tx
    fn get_tx(&self, txid: &Txid) -> Result<Option<GetTxResponse>, Error>;

    /// get tx info
    fn get_tx_info(
        &self,
        txid: &Txid,
        block_hash: &BlockHash,
    ) -> Result<Option<BitcoinTxInfo>, Error>;

    /// Estimate fee rate
    // This should be implemented with the help of the `fees::EstimateFees` trait
    fn estimate_fee_rate(&self) -> impl std::future::Future<Output = Result<f64, Error>> + Send;

    /// Get the outstanding signer UTXO
    fn get_signer_utxo(
        &self,
        aggregate_key: &PublicKey,
    ) -> impl Future<Output = Result<Option<utxo::SignerUtxo>, Error>> + Send;

    /// Get the total fee amount and the fee rate for the last transaction that
    /// used the given UTXO as an input.
    fn get_last_fee(
        &self,
        utxo: bitcoin::OutPoint,
    ) -> impl Future<Output = Result<Option<utxo::Fees>, Error>> + Send;

    /// Broadcast transaction
    fn broadcast_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
