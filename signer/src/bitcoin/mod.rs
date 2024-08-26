//! Contains functionality for interacting with the Bitcoin blockchain

use std::future::Future;

use crate::keys::PublicKey;

pub mod fees;
pub mod packaging;
pub mod utxo;
pub mod zmq;

/// Represents the ability to interact with the bitcoin blockchain
#[cfg_attr(any(test, feature = "testing"), mockall::automock(type Error=crate::error::Error;))]
pub trait BitcoinInteract {
    /// Error type
    type Error;

    /// Get block
    fn get_block(
        &mut self,
        block_hash: &bitcoin::BlockHash,
    ) -> impl Future<Output = Result<Option<bitcoin::Block>, Self::Error>> + Send;

    /// Estimate fee rate
    // This should be implemented with the help of the `fees::EstimateFees` trait
    fn estimate_fee_rate(
        &mut self,
    ) -> impl std::future::Future<Output = Result<f64, Self::Error>> + Send;

    /// Get the outstanding signer UTXO
    fn get_signer_utxo(
        &mut self,
        aggregate_key: &PublicKey,
    ) -> impl Future<Output = Result<Option<utxo::SignerUtxo>, Self::Error>> + Send;

    /// Get the total fee amount and the fee rate for the last transaction that
    /// used the given UTXO as an input.
    fn get_last_fee(
        &mut self,
        utxo: bitcoin::OutPoint,
    ) -> impl Future<Output = Result<Option<utxo::Fees>, Self::Error>> + Send;

    /// Broadcast transaction
    fn broadcast_transaction(
        &mut self,
        tx: &bitcoin::Transaction,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
