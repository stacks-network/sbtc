//! Contains functionality for interacting with the Bitcoin blockchain

/// Represents the ability to interact with the bitcoin blockchain
pub trait BitcoinInteract {
    /// Error type
    type Error;

    /// Get block
    fn get_block(
        &mut self,
        block_hash: &bitcoin::BlockHash,
    ) -> impl std::future::Future<Output = Result<Option<bitcoin::Block>, Self::Error>>;

    /// Estimate fee rate
    // This should be implemented with the help of the `fees::EstimateFees` trait
    fn estimate_fee_rate(&mut self) -> impl std::future::Future<Output = Result<f64, Self::Error>>;
}
