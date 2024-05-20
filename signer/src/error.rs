//! Top-level error type for the signer

/// Top-level signer error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid amount
    #[error("The change amounts for the transaction is negative: {0}")]
    InvalidAmount(i64),

    /// Old fee estimate
    #[error("Got an old fee estimate")]
    OldFeeEstimate,

    /// No good fee estimate
    #[error("Failed to get fee estimates from all fee estimate sources")]
    NoGoodFeeEstimates,

    /// Reqwest error
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),

    /// Taproot error
    #[error("An error occured when constructing the taproot signing digest: {0}")]
    Taproot(#[from] bitcoin::sighash::TaprootError),
}
