#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The change amounts for the transaction is negative: {0}")]
    InvalidAmount(i64),

    #[error("Got an old fee estimate")]
    OldFeeEstimate,

    #[error("Failed to get fee estimates from all fee estimate sources")]
    NoGoodFeeEstimates,

    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("An error occured when constructing the taproot signing digest: {0}")]
    Taproot(#[from] bitcoin::sighash::TaprootError),
}
