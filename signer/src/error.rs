#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The change amounts for the transaction is negative: {0}")]
    InvalidAmount(i64),

    #[error("An error occured when constructing the taproot signing digest: {0}")]
    Taproot(#[from] bitcoin::sighash::TaprootError),
}
