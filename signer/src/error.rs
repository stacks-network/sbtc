#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The change amounts for the transaction is negative: {0}")]
    InvalidAmount(i64),
}
