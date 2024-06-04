//! Top-level error type for the signer
use blockstack_lib::types::chainstate::StacksBlockId;

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

    /// Parsing the Hex Error
    #[error("Could not parse the Hex string to a StacksBlockId: {0}, original: {1}")]
    ParseStacksBlockId(#[source] blockstack_lib::util::HexError, String),

    /// Parsing the Hex Error
    #[error("Could not decode the Nakamoto block with ID: {1}; {0}")]
    DecodeNakamotoBlock(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// Could not parse the path part of a url
    #[error("{0}")]
    PathParse(#[source] url::ParseError),

    /// Reqwest error
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),

    /// Error when reading the signer config.toml
    #[error("Failed to read the signers config file: {0}")]
    SignerConfig(#[source] config::ConfigError),

    /// Error when reading the stacks API part of the config.toml
    #[error("Failed to parse the stacks.api portion of the config: {0}")]
    StacksApiConfig(#[source] config::ConfigError),

    /// Taproot error
    #[error("An error occured when constructing the taproot signing digest: {0}")]
    Taproot(#[from] bitcoin::sighash::TaprootError),
}
