//! Top-level error type for the signer
use std::borrow::Cow;

use blockstack_lib::types::chainstate::StacksBlockId;

use crate::{ecdsa, network};

/// Top-level signer error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid amount
    #[error("the change amounts for the transaction is negative: {0}")]
    InvalidAmount(i64),

    /// Old fee estimate
    #[error("got an old fee estimate")]
    OldFeeEstimate,

    /// No good fee estimate
    #[error("failed to get fee estimates from all fee estimate sources")]
    NoGoodFeeEstimates,

    /// Parsing the Hex Error
    #[error("Could not parse the Hex string to a StacksBlockId: {0}, original: {1}")]
    ParseStacksBlockId(#[source] blockstack_lib::util::HexError, String),

    /// Parsing the Hex Error
    #[error("Could not decode the Nakamoto block with ID: {1}; {0}")]
    DecodeNakamotoBlock(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// Thrown when parsing a Nakamoto block within a given tenure.
    #[error("Could not decode Nakamoto block from tenure with block: {1}; {0}")]
    DecodeNakamotoTenure(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// An error when serializing an object to JSON
    #[error("{0}")]
    JsonSerialize(#[source] serde_json::Error),

    /// Could not parse the path part of a url
    #[error("Failed to construct a valid URL from {1} and {2}: {0}")]
    PathJoin(#[source] url::ParseError, url::Url, Cow<'static, str>),

    /// Reqwest error
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    /// Error when reading the signer config.toml
    #[error("Failed to read the signers config file: {0}")]
    SignerConfig(#[source] config::ConfigError),

    /// An error when querying the signer's database.
    #[error("Received an error when attempting to query the database: {0}")]
    SqlxQuery(#[source] sqlx::Error),

    /// Error when reading the stacks API part of the config.toml
    #[error("Failed to parse the stacks.api portion of the config: {0}")]
    StacksApiConfig(#[source] config::ConfigError),

    /// Could not make a successful request to the stacks API.
    #[error("Failed to make a request to the stacks API: {0}")]
    StacksApiRequest(#[source] reqwest::Error),

    /// Could not make a successful request to the stacks node.
    #[error("Failed to make a request to the stacks Node: {0}")]
    StacksNodeRequest(#[source] reqwest::Error),

    /// Reqwest error
    #[error("Response from stacks node did not conform to the expected schema: {0}")]
    UnexpectedStacksResponse(#[source] reqwest::Error),

    /// Taproot error
    #[error("an error occured when constructing the taproot signing digest: {0}")]
    Taproot(#[from] bitcoin::sighash::TaprootError),

    /// Signer loop error
    #[error("signer loop error: {0}")]
    TransactionSignerError(#[from] crate::transaction_signer::Error),

    /// Key error
    #[error("key error: {0}")]
    KeyError(#[from] p256k1::keys::Error),

    /// Missing block
    #[error("missing block")]
    MissingBlock,

    /// Invalid signature
    #[error("invalid signature")]
    InvalidSignature,

    /// Slice conversion error
    #[error("slice conversion failed: {0}")]
    SliceConversion(#[source] bitcoin::hashes::FromSliceError),

    /// ECDSA error
    #[error("ECDSA error: {0}")]
    Ecdsa(#[from] ecdsa::Error),

    /// In-memory network error
    #[error("in-memory network error: {0}")]
    InMemoryNetwork(#[from] network::in_memory::Error),

    /// GRPC relay network error
    #[error("GRPC relay network error: {0}")]
    GrpcRelayNetworkError(#[from] network::grpc_relay::RelayError),
}

impl From<std::convert::Infallible> for Error {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}
