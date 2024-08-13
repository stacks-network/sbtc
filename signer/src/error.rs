//! Top-level error type for the signer
use std::borrow::Cow;

use blockstack_lib::types::chainstate::StacksBlockId;

use crate::{codec, ecdsa, network};

/// Top-level signer error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error when breaking out the ZeroMQ message into three parts.
    #[error("bitcoin messages should have a three part layout, received {0} parts")]
    BitcoinCoreZmqMessageLayout(usize),

    /// Happens when the bitcoin block hash in the ZeroMQ message is not 32
    /// bytes.
    #[error("block hashes should be 32 bytes, but we received {0} bytes")]
    BitcoinCoreZmqBlockHash(usize),

    /// Happens when the ZeroMQ sequence number is not 4 bytes.
    #[error("sequence numbers should be 4 bytes, but we received {0} bytes")]
    BitcoinCoreZmqSequenceNumber(usize),

    /// The given message type is unsupported. We attempt to parse what the
    /// topic is but that might fail as well.
    #[error("the message topic {0:?} is unsupported")]
    BitcoinCoreZmqUnsupported(Result<String, std::str::Utf8Error>),

    /// This is for when bitcoin::Transaction::consensus_encode fails. It
    /// should never happen.
    #[error("could not serialize bitcoin transaction into bytes.")]
    BitcoinEncodeTransaction(#[source] bitcoin::io::Error),

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
    #[error("could not parse the Hex string to a StacksBlockId: {0}, original: {1}")]
    ParseStacksBlockId(#[source] blockstack_lib::util::HexError, String),

    /// Parsing the Hex Error
    #[error("could not decode the bitcoin block: {0}")]
    DecodeBitcoinBlock(#[source] bitcoin::consensus::encode::Error),

    /// Parsing the Hex Error
    #[error("could not decode the Nakamoto block with ID: {1}; {0}")]
    DecodeNakamotoBlock(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// Thrown when parsing a Nakamoto block within a given tenure.
    #[error("could not decode Nakamoto block from tenure with block: {1}; {0}")]
    DecodeNakamotoTenure(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// An error when serializing an object to JSON
    #[error("{0}")]
    JsonSerialize(#[source] serde_json::Error),

    /// Could not parse the path part of a URL
    #[error("failed to construct a valid URL from {1} and {2}: {0}")]
    PathJoin(#[source] url::ParseError, url::Url, Cow<'static, str>),

    /// This occurs when combining many public keys would result in a
    /// "public key" that is the point at infinity.
    #[error("{0}")]
    InvalidAggregateKey(#[source] secp256k1::Error),

    /// This occurs when converting a byte slice to our internal public key
    /// type, which is a thin wrapper around the secp256k1::PublicKey.
    #[error("{0}")]
    InvalidPublicKey(#[source] secp256k1::Error),

    /// This happens when we tweak our public key by a scalar, and the
    /// result is an invalid public key. I think It is very unlikely that
    /// we will see this one by chance, since the probability that this
    /// happens is something like: 1 / (2^256 - 2^32^ - 977), where the
    /// denominator is the order of the secp256k1 curve. This is because
    /// for a given public key, the there is only one tweak that will lead
    /// to an invalid public key.
    #[error("invalid tweak? seriously? {0}")]
    InvalidPublicKeyTweak(#[source] secp256k1::Error),

    /// This occurs when converting a byte slice to our internal public key
    /// type, which is a thin wrapper around the secp256k1::SecretKey.
    #[error("{0}")]
    InvalidPrivateKey(#[source] secp256k1::Error),

    /// This happens when we attempt to recover a public key from a
    /// recoverable EDCSA signature.
    #[error("could not recover the public key from the signature: {0}, digest: {1}")]
    InvalidRecoverableSignature(#[source] secp256k1::Error, secp256k1::Message),

    /// This is thrown when we attempt to create a wallet with:
    /// 1. No public keys.
    /// 2. No required signatures.
    /// 3. The number of required signatures exceeding the number of public
    ///    keys.
    /// 4. The number of public keys exceeds the MAX_KEYS constant.
    #[error("invalid wallet definition, signatures required: {0}, number of keys: {1}")]
    InvalidWalletDefinition(u16, usize),

    /// This is thrown when failing to parse a hex string into an integer.
    #[error("could not parse the hex string into an integer")]
    ParseHexInt(#[source] std::num::ParseIntError),

    /// Reqwest error
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    /// Error when reading the signer config.toml
    #[error("failed to read the signers config file: {0}")]
    SignerConfig(#[source] config::ConfigError),

    /// An error when querying the signer's database.
    #[error("received an error when attempting to query the database: {0}")]
    SqlxQuery(#[source] sqlx::Error),

    /// An error for the case where we cannot create a multi-sig
    /// StacksAddress using given public keys.
    #[error("could not create a StacksAddress from the public keys: threshold {0}, keys {1}")]
    StacksMultiSig(u16, usize),

    /// Error when reading the stacks API part of the config.toml
    #[error("failed to parse the stacks.api portion of the config: {0}")]
    StacksApiConfig(#[source] config::ConfigError),

    /// This error happens when converting a sepc256k1::PublicKey into a
    /// blockstack_lib::util::secp256k1::Secp256k1PublicKey. In general, it
    /// shouldn't happen.
    #[error("could not transform sepc256k1::PublicKey to stacks variant: {0}")]
    StacksPublicKey(&'static str),

    /// Could not make a successful request to the stacks API.
    #[error("received a non success status code response from a stacks node: {0}")]
    StacksNodeResponse(#[source] reqwest::Error),

    /// Could not make a successful request to the Stacks node.
    #[error("failed to make a request to the stacks Node: {0}")]
    StacksNodeRequest(#[source] reqwest::Error),

    /// Reqwest error
    #[error("response from stacks node did not conform to the expected schema: {0}")]
    UnexpectedStacksResponse(#[source] reqwest::Error),

    /// Taproot error
    #[error("an error occurred when constructing the taproot signing digest: {0}")]
    Taproot(#[from] bitcoin::sighash::TaprootError),

    /// Key error
    #[error("key error: {0}")]
    KeyError(#[from] p256k1::keys::Error),

    /// Missing block
    #[error("missing block")]
    MissingBlock,

    /// Missing dkg shares
    #[error("missing dkg shares")]
    MissingDkgShares,

    /// Missing public key
    #[error("missing public key")]
    MissingPublicKey,

    /// Missing state machine
    #[error("missing state machine")]
    MissingStateMachine,

    /// Missing key rotation
    #[error("missing key rotation")]
    MissingKeyRotation,

    /// Invalid signature
    #[error("invalid signature")]
    InvalidSignature,

    /// Slice conversion error
    #[error("slice conversion failed: {0}")]
    SliceConversion(#[source] bitcoin::hashes::FromSliceError),

    /// ECDSA error
    #[error("ECDSA error: {0}")]
    Ecdsa(#[from] ecdsa::Error),

    /// Codec error
    #[error("codec error: {0}")]
    Codec(#[source] codec::Error),

    /// In-memory network error
    #[error("in-memory network error: {0}")]
    InMemoryNetwork(#[from] network::in_memory::Error),

    /// GRPC relay network error
    #[error("GRPC relay network error: {0}")]
    GrpcRelayNetworkError(#[from] network::grpc_relay::RelayError),

    /// Type conversion error
    #[error("type conversion error")]
    TypeConversion,

    /// Encryption error
    #[error("encryption error")]
    Encryption,

    /// Invalid configuration
    #[error("invalid configuration")]
    InvalidConfiguration,

    /// Observer dropped
    #[error("observer dropped")]
    ObserverDropped,

    /// Thrown when the recoverable signature has a public key that is
    /// unexpected.
    #[error("unexpected public key from signature. key {0}; digest: {1}")]
    UnknownPublicKey(crate::keys::PublicKey, secp256k1::Message),

    /// WSTS error.
    #[error("WSTS error: {0}")]
    Wsts(#[source] wsts::state_machine::signer::Error),

    /// WSTS coordinator error.
    #[error("WSTS coordinator error: {0}")]
    WstsCoordinator(#[source] Box<wsts::state_machine::coordinator::Error>),

    /// No chain tip found.
    #[error("no bitcoin chain tip")]
    NoChainTip,

    /// Bitcoin address parse error
    #[error("bitcoin address parse error")]
    BitcoinAddressParse(#[source] bitcoin::address::ParseError),

    /// Parsing address failed
    #[error("failed to parse address")]
    ParseAddress(#[source] bitcoin::address::ParseError),

    /// Could not connect to bitcoin-core with a zeromq subscription
    /// socket.
    #[error("{0}")]
    ZmqConnect(#[source] zeromq::ZmqError),

    /// Error when receiving a message from to bitcoin-core over zeromq.
    #[error("{0}")]
    ZmqReceive(#[source] zeromq::ZmqError),

    /// Could not subscribe to bitcoin-core with a zeromq subscription
    /// socket.
    #[error("{0}")]
    ZmqSubscribe(#[source] zeromq::ZmqError),
}

impl From<std::convert::Infallible> for Error {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}
