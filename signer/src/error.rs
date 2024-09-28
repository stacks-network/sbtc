//! Top-level error type for the signer
use std::borrow::Cow;

use blockstack_lib::types::chainstate::StacksBlockId;

use crate::codec;
use crate::ecdsa;
use crate::emily_client::EmilyClientError;
use crate::stacks::contracts::DepositValidationError;
use crate::stacks::contracts::WithdrawalAcceptValidationError;

/// Top-level signer error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error occurred while communicating with the Emily API
    #[error("emily API error: {0}")]
    EmilyApi(#[from] EmilyClientError),

    /// Attemmpt to fetch a bitcoin blockhash ended in an unexpected error.
    /// This is not triggered if the block is missing.
    #[error("bitcoin-core getblock RPC error for hash {1}: {0}")]
    BitcoinCoreGetBlock(#[source] bitcoincore_rpc::Error, bitcoin::BlockHash),

    /// Received an error in response to getrawtransaction RPC call
    #[error("failed to retrieve the raw transaction for txid {1} from bitcoin-core. {0}")]
    BitcoinCoreGetTransaction(#[source] bitcoincore_rpc::Error, bitcoin::Txid),

    /// Error when creating an RPC client to bitcoin-core
    #[error("could not create RPC client to {1}: {0}")]
    BitcoinCoreRpcClient(#[source] bitcoincore_rpc::Error, String),

    /// The bitcoin tranaction was not found in the mempool or on the
    /// bitcoin blockchain. This is thrown when we expect the transaction
    /// to exist in bitcoin core but it does not.
    #[error("Transaction is missing from mempool")]
    BitcoinTxMissing(bitcoin::Txid),

    /// Received an error in call to estimatesmartfee RPC call
    #[error("failed to get fee estimate from bitcoin-core for target {1}. {0}")]
    EstimateSmartFee(#[source] bitcoincore_rpc::Error, u16),

    /// Received an error in response to estimatesmartfee RPC call
    #[error("failed to get fee estimate from bitcoin-core for target {1}. {0:?}")]
    EstimateSmartFeeResponse(Option<Vec<String>>, u16),

    /// Error from the fallback client.
    #[error("fallback client error: {0}")]
    FallbackClient(#[from] crate::util::FallbackClientError),

    /// Error from the Bitcoin RPC client.
    #[error("bitcoin RPC error: {0}")]
    BitcoinCoreRpc(#[from] bitcoincore_rpc::Error),

    /// An error propogated from the sBTC library.
    #[error("sBTC lib error: {0}")]
    SbtcLib(#[from] sbtc::error::Error),

    /// Error incurred during the execution of the libp2p swarm.
    #[error("an error occurred running the libp2p swarm: {0}")]
    SignerSwarm(#[from] crate::network::libp2p::SignerSwarmError),

    /// The requested operation is not allowed in the current state as the
    /// signer is being shut down.
    #[error("the signer is shutting down")]
    SignerShutdown,

    /// I/O Error raised by the Tokio runtime.
    #[error("tokio i/o error: {0}")]
    TokioIo(#[from] tokio::io::Error),

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

    /// This happens when parsing a string, usually from the database, into
    /// a PrincipalData.
    #[error("Could not parse the string into PrincipalData: {0}")]
    ParsePrincipalData(#[source] clarity::vm::errors::Error),

    /// Could not send a message
    #[error("Could not send a message from the in-memory MessageTransfer broadcast function")]
    SendMessage,

    /// Could not receive a message from the channel.
    #[error("{0}")]
    ChannelReceive(#[source] tokio::sync::broadcast::error::RecvError),

    /// Thrown when doing [`i64::try_from`] or [`i32::try_from`] before
    /// inserting a value into the database. This only happens if the value
    /// is greater than MAX for the signed type.
    #[error("could not convert integer type to the signed version for storing in postgres {0}")]
    ConversionDatabaseInt(#[source] std::num::TryFromIntError),

    /// Parsing the Hex Error
    #[error("could not decode the bitcoin block: {0}")]
    DecodeBitcoinBlock(#[source] bitcoin::consensus::encode::Error),

    /// Parsing the Hex Error
    #[error("could not decode the Nakamoto block with ID: {1}; {0}")]
    DecodeNakamotoBlock(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// Thrown when parsing a Nakamoto block within a given tenure.
    #[error("could not decode Nakamoto block from tenure with block: {1}; {0}")]
    DecodeNakamotoTenure(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// Failed to validate the complete-deposit contract call transaction.
    #[error("{0}")]
    DepositValidation(#[from] Box<DepositValidationError>),

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

    /// This occurs when converting a byte slice to a [`PrivateKey`](crate::keys::PrivateKey)
    /// and the length of the byte slice is not 32.
    #[error("invalid private key length={0}, expected 32.")]
    InvalidPrivateKeyLength(usize),

    /// This happens when we attempt to convert a `[u8; 65]` into a
    /// recoverable EDCSA signature.
    #[error("could not recover the public key from the signature: {0}")]
    InvalidRecoverableSignatureBytes(#[source] secp256k1::Error),

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

    /// Error when parsing a URL
    #[error("could not parse the provided URL: {0}")]
    InvalidUrl(#[source] url::ParseError),

    /// This is thrown when failing to parse a hex string into an integer.
    #[error("could not parse the hex string into an integer")]
    ParseHexInt(#[source] std::num::ParseIntError),

    /// Error when the port is not provided
    #[error("a port must be specified")]
    PortRequired,

    /// This is thrown when failing to parse a hex string into bytes.
    #[error("could not decode the hex string into bytes: {0}")]
    DecodeHexBytes(#[source] hex::FromHexError),

    /// Reqwest error
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    /// Error when reading the signer config.toml
    #[error("failed to read the signers config file: {0}")]
    SignerConfig(#[source] config::ConfigError),

    /// An error when querying the signer's database.
    #[error("received an error when attempting to query the database: {0}")]
    SqlxQuery(#[source] sqlx::Error),

    /// An error occurred while attempting to connect to the database.
    #[error("received an error when attempting to connect to the database: {0}")]
    SqlxConnect(#[source] sqlx::Error),

    /// An error occurred while attempting to run sqlx migrations.
    #[error("encountered an error while running sqlx migrations: {0}")]
    SqlxMigrate(#[source] sqlx::Error),

    /// An error occurred while attempting to begin an sqlx transaction.
    #[error("encountered an error while beginning an sqlx transaction: {0}")]
    SqlxBeginTransaction(#[source] sqlx::Error),

    /// An error occurred while attempting to commit an sqlx transaction.
    #[error("encountered an error while committing an sqlx transaction: {0}")]
    SqlxCommitTransaction(#[source] sqlx::Error),

    /// An error occurred while attempting to rollback an sqlx transaction.
    #[error("encountered an error while rolling back an sqlx transaction: {0}")]
    SqlxRollbackTransaction(#[source] sqlx::Error),

    /// An error when attempting to read a migration script.
    #[error("failed to read migration script: {0}")]
    ReadSqlMigration(Cow<'static, str>),

    /// An error when attempting to generically decode bytes using the
    /// trait implementation.
    #[error("got an error wen attempting to call StacksMessageCodec::consensus_deserialize {0}")]
    StacksCodec(#[source] blockstack_lib::codec::Error),

    /// An error for the case where we cannot create a multi-sig
    /// StacksAddress using given public keys.
    #[error("could not create a StacksAddress from the public keys: threshold {0}, keys {1}")]
    StacksMultiSig(u16, usize),

    /// Error when reading the stacks API part of the config.toml
    #[error("failed to parse the stacks.api portion of the config: {0}")]
    StacksApiConfig(#[source] config::ConfigError),

    /// Could not make a successful request to the stacks API.
    #[error("received a non success status code response from a stacks node: {0}")]
    StacksNodeResponse(#[source] reqwest::Error),

    /// Could not make a successful request to the Stacks node.
    #[error("failed to make a request to the stacks Node: {0}")]
    StacksNodeRequest(#[source] reqwest::Error),

    /// Reqwest error
    #[error("response from stacks node did not conform to the expected schema: {0}")]
    UnexpectedStacksResponse(#[source] reqwest::Error),

    /// The response from the Stacks node was invalid or malformed.
    #[error("invalid stacks response: {0}")]
    InvalidStacksResponse(&'static str),

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

    /// Missing signer utxo
    #[error("missing signer utxo")]
    MissingSignerUtxo,

    /// Invalid signature
    #[error("invalid signature")]
    InvalidSignature,

    /// ECDSA error
    #[error("ECDSA error: {0}")]
    Ecdsa(#[from] ecdsa::Error),

    /// Codec error
    #[error("codec error: {0}")]
    Codec(#[source] codec::Error),

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

    /// The error for when the request to sign a withdrawal-accept
    /// transaction fails at the validation step.
    #[error("{0}")]
    WithdrawalAcceptValidation(#[source] Box<WithdrawalAcceptValidationError>),

    /// WSTS error.
    #[error("WSTS error: {0}")]
    Wsts(#[source] wsts::state_machine::signer::Error),

    /// WSTS coordinator error.
    #[error("WSTS coordinator error: {0}")]
    WstsCoordinator(#[source] Box<wsts::state_machine::coordinator::Error>),

    /// No chain tip found.
    #[error("no bitcoin chain tip")]
    NoChainTip,

    /// Bitcoin error when attempting to construct an address from a
    /// scriptPubKey.
    #[error("bitcoin address parse error")]
    BitcoinAddressFromScript(
        #[source] bitcoin::address::FromScriptError,
        bitcoin::OutPoint,
    ),

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

    /// Transaction coordinator timed out
    #[error("coordinator timed out after {0} seconds")]
    CoordinatorTimeout(u64),

    /// Wsts state machine returned unexpected operation result
    #[error("unexpected operation result")]
    UnexpectedOperationResult,
}

impl From<std::convert::Infallible> for Error {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}
