//! Top-level error type for the signer
use std::borrow::Cow;

use blockstack_lib::types::chainstate::StacksBlockId;

use crate::codec;
use crate::emily_client::EmilyClientError;
use crate::keys::PublicKey;
use crate::stacks::contracts::DepositValidationError;
use crate::stacks::contracts::RotateKeysValidationError;
use crate::stacks::contracts::WithdrawalAcceptValidationError;
use crate::storage::model::SigHash;

/// Top-level signer error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The aggregate key for the given block hash could not be determined.
    #[error("the signer set aggregate key could not be determined for bitcoin block {0}")]
    MissingAggregateKey(bitcoin::BlockHash),

    /// An error occurred while attempting to connect to the Bitcoin Core ZMQ socket.
    #[error("timed-out trying to connect to bitcoin-core ZMQ endpoint: {0}")]
    BitcoinCoreZmqConnectTimeout(String),

    /// An error was received from the Bitcoin Core ZMQ subscriber.
    #[error("error from bitcoin-core ZMQ: {0}")]
    BitcoinCoreZmq(#[source] bitcoincore_zmq::Error),

    /// Indicates an error when decoding a protobuf
    #[error("could not decode protobuf {0}")]
    DecodeProtobuf(#[source] prost::DecodeError),

    /// This happens when the tag order of the serialized protobuf is not
    /// increasing.
    #[error("protobuf field not encoded in field tag order")]
    ProtobufTagCodec,

    /// Attempted division by zero
    #[error("attempted division by zero")]
    DivideByZero,

    /// Arithmetic overflow
    #[error("arithmetic overflow")]
    ArithmeticOverflow,

    /// Indicates that a sweep transaction with the specified txid could not be found.
    #[error("sweep transaction not found: {0}")]
    MissingSweepTransaction(bitcoin::Txid),

    /// Indicates that a deposit request with the specified txid and vout could not be found.
    #[error("deposit request not found: {0}")]
    MissingDepositRequest(bitcoin::OutPoint),

    /// Received an error in response to gettxout RPC call
    #[error("bitcoin-core gettxout error for outpoint {1} (search mempool? {2}): {0}")]
    BitcoinCoreGetTxOut(#[source] bitcoincore_rpc::Error, bitcoin::OutPoint, bool),

    /// Received an error in response to getmempooldescendants RPC call
    #[error("bitcoin-core getmempooldescendants error for txid {1}: {0}")]
    BitcoinCoreGetMempoolDescendants(bitcoincore_rpc::Error, bitcoin::Txid),

    /// Received an error in response to gettxspendingprevout RPC call
    #[error("bitcoin-core gettxspendingprevout error for outpoint: {0}")]
    BitcoinCoreGetTxSpendingPrevout(#[source] bitcoincore_rpc::Error, bitcoin::OutPoint),

    /// The nakamoto start height could not be determined.
    #[error("nakamoto start height could not be determined")]
    MissingNakamotoStartHeight,

    /// An error occurred while communicating with the Emily API
    #[error("emily API error: {0}")]
    EmilyApi(#[from] EmilyClientError),

    /// Attempt to fetch a bitcoin blockhash ended in an unexpected error.
    /// This is not triggered if the block is missing.
    #[error("bitcoin-core getblock RPC error for hash {1}: {0}")]
    BitcoinCoreGetBlock(#[source] bitcoincore_rpc::Error, bitcoin::BlockHash),

    /// Attempt to fetch a bitcoin block header resulted in an unexpected
    /// error. This is not triggered if the block header is missing.
    #[error("bitcoin-core getblockheader RPC error for hash {1}: {0}")]
    BitcoinCoreGetBlockHeader(#[source] bitcoincore_rpc::Error, bitcoin::BlockHash),

    /// Bitcoin block header is unknown to bitcoin-core. This is only
    /// triggered if bitcoin-core does not know about the block hash.
    #[error("Unknown block hash response from bitcoin-core getblockheader RPC call: {0}")]
    BitcoinCoreUnknownBlockHeader(bitcoin::BlockHash),

    /// Received an error in response to getrawtransaction RPC call
    #[error("failed to retrieve the raw transaction for txid {1} from bitcoin-core. {0}")]
    BitcoinCoreGetTransaction(#[source] bitcoincore_rpc::Error, bitcoin::Txid),

    /// Error when creating an RPC client to bitcoin-core
    #[error("could not create RPC client to {1}: {0}")]
    BitcoinCoreRpcClient(#[source] bitcoincore_rpc::Error, String),

    /// The bitcoin transaction was not found in the mempool or on the
    /// bitcoin blockchain. This is thrown when we expect the transaction
    /// to exist in bitcoin core, but it does not.
    #[error("transaction is missing, txid: {0}, block hash {1:?}")]
    BitcoinTxMissing(bitcoin::Txid, Option<bitcoin::BlockHash>),

    /// This is the error that is returned when validating a bitcoin
    /// trasnaction.
    #[error("bitcoin validation error: {0}")]
    BitcoinValidation(#[from] Box<crate::bitcoin::validation::BitcoinValidationError>),

    /// This can only be thrown when the number of bytes for a sighash or
    /// not exactly equal to 32. This should never occur.
    #[error("could not convert message in nonce request to sighash {0}")]
    SigHashConversion(#[source] bitcoin::hashes::FromSliceError),

    /// This happens when the tx-signer is validating the sighash and it is
    /// known but has failed validation.
    #[error("the given sighash is known and failed validation: {0}")]
    InvalidSigHash(SigHash),

    /// This happens when the tx-signer is validating the sighash and it
    /// does not have a row for it in the database.
    #[error("the given sighash is unknown: {0}")]
    UnknownSigHash(SigHash),

    /// This should never happen
    #[error("observed a tenure identified by a StacksBlockId with with no blocks")]
    EmptyStacksTenure,

    /// This happens when StacksClient::get_tenure_raw returns an array of blocks which starts
    /// with a block with id {0}, while we expect it to return an array of blocks starting with
    /// a block with id {1}
    #[error("get_tenure_raw returned unexpected response: {0}. Expected: {1}")]
    GetTenureRawMismatch(StacksBlockId, StacksBlockId),

    /// Received an error in call to estimatesmartfee RPC call
    #[error("failed to get fee estimate from bitcoin-core for target {1}. {0}")]
    EstimateSmartFee(#[source] bitcoincore_rpc::Error, u16),

    /// Received an error in response to estimatesmartfee RPC call
    #[error("failed to get fee estimate from bitcoin-core in target blocks {1}. errors: {0}")]
    EstimateSmartFeeResponse(String, u16),

    /// Error from the fallback client.
    #[error("fallback client error: {0}")]
    FallbackClient(#[from] crate::util::FallbackClientError),

    /// Error from the Bitcoin RPC client.
    #[error("bitcoin RPC error: {0}")]
    BitcoinCoreRpc(#[from] bitcoincore_rpc::Error),

    /// An error propagated from the sBTC library.
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
    #[error("receive error: {0}")]
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
    #[error("could not decode the bitcoin transaction: {0}")]
    DecodeBitcoinTransaction(#[source] bitcoin::consensus::encode::Error),

    /// Parsing the Hex Error
    #[error("could not decode the Nakamoto block with ID: {1}; {0}")]
    DecodeNakamotoBlock(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// Thrown when parsing a Nakamoto block within a given tenure.
    #[error("could not decode Nakamoto block from tenure with block: {1}; {0}")]
    DecodeNakamotoTenure(#[source] blockstack_lib::codec::Error, StacksBlockId),

    /// Failed to validate the complete-deposit contract call transaction.
    #[error("deposit validation error: {0}")]
    DepositValidation(#[from] Box<DepositValidationError>),

    /// An error when serializing an object to JSON
    #[error("JSON serialization error: {0}")]
    JsonSerialize(#[source] serde_json::Error),

    /// Could not parse the path part of a URL
    #[error("failed to construct a valid URL from {1} and {2}: {0}")]
    PathJoin(#[source] url::ParseError, url::Url, Cow<'static, str>),

    /// This occurs when combining many public keys would result in a
    /// "public key" that is the point at infinity.
    #[error("invalid aggregate key: {0}")]
    InvalidAggregateKey(#[source] secp256k1::Error),

    /// This happens when we realize that the lock-time in the reclaim
    /// script disables the OP_CSV check.
    #[error("invalid lock-time: {0}")]
    DisabledLockTime(#[source] bitcoin::locktime::relative::DisabledLockTimeError),

    /// This occurs when converting a byte slice to our internal public key
    /// type, which is a thin wrapper around the secp256k1::PublicKey.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] secp256k1::Error),

    /// This occurs when converting a byte slice to our internal x-only
    /// public key type, which is a thin wrapper around the
    /// secp256k1::XOnlyPublicKey.
    #[error("invalid x-only public key: {0}")]
    InvalidXOnlyPublicKey(#[source] secp256k1::Error),

    /// This happens when we tweak our public key by a scalar, and the
    /// result is an invalid public key. I think It is very unlikely that
    /// we will see this one by chance, since the probability that this
    /// happens is something like: 1 / (2^256 - 2^32^ - 977), where the
    /// denominator is the order of the secp256k1 curve. This is because
    /// for a given public key, the there is only one tweak that will lead
    /// to an invalid public key.
    #[error("invalid tweak? seriously? {0}")]
    InvalidPublicKeyTweak(#[source] secp256k1::Error),

    /// This happens when a tweak produced by [`XOnlyPublicKey::add_tweak`] was computed incorrectly.
    #[error("Tweak was computed incorrectly.")]
    InvalidPublicKeyTweakCheck,

    /// This occurs when converting a byte slice to our internal public key
    /// type, which is a thin wrapper around the secp256k1::SecretKey.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(#[source] secp256k1::Error),

    /// This occurs when converting a byte slice to a [`PrivateKey`](crate::keys::PrivateKey)
    /// and the length of the byte slice is not 32.
    #[error("invalid private key length={0}, expected 32.")]
    InvalidPrivateKeyLength(usize),

    /// The given signature was invalid
    #[error("could not convert the given compact bytes into an ECDSA signature: {0}")]
    InvalidEcdsaSignatureBytes(#[source] secp256k1::Error),

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

    /// This should never happen.
    #[error("outpoint missing from transaction when assessing fee {0}")]
    OutPointMissing(bitcoin::OutPoint),

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

    /// An error when we exceeded the timeout when trying to sign a stacks
    /// transaction.
    #[error("took too long to receive enough signatures for transaction: {0}")]
    SignatureTimeout(blockstack_lib::burnchains::Txid),

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

    /// We failed to submit the transaction to the mempool.
    #[error("stacks transaction rejected: {0}")]
    StacksTxRejection(#[from] crate::stacks::api::TxRejection),

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

    /// Missing bitcoin block
    #[error("bitcoin-core is missing bitcoin block {0}")]
    BitcoinCoreMissingBlock(bitcoin::BlockHash),

    /// Missing bitcoin block
    #[error("the database is missing bitcoin block {0}")]
    MissingBitcoinBlock(crate::storage::model::BitcoinBlockHash),

    /// Missing block
    #[error("missing block")]
    MissingBlock,

    /// Missing dkg shares
    #[error("missing dkg shares for the given aggregate key: {0}")]
    MissingDkgShares(crate::keys::PublicKeyXOnly),

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

    /// The public key indicated in the message does not match the sender
    /// public key.
    #[error("public key from sender does not match one in state machine {wsts} {sender}")]
    PublicKeyMismatch {
        /// The sender sent a signer_id in their WSTS message, and this
        /// corresponds to the following public key. It is s
        wsts: Box<PublicKey>,
        /// This is the public key of the sender of the WSTS message.
        sender: Box<PublicKey>,
    },

    /// This should never happen. It arises when a signer gets a message
    /// that requires DKG to have been run at some point, but it hasn't
    /// been.
    #[error("DKG has not been run")]
    NoDkgShares,

    /// TODO: We don't want to be able to run DKG more than once. Soon this
    /// restriction will be lifted.
    #[error("DKG has already been run, can only run once")]
    DkgHasAlreadyRun,

    /// Too many signer utxos
    #[error("too many signer utxos")]
    TooManySignerUtxos,

    /// Invalid signature
    #[error("invalid signature")]
    InvalidSignature,

    /// Invalid ECDSA signature
    #[error("invalid ECDSA signature")]
    InvalidEcdsaSignature(#[source] secp256k1::Error),

    /// Codec error
    #[error("codec error: {0}")]
    Codec(#[from] codec::CodecError),

    /// Type conversion error
    #[error("type conversion error")]
    TypeConversion,

    /// Encryption error
    #[error("encryption error")]
    Encryption,

    /// Invalid configuration
    #[error("invalid configuration")]
    InvalidConfiguration,

    /// We throw this when signer produced txid and coordinator produced txid differ.
    #[error(
        "Signer and coordinator txid mismatch. Signer produced txid {0}, but coordinator send txid {1}"
    )]
    SignerCoordinatorTxidMismatch(
        blockstack_lib::burnchains::Txid,
        blockstack_lib::burnchains::Txid,
    ),

    /// Observer dropped
    #[error("observer dropped")]
    ObserverDropped,

    /// A required field in a protobuf type was not set.
    #[error("a required protobuf field was not set")]
    RequiredProtobufFieldMissing,

    /// The error for when the request to sign a rotate-keys
    /// transaction fails at the validation step.
    #[error("rotate keys validation error: {0}")]
    RotateKeysValidation(#[source] Box<RotateKeysValidationError>),

    /// Thrown when the recoverable signature has a public key that is
    /// unexpected.
    #[error("unexpected public key from signature. key {0}; digest: {1}")]
    UnknownPublicKey(crate::keys::PublicKey, secp256k1::Message),

    /// This is thrown when there is a deposit that parses correctly but
    /// the public key in the deposit script is not known to the signer.
    #[error("Unknown x-only public key in deposit outpoint: {0}, public key {1}")]
    UnknownAggregateKey(bitcoin::OutPoint, secp256k1::XOnlyPublicKey),

    /// The error for when the request to sign a withdrawal-accept
    /// transaction fails at the validation step.
    #[error("withdrawal accept validation error: {0}")]
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

    /// No stacks chain tip found.
    #[error("no stacks chain tip")]
    NoStacksChainTip,

    /// Bitcoin error when attempting to construct an address from a
    /// scriptPubKey.
    #[error("bitcoin address parse error: {0}; txid {}, vout: {}", .1.txid, .1.vout)]
    BitcoinAddressFromScript(
        #[source] bitcoin::address::FromScriptError,
        bitcoin::OutPoint,
    ),

    /// Could not parse hex script.
    #[error("could not parse hex script: {0}")]
    DecodeHexScript(#[source] bitcoin::hex::HexToBytesError),

    /// Could not parse hex txid.
    #[error("could not parse hex txid: {0}")]
    DecodeHexTxid(#[source] bitcoin::hex::HexToArrayError),

    /// This happens during the validation of a stacks transaction when the
    /// current signer is not a member of the signer set indicated by the
    /// aggregate key.
    #[error("current signer not part of signer set indicated by: {0}")]
    ValidationSignerSet(crate::keys::PublicKey),

    /// Transaction coordinator timed out
    #[error("coordinator timed out after {0} seconds")]
    CoordinatorTimeout(u64),

    /// Wsts state machine returned unexpected operation result
    #[error("unexpected operation result: {0:?}")]
    UnexpectedOperationResult(Box<wsts::state_machine::OperationResult>),

    /// The smart contract has already been deployed
    #[error("smart contract already deployed, contract name: {0}")]
    ContractAlreadyDeployed(&'static str),

    /// Received coordinator message wasn't from coordinator for this chain tip
    #[error("not chain tip coordinator")]
    NotChainTipCoordinator,

    /// Indicates that the request packages contain duplicate deposit or withdrawal entries.
    #[error("The request packages contain duplicate deposit or withdrawal entries.")]
    DuplicateRequests,

    /// Indicates that the BitcoinPreSignRequest object does not contain
    /// any deposit or withdrawal requests.
    #[error("The BitcoinPreSignRequest object does not contain deposit or withdrawal requests")]
    PreSignContainsNoRequests,

    /// Indicates that we tried to create an UnsignedTransaction object
    /// without any deposit or withdrawal requests.
    #[error("The UnsignedTransaction must contain deposit or withdrawal requests")]
    BitcoinNoRequests,

    /// Indicates that the BitcoinPreSignRequest object contains a fee rate
    /// that is less than or equal to zero.
    #[error("The fee rate in the BitcoinPreSignRequest object is not greater than zero: {0}")]
    PreSignInvalidFeeRate(f64),

    /// Error when deposit requests would exceed sBTC supply cap
    #[error("Total deposit amount ({total_amount} sats) would exceed sBTC supply cap (current max mintable is {max_mintable} sats)")]
    ExceedsSbtcSupplyCap {
        /// Total deposit amount in sats
        total_amount: u64,
        /// Maximum sBTC mintable
        max_mintable: u64,
    },
}

impl From<std::convert::Infallible> for Error {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}

impl Error {
    /// Convert a coordinator error to an `error::Error`
    pub fn wsts_coordinator(err: wsts::state_machine::coordinator::Error) -> Self {
        Error::WstsCoordinator(Box::new(err))
    }
}
