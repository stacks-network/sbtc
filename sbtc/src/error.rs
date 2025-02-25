//! Top-level error type for the sbtc library
//!

use bitcoin::OutPoint;
use bitcoin::Txid;

/// Errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// This happens when we realize that the lock-time in the reclaim
    /// script disables the OP_CSV check.
    #[error("invalid lock-time: {0}")]
    DisabledLockTime(#[source] bitcoin::locktime::relative::DisabledLockTimeError),
    /// The end of the deposit script has a fixed format that is very
    /// similar to a P2PK check_sig script, the script violated that format
    #[error("script is CHECKSIG part of script")]
    InvalidDepositCheckSigPart,
    /// The deposit script was invalid
    #[error("invalid deposit script")]
    InvalidDepositScript,
    /// Length of the deposit script is necessarily too short.
    #[error("script is invalid, it is too short")]
    InvalidDepositScriptLength,
    /// The lock time included in the reclaim script was invalid. This
    /// could be because the number is out of range for an acceptable lock
    /// time, or because the 32nd bit has been set.
    #[error("the lock time included in the reclaim script was invalid: {0}")]
    InvalidReclaimScriptLockTime(i64),
    /// The reclaim script was invalid.
    #[error("the reclaim script format was invalid")]
    InvalidReclaimScript,
    /// The reclaim script lock time was invalid
    #[error("reclaim script lock time was either too large or non-minimal: {0}")]
    ScriptNum(#[source] bitcoin::script::Error),
    /// The X-only public key was invalid
    #[error("the x-only public key in the script was invalid: {0}")]
    InvalidXOnlyPublicKey(#[source] secp256k1::Error),
    /// The deposit script was non-standard because it did not follow the
    /// minimal push rule.
    #[error("deposit script did not follow the minimal push rule")]
    NonMinimalPushDepositScript,
    /// Could not parse the Stacks principal address.
    #[error("could not parse the stacks principal address: {0}")]
    ParseStacksAddress(#[source] stacks_common::codec::Error),
    /// The network of the recipient address does not match the expected
    /// network.
    #[error("incorrect network of the recipient address: {0}")]
    RecipientNetworkMismatch(clarity::vm::types::PrincipalData),
    /// This happens when the lock-time is given in time units instead of
    /// block units.
    #[error("lock-time given in time units, but only block units are supported: {0}")]
    UnsupportedLockTimeUnits(u32),
    /// Failed to extract the outpoint from the bitcoin::Transaction.
    #[error("could not get outpoint {1} from BTC transaction: {0}")]
    OutpointIndex(
        #[source] bitcoin::blockdata::transaction::OutputsIndexError,
        OutPoint,
    ),
    /// The ScriptPubKey of the UTXO did not match what was expected from
    /// the given deposit script and reclaim script.
    #[error("mismatch in expected and actual ScriptPubKeys. outpoint: {0}")]
    UtxoScriptPubKeyMismatch(OutPoint),
    /// Failed to parse the hex as a bitcoin::Transaction.
    #[error("The txid of the transaction did not match the given txid")]
    TxidMismatch {
        /// This is the transaction ID of the actual transaction
        from_tx: Txid,
        /// This is the transaction ID of from the request
        from_request: Txid,
    },

    /// This is thrown when failing to parse a hex string into bytes.
    #[cfg(feature = "webhooks")]
    #[error("could not decode the hex string into bytes: {0}")]
    DecodeHexBytes(#[source] hex::FromHexError),
    /// An error when attempting to generically decode bytes using the
    /// trait implementation.
    #[cfg(feature = "webhooks")]
    #[error("got an error when attempting to call StacksMessageCodec::consensus_deserialize {0}")]
    StacksCodec(#[source] blockstack_lib::codec::Error),
}
