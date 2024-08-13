//! This module features internal types for both ECDSA and Schnorr
//! signatures.
//!

use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TransactionAuthFlags;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use serde::Deserialize;
use serde::Serialize;

use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;

/// For creating signatures.
pub trait MessageDigest {
    /// The digest to sign.
    fn digest(&self) -> [u8; 32];
}

impl MessageDigest for secp256k1::Message {
    fn digest(&self) -> [u8; 32] {
        *self.as_ref()
    }
}

impl MessageDigest for [u8; 32] {
    fn digest(&self) -> [u8; 32] {
        *self
    }
}

impl MessageDigest for StacksTransaction {
    /// Construct the digest that each signer needs to sign from a given
    /// transaction.
    ///
    /// # Note
    ///
    /// This function follows the same procedure as the
    /// TransactionSpendingCondition::next_signature function in
    /// stacks-core, except that it stops after the digest is created.
    fn digest(&self) -> [u8; 32] {
        let mut cleared_tx = self.clone();
        cleared_tx.auth = cleared_tx.auth.into_initial_sighash_auth();

        let sighash = cleared_tx.txid();
        let flags = TransactionAuthFlags::AuthStandard;
        let tx_fee = self.get_tx_fee();
        let nonce = self.get_origin_nonce();

        TransactionSpendingCondition::make_sighash_presign(&sighash, &flags, tx_fee, nonce)
            .into_bytes()
    }
}

/// A thin wrapper for the [`secp256k1::ecdsa::RecoverableSignature`] type.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Ord, PartialOrd, Deserialize, Serialize)]
pub struct RecoverableSignature(
    #[serde(with = "serde_utils")] secp256k1::ecdsa::RecoverableSignature,
);

impl RecoverableSignature {
    /// Create a signature from the compact representation of the signature.
    pub fn from_compact(data: &[u8; 65]) -> Result<Self, Error> {
        from_compact_bytes(data).map(Self)
    }

    /// Convert a recoverable signature into compact bytes.
    pub fn to_bytes(&self) -> [u8; 65] {
        from_secp256k1_recoverable(&self.0)
    }

    /// Recover the public key from the signature
    pub fn recover<M>(&self, msg: &M) -> Result<PublicKey, Error>
    where
        M: MessageDigest,
    {
        let msg = secp256k1::Message::from_digest(msg.digest());

        self.0
            .recover(&msg)
            .map(PublicKey::from)
            .map_err(|err| Error::InvalidRecoverableSignature(err, msg))
    }
}

impl From<RecoverableSignature> for stacks_common::util::secp256k1::MessageSignature {
    /// Convert a recoverable signature into a Message Signature.
    fn from(sig: RecoverableSignature) -> Self {
        stacks_common::util::secp256k1::MessageSignature(sig.to_bytes())
    }
}

impl From<&stacks_common::util::secp256k1::MessageSignature> for RecoverableSignature {
    /// Convert a recoverable signature into a Message Signature.
    fn from(sig: &stacks_common::util::secp256k1::MessageSignature) -> Self {
        RecoverableSignature::from_compact(&sig.0).expect("msg")
    }
}

impl From<RecoverableSignature> for secp256k1::ecdsa::RecoverableSignature {
    /// Convert a recoverable signature into a Message Signature.
    fn from(sig: RecoverableSignature) -> Self {
        sig.0
    }
}

impl From<secp256k1::ecdsa::RecoverableSignature> for RecoverableSignature {
    /// Convert a recoverable signature into a Message Signature.
    fn from(sig: secp256k1::ecdsa::RecoverableSignature) -> Self {
        Self(sig)
    }
}

/// Generate a signature for the transaction using a private key.
///
/// # Note
///
/// This function constructs a signature for the underlying transaction
/// using the same process that is done in the
/// TransactionSpendingCondition::next_signature function, but we skip a
/// step of generating the next sighash, since we do not need it.
pub fn sign_stacks_tx<K>(tx: &StacksTransaction, key: K) -> RecoverableSignature
where
    K: Into<PrivateKey>,
{
    let msg = tx.digest();
    let private_key = key.into();
    RecoverableSignature(private_key.sign_ecdsa_recoverable(msg))
}

/// Convert a recoverable signature into a Message Signature.
///
/// The [`secp256k1::ecdsa::RecoverableSignature`] type is a wrapper of a
/// wrapper for [u8; 65]. Unfortunately, the outermost wrapper type does
/// not provide a way to get at the underlying bytes except through the
/// [`secp256k1::ecdsa::RecoverableSignature::serialize_compact`] function,
/// so we use that function to extract the bytes.
///
/// This function is basically lifted from stacks-core at:
/// https://github.com/stacks-network/stacks-core/blob/35d0840c626d258f1e2d72becdcf207a0572ddcd/stacks-common/src/util/secp256k1.rs#L88-L95
fn from_secp256k1_recoverable(sig: &secp256k1::ecdsa::RecoverableSignature) -> [u8; 65] {
    let (recovery_id, bytes) = sig.serialize_compact();
    let mut ret_bytes = [0u8; 65];
    // The recovery ID will be 0, 1, 2, or 3
    ret_bytes[0] = recovery_id.to_i32() as u8;
    debug_assert!(recovery_id.to_i32() < 4);

    ret_bytes[1..].copy_from_slice(&bytes[..]);
    ret_bytes
}

/// Create a [`secp256k1::ecdsa::RecoverableSignature`] from the compact
/// representation of the signature. This is the inverse of the above
/// [`from_secp256k1_recoverable`] function.
fn from_compact_bytes(data: &[u8; 65]) -> Result<secp256k1::ecdsa::RecoverableSignature, Error> {
    let id = data[0] as i32;
    let recid =
        secp256k1::ecdsa::RecoveryId::from_i32(id).map_err(|err| Error::InvalidPublicKey(err))?;

    secp256k1::ecdsa::RecoverableSignature::from_compact(&data[1..], recid)
        .map_err(Error::InvalidPublicKey)
}

mod serde_utils {
    use super::*;
    use secp256k1::ecdsa;

    pub fn serialize<S>(sig: &ecdsa::RecoverableSignature, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = from_secp256k1_recoverable(sig);
        s.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ecdsa::RecoverableSignature, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let byte_array = serde_bytes::ByteArray::<65>::deserialize(deserializer)?;
        let data = byte_array.into_array();
        from_compact_bytes(&data).map_err(serde::de::Error::custom)
    }
}
