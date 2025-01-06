//! This module features internal traits and functions for both ECDSA
//! signatures.
//!

use std::ops::Deref;

use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TransactionAuthFlags;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use secp256k1::ecdsa::RecoverableSignature;
use serde::Deserialize;

use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;

/// A BIP 340-341 Schnorr proof.
#[derive(Debug, Clone, Copy)]
pub struct TaprootSignature(bitcoin::taproot::Signature);

impl Deref for TaprootSignature {
    type Target = bitcoin::taproot::Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&bitcoin::taproot::Signature> for TaprootSignature {
    fn from(value: &bitcoin::taproot::Signature) -> Self {
        Self(*value)
    }
}

impl From<bitcoin::taproot::Signature> for TaprootSignature {
    fn from(value: bitcoin::taproot::Signature) -> Self {
        Self(value)
    }
}

impl From<TaprootSignature> for bitcoin::taproot::Signature {
    fn from(value: TaprootSignature) -> Self {
        value.0
    }
}

impl From<wsts::taproot::SchnorrProof> for TaprootSignature {
    fn from(sig: wsts::taproot::SchnorrProof) -> Self {
        // This `expect()` is fine since the only requirement for a Schnorr
        // signature is that it be 64 bytes long. We know this is the case
        // because [`wsts::taproot::SchnorrProof::to_bytes`] always returns
        // a 64 byte array.
        let signature = secp256k1::schnorr::Signature::from_slice(&sig.to_bytes())
            .expect("We know to_bytes returns 64 bytes");
        let sighash_type = bitcoin::TapSighashType::All;
        Self(bitcoin::taproot::Signature { signature, sighash_type })
    }
}

/// For creating signatures.
pub trait SighashDigest {
    /// The digest to sign.
    fn digest(&self) -> [u8; 32];
}

impl SighashDigest for StacksTransaction {
    /// Construct the digest that each signer needs to sign from a given
    /// transaction.
    ///
    /// # Note
    ///
    /// This function follows the same procedure as the
    /// [`TransactionSpendingCondition::next_signature`] function in
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

/// This trait is to add additional functionality to the
/// [`RecoverableSignature`] type
pub trait RecoverableEcdsaSignature: Sized {
    /// Create a signature from the compact representation of the
    /// signature. This is supposed to be the inverse of [`to_byte_array`].
    fn from_byte_array(data: &[u8; 65]) -> Result<Self, Error>;
    /// Convert a recoverable signature into compact bytes.
    fn to_byte_array(&self) -> [u8; 65];
    /// Determines the public key for which this signature is valid for
    /// `msg`.
    fn recover_ecdsa(&self, msg: &secp256k1::Message) -> Result<PublicKey, Error>;
    /// Convert this type to the equivalent stacks signature
    fn as_stacks_sig(&self) -> stacks_common::util::secp256k1::MessageSignature {
        stacks_common::util::secp256k1::MessageSignature(self.to_byte_array())
    }
}

impl RecoverableEcdsaSignature for RecoverableSignature {
    /// Create a [`RecoverableSignature`] from the compact representation
    /// of the signature. This inverts the
    /// [`RecoverableEcdsaSignature::to_byte_array`] function.
    fn from_byte_array(data: &[u8; 65]) -> Result<Self, Error> {
        let id = data[0] as i32;
        let rec_id = secp256k1::ecdsa::RecoveryId::from_i32(id)
            .map_err(Error::InvalidRecoverableSignatureBytes)?;

        RecoverableSignature::from_compact(&data[1..], rec_id)
            .map_err(Error::InvalidRecoverableSignatureBytes)
    }
    /// Convert a recoverable signature into a byte array.
    ///
    /// The [`RecoverableSignature`] type is a wrapper of a wrapper for
    /// [u8; 65]. Unfortunately, the outermost wrapper type does not
    /// provide a way to get at the underlying bytes except through the
    /// [`RecoverableSignature::serialize_compact`] function, so we use
    /// that function to extract the bytes.
    ///
    /// This function is basically lifted from stacks-core at:
    /// https://github.com/stacks-network/stacks-core/blob/35d0840c626d258f1e2d72becdcf207a0572ddcd/stacks-common/src/util/secp256k1.rs#L88-L95
    fn to_byte_array(&self) -> [u8; 65] {
        let (recovery_id, bytes) = self.serialize_compact();
        let mut ret_bytes = [0u8; 65];
        // The recovery ID will be 0, 1, 2, or 3 as described in the secp256k1 docs:
        // https://docs.rs/secp256k1/0.30.0/secp256k1/ecdsa/enum.RecoveryId.html
        ret_bytes[0] = recovery_id.to_i32() as u8;

        ret_bytes[1..].copy_from_slice(&bytes[..]);
        ret_bytes
    }
    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`.
    fn recover_ecdsa(&self, msg: &secp256k1::Message) -> Result<PublicKey, Error> {
        self.recover(msg)
            .map(PublicKey::from)
            .map_err(|err| Error::InvalidRecoverableSignature(err, *msg))
    }
}

/// Generate a signature for the transaction using a private key.
///
/// # Note
///
/// This function constructs a signature for the underlying transaction
/// using the same process that is done in the
/// [`TransactionSpendingCondition::next_signature`] function, but we skip
/// a step of generating the next sighash, since we do not need it.
pub fn sign_stacks_tx(tx: &StacksTransaction, private_key: &PrivateKey) -> RecoverableSignature {
    let msg = secp256k1::Message::from_digest(tx.digest());
    private_key.sign_ecdsa_recoverable(&msg)
}

/// A module for Serialize and Deserialize implementations of the
/// [`RecoverableSignature`] type
pub mod serde_utils {
    use super::*;

    /// For the Serialize impl
    pub fn serialize<S>(sig: &RecoverableSignature, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = sig.to_byte_array();
        s.serialize_bytes(&bytes)
    }

    /// For the Deserialize impl
    pub fn deserialize<'de, D>(deserializer: D) -> Result<RecoverableSignature, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let byte_array = serde_bytes::ByteArray::<65>::deserialize(deserializer)?;
        let data = byte_array.into_array();
        RecoverableSignature::from_byte_array(&data).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use fake::Fake;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn recoverable_signatures_recover_public_key() {
        // Let's create a random digest to sign, sign it, and recover the
        // public key from the signature.
        let private_key = PrivateKey::new(&mut OsRng);

        let digest: [u8; 32] = fake::Faker.fake_with_rng(&mut OsRng);
        let msg = secp256k1::Message::from_digest(digest);
        let sig = private_key.sign_ecdsa_recoverable(&msg);

        let expected_public_key = PublicKey::from_private_key(&private_key);
        let actual_public_key = sig.recover_ecdsa(&msg).unwrap();
        assert_eq!(actual_public_key, expected_public_key);

        // Okay, now for good measure, let's transform this signature into
        // a "regular" one and verify that all is well. This is entirely
        // unnecessary, but couldn't hurt.
        sig.to_standard()
            .verify(&msg, &actual_public_key.into())
            .unwrap();
    }

    #[test]
    fn deserialize_inverts_serialize_compact() {
        let sig1 = crate::testing::dummy::recoverable_signature(&fake::Faker, &mut OsRng);
        let data = sig1.to_byte_array();
        let sig2 = RecoverableSignature::from_byte_array(&data).unwrap();

        assert_eq!(sig1, sig2);
    }
}
