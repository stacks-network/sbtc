//! # ECDSA Signing and Verification
//!
//! This module provides functionality to sign and verify data using the ECDSA signature scheme.
//! The core component is the `Signed<T>` structure, which wraps any signable data along with the signer's public key
//! and a signature. The module also defines the `SignECDSA` trait to facilitate signing operations.
//!
//! ## Features
//!
//! - **Signed**: A generic wrapper that binds a piece of data (`inner`) with its ECDSA signature and the public key
//!   of the signer. It provides a method to verify the integrity and authenticity of the data.
//! - **SignECDSA**: A trait implemented by data types that can be signed using ECDSA. It is automatically implemented for any type implementing `wsts::net::Signable`.
//!
//! ## Examples
//!
//! ### Signing and Verifying a String
//!
//! The following example demonstrates how to sign a simple string and then verify its signature:
//!
//! ```
//! use sha2::Digest;
//! use signer::ecdsa::SignEcdsa;
//! use signer::keys::PrivateKey;
//!
//! struct SignableStr(&'static str);
//!
//! // Implementing `ProtoSerializable` and conversion traits unlock the signing
//! // functionality in this module.
//! #[allow(clippy::derive_partial_eq_without_eq)]
//! #[derive(Clone, PartialEq, ::prost::Message)]
//! pub struct ProtoSignableStr {
//!     /// The string
//!     #[prost(string, tag = "1")]
//!     pub string: ::prost::alloc::string::String,
//! }
//!
//! impl ProtoSerializable for SignableStr {
//!     type Message = ProtoSignableStr;
//!
//!     fn type_tag(&self) -> &'static str {
//!         "SBTC_SIGNABLE_STR"
//!     }
//! }
//!
//! let msg = SignableStr("Sign me please!");
//! let private_key = PrivateKey::try_from(&p256k1::scalar::Scalar::from(1337)).unwrap();
//!
//! // Sign the message.
//! let signed_msg = msg.sign_ecdsa(&private_key);
//!
//! // Verify the signed message.
//! assert_eq!(signed_msg.recover_ecdsa(), Ok(private_key.into()));

use secp256k1::ecdsa::RecoverableSignature;

use crate::codec::ProtoSerializable;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::signature::RecoverableEcdsaSignature;
use crate::signature::SighashDigest as _;

/// Wraps an inner type with a public key and a signature,
/// allowing easy verification of the integrity of the inner data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signed<T> {
    /// The signed structure.
    pub inner: T,
    /// A signature over the hash of the inner structure.
    pub signature: RecoverableSignature,
}

impl<T> Signed<T>
where
    T: ProtoSerializable + Clone,
    T: Into<<T as ProtoSerializable>::Message>,
{
    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`.
    pub fn recover_ecdsa(&self) -> Result<PublicKey, Error> {
        let msg = secp256k1::Message::from_digest(self.inner.digest());
        self.signature.recover_ecdsa(&msg)
    }

    /// Unique identifier for the signed message
    pub fn id(&self) -> [u8; 32] {
        self.inner.digest()
    }
}

impl<T> std::ops::Deref for Signed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> std::ops::DerefMut for Signed<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Helper trait to provide the ability to construct a `Signed<T>`.
pub trait SignEcdsa: Sized {
    /// Wrap this type into a [`Signed<Self>`]
    fn sign_ecdsa(self, private_key: &PrivateKey) -> Signed<Self>;
}

impl<T> SignEcdsa for T
where
    T: ProtoSerializable + Clone,
    T: Into<<T as ProtoSerializable>::Message>,
{
    fn sign_ecdsa(self, private_key: &PrivateKey) -> Signed<Self> {
        let msg = secp256k1::Message::from_digest(self.digest());

        Signed {
            signature: private_key.sign_ecdsa_recoverable(&msg),
            inner: self,
        }
    }
}

#[cfg(feature = "testing")]
impl Signed<crate::message::SignerMessage> {
    /// Generate a random signed message
    pub fn random<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
        let private_key = PrivateKey::new(rng);
        Self::random_with_private_key(rng, &private_key)
    }

    /// Generate a random signed message with the given private key
    pub fn random_with_private_key<R: rand::CryptoRng + rand::Rng>(
        rng: &mut R,
        private_key: &PrivateKey,
    ) -> Self {
        let inner = crate::message::SignerMessage::random(rng);
        inner.sign_ecdsa(private_key)
    }
}

#[cfg(feature = "testing")]
impl<T> Signed<T>
where
    T: ProtoSerializable + Clone,
    T: Into<<T as ProtoSerializable>::Message>,
{
    /// Verify the signature over the inner data.
    pub fn verify(&self, public_key: PublicKey) -> bool {
        self.recover_ecdsa().is_ok_and(|key| key == public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256k1::scalar::Scalar;

    #[test]
    fn verify_should_return_true_given_properly_signed_data() {
        let msg = SignableStr("I'm Batman");
        let bruce_wayne_private_key = PrivateKey::try_from(&Scalar::from(1337)).unwrap();
        let bruce_wayne_public_key = PublicKey::from_private_key(&bruce_wayne_private_key);

        let signed_msg = msg.sign_ecdsa(&bruce_wayne_private_key);

        // Bruce Wayne is Batman.
        assert!(signed_msg.verify(bruce_wayne_public_key));
    }

    #[test]
    fn verify_should_return_false_given_tampered_data() {
        let msg = SignableStr("I'm Batman");
        let bruce_wayne_private_key = PrivateKey::try_from(&Scalar::from(1337)).unwrap();
        let bruce_wayne_public_key = PublicKey::from_private_key(&bruce_wayne_private_key);

        let mut signed_msg = msg.sign_ecdsa(&bruce_wayne_private_key);
        assert!(signed_msg.verify(bruce_wayne_public_key));

        signed_msg.inner = SignableStr("I'm Satoshi Nakamoto");

        // Bruce Wayne is not Satoshi Nakamoto.
        assert!(!signed_msg.verify(bruce_wayne_public_key));
    }

    #[test]
    fn verify_should_return_false_given_the_wrong_public_key() {
        let msg = SignableStr("I'm Batman");
        let bruce_wayne_private_key = PrivateKey::try_from(&Scalar::from(1337)).unwrap();
        let craig_wright_public_key = p256k1::ecdsa::PublicKey::new(&Scalar::from(1338))
            .unwrap()
            .into();

        let signed_msg = msg.sign_ecdsa(&bruce_wayne_private_key);

        // Craig Wright is not Batman.
        assert_ne!(signed_msg.recover_ecdsa().unwrap(), craig_wright_public_key);
    }

    #[test]
    fn signed_should_deref_to_the_underlying_type() {
        let msg = SignableStr("I'm Batman");
        let bruce_wayne_private_key = PrivateKey::try_from(&Scalar::from(1337)).unwrap();

        let signed_msg = msg.sign_ecdsa(&bruce_wayne_private_key);

        assert_eq!(signed_msg.len(), 10);
    }

    #[derive(Clone, PartialEq)]
    struct SignableStr(&'static str);

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ProtoSignableStr {
        /// The string
        #[prost(string, tag = "1")]
        pub string: ::prost::alloc::string::String,
    }

    impl ProtoSerializable for SignableStr {
        type Message = ProtoSignableStr;

        fn type_tag(&self) -> &'static str {
            "SBTC_SIGNABLE_STR"
        }
    }

    impl From<SignableStr> for ProtoSignableStr {
        fn from(value: SignableStr) -> Self {
            ProtoSignableStr { string: value.0.to_string() }
        }
    }

    impl std::ops::Deref for SignableStr {
        type Target = &'static str;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
}
