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
//! use sbtc_signer::ecdsa::SignECDSA;
//!
//! struct SignableStr(&'static str);
//!
//! // Implementing `wsts::net::Signable` unlocks the signing functionality in this module.
//! impl wsts::net::Signable for SignableStr {
//!     fn hash(&self, hasher: &mut sha2::Sha256) {
//!         hasher.update(self.0)
//!     }
//! }
//!
//! let msg = SignableStr("Sign me please!");
//! let private_key = p256k1::scalar::Scalar::from(1337);
//!
//! // Sign the message.
//! let signed_msg = msg
//!     .sign_ecdsa(&private_key)
//!     .expect("Failed to sign message");
//!
//! // Verify the signed message.
//! assert!(signed_msg.verify());

use p256k1::ecdsa;
use p256k1::scalar::Scalar;

/// Wraps an inner type with a public key and a signature,
/// allowing easy verification of the integrity of the inner data.
#[derive(Debug, Clone)]
pub struct Signed<T> {
    /// The signed structure.
    pub inner: T,
    /// The public key of the signer.
    pub signer_pub_key: ecdsa::PublicKey,
    /// A signature over the hash of the inner structure.
    pub signature: Vec<u8>,
}

impl<T: wsts::net::Signable> Signed<T> {
    /// Verify the signature over the inner data.
    pub fn verify(&self) -> bool {
        self.inner.verify(&self.signature, &self.signer_pub_key)
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
    fn sign_ecdsa(self, private_key: &Scalar) -> Result<Signed<Self>, Error>;
}

impl<T: wsts::net::Signable> SignEcdsa for T {
    /// Create a `Signed<T>` instance with a signature and public key constructed from `private_key`.
    fn sign_ecdsa(self, private_key: &Scalar) -> Result<Signed<Self>, Error> {
        let signer_pub_key = ecdsa::PublicKey::new(private_key)?;
        let signature = self.sign(private_key)?;

        Ok(Signed {
            inner: self,
            signer_pub_key,
            signature,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("KeyError")]
    KeyError(#[from] p256k1::keys::Error),
    #[error("SignError")]
    SignError(#[from] ecdsa::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::Digest;

    #[test]
    fn verify_should_return_true_given_properly_signed_data() {
        let msg = SignableStr("I'm Batman");
        let bruce_wayne_private_key = Scalar::from(1337);

        let signed_msg = msg
            .sign_ecdsa(&bruce_wayne_private_key)
            .expect("Failed to sign message");

        // Bruce Wayne is Batman.
        assert!(signed_msg.verify());
    }

    #[test]
    fn verify_should_return_false_given_tampered_data() {
        let msg = SignableStr("I'm Batman");
        let bruce_wayne_private_key = Scalar::from(1337);

        let mut signed_msg = msg
            .sign_ecdsa(&bruce_wayne_private_key)
            .expect("Failed to sign message");

        signed_msg.inner = SignableStr("I'm Satoshi Nakamoto");

        // Bruce Wayne is not Satoshi Nakamoto.
        assert!(!signed_msg.verify());
    }

    #[test]
    fn verify_should_return_false_given_the_wrong_public_key() {
        let msg = SignableStr("I'm Batman");
        let bruce_wayne_private_key = Scalar::from(1337);
        let craig_wright_public_key = ecdsa::PublicKey::new(&Scalar::from(1338)).unwrap();

        let mut signed_msg = msg
            .sign_ecdsa(&bruce_wayne_private_key)
            .expect("Failed to sign message");

        signed_msg.signer_pub_key = craig_wright_public_key;

        // Craig Wright is not Batman.
        assert!(!signed_msg.verify());
    }

    #[test]
    fn signed_should_deref_to_the_underlying_type() {
        let msg = SignableStr("I'm Batman");
        let bruce_wayne_private_key = Scalar::from(1337);

        let signed_msg = msg
            .sign_ecdsa(&bruce_wayne_private_key)
            .expect("Failed to sign message");

        assert_eq!(signed_msg.len(), 10);
    }

    struct SignableStr(&'static str);

    impl wsts::net::Signable for SignableStr {
        fn hash(&self, hasher: &mut sha2::Sha256) {
            hasher.update(self.0)
        }
    }

    impl std::ops::Deref for SignableStr {
        type Target = &'static str;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
}
