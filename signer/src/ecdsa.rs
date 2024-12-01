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

use prost::bytes::Buf as _;
use prost::Message as _;
use secp256k1::ecdsa::RecoverableSignature;
use sha2::Digest as _;

use crate::codec::ProtoSerializable;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message::SignerMessage;
use crate::proto;
use crate::signature::RecoverableEcdsaSignature;

/// Wraps an inner type with a public key and a signature,
/// allowing easy verification of the integrity of the inner data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signed<T> {
    /// The signed structure.
    pub inner: T,
    /// A signature over the hash of the inner structure.
    pub signature: RecoverableSignature,
}

impl Signed<SignerMessage> {
    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`.
    pub fn recover_ecdsa(&self) -> Result<PublicKey, Error> {
        let msg = secp256k1::Message::from_digest(self.inner.to_digest());
        self.signature.recover_ecdsa(&msg)
    }

    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`.
    pub fn recover_ecdsa_with_digest(&self, digest: [u8; 32]) -> Result<PublicKey, Error> {
        let msg = secp256k1::Message::from_digest(digest);
        self.signature.recover_ecdsa(&msg)
    }

    /// Unique identifier for the signed message
    pub fn id(&self) -> [u8; 32] {
        self.inner.to_digest()
    }

    /// Decodes an encoded protobuf message, transforming it into a
    /// [`Signed<SignerMessage>`], and returning the signed message and
    /// with the digest that the signature was signed over.
    ///
    /// # Notes
    ///
    /// This function uses the fact that the protobuf [`proto::Signed`]
    /// type has a particular layout to decode the message and get the
    /// bytes that were signed by the signer that generated the message. It
    /// does the following:
    /// 1. Decode the first field using the given bytes. This field is the
    ///    signature field.
    /// 2. Takes a reference to the bytes after the protobuf signature
    ///    bytes. These were supposed to be used generate the digest that
    ///    was signed over.
    /// 3. Finish decoding the given bytes into the signed message.
    /// 4. Transform the protobuf rust type into the local rust type.
    /// 5. Use the local rust type along with the bytes from (2) to create
    ///    the signed digest.
    ///
    /// One of the assumptions is that repeated serialization of prost
    /// types generate the same bytes. It also assumes that fields are
    /// serialized in order by their tag. This is not true for protobuf
    /// generally, but it is for the prost protobuf implementation.
    /// <https://protobuf.dev/programming-guides/serialization-not-canonical/>
    /// <https://protobuf.dev/programming-guides/encoding/#order>
    /// <https://github.com/tokio-rs/prost/blob/v0.12.6/prost/src/message.rs#L108-L134>
    pub fn decode_with_digest(data: &[u8]) -> Result<(Self, [u8; 32]), Error> {
        let mut buf = data;
        let mut pre_hash_data = data;

        // This is almost exactly what prost does when decoding protobuf
        // bytes.
        let mut message = proto::Signed::default();
        let ctx = prost::encoding::DecodeContext::default();

        while buf.has_remaining() {
            let (tag, wire_type) = prost::encoding::decode_key(&mut buf)?;
            message.merge_field(tag, wire_type, &mut buf, ctx.clone())?;
            // This is the only part here that is not in prost. The field
            // with tag 1 is the signature field. We note a reference to
            // the remaining bytes because these bytes were used to create
            // the digest that was signed over.
            if tag == 1 {
                pre_hash_data = buf;
            }
        }

        // Okay now we transform the protobuf type into our local type.
        let msg = Signed::<SignerMessage>::try_from(message)?;
        // Now we construct the digest that was signed over.
        let mut hasher = sha2::Sha256::new_with_prefix(msg.type_tag());
        hasher.update(pre_hash_data);

        Ok((msg, hasher.finalize().into()))
    }
}

impl SignerMessage {
    /// Transform this into the digest that needs to be signed
    pub fn to_digest(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new_with_prefix(self.type_tag());

        let ans = proto::Signed {
            signature: None,
            signer_message: Some(self.clone().into()),
        };

        hasher.update(ans.encode_to_vec());
        hasher.finalize().into()
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

impl SignEcdsa for SignerMessage {
    fn sign_ecdsa(self, private_key: &PrivateKey) -> Signed<Self> {
        let msg = secp256k1::Message::from_digest(self.to_digest());

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
    pub fn verify(&self, _public_key: PublicKey) -> bool {
        unimplemented!()
        // self.recover_ecdsa().is_ok_and(|key| key == public_key)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use fake::Fake as _;
    use rand::rngs::OsRng;

    use crate::codec::Encode as _;
    use crate::ecdsa::SignEcdsa;
    use crate::keys::PrivateKey;
    use crate::message;
    use crate::proto;
    use crate::signature::RecoverableEcdsaSignature as _;
    use crate::storage::model::BitcoinBlockHash;

    use super::*;

    // #[test]
    // fn verify_should_return_true_given_properly_signed_data() {
    //     let msg = SignableStr("I'm Batman");
    //     let bruce_wayne_private_key = PrivateKey::try_from(&Scalar::from(1337)).unwrap();
    //     let bruce_wayne_public_key = PublicKey::from_private_key(&bruce_wayne_private_key);

    //     let signed_msg = msg.sign_ecdsa(&bruce_wayne_private_key);

    //     // Bruce Wayne is Batman.
    //     assert!(signed_msg.verify(bruce_wayne_public_key));
    // }

    // #[test]
    // fn verify_should_return_false_given_tampered_data() {
    //     let msg = SignableStr("I'm Batman");
    //     let bruce_wayne_private_key = PrivateKey::try_from(&Scalar::from(1337)).unwrap();
    //     let bruce_wayne_public_key = PublicKey::from_private_key(&bruce_wayne_private_key);

    //     let mut signed_msg = msg.sign_ecdsa(&bruce_wayne_private_key);
    //     assert!(signed_msg.verify(bruce_wayne_public_key));

    //     signed_msg.inner = SignableStr("I'm Satoshi Nakamoto");

    //     // Bruce Wayne is not Satoshi Nakamoto.
    //     assert!(!signed_msg.verify(bruce_wayne_public_key));
    // }

    // #[test]
    // fn verify_should_return_false_given_the_wrong_public_key() {
    //     let msg = SignableStr("I'm Batman");
    //     let bruce_wayne_private_key = PrivateKey::try_from(&Scalar::from(1337)).unwrap();
    //     let craig_wright_public_key = p256k1::ecdsa::PublicKey::new(&Scalar::from(1338))
    //         .unwrap()
    //         .into();

    //     let signed_msg = msg.sign_ecdsa(&bruce_wayne_private_key);

    //     // Craig Wright is not Batman.
    //     assert_ne!(signed_msg.recover_ecdsa().unwrap(), craig_wright_public_key);
    // }

    // #[test]
    // fn signed_should_deref_to_the_underlying_type() {
    //     let msg = SignableStr("I'm Batman");
    //     let bruce_wayne_private_key = PrivateKey::try_from(&Scalar::from(1337)).unwrap();

    //     let signed_msg = msg.sign_ecdsa(&bruce_wayne_private_key);

    //     assert_eq!(signed_msg.len(), 10);
    // }

    // #[derive(Clone, PartialEq)]
    // struct SignableStr(&'static str);

    // #[allow(clippy::derive_partial_eq_without_eq)]
    // #[derive(Clone, PartialEq, ::prost::Message)]
    // pub struct ProtoSignableStr {
    //     /// The string
    //     #[prost(string, tag = "1")]
    //     pub string: ::prost::alloc::string::String,
    // }

    // impl ProtoSerializable for SignableStr {
    //     type Message = ProtoSignableStr;

    //     fn type_tag(&self) -> &'static str {
    //         "SBTC_SIGNABLE_STR"
    //     }
    // }

    // impl From<SignableStr> for ProtoSignableStr {
    //     fn from(value: SignableStr) -> Self {
    //         ProtoSignableStr { string: value.0.to_string() }
    //     }
    // }

    // impl std::ops::Deref for SignableStr {
    //     type Target = &'static str;

    //     fn deref(&self) -> &Self::Target {
    //         &self.0
    //     }
    // }

    /// These tests check that if we sign a message with a private key,
    /// that [`Signed::<SignerMessage>::decode_with_digest`] will give the
    /// correct message and recover the correct public key that signed it.
    #[test_case::test_case(PhantomData::<message::SignerDepositDecision> ; "SignerDepositDecision")]
    #[test_case::test_case(PhantomData::<message::SignerWithdrawalDecision> ; "SignerWithdrawalDecision")]
    #[test_case::test_case(PhantomData::<message::StacksTransactionSignRequest> ; "StacksTransactionSignRequest")]
    #[test_case::test_case(PhantomData::<message::StacksTransactionSignature> ; "StacksTransactionSignature")]
    #[test_case::test_case(PhantomData::<message::BitcoinTransactionSignRequest> ; "BitcoinTransactionSignRequest")]
    #[test_case::test_case(PhantomData::<message::BitcoinTransactionSignAck> ; "BitcoinTransactionSignAck")]
    #[test_case::test_case(PhantomData::<message::WstsMessage> ; "WstsMessage")]
    #[test_case::test_case(PhantomData::<message::SweepTransactionInfo> ; "SweepTransactionInfo")]
    #[test_case::test_case(PhantomData::<message::BitcoinPreSignRequest> ; "BitcoinPreSignRequest")]
    fn payload_signing_recovery<T>(_: PhantomData<T>)
    where
        T: Into<message::Payload> + fake::Dummy<fake::Faker>,
    {
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        let private_key: PrivateKey = keypair.secret_key().into();
        let original_message = SignerMessage {
            bitcoin_chain_tip: BitcoinBlockHash::from([1; 32]),
            payload: fake::Faker.fake_with_rng::<T, _>(&mut OsRng).into(),
        };

        // We sign a payload digest. It should always be what this function
        // returned **but only for the signer who is signing the digest**.
        // The signer that receives the message may not be able to
        // reproduce the original digest that was signed after deserializing
        // the protobuf. This is why we use the
        // Signed::<SignerMessage>::decode_with_digest function.
        let original_digest = original_message.to_digest();

        let signed_message: Signed<SignerMessage> = original_message.sign_ecdsa(&private_key);
        let buf = signed_message.clone().encode_to_vec();

        let proto_message = proto::Signed::decode(&mut buf.as_slice()).unwrap();
        let msg = Signed::<SignerMessage>::try_from(proto_message).unwrap();

        // We should have the same signed message. This just tests protobuf
        // deserialization.
        assert_eq!(signed_message, msg);
        let (msg2, digest) = Signed::<SignerMessage>::decode_with_digest(&buf).unwrap();

        // The decode_with_digest function is not the most intuitive, so
        // lets check that it works the way that we expect, which is that
        // it deserializes just like protobuf deserialization but returns
        // the digest that was signed.
        assert_eq!(msg2, msg);
        assert_eq!(digest, original_digest);

        // Okay, now we need to check that the digest returned from
        // decode_with_digest was indeed what it was supposed to be. The
        // only way to check that is to attempt to recover the public key
        // that signed it. If the digest was wrong we'll get either an
        // error (so a panic) or the wrong public key.
        let digest = secp256k1::Message::from_digest(digest);
        let public_key = msg.signature.recover_ecdsa(&digest).unwrap();
        assert_eq!(public_key, keypair.public_key().into());
    }
}
