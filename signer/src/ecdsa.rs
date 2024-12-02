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
//! - **SignECDSA**: A trait implemented by data types that can be signed using ECDSA.
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
//! use signer::codec::ProtoSerializable;
//!
//! #[derive(Clone, PartialEq)]
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
//! impl From<SignableStr> for ProtoSignableStr {
//!     fn from(value: SignableStr) -> Self {
//!         ProtoSignableStr { string: value.0.to_string() }
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
//! assert!(signed_msg.verify());

use prost::bytes::Buf as _;
use prost::Message as _;
use sha2::Digest as _;

use crate::codec::ProtoSerializable;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message::SignerMessage;
use crate::proto;

/// Wraps an inner type with a public key and a signature,
/// allowing easy verification of the integrity of the inner data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signed<T> {
    /// The signed structure.
    pub inner: T,
    /// A signature over the hash of the inner structure.
    pub signature: secp256k1::ecdsa::Signature,
    /// The public key of the signer that generated the message.
    pub signer_public_key: PublicKey,
}

impl Signed<SignerMessage> {
    /// Unique identifier for the signed message
    pub fn id(&self) -> [u8; 32] {
        self.inner.to_digest(self.signer_public_key)
    }

    /// Verify that the signature was created over the given digest with
    /// the public key in this struct.
    pub fn verify_digest(&self, digest: [u8; 32]) -> Result<(), Error> {
        let msg = secp256k1::Message::from_digest(digest);

        self.signature
            .verify(&msg, &self.signer_public_key)
            .map_err(Error::InvalidEcdsaSignature)
    }

    /// Decodes an encoded protobuf message, transforming it into a
    /// [`Signed<SignerMessage>`], returning the signed message with the
    /// digest that was signed.
    ///
    /// # Notes
    ///
    /// This function uses the fact that the protobuf [`proto::Signed`]
    /// type has a particular layout when decoding the message to
    /// efficiently get the bytes that were signed by the signer that
    /// generated the message. It does the following:
    /// 1. Decode the first field using the given bytes. This field is the
    ///    signature field.
    /// 2. Takes a reference to the bytes after the protobuf signature
    ///    field. These were supposed to be used generate the digest that
    ///    was signed over.
    /// 3. Finish decoding the given bytes into the signed message.
    /// 4. Transform the protobuf type into the local type.
    /// 5. Use the local type along with the bytes from (2) to create the
    ///    signed digest.
    ///
    /// One of the assumptions is that repeated serialization of prost
    /// types generate the same bytes. It also assumes that fields are
    /// serialized in order by their tag. This is not true for protobufs
    /// generally, but it is for the prost protobuf implementation. The
    /// implementation was checked by inspecting the output of `cargo
    /// expand`.
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
            let (tag, wire_type) =
                prost::encoding::decode_key(&mut buf).map_err(Error::DecodeProtobuf)?;
            message
                .merge_field(tag, wire_type, &mut buf, ctx.clone())
                .map_err(Error::DecodeProtobuf)?;
            // This part here is not in prost. The purpose is to note the
            // pre-hashed-data that is hashed and then signed, and the
            // underlying assumption is that all non-signature field bytes
            // are signed. The approach here assumes that protobuf fields
            // are serialized in order of their tag and the field with tag
            // 1 is the signature field. We copy a reference to the
            // remaining bytes because these bytes were used to create the
            // digest that was signed over.
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
    fn to_digest(&self, public_key: PublicKey) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new_with_prefix(self.type_tag());

        let ans = proto::Signed {
            signature: None,
            signer_public_key: Some(public_key.into()),
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
        let public_key = PublicKey::from_private_key(private_key);
        let msg = secp256k1::Message::from_digest(self.to_digest(public_key));

        Signed {
            signature: private_key.sign_ecdsa(&msg),
            inner: self,
            signer_public_key: public_key,
        }
    }
}

#[cfg(feature = "testing")]
impl Signed<SignerMessage> {
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
        let inner = SignerMessage::random(rng);
        inner.sign_ecdsa(private_key)
    }

    /// Verify the signature over the inner data.
    pub fn verify(&self, public_key: PublicKey) -> bool {
        let digest = self.inner.to_digest(public_key);
        self.verify_digest(digest).is_ok()
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
    use crate::storage::model::{BitcoinBlockHash, StacksBlockHash, StacksTxId};

    use super::*;
    use fake::Faker;
    use test_case::test_case;

    /// These tests check that if we sign a message with a private key,
    /// that [`Signed::<SignerMessage>::decode_with_digest`] will give the
    /// correct message and recover the correct public key that signed it.
    #[test_case(PhantomData::<message::SignerDepositDecision> ; "SignerDepositDecision")]
    #[test_case(PhantomData::<message::SignerWithdrawalDecision> ; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<message::StacksTransactionSignRequest> ; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<message::StacksTransactionSignature> ; "StacksTransactionSignature")]
    #[test_case(PhantomData::<message::BitcoinTransactionSignRequest> ; "BitcoinTransactionSignRequest")]
    #[test_case(PhantomData::<message::BitcoinTransactionSignAck> ; "BitcoinTransactionSignAck")]
    #[test_case(PhantomData::<message::WstsMessage> ; "WstsMessage")]
    #[test_case(PhantomData::<message::SweepTransactionInfo> ; "SweepTransactionInfo")]
    #[test_case(PhantomData::<message::BitcoinPreSignRequest> ; "BitcoinPreSignRequest")]
    #[test_case(PhantomData::<message::BitcoinPreSignAck> ; "BitcoinPreSignAck")]
    fn payload_signing_recovery<T>(_: PhantomData<T>)
    where
        T: Into<message::Payload> + fake::Dummy<Faker>,
    {
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        let private_key: PrivateKey = keypair.secret_key().into();
        let public_key: PublicKey = keypair.public_key().into();
        let original_message = SignerMessage {
            bitcoin_chain_tip: BitcoinBlockHash::from([1; 32]),
            payload: Faker.fake_with_rng::<T, _>(&mut OsRng).into(),
        };

        // We sign a payload digest. It should always be what this function
        // returned **but only for the signer who is signing the digest**.
        // The signer that receives the message may not be able to
        // reproduce the original digest that was signed after deserializing
        // the protobuf. This is why we use the
        // Signed::<SignerMessage>::decode_with_digest function.
        let original_digest = original_message.to_digest(public_key);

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
        msg.verify_digest(digest).unwrap();
        assert_eq!(msg.signer_public_key, keypair.public_key().into());
    }

    /// These tests check that if we sign a message with a private key,
    /// that [`Signed::<SignerMessage>::decode_with_digest`] will give the
    /// correct message but the recoverable signature will not yield the
    /// correct public key that signed it.
    #[test_case(PhantomData::<message::SignerDepositDecision> ; "SignerDepositDecision")]
    #[test_case(PhantomData::<message::SignerWithdrawalDecision> ; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<message::StacksTransactionSignRequest> ; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<message::StacksTransactionSignature> ; "StacksTransactionSignature")]
    #[test_case(PhantomData::<message::BitcoinTransactionSignRequest> ; "BitcoinTransactionSignRequest")]
    #[test_case(PhantomData::<message::BitcoinTransactionSignAck> ; "BitcoinTransactionSignAck")]
    #[test_case(PhantomData::<message::WstsMessage> ; "WstsMessage")]
    #[test_case(PhantomData::<message::SweepTransactionInfo> ; "SweepTransactionInfo")]
    #[test_case(PhantomData::<message::BitcoinPreSignRequest> ; "BitcoinPreSignRequest")]
    #[test_case(PhantomData::<message::BitcoinPreSignAck> ; "BitcoinPreSignAck")]
    fn payload_signing_failing_validation<T>(_: PhantomData<T>)
    where
        T: Into<message::Payload> + fake::Dummy<Faker>,
    {
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        let private_key: PrivateKey = keypair.secret_key().into();
        let public_key: PublicKey = keypair.public_key().into();
        let original_message = SignerMessage {
            bitcoin_chain_tip: BitcoinBlockHash::from([1; 32]),
            payload: Faker.fake_with_rng::<T, _>(&mut OsRng).into(),
        };

        // We sign a payload digest. It should always be what this function
        // returned **but only for the signer who is signing the digest**.
        // The signer that receives the message may not be able to
        // reproduce the original digest that was signed after deserializing
        // the protobuf. This is why we use the
        // Signed::<SignerMessage>::decode_with_digest function.
        let original_digest = original_message.to_digest(public_key);

        let mut signed_message: Signed<SignerMessage> = original_message.sign_ecdsa(&private_key);
        // Let's change one byte of the signed payload
        let mut block_hash_bytes = [1; 32];
        block_hash_bytes[0] = 2;
        signed_message.inner.bitcoin_chain_tip = BitcoinBlockHash::from(block_hash_bytes);
        let buf = signed_message.clone().encode_to_vec();

        let proto_message = proto::Signed::decode(&mut buf.as_slice()).unwrap();
        let msg = Signed::<SignerMessage>::try_from(proto_message).unwrap();

        // We should have the same signed message. This only tests protobuf
        // deserialization, so everything should be fine.
        assert_eq!(signed_message, msg);
        let (msg2, digest) = Signed::<SignerMessage>::decode_with_digest(&buf).unwrap();

        // The decode_with_digest function is not the most intuitive, so
        // lets check that it works the way that we expect, which is that
        // it deserializes just like protobuf deserialization but returns
        // the digest that was signed.
        assert_eq!(msg2, msg);
        // Now the digests should be different, since we changed one of the
        // bytes that was signed over.
        assert_ne!(digest, original_digest);

        // Okay, we changed one of the bytes, let's make sure that the
        // signatures do not verify the digest.
        msg.verify_digest(digest).unwrap_err();
    }

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct Timestamp {
        /// A field for timestamps.
        #[prost(uint64, tag = "1")]
        pub unix_timestamp: u64,
    }

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct SignedUpgraded {
        #[prost(message, optional, tag = "1")]
        pub signature: Option<proto::EcdsaSignature>,
        #[prost(message, optional, tag = "2")]
        pub signer_public_key: Option<proto::PublicKey>,
        /// The signed structure.
        #[prost(message, optional, tag = "3")]
        pub signer_message: Option<proto::SignerMessage>,
        /// An additional field for timestamps. Maybe we use this to
        /// prevent replay attacks. This field is a backwards compatible
        /// upgrade.
        #[prost(message, optional, tag = "4")]
        pub timestamp: Option<Timestamp>,
    }

    /// In these tests, we check what would happen if we upgraded the
    /// [`proto::Signed`] type. We pretend to be a signer who is using an
    /// updated protobuf schema and sending a message to another signer who
    /// has not upgraded. Here we check that the receiving signer can
    /// properly decode the message and verify the signature.
    #[test_case(PhantomData::<message::SignerDepositDecision> ; "SignerDepositDecision")]
    #[test_case(PhantomData::<message::SignerWithdrawalDecision> ; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<message::StacksTransactionSignRequest> ; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<message::StacksTransactionSignature> ; "StacksTransactionSignature")]
    #[test_case(PhantomData::<message::BitcoinTransactionSignRequest> ; "BitcoinTransactionSignRequest")]
    #[test_case(PhantomData::<message::BitcoinTransactionSignAck> ; "BitcoinTransactionSignAck")]
    #[test_case(PhantomData::<message::WstsMessage> ; "WstsMessage")]
    #[test_case(PhantomData::<message::SweepTransactionInfo> ; "SweepTransactionInfo")]
    #[test_case(PhantomData::<message::BitcoinPreSignRequest> ; "BitcoinPreSignRequest")]
    #[test_case(PhantomData::<message::BitcoinPreSignAck> ; "BitcoinPreSignAck")]
    fn backwards_compatible_updates<T>(_: PhantomData<T>)
    where
        T: Into<message::Payload> + fake::Dummy<Faker>,
    {
        // This is the upgraded signer. They will construct a message for
        // consumption by another signer.
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        let private_key: PrivateKey = keypair.secret_key().into();
        let public_key: PublicKey = keypair.public_key().into();
        let original_message = SignerMessage {
            bitcoin_chain_tip: BitcoinBlockHash::from([1; 32]),
            payload: Faker.fake_with_rng::<T, _>(&mut OsRng).into(),
        };

        // The upgraded signer sends messages with an additional field.
        // Let's populate it. Note that we need to hash all the message
        // bytes except for the signature field and then sign it.
        let unix_timestamp = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let mut signed_message_v2 = SignedUpgraded {
            signature: None,
            signer_public_key: Some(public_key.into()),
            signer_message: Some(original_message.clone().into()),
            timestamp: Some(Timestamp { unix_timestamp }),
        };

        // That signer needs to add a signature, let's do it.
        let mut hasher = sha2::Sha256::new_with_prefix(original_message.type_tag());

        hasher.update(signed_message_v2.encode_to_vec());
        let digest = hasher.finalize().into();
        let msg = secp256k1::Message::from_digest(digest);
        signed_message_v2.signature = Some(private_key.sign_ecdsa(&msg).into());

        // Okay now we have a signed upgraded message. We encoded it and
        // send it out.
        let received_data = signed_message_v2.encode_to_vec();
        // Now the other signer receives it. This signer does not have the
        // "new" `SignedUpgraded` protobuf definition. The implementation
        // in Signed::<SignerMessage>::decode_with_digest uses the
        // proto::Signed type for decoding. Still, this function shouldn't
        // fail.
        let (msg, digest) = Signed::<SignerMessage>::decode_with_digest(&received_data).unwrap();

        // We can verify the signature, even though we sent an upgraded
        // protobuf message.
        msg.verify_digest(digest).unwrap();
        assert_eq!(msg.signer_public_key, keypair.public_key().into());

        // The received message can be decoded correctly if the signer had
        // the right definition.
        let original_proto = SignedUpgraded::decode(received_data.as_slice()).unwrap();

        assert_eq!(signed_message_v2, original_proto);
    }

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct SignedUpgraded2 {
        #[prost(message, optional, tag = "1")]
        pub signature: Option<proto::EcdsaSignature>,
        #[prost(message, optional, tag = "2")]
        pub signer_public_key: Option<proto::PublicKey>,
        #[prost(message, optional, tag = "3")]
        pub signer_message: Option<SignerMessageUpgraded>,
        /// An additional field for timestamps. Maybe we use this to
        /// prevent replay attacks. This field is a backwards compatible
        /// upgrade.
        #[prost(message, optional, tag = "4")]
        pub timestamp: Option<Timestamp>,
    }

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct SignerMessageUpgraded {
        #[prost(message, optional, tag = "1")]
        pub bitcoin_chain_tip: Option<proto::BitcoinBlockHash>,
        #[prost(oneof = "PayloadUpgraded", tags = "3")]
        pub payload: Option<PayloadUpgraded>,
    }

    /// The message payload
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum PayloadUpgraded {
        #[prost(message, tag = "3")]
        SignerWithdrawalDecisionUpgraded(SignerWithdrawalDecisionUpgraded),
    }

    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SignerWithdrawalDecisionUpgraded {
        #[prost(uint64, tag = "1")]
        pub request_id: u64,
        #[prost(message, optional, tag = "2")]
        pub block_id: Option<proto::StacksBlockId>,
        #[prost(message, optional, tag = "3")]
        pub txid: Option<proto::StacksTxid>,
        #[prost(bool, tag = "4")]
        pub accepted: bool,
        /// Some new map field. It is added in a backwards compatible way.
        #[prost(map = "uint32, message", tag = "5")]
        pub new_field: std::collections::HashMap<u32, proto::SetValueZst>,
    }

    #[test]
    fn backwards_compatible_updates2() {
        // This is the upgraded signer. They will construct a message for
        // consumption by another signer.
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        let private_key: PrivateKey = keypair.secret_key().into();
        let public_key: PublicKey = keypair.public_key().into();

        // The upgraded signer sends messages with an additional field for
        // the SignerWithdrawalDecision and for the proto::Signed type.
        // Let's generate it. Note that we always hash all the message
        // bytes except for the signature field and then sign it.

        // This new field is a map field. Let's populate it with some
        // values.
        let mut new_field = std::collections::HashMap::new();
        for _ in 0..100 {
            new_field.insert(Faker.fake_with_rng(&mut OsRng), proto::SetValueZst {});
        }
        let block_hash = Faker.fake_with_rng::<StacksBlockHash, _>(&mut OsRng);
        let txid = Faker.fake_with_rng::<StacksTxId, _>(&mut OsRng);
        let decision = SignerWithdrawalDecisionUpgraded {
            request_id: 102,
            block_id: Some(proto::StacksBlockId::from(block_hash)),
            txid: Some(proto::StacksTxid::from(txid)),
            accepted: true,
            new_field,
        };

        // Now we prepare to sign the upgraded message.
        let unix_timestamp = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let mut signed_message_v2 = SignedUpgraded2 {
            signature: None,
            signer_public_key: Some(public_key.into()),
            signer_message: Some(SignerMessageUpgraded {
                bitcoin_chain_tip: Some(BitcoinBlockHash::from([1; 32]).into()),
                payload: Some(PayloadUpgraded::SignerWithdrawalDecisionUpgraded(decision)),
            }),
            timestamp: Some(Timestamp { unix_timestamp }),
        };

        // That signer needs to add a signature, let's do it. The type tag
        // should not change when we update our payload types, and we are
        // sending an updated withdrawal decision.
        let mut hasher = sha2::Sha256::new_with_prefix("SBTC_SIGNER_WITHDRAWAL_DECISION");
        // We hash all but the signature field to get the digest to be
        // signed.
        hasher.update(signed_message_v2.encode_to_vec());
        let digest = hasher.finalize().into();
        let msg = secp256k1::Message::from_digest(digest);
        // Let's add the signature.
        signed_message_v2.signature = Some(private_key.sign_ecdsa(&msg).into());

        // Okay now we have a signed upgraded message. We encoded it and
        // send it out.
        let received_data = signed_message_v2.encode_to_vec();
        // Now the other signer receives it. This signer does not have the
        // "new" `SignedUpgraded2` protobuf definition, nor do they have
        // the SignerWithdrawalDecisionUpgraded. The implementation in
        // Signed::<SignerMessage>::decode_with_digest uses the
        // proto::Signed type for decoding. Still, this function shouldn't
        // fail.
        let (msg, digest) = Signed::<SignerMessage>::decode_with_digest(&received_data).unwrap();

        // The signature should verify with the returned digest
        msg.verify_digest(digest).unwrap();
        assert_eq!(msg.signer_public_key, keypair.public_key().into());

        // The received message can be decoded correctly if the signer had
        // the right definition.
        let original_proto = SignedUpgraded2::decode(received_data.as_slice()).unwrap();

        assert_eq!(signed_message_v2, original_proto);
    }
}
