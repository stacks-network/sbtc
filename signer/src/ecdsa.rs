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
use crate::signature::SighashDigest;

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
        let msg = secp256k1::Message::from_digest(self.inner.digest());
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
        self.inner.digest()
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
            let (tag, wire_type) = prost::encoding::decode_key(&mut buf)?;
            message.merge_field(tag, wire_type, &mut buf, ctx.clone())?;
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

impl SighashDigest for SignerMessage {
    fn digest(&self) -> [u8; 32] {
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

impl<T: SighashDigest> SignEcdsa for T {
    fn sign_ecdsa(self, private_key: &PrivateKey) -> Signed<Self> {
        let msg = secp256k1::Message::from_digest(self.digest());

        Signed {
            signature: private_key.sign_ecdsa_recoverable(&msg),
            inner: self,
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
        self.recover_ecdsa().is_ok_and(|key| key == public_key)
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
    use crate::message::SignerWithdrawalDecision;
    use crate::proto;
    use crate::signature::RecoverableEcdsaSignature as _;
    use crate::storage::model::BitcoinBlockHash;

    use super::*;
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
        let original_digest = original_message.digest();

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
    fn payload_signing_failing_validation<T>(_: PhantomData<T>)
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
        let original_digest = original_message.digest();

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
        // public key does not match either.
        let digest = secp256k1::Message::from_digest(digest);
        // I don't think that this will return an error, but I don't know
        // for sure that it cannot. If it returns an error then that counts
        // as the message failing validation so.
        match msg.signature.recover_ecdsa(&digest) {
            Ok(public_key) => assert_ne!(public_key, keypair.public_key().into()),
            Err(_) => (),
        };
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
        /// A signature over the hash of the inner structure.
        #[prost(message, optional, tag = "1")]
        pub signature: Option<proto::RecoverableSignature>,
        /// The signed structure.
        #[prost(message, optional, tag = "2")]
        pub signer_message: Option<proto::SignerMessage>,
        /// An additional field for timestamps. Maybe we use this to
        /// prevent replay attacks. This field is a backwards compatible
        /// upgrade.
        #[prost(message, optional, tag = "3")]
        pub timestamp: Option<Timestamp>,
    }

    /// In these tests, we check what would happen if we upgraded one of
    /// the [`proto::Signed`] type. We pretend to be a signer who is using
    /// an updated protobuf schema and sending a message to another signer.
    /// Here we check that the receiving signer can properly decode the
    /// message and verify the signature.
    #[test]
    fn backwards_compatible_updates() {
        // This is the upgraded signer. They will construct a message for
        // consumption by another signer.
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        let private_key: PrivateKey = keypair.secret_key().into();
        let original_message = SignerMessage {
            bitcoin_chain_tip: BitcoinBlockHash::from([1; 32]),
            payload: fake::Faker
                .fake_with_rng::<SignerWithdrawalDecision, _>(&mut OsRng)
                .into(),
        };

        // The upgraded signer sends messages with an additional field.
        // Let's populate it. Note that we need to hash all of the message
        // bytes except for the signature field and then sign it.
        let unix_timestamp = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        let mut signed_message_v2 = SignedUpgraded {
            signature: None,
            signer_message: Some(original_message.clone().into()),
            timestamp: Some(Timestamp { unix_timestamp }),
        };

        // That signer needs to add a signature, let's do it.
        let mut hasher = sha2::Sha256::new_with_prefix(original_message.type_tag());

        hasher.update(signed_message_v2.encode_to_vec());
        let digest = hasher.finalize().into();
        let msg = secp256k1::Message::from_digest(digest);
        signed_message_v2.signature = Some(private_key.sign_ecdsa_recoverable(&msg).into());

        // Okay now we have a signed upgraded message. We encoded it and
        // send it out.
        let received_data = signed_message_v2.encode_to_vec();
        // Now the other signer receives it. This signer does not have the
        // "new" `SignedUpgraded` protobuf definition. The implementation
        // in Signed::<SignerMessage>::decode_with_digest uses the
        // proto::Signed type for decoding. Still, this function shouldn't
        // fail.
        let (msg, digest) = Signed::<SignerMessage>::decode_with_digest(&received_data).unwrap();

        // We can recover the public key using the returned digest, it
        // should match what we expect, even though we sent an upgraded
        // protobuf message.
        let public_key = msg.recover_ecdsa_with_digest(digest).unwrap();
        assert_eq!(public_key, keypair.public_key().into());

        // The received message can be decoded correctly if the signer had
        // the right definition.
        let original_proto = SignedUpgraded::decode(received_data.as_slice()).unwrap();

        assert_eq!(signed_message_v2, original_proto);
    }
}
