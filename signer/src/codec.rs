//! # Canonical encoding and decoding for the sBTC signer
//!
//! The purpose of this module is to define how to encode and decode
//! signer messages as byte sequences.
//!
//! This is achieved by
//!
//! 1. Providing the `Encode` and `Decode` traits, defining the encode and decode
//!    methods we intend to use throughout the signer.
//! 2. Implementing these traits for any type implementing `ProtoSerializable` defined in here.
//!
//! ## Examples
//!
//! ### Encoding a string slice and decoding it as a string
//!
//! ```
//! use signer::codec::{Encode, Decode};
//!
//! let message = "Encode me";
//!
//! // `.encode_to_vec()` provided by the `Encode` trait
//! let encoded = message.encode_to_vec().unwrap();
//!
//! // `.decode()` provided by the `Decode` trait
//! let decoded = String::decode(encoded.as_slice()).unwrap();
//!
//! assert_eq!(decoded, message);
//! ```

use std::io;

use prost::Message as _;
use sha2::Digest as _;

use crate::ecdsa::Signed;
use crate::error::Error;
use crate::message::SignerMessage;
use crate::proto;

/// Utility trait to specify mapping between internal types and proto
/// counterparts. The implementation of `Encode` and `Decode` for a type
/// `T` implementing `ProtoSerializable` assume `T: Into<Message> +
/// TryFrom<Message>`.
/// ```
/// impl ProtoSerializable for PublicKey {
///    type Message = proto::PublicKey;
/// }
/// ```
pub trait ProtoSerializable {
    /// The proto message type used for conversions
    type Message: ::prost::Message + Default;
    /// A message type tag used for hashing the message before signing.
    fn type_tag(&self) -> &'static str;
}

/// Provides a method for encoding an object into a writer using a canonical serialization format.
///
/// This trait is designed to be implemented by types that need to serialize their data into a byte stream
/// in a standardized format, primarily to ensure consistency across different components of the signer system.
pub trait Encode: Sized {
    /// Encodes the calling object into a vector of bytes.
    ///
    /// # Returns
    /// The vector of bytes.
    /// TODO: change to &self
    fn encode_to_vec(self) -> Vec<u8>;
}

/// Provides a method for decoding an object from a reader using a canonical deserialization format.
///
/// This trait is intended for types that need to reconstruct themselves from a byte stream, ensuring
/// that objects across the signer system are restored from bytes uniformly.
///
/// It includes a generic method for reading from any input that implements `io::Read`, as well as
/// a convenience method for decoding from a byte slice.
pub trait Decode: Sized {
    /// Decodes an object from a reader in a canonical format.
    ///
    /// # Arguments
    /// * `reader` - An object implementing `io::Read` from which the bytes will be read.
    ///
    /// # Returns
    /// A `Result` which is `Ok` containing the decoded object, or an `Error` if decoding failed.
    fn decode<R: io::Read>(reader: R) -> Result<Self, Error>;
}

impl<T> Encode for T
where
    T: ProtoSerializable + Clone,
    T: Into<<T as ProtoSerializable>::Message>,
{
    fn encode_to_vec(self) -> Vec<u8> {
        let message: <Self as ProtoSerializable>::Message = self.into();
        prost::Message::encode_to_vec(&message)
    }
}

impl<T> Decode for T
where
    T: ProtoSerializable + Clone,
    T: TryFrom<<T as ProtoSerializable>::Message, Error = Error>,
{
    fn decode<R: io::Read>(mut reader: R) -> Result<Self, Error> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(CodecError::DecodeIOError)?;

        let message =
            <<T as ProtoSerializable>::Message>::decode(&*buf).map_err(CodecError::DecodeError)?;

        T::try_from(message)
    }
}

impl Signed<SignerMessage> {
    /// Decodes an encoded protobuf message returning the decoded and
    /// transformed type with the digest that was signed over.
    pub fn decode_with_digest(data: &[u8]) -> Result<(Self, [u8; 32]), Error> {
        let mut buf = data;

        let mut message = proto::Signed::default();
        let ctx = prost::encoding::DecodeContext::default();
        let (tag, wire_type) = prost::encoding::decode_key(&mut buf)?;
        message.merge_field(tag, wire_type, &mut buf, ctx.clone())?;

        let pre_hash_data = buf;
        let (tag, wire_type) = prost::encoding::decode_key(&mut buf)?;

        message.merge_field(tag, wire_type, &mut buf, ctx.clone())?;

        let msg = Signed::<crate::message::SignerMessage>::try_from(message)?;
        let mut hasher = sha2::Sha256::new_with_prefix(msg.type_tag());

        hasher.update(pre_hash_data);
        let digest: [u8; 32] = hasher.finalize().into();

        Ok((msg, digest))
    }
}

impl SignerMessage {
    /// Transform this into the digest that needs to be signed
    pub fn to_digest(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new_with_prefix(self.type_tag());

        let ans = crate::proto::Signed {
            signature: None,
            signer_message: Some(self.clone().into()),
        };

        hasher.update(ans.encode_to_vec());
        hasher.finalize().into()
    }
}

/// The error used in the [`Encode`] and [`Decode`] trait.
#[derive(thiserror::Error, Debug)]
pub enum CodecError {
    /// Decode error
    #[error("Decode error: {0}")]
    DecodeError(#[source] ::prost::DecodeError),
    /// Decode error
    #[error("Decode error: {0}")]
    DecodeIOError(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use fake::Dummy as _;
    use fake::Fake as _;
    use rand::{rngs::OsRng, SeedableRng as _};

    use crate::ecdsa::SignEcdsa;
    use crate::keys::{PrivateKey, PublicKey};
    use crate::message;
    use crate::proto;
    use crate::signature::RecoverableEcdsaSignature as _;
    use crate::storage::model::BitcoinBlockHash;

    use super::*;

    impl ProtoSerializable for PublicKey {
        type Message = proto::PublicKey;

        fn type_tag(&self) -> &'static str {
            "SBTC_PUBLIC_KEY"
        }
    }

    #[test]
    fn public_key_should_be_able_to_encode_and_decode_correctly() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let message = PublicKey::dummy_with_rng(&fake::Faker, &mut rng);

        let encoded = message.encode_to_vec();

        let decoded = <PublicKey as Decode>::decode(encoded.as_slice()).unwrap();

        assert_eq!(decoded, message);
    }

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
        // reproduce the orignal digest that was signed after deserializing
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
