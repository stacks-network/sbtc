//! # Canonical encoding and decoding for the sBTC signer
//!
//! The purpose of this module is to define how to encode and decode signer
//! messages as byte sequences.
//!
//! ## Codec specification
//!
//! The signers communicate with each other by sending protobuf messages
//! serialized in a canonical way. Specifically, signer message
//! serialization must adhere to the following constraints:
//! 1. Each field must be serialized in the order of its tag number. If
//!    `field_a` has a lower tag than `field_b`, then `field_a` will be
//!    serialized before `field_b`.
//! 2. Map protobuf fields can only be used if the key type is
//!    well-ordered. In particular, the Rust version of these types must
//!    implement the `Ord` trait.
//! 3. Map elements must be serialized in order of their keys.
//! 4. The specific encoding and decoding of a field or message must follow
//!    the protobuf spec. In particular, missing fields are not serialized.
//!
//! Serialization of signer messages that adhere to the above constraints
//! is achieved by doing the following:
//! 1. Use [`prost`] to generate rust serialization and deserialization
//!    code. We do so in a way that satisfies all four of the above
//!    constraints.
//! 2. Provide a `ProtoSerializable` trait for types that can be serialized
//!    by their corresponding protobuf analog.
//! 3. Provide the `Encode` and `Decode` traits.  Use them for
//!    serialization and deserialization of any types that implement the
//!    `ProtoSerializable` trait.
//!
//! At this time, we do not enforce the above serialization rules during
//! deserialization, with a partial exception for the
//! [`Signed<SignerMessage>`](crate::ecdsa::Signed) type, where we enforce
//! rule (1).

use std::io;

use prost::Message as _;

use crate::error::Error;

/// Utility trait to specify mapping between internal types and proto
/// counterparts. The implementation of `Encode` and `Decode` for a type
/// `T` implementing `ProtoSerializable` assume `T: Into<Message> +
/// TryFrom<Message>`.
/// ```
/// use signer::codec::ProtoSerializable;
/// use signer::proto;
///
/// struct MyPublicKey(signer::keys::PublicKey);
///
/// impl ProtoSerializable for MyPublicKey {
///     type Message = proto::PublicKey;
///
///     fn type_tag(&self) -> &'static str {
///         "MY_PUBLIC_KEY"
///     }
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

/// The error used in the [`Encode`] and [`Decode`] trait.
#[derive(thiserror::Error, Debug)]
pub enum CodecError {
    /// Decode error
    #[error("Decode error: {0}")]
    DecodeError(#[source] prost::DecodeError),
    /// Decode error
    #[error("Decode error: {0}")]
    DecodeIOError(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::marker::PhantomData;

    use fake::Dummy;
    use fake::Fake as _;
    use fake::Faker;
    use prost::bytes::Buf as _;
    use rand::rngs::OsRng;
    use rand::SeedableRng as _;
    use test_case::test_case;

    use p256k1::point::Point;
    use p256k1::scalar::Scalar;
    use polynomial::Polynomial;
    use secp256k1::ecdsa::RecoverableSignature;
    use stacks_common::types::chainstate::StacksAddress;
    use wsts::common::Nonce;
    use wsts::common::PolyCommitment;
    use wsts::common::PublicNonce;
    use wsts::common::SignatureShare;
    use wsts::common::TupleProof;
    use wsts::net::BadPrivateShare;
    use wsts::net::DkgBegin;
    use wsts::net::DkgEnd;
    use wsts::net::DkgEndBegin;
    use wsts::net::DkgPrivateBegin;
    use wsts::net::DkgPrivateShares;
    use wsts::net::DkgPublicShares;
    use wsts::net::DkgStatus;
    use wsts::net::NonceRequest;
    use wsts::net::NonceResponse;
    use wsts::net::SignatureShareRequest;
    use wsts::net::SignatureShareResponse;
    use wsts::net::SignatureType;

    use crate::bitcoin::utxo::Fees;
    use crate::bitcoin::validation::TxRequestIds;
    use crate::ecdsa::Signed;
    use crate::keys::PublicKey;
    use crate::message::BitcoinPreSignAck;
    use crate::message::BitcoinPreSignRequest;
    use crate::message::SignerDepositDecision;
    use crate::message::SignerMessage;
    use crate::message::SignerWithdrawalDecision;
    use crate::message::StacksTransactionSignRequest;
    use crate::message::StacksTransactionSignature;
    use crate::message::WstsMessage;
    use crate::proto;
    use crate::stacks::contracts::AcceptWithdrawalV1;
    use crate::stacks::contracts::CompleteDepositV1;
    use crate::stacks::contracts::RejectWithdrawalV1;
    use crate::stacks::contracts::RotateKeysV1;
    use crate::storage::model::BitcoinBlockHash;
    use crate::storage::model::BitcoinTxId;
    use crate::storage::model::QualifiedRequestId;
    use crate::storage::model::StacksBlockHash;
    use crate::storage::model::StacksPrincipal;
    use crate::storage::model::StacksTxId;
    use crate::testing::dummy::Unit;

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

    #[test_case(PhantomData::<([u8; 32], proto::Uint256)>; "Uint256")]
    #[test_case(PhantomData::<(PublicKey, proto::PublicKey)>; "PublicKey")]
    #[test_case(PhantomData::<(BitcoinTxId, proto::BitcoinTxid)>; "BitcoinTxId")]
    #[test_case(PhantomData::<(BitcoinBlockHash, proto::BitcoinBlockHash)>; "BitcoinBlockHash")]
    #[test_case(PhantomData::<(StacksTxId, proto::StacksTxid)>; "StacksTxId")]
    #[test_case(PhantomData::<(StacksBlockHash, proto::StacksBlockId)>; "StacksBlockHash")]
    #[test_case(PhantomData::<(StacksPrincipal, proto::StacksPrincipal)>; "StacksPrincipal")]
    #[test_case(PhantomData::<(SignerDepositDecision, proto::SignerDepositDecision)>; "SignerDepositDecision")]
    #[test_case(PhantomData::<(SignerWithdrawalDecision, proto::SignerWithdrawalDecision)>; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<(StacksTransactionSignature, proto::StacksTransactionSignature)>; "StacksTransactionSignature")]
    #[test_case(PhantomData::<(CompleteDepositV1, proto::CompleteDeposit)>; "CompleteDeposit")]
    #[test_case(PhantomData::<(AcceptWithdrawalV1, proto::AcceptWithdrawal)>; "AcceptWithdrawal")]
    #[test_case(PhantomData::<(RejectWithdrawalV1, proto::RejectWithdrawal)>; "RejectWithdrawal")]
    #[test_case(PhantomData::<(RotateKeysV1, proto::RotateKeys)>; "RotateKeys")]
    #[test_case(PhantomData::<(StacksTransactionSignRequest, proto::StacksTransactionSignRequest)>; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<(WstsMessage, proto::WstsMessage)>; "WstsMessage")]
    #[test_case(PhantomData::<(SignerMessage, proto::SignerMessage)>; "SignerMessage")]
    #[test_case(PhantomData::<(Signed<SignerMessage>, proto::Signed)>; "Signed")]
    #[test_case(PhantomData::<(QualifiedRequestId, proto::QualifiedRequestId)>; "QualifiedRequestId")]
    #[test_case(PhantomData::<(TxRequestIds, proto::TxRequestIds)>; "TxRequestIds")]
    #[test_case(PhantomData::<(Fees, proto::Fees)>; "Fees")]
    #[test_case(PhantomData::<(BitcoinPreSignRequest, proto::BitcoinPreSignRequest)>; "BitcoinPreSignRequest")]
    #[test_case(PhantomData::<(BitcoinPreSignAck, proto::BitcoinPreSignAck)>; "BitcoinPreSignAck")]
    fn sbtc_protobuf_message_codec_tag_order<T, U, E>(_: PhantomData<(T, U)>)
    where
        // `.unwrap()` requires that `E` implement `std::fmt::Debug` and
        // `assert_eq!` requires `PartialEq + std::fmt::Debug`.
        T: Dummy<Faker> + TryFrom<U, Error = E> + Clone + PartialEq + std::fmt::Debug,
        U: From<T> + prost::Message + Default + PartialEq,
        E: std::fmt::Debug,
    {
        let original: T = Faker.fake_with_rng(&mut OsRng);
        let proto_original = U::from(original.clone());
        let data = proto_original.encode_to_vec();
        let mut buf = data.as_slice();

        // This is almost exactly what prost does when decoding protobuf
        // bytes.
        let mut proto_orig = U::default();
        let ctx = prost::encoding::DecodeContext::default();
        let mut last_tag = 0;

        while buf.has_remaining() {
            let (tag, wire_type) = prost::encoding::decode_key(&mut buf).unwrap();

            // Repeated fields are encoded with the same tag.
            more_asserts::assert_le!(last_tag, tag);
            last_tag = tag;

            proto_orig
                .merge_field(tag, wire_type, &mut buf, ctx.clone())
                .unwrap();
        }

        assert_eq!(proto_original, proto_orig);

        let orig = T::try_from(proto_orig).unwrap();
        assert_eq!(original, orig);
    }

    #[test_case(PhantomData::<(bitcoin::OutPoint, proto::OutPoint)>; "OutPoint")]
    #[test_case(PhantomData::<(RecoverableSignature, proto::RecoverableSignature)>; "RecoverableSignature")]
    #[test_case(PhantomData::<(secp256k1::ecdsa::Signature, proto::EcdsaSignature)>; "EcdsaSignature")]
    #[test_case(PhantomData::<(StacksAddress, proto::StacksAddress)>; "StacksAddress")]
    #[test_case(PhantomData::<(Point, proto::Point)>; "Point")]
    #[test_case(PhantomData::<(Scalar, proto::Scalar)>; "Scalar")]
    #[test_case(PhantomData::<(Polynomial<Scalar>, proto::Polynomial)>; "Polynomial")]
    #[test_case(PhantomData::<((u32, Scalar), proto::PrivateKeyShare)>; "PrivateKeyShare")]
    #[test_case(PhantomData::<(DkgBegin, proto::DkgBegin)>; "DkgBegin")]
    #[test_case(PhantomData::<(DkgPrivateBegin, proto::DkgPrivateBegin)>; "DkgPrivateBegin")]
    #[test_case(PhantomData::<(DkgPrivateShares, proto::DkgPrivateShares)>; "DkgPrivateShares")]
    #[test_case(PhantomData::<(DkgEndBegin, proto::DkgEndBegin)>; "DkgEndBegin")]
    #[test_case(PhantomData::<(TupleProof, proto::TupleProof)>; "TupleProof")]
    #[test_case(PhantomData::<(BadPrivateShare, proto::BadPrivateShare)>; "BadPrivateShare")]
    #[test_case(PhantomData::<(hashbrown::HashMap<u32, BadPrivateShare>, proto::BadPrivateShares)>; "BadPrivateShares")]
    #[test_case(PhantomData::<(DkgStatus, proto::DkgStatus)>; "DkgStatus")]
    #[test_case(PhantomData::<(DkgEnd, proto::DkgEnd)>; "DkgEnd")]
    #[test_case(PhantomData::<(SignatureType, proto::SignatureType)>; "SignatureType")]
    #[test_case(PhantomData::<(NonceRequest, proto::NonceRequest)>; "NonceRequest")]
    #[test_case(PhantomData::<(PublicNonce, proto::PublicNonce)>; "PublicNonce")]
    #[test_case(PhantomData::<(NonceResponse, proto::NonceResponse)>; "NonceResponse")]
    #[test_case(PhantomData::<(SignatureShareRequest, proto::SignatureShareRequest)>; "SignatureShareRequest")]
    #[test_case(PhantomData::<(SignatureShare, proto::SignatureShare)>; "SignatureShare")]
    #[test_case(PhantomData::<(SignatureShareResponse, proto::SignatureShareResponse)>; "SignatureShareResponse")]
    #[test_case(PhantomData::<(Nonce, proto::PrivateNonce)>; "PrivateNonce")]
    #[test_case(PhantomData::<(wsts::schnorr::ID, proto::ProofIdentifier)>; "ProofIdentifier")]
    #[test_case(PhantomData::<(PolyCommitment, proto::PolyCommitment)>; "PolyCommitment")]
    #[test_case(PhantomData::<((u32, PolyCommitment), proto::PartyCommitment)>; "PartyCommitment")]
    #[test_case(PhantomData::<(DkgPublicShares, proto::SignerDkgPublicShares)>; "SignerDkgPublicShares")]
    #[test_case(PhantomData::<(BTreeMap<u32, DkgPublicShares>, proto::DkgPublicShares)>; "DkgPublicShares")]
    fn sbtc_protobuf_message_codec_tag_order2<T, U, E>(_: PhantomData<(T, U)>)
    where
        T: Dummy<Unit> + TryFrom<U, Error = E> + Clone + PartialEq + std::fmt::Debug,
        U: From<T> + prost::Message + Default + PartialEq,
        E: std::fmt::Debug,
    {
        let original: T = Unit.fake_with_rng(&mut OsRng);
        let proto_original = U::from(original.clone());
        let data = proto_original.encode_to_vec();
        let mut buf = data.as_slice();

        // This is almost exactly what prost does when decoding protobuf
        // bytes.
        let mut proto_orig = U::default();
        let ctx = prost::encoding::DecodeContext::default();
        let mut last_tag = 0;

        while buf.has_remaining() {
            let (tag, wire_type) = prost::encoding::decode_key(&mut buf).unwrap();

            // Repeated fields are encoded with the same tag.
            more_asserts::assert_le!(last_tag, tag);
            last_tag = tag;

            proto_orig
                .merge_field(tag, wire_type, &mut buf, ctx.clone())
                .unwrap();
        }

        assert_eq!(proto_original, proto_orig);

        let orig = T::try_from(proto_orig).unwrap();
        assert_eq!(original, orig);
    }

    #[test_case(PhantomData::<proto::Uint256>; "Uint256")]
    #[test_case(PhantomData::<proto::PublicKey>; "PublicKey")]
    #[test_case(PhantomData::<proto::BitcoinTxid>; "BitcoinTxId")]
    #[test_case(PhantomData::<proto::BitcoinBlockHash>; "BitcoinBlockHash")]
    #[test_case(PhantomData::<proto::StacksTxid>; "StacksTxId")]
    #[test_case(PhantomData::<proto::StacksBlockId>; "StacksBlockHash")]
    #[test_case(PhantomData::<proto::StacksPrincipal>; "StacksPrincipal")]
    #[test_case(PhantomData::<proto::SignerDepositDecision>; "SignerDepositDecision")]
    #[test_case(PhantomData::<proto::SignerWithdrawalDecision>; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<proto::StacksTransactionSignature>; "StacksTransactionSignature")]
    #[test_case(PhantomData::<proto::CompleteDeposit>; "CompleteDeposit")]
    #[test_case(PhantomData::<proto::AcceptWithdrawal>; "AcceptWithdrawal")]
    #[test_case(PhantomData::<proto::RejectWithdrawal>; "RejectWithdrawal")]
    #[test_case(PhantomData::<proto::RotateKeys>; "RotateKeys")]
    #[test_case(PhantomData::<proto::StacksTransactionSignRequest>; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<proto::WstsMessage>; "WstsMessage")]
    #[test_case(PhantomData::<proto::SignerMessage>; "SignerMessage")]
    #[test_case(PhantomData::<proto::Signed>; "Signed")]
    #[test_case(PhantomData::<proto::QualifiedRequestId>; "QualifiedRequestId")]
    #[test_case(PhantomData::<proto::TxRequestIds>; "TxRequestIds")]
    #[test_case(PhantomData::<proto::Fees>; "Fees")]
    #[test_case(PhantomData::<proto::BitcoinPreSignRequest>; "BitcoinPreSignRequest")]
    #[test_case(PhantomData::<proto::BitcoinPreSignAck>; "BitcoinPreSignAck")]
    #[test_case(PhantomData::<proto::OutPoint>; "OutPoint")]
    #[test_case(PhantomData::<proto::RecoverableSignature>; "RecoverableSignature")]
    #[test_case(PhantomData::<proto::EcdsaSignature>; "EcdsaSignature")]
    #[test_case(PhantomData::<proto::StacksAddress>; "StacksAddress")]
    #[test_case(PhantomData::<proto::Point>; "Point")]
    #[test_case(PhantomData::<proto::Scalar>; "Scalar")]
    #[test_case(PhantomData::<proto::Polynomial>; "Polynomial")]
    #[test_case(PhantomData::<proto::PrivateKeyShare>; "PrivateKeyShare")]
    #[test_case(PhantomData::<proto::DkgBegin>; "DkgBegin")]
    #[test_case(PhantomData::<proto::DkgPrivateBegin>; "DkgPrivateBegin")]
    #[test_case(PhantomData::<proto::DkgPrivateShares>; "DkgPrivateShares")]
    #[test_case(PhantomData::<proto::DkgEndBegin>; "DkgEndBegin")]
    #[test_case(PhantomData::<proto::TupleProof>; "TupleProof")]
    #[test_case(PhantomData::<proto::BadPrivateShare>; "BadPrivateShare")]
    #[test_case(PhantomData::<proto::BadPrivateShares>; "BadPrivateShares")]
    #[test_case(PhantomData::<proto::DkgStatus>; "DkgStatus")]
    #[test_case(PhantomData::<proto::DkgEnd>; "DkgEnd")]
    #[test_case(PhantomData::<proto::SignatureType>; "SignatureType")]
    #[test_case(PhantomData::<proto::NonceRequest>; "NonceRequest")]
    #[test_case(PhantomData::<proto::PublicNonce>; "PublicNonce")]
    #[test_case(PhantomData::<proto::NonceResponse>; "NonceResponse")]
    #[test_case(PhantomData::<proto::SignatureShareRequest>; "SignatureShareRequest")]
    #[test_case(PhantomData::<proto::SignatureShare>; "SignatureShare")]
    #[test_case(PhantomData::<proto::SignatureShareResponse>; "SignatureShareResponse")]
    #[test_case(PhantomData::<proto::PrivateNonce>; "PrivateNonce")]
    #[test_case(PhantomData::<proto::ProofIdentifier>; "ProofIdentifier")]
    #[test_case(PhantomData::<proto::PolyCommitment>; "PolyCommitment")]
    #[test_case(PhantomData::<proto::PartyCommitment>; "PartyCommitment")]
    #[test_case(PhantomData::<proto::SignerDkgPublicShares>; "SignerDkgPublicShares")]
    #[test_case(PhantomData::<proto::DkgPublicShares>; "DkgPublicShares")]
    fn sbtc_protobuf_codec_default_value_no_serialization<U>(_: PhantomData<U>)
    where
        U: prost::Message + Default,
    {
        let proto_original = U::default();
        let data = proto_original.encode_to_vec();
        assert!(data.is_empty());
    }
}
