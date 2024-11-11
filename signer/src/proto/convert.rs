//! Conversion functions from a protobuf type to regular type and vice
//! versa.
//!
//! Converting to a protobuf type must be infallible, while converting from
//! a protobuf type can be fallible.
//!

use clarity::codec::StacksMessageCodec as _;
use clarity::vm::types::PrincipalData;
use secp256k1::ecdsa::RecoverableSignature;
use stacks_common::types::chainstate::StacksAddress;

use crate::error::Error;
use crate::keys::PublicKey;
use crate::message::BitcoinTransactionSignAck;
use crate::message::SignerDepositDecision;
use crate::message::SignerWithdrawalDecision;
use crate::message::StacksTransactionSignature;
use crate::proto;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksPrincipal;
use crate::storage::model::StacksTxId;

/// This trait is to make it easy to handle fields of protobuf structs that
/// are `None`, when they should be `Some(_)`.
trait RequiredField: Sized {
    type Inner;
    fn required(self) -> Result<Self::Inner, Error>;
}

impl<T> RequiredField for Option<T> {
    type Inner = T;
    fn required(self) -> Result<Self::Inner, Error> {
        self.ok_or(Error::RequiredProtobufFieldMissing)
    }
}

impl From<[u8; 32]> for proto::Uint256 {
    fn from(value: [u8; 32]) -> Self {
        let mut part0 = [0u8; 8];
        let mut part1 = [0u8; 8];
        let mut part2 = [0u8; 8];
        let mut part3 = [0u8; 8];

        part0.copy_from_slice(&value[..8]);
        part1.copy_from_slice(&value[8..16]);
        part2.copy_from_slice(&value[16..24]);
        part3.copy_from_slice(&value[24..32]);

        proto::Uint256 {
            bits_part0: u64::from_le_bytes(part0),
            bits_part1: u64::from_le_bytes(part1),
            bits_part2: u64::from_le_bytes(part2),
            bits_part3: u64::from_le_bytes(part3),
        }
    }
}

impl From<proto::Uint256> for [u8; 32] {
    fn from(value: proto::Uint256) -> Self {
        let mut bytes = [0u8; 32];

        bytes[..8].copy_from_slice(&value.bits_part0.to_le_bytes());
        bytes[8..16].copy_from_slice(&value.bits_part1.to_le_bytes());
        bytes[16..24].copy_from_slice(&value.bits_part2.to_le_bytes());
        bytes[24..32].copy_from_slice(&value.bits_part3.to_le_bytes());
        bytes
    }
}

impl From<PublicKey> for proto::PublicKey {
    fn from(value: PublicKey) -> Self {
        let (x_only, parity) = value.x_only_public_key();
        proto::PublicKey {
            x_only_public_key: Some(proto::Uint256::from(x_only.serialize())),
            parity_is_odd: parity == secp256k1::Parity::Odd,
        }
    }
}

impl TryFrom<proto::PublicKey> for PublicKey {
    type Error = Error;
    fn try_from(value: proto::PublicKey) -> Result<Self, Self::Error> {
        let x_only: [u8; 32] = value.x_only_public_key.required()?.into();
        let pk = secp256k1::XOnlyPublicKey::from_slice(&x_only).map_err(Error::InvalidPublicKey)?;
        let parity = if value.parity_is_odd {
            secp256k1::Parity::Odd
        } else {
            secp256k1::Parity::Even
        };
        let public_key = secp256k1::PublicKey::from_x_only_public_key(pk, parity);
        Ok(Self::from(public_key))
    }
}

impl From<RecoverableSignature> for proto::RecoverableSignature {
    fn from(value: RecoverableSignature) -> Self {
        let mut lower_bits = [0; 32];
        let mut upper_bits = [0; 32];

        let (recovery_id, bytes) = value.serialize_compact();

        lower_bits.copy_from_slice(&bytes[..32]);
        upper_bits.copy_from_slice(&bytes[32..]);

        Self {
            lower_bits: Some(proto::Uint256::from(lower_bits)),
            upper_bits: Some(proto::Uint256::from(upper_bits)),
            recovery_id: recovery_id.to_i32(),
        }
    }
}

impl TryFrom<proto::RecoverableSignature> for RecoverableSignature {
    type Error = Error;
    fn try_from(value: proto::RecoverableSignature) -> Result<Self, Self::Error> {
        let mut data = [0; 64];

        let lower_bits: [u8; 32] = value.lower_bits.required()?.into();
        let upper_bits: [u8; 32] = value.upper_bits.required()?.into();

        data[..32].copy_from_slice(&lower_bits);
        data[32..].copy_from_slice(&upper_bits);

        let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(value.recovery_id)
            .map_err(Error::InvalidPublicKey)?;

        RecoverableSignature::from_compact(&data, recovery_id)
            .map_err(Error::InvalidRecoverableSignatureBytes)
    }
}

impl From<BitcoinTxId> for proto::BitcoinTxid {
    fn from(value: BitcoinTxId) -> Self {
        proto::BitcoinTxid {
            txid: Some(proto::Uint256::from(value.into_bytes())),
        }
    }
}

impl TryFrom<proto::BitcoinTxid> for BitcoinTxId {
    type Error = Error;
    fn try_from(value: proto::BitcoinTxid) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.txid.required()?.into();
        Ok(BitcoinTxId::from(bytes))
    }
}

impl From<BitcoinBlockHash> for proto::BitcoinBlockHash {
    fn from(value: BitcoinBlockHash) -> Self {
        proto::BitcoinBlockHash {
            block_hash: Some(proto::Uint256::from(value.into_bytes())),
        }
    }
}

impl TryFrom<proto::BitcoinBlockHash> for BitcoinBlockHash {
    type Error = Error;
    fn try_from(value: proto::BitcoinBlockHash) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.block_hash.required()?.into();
        Ok(BitcoinBlockHash::from(bytes))
    }
}

impl From<bitcoin::OutPoint> for proto::OutPoint {
    fn from(value: bitcoin::OutPoint) -> Self {
        proto::OutPoint {
            txid: Some(proto::BitcoinTxid::from(BitcoinTxId::from(value.txid))),
            vout: value.vout,
        }
    }
}

impl TryFrom<proto::OutPoint> for bitcoin::OutPoint {
    type Error = Error;
    fn try_from(value: proto::OutPoint) -> Result<Self, Self::Error> {
        let txid: BitcoinTxId = value.txid.required()?.try_into()?;

        Ok(bitcoin::OutPoint {
            txid: txid.into(),
            vout: value.vout,
        })
    }
}

impl From<StacksTxId> for proto::StacksTxid {
    fn from(value: StacksTxId) -> Self {
        proto::StacksTxid {
            txid: Some(proto::Uint256::from(value.into_bytes())),
        }
    }
}

impl TryFrom<proto::StacksTxid> for StacksTxId {
    type Error = Error;
    fn try_from(value: proto::StacksTxid) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.txid.required()?.into();
        Ok(StacksTxId::from(bytes))
    }
}

impl From<StacksBlockHash> for proto::StacksBlockId {
    fn from(value: StacksBlockHash) -> Self {
        proto::StacksBlockId {
            block_id: Some(proto::Uint256::from(value.into_bytes())),
        }
    }
}

impl TryFrom<proto::StacksBlockId> for StacksBlockHash {
    type Error = Error;
    fn try_from(value: proto::StacksBlockId) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.block_id.required()?.into();
        Ok(StacksBlockHash::from(bytes))
    }
}

impl From<StacksAddress> for proto::StacksAddress {
    fn from(value: StacksAddress) -> Self {
        proto::StacksAddress {
            address: value.serialize_to_vec(),
        }
    }
}

impl TryFrom<proto::StacksAddress> for StacksAddress {
    type Error = Error;
    fn try_from(value: proto::StacksAddress) -> Result<Self, Self::Error> {
        let fd = &mut value.address.as_slice();
        StacksAddress::consensus_deserialize(fd).map_err(Error::StacksCodec)
    }
}

impl From<StacksPrincipal> for proto::StacksPrincipal {
    fn from(value: StacksPrincipal) -> Self {
        proto::StacksPrincipal { data: value.serialize_to_vec() }
    }
}

impl TryFrom<proto::StacksPrincipal> for StacksPrincipal {
    type Error = Error;
    fn try_from(value: proto::StacksPrincipal) -> Result<Self, Self::Error> {
        let fd = &mut value.data.as_slice();

        PrincipalData::consensus_deserialize(fd)
            .map(StacksPrincipal::from)
            .map_err(Error::StacksCodec)
    }
}

impl From<SignerDepositDecision> for proto::SignerDepositDecision {
    fn from(value: SignerDepositDecision) -> Self {
        proto::SignerDepositDecision {
            outpoint: Some(proto::OutPoint {
                txid: Some(BitcoinTxId::from(value.txid).into()),
                vout: value.output_index,
            }),
            accepted: value.accepted,
            can_sign: value.can_sign,
        }
    }
}

impl TryFrom<proto::SignerDepositDecision> for SignerDepositDecision {
    type Error = Error;
    fn try_from(value: proto::SignerDepositDecision) -> Result<Self, Self::Error> {
        let outpoint: bitcoin::OutPoint = value.outpoint.required()?.try_into()?;
        Ok(SignerDepositDecision {
            txid: outpoint.txid,
            output_index: outpoint.vout,
            accepted: value.accepted,
            can_sign: value.can_sign,
        })
    }
}

impl From<SignerWithdrawalDecision> for proto::SignerWithdrawalDecision {
    fn from(value: SignerWithdrawalDecision) -> Self {
        proto::SignerWithdrawalDecision {
            request_id: value.request_id,
            block_id: Some(StacksBlockHash::from(value.block_hash).into()),
            accepted: value.accepted,
            txid: Some(value.txid.into()),
        }
    }
}

impl TryFrom<proto::SignerWithdrawalDecision> for SignerWithdrawalDecision {
    type Error = Error;
    fn try_from(value: proto::SignerWithdrawalDecision) -> Result<Self, Self::Error> {
        Ok(SignerWithdrawalDecision {
            request_id: value.request_id,
            block_hash: StacksBlockHash::try_from(value.block_id.required()?)?.into_bytes(),
            accepted: value.accepted,
            txid: value.txid.required()?.try_into()?,
        })
    }
}

impl From<BitcoinTransactionSignAck> for proto::BitcoinTransactionSignAck {
    fn from(value: BitcoinTransactionSignAck) -> Self {
        proto::BitcoinTransactionSignAck {
            txid: Some(BitcoinTxId::from(value.txid).into()),
        }
    }
}

impl TryFrom<proto::BitcoinTransactionSignAck> for BitcoinTransactionSignAck {
    type Error = Error;
    fn try_from(value: proto::BitcoinTransactionSignAck) -> Result<Self, Self::Error> {
        Ok(BitcoinTransactionSignAck {
            txid: BitcoinTxId::try_from(value.txid.required()?)?.into(),
        })
    }
}

impl From<StacksTransactionSignature> for proto::StacksTransactionSignature {
    fn from(value: StacksTransactionSignature) -> Self {
        proto::StacksTransactionSignature {
            txid: Some(StacksTxId::from(value.txid).into()),
            signature: Some(value.signature.into()),
        }
    }
}

impl TryFrom<proto::StacksTransactionSignature> for StacksTransactionSignature {
    type Error = Error;
    fn try_from(value: proto::StacksTransactionSignature) -> Result<Self, Self::Error> {
        Ok(StacksTransactionSignature {
            txid: StacksTxId::try_from(value.txid.required()?)?.into(),
            signature: value.signature.required()?.try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::PrivateKey;

    use super::*;

    use std::marker::PhantomData;

    use bitcoin::hashes::Hash as _;

    use fake::Dummy;
    use fake::Fake;
    use fake::Faker;
    use rand::rngs::OsRng;
    use test_case::test_case;

    struct Unit;

    impl Dummy<Unit> for bitcoin::OutPoint {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
            let bytes: [u8; 32] = Faker.fake_with_rng(rng);
            let txid = bitcoin::Txid::from_byte_array(bytes);
            let vout: u32 = Faker.fake_with_rng(rng);
            bitcoin::OutPoint { txid, vout }
        }
    }

    impl Dummy<Unit> for RecoverableSignature {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
            let private_key = PrivateKey::new(rng);
            let msg = secp256k1::Message::from_digest([0; 32]);
            private_key.sign_ecdsa_recoverable(&msg)
        }
    }

    impl Dummy<Unit> for StacksAddress {
        fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &Unit, rng: &mut R) -> Self {
            let public_key: PublicKey = Faker.fake_with_rng(rng);
            let pubkey = public_key.into();
            let mainnet: bool = Faker.fake_with_rng(rng);
            StacksAddress::p2pkh(mainnet, &pubkey)
        }
    }

    #[test]
    fn conversion_between_bytes_and_uint256() {
        let number = proto::Uint256 {
            bits_part0: Faker.fake_with_rng(&mut OsRng),
            bits_part1: Faker.fake_with_rng(&mut OsRng),
            bits_part2: Faker.fake_with_rng(&mut OsRng),
            bits_part3: Faker.fake_with_rng(&mut OsRng),
        };

        let bytes = <[u8; 32]>::from(number);
        let round_trip_number = proto::Uint256::from(bytes);
        assert_eq!(round_trip_number, number);
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
    #[test_case(PhantomData::<(BitcoinTransactionSignAck, proto::BitcoinTransactionSignAck)>; "BitcoinTransactionSignAck")]
    #[test_case(PhantomData::<(StacksTransactionSignature, proto::StacksTransactionSignature)>; "StacksTransactionSignature")]
    fn convert_protobuf_type<T, U, E>(_: PhantomData<(T, U)>)
    where
        // `.unwrap()` requires that `E` implement `std::fmt::Debug` and
        // `assert_eq!` requires `PartialEq + std::fmt::Debug`.
        T: Dummy<Faker> + TryFrom<U, Error = E> + Clone + PartialEq + std::fmt::Debug,
        U: From<T>,
        E: std::fmt::Debug,
    {
        // The type T originates from a signer. Let's create a random
        // instance of one.
        let original: T = Faker.fake_with_rng(&mut OsRng);
        // The type U is a protobuf type. Before sending it to other
        // signers, we convert our internal type into it's protobuf
        // counterpart. We can always infallibly create U from T.
        let proto_original = U::from(original.clone());

        // Some other signer receives an instance of U. This could be a
        // malicious actor or a modified version of the signer binary
        // where they made some mistake, so converting back to T can fail.
        let original_from_proto = T::try_from(proto_original).unwrap();
        // In this case, we know U was created from T correctly, so we
        // should be able to convert back without issues.
        assert_eq!(original, original_from_proto);
    }

    /// This test is identical to [`convert_protobuf_types`] tests above,
    /// except we cannot implement Dummy<Faker> on these types.
    #[test_case(PhantomData::<(bitcoin::OutPoint, proto::OutPoint)>; "OutPoint")]
    #[test_case(PhantomData::<(RecoverableSignature, proto::RecoverableSignature)>; "RecoverableSignature")]
    #[test_case(PhantomData::<(StacksAddress, proto::StacksAddress)>; "StacksAddress")]
    fn convert_protobuf_type2<T, U, E>(_: PhantomData<(T, U)>)
    where
        T: Dummy<Unit> + TryFrom<U, Error = E> + Clone + PartialEq + std::fmt::Debug,
        U: From<T>,
        E: std::fmt::Debug,
    {
        let original: T = Unit.fake_with_rng(&mut OsRng);
        let proto_original = U::from(original.clone());

        let original_from_proto = T::try_from(proto_original).unwrap();
        assert_eq!(original, original_from_proto);
    }
}
