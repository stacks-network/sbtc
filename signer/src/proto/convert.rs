//! Conversion functions from protobufs to regular types
//!

use secp256k1::ecdsa::RecoverableSignature;

use crate::error::Error;
use crate::keys::PublicKey;
use crate::proto;
use crate::storage::model::{BitcoinTxId, StacksTxId};

use crate::proto::Uint256;

pub trait RequiredField: Sized {
    type Inner;
    fn required(self) -> Result<Self::Inner, Error>;
}

impl<T> RequiredField for Option<T> {
    type Inner = T;
    fn required(self) -> Result<Self::Inner, Error> {
        self.ok_or(Error::TypeConversion)
    }
}

impl From<[u8; 32]> for Uint256 {
    fn from(value: [u8; 32]) -> Self {
        let mut part0 = [0u8; 8];
        let mut part1 = [0u8; 8];
        let mut part2 = [0u8; 8];
        let mut part3 = [0u8; 8];

        part0.copy_from_slice(&value[..8]);
        part1.copy_from_slice(&value[8..16]);
        part2.copy_from_slice(&value[16..24]);
        part3.copy_from_slice(&value[24..32]);

        Uint256 {
            bits_part0: u64::from_le_bytes(part0),
            bits_part1: u64::from_le_bytes(part1),
            bits_part2: u64::from_le_bytes(part2),
            bits_part3: u64::from_le_bytes(part3),
        }
    }
}

impl From<Uint256> for [u8; 32] {
    fn from(value: Uint256) -> Self {
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
            x_only_public_key: Some(Uint256::from(x_only.serialize())),
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
            lower_bits: Some(Uint256::from(lower_bits)),
            upper_bits: Some(Uint256::from(upper_bits)),
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

impl From<StacksTxId> for proto::StacksTxid {
    fn from(value: StacksTxId) -> Self {
        proto::StacksTxid {
            txid: Some(Uint256::from(value.into_bytes())),
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

impl From<BitcoinTxId> for proto::BitcoinTxid {
    fn from(value: BitcoinTxId) -> Self {
        proto::BitcoinTxid {
            txid: Some(Uint256::from(value.into_bytes())),
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

#[cfg(test)]
mod tests {
    use super::*;
    use fake::Fake;
    use fake::Faker;
    use rand::rngs::OsRng;

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

    #[test]
    fn conversion_between_uint256_and_bytes() {
        let bytes: [u8; 32] = Faker.fake_with_rng(&mut OsRng);
        let number = proto::Uint256::from(bytes);

        let rount_trip_bytes = <[u8; 32]>::from(number);
        assert_eq!(rount_trip_bytes, bytes);
    }
}
