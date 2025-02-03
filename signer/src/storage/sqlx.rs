//! This module contains implementations of structs that make reading from
//! and writing from postgres easy.
//!
//!

use std::ops::Deref;
use std::str::FromStr as _;

use bitcoin::consensus::Decodable as _;
use bitcoin::consensus::Encodable as _;
use bitcoin::hashes::Hash as _;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::PgArgumentBuffer;
use sqlx::postgres::PgRow;
use sqlx::FromRow;
use sqlx::Row as _;

use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTx;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::ScriptPubKey;
use crate::storage::model::SigHash;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksPrincipal;
use crate::storage::model::StacksTxId;

use super::model::BitcoinBlockRef;
use super::model::DkgSharesStatus;
use super::model::EncryptedDkgShares;

// For the [`ScriptPubKey`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for ScriptPubKey {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(ScriptPubKey::from_bytes(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for ScriptPubKey {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for ScriptPubKey {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.deref().to_bytes();
        <Vec<u8> as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for ScriptPubKey {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<u8> as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`BitcoinBlockHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for BitcoinBlockHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(BitcoinBlockHash::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for BitcoinBlockHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for BitcoinBlockHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.as_ref();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for BitcoinBlockHash {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`BitcoinTx`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for BitcoinTx {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        let mut reader = bytes.as_slice();
        let tx = bitcoin::Transaction::consensus_decode(&mut reader)?;
        Ok(BitcoinTx::from(tx))
    }
}

impl sqlx::Type<sqlx::Postgres> for BitcoinTx {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<u8> as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for BitcoinTx {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let mut writer: Vec<u8> = Vec::<u8>::new();
        self.consensus_encode(&mut writer)?;
        <Vec<u8> as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&writer, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for BitcoinTx {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<u8> as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`BitcoinTxId`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for BitcoinTxId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(BitcoinTxId::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for BitcoinTxId {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for BitcoinTxId {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.into_bytes();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for BitcoinTxId {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`PublicKey`]

/// We expect the compressed public key bytes from the database
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for PublicKey {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 33] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(PublicKey::from_slice(&bytes)?)
    }
}

impl sqlx::Type<sqlx::Postgres> for PublicKey {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 33] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

/// We write the compressed public key bytes to the database
impl<'r> sqlx::Encode<'r, sqlx::Postgres> for PublicKey {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.serialize();
        <[u8; 33] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for PublicKey {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 33] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`PublicKeyXOnly`]

/// We expect the compressed public key bytes from the database
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for PublicKeyXOnly {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(PublicKeyXOnly::from_slice(&bytes)?)
    }
}

impl sqlx::Type<sqlx::Postgres> for PublicKeyXOnly {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

/// We write the compressed public key bytes to the database
impl<'r> sqlx::Encode<'r, sqlx::Postgres> for PublicKeyXOnly {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.serialize();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for PublicKeyXOnly {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`StacksBlockHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksBlockHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(StacksBlockHash::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for StacksBlockHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for StacksBlockHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&self.to_bytes(), buf)
    }
}

impl sqlx::postgres::PgHasArrayType for StacksBlockHash {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`StacksPrincipal`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksPrincipal {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(StacksPrincipal::from_str(&bytes)?)
    }
}

impl sqlx::Type<sqlx::Postgres> for StacksPrincipal {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for StacksPrincipal {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <String as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&self.to_string(), buf)
    }
}

impl sqlx::postgres::PgHasArrayType for StacksPrincipal {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`StacksTxId`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksTxId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(StacksTxId::from(bytes))
    }
}

impl sqlx::Type<sqlx::Postgres> for StacksTxId {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for StacksTxId {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&self.to_bytes(), buf)
    }
}

impl sqlx::postgres::PgHasArrayType for StacksTxId {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

// For the [`SigHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for SigHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(bitcoin::TapSighash::from_byte_array(bytes).into())
    }
}

impl sqlx::Type<sqlx::Postgres> for SigHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for SigHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&self.to_byte_array(), buf)
    }
}

impl sqlx::postgres::PgHasArrayType for SigHash {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

impl<'r> FromRow<'r, PgRow> for EncryptedDkgShares {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let block_hash: Option<Vec<u8>> =
            row.try_get(EncryptedDkgShares::VERIFIED_AT_BITCOIN_BLOCK_HASH)?;
        let block_height: Option<i64> =
            row.try_get(EncryptedDkgShares::VERIFIED_AT_BITCOIN_BLOCK_HEIGHT)?;

        let verified_at_bitcoin_block = block_hash
            .zip(block_height)
            .map(|(hash, height)| {
                let hash: [u8; 32] = hash
                    .as_slice()
                    .try_into()
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
                Ok::<BitcoinBlockRef, sqlx::Error>(BitcoinBlockRef {
                    block_hash: hash.into(),
                    block_height: height as u64,
                })
            })
            .transpose()?;

        let status_id: i32 = row.try_get(EncryptedDkgShares::DKG_SHARES_STATUS_ID)?;
        let status = match status_id {
            0 => DkgSharesStatus::Pending,
            1 => {
                let verified_at_bitcoin_block = verified_at_bitcoin_block.ok_or_else(|| {
                    let message = format!(
                        "{} is '1' but {} or {} is NULL",
                        EncryptedDkgShares::DKG_SHARES_STATUS_ID,
                        EncryptedDkgShares::VERIFIED_AT_BITCOIN_BLOCK_HASH,
                        EncryptedDkgShares::VERIFIED_AT_BITCOIN_BLOCK_HEIGHT
                    );
                    sqlx::Error::Decode(Box::new(crate::error::Error::SqlxFromRow(message.into())))
                })?;
                DkgSharesStatus::Verified(verified_at_bitcoin_block)
            }
            2 => DkgSharesStatus::Revoked,
            _ => {
                let message = format!(
                    "{} is not in [0, 1, 2]",
                    EncryptedDkgShares::DKG_SHARES_STATUS_ID
                );
                return Err(sqlx::Error::Decode(Box::new(
                    crate::error::Error::SqlxFromRow(message.into()),
                )));
            }
        };

        Ok(Self {
            aggregate_key: row.try_get(EncryptedDkgShares::AGGREGATE_KEY)?,
            tweaked_aggregate_key: row.try_get(EncryptedDkgShares::TWEAKED_AGGREGATE_KEY)?,
            script_pubkey: row.try_get(EncryptedDkgShares::SCRIPT_PUBKEY)?,
            encrypted_private_shares: row.try_get(EncryptedDkgShares::ENCRYPTED_PRIVATE_SHARES)?,
            public_shares: row.try_get(EncryptedDkgShares::PUBLIC_SHARES)?,
            signer_set_public_keys: row.try_get(EncryptedDkgShares::SIGNER_SET_PUBLIC_KEYS)?,
            signature_share_threshold: row
                .try_get::<i32, _>(EncryptedDkgShares::SIGNATURE_SHARE_THRESHOLD)?
                as u16,
            status,
        })
    }
}
