//! This module contains implementations of structs that make reading from
//! and writing from postgres easy.
//!
//!

use std::ops::Deref;
use std::str::FromStr as _;

use bitcoin::consensus::Decodable as _;
use bitcoin::consensus::Encodable as _;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::PgArgumentBuffer;

use crate::keys::PublicKey;
use crate::keys::PublicKeyXOnly;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTx;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::ScriptPubKey;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksPrincipal;
use crate::storage::model::StacksTxId;

/// For the [`ScriptPubKey`]

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

/// For the [`BitcoinBlockHash`]

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

/// For the [`BitcoinTx`]

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

/// For the [`BitcoinTxId`]

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

/// For the [`PublicKey`]

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

/// For the [`PublicKeyXOnly`]

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

/// For the [`StacksBlockHash`]

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

/// For the [`StacksPrincipal`]

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

/// For the [`StacksTxId`]

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
