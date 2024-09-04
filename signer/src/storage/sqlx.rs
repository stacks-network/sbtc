//! This module contains implementations of structs that make reading from
//! and writing from postgres easy.
//!
//!

use bitcoin::hashes::Hash as _;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::PgArgumentBuffer;
use stacks_common::types::chainstate::StacksBlockId;

use crate::keys::PublicKey;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksTxId;

/// For the [`BitcoinBlockHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for BitcoinBlockHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(BitcoinBlockHash(bitcoin::BlockHash::from_byte_array(bytes)))
    }
}

impl sqlx::Type<sqlx::Postgres> for BitcoinBlockHash {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for BitcoinBlockHash {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.to_byte_array();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for BitcoinBlockHash {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

/// For the [`BitcoinTxId`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for BitcoinTxId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(BitcoinTxId(bitcoin::Txid::from_byte_array(bytes)))
    }
}

impl sqlx::Type<sqlx::Postgres> for BitcoinTxId {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Encode<'r, sqlx::Postgres> for BitcoinTxId {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = self.0.to_byte_array();
        <[u8; 32] as sqlx::Encode<'r, sqlx::Postgres>>::encode_by_ref(&bytes, buf)
    }
}

impl sqlx::postgres::PgHasArrayType for BitcoinTxId {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <[u8; 32] as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}
/// For the [`StacksBlockHash`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksBlockHash {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(StacksBlockHash(StacksBlockId(bytes)))
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

/// For the [`StacksTxId`]

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for StacksTxId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <[u8; 32] as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(StacksTxId(blockstack_lib::burnchains::Txid(bytes)))
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
