//! Postgres storage implementation.

use crate::storage::model;

/// A wrapper around a [`sqlx::PgPool`] which implements
/// [`signer::storage::Read`] and [`signer::storage::Write`].
#[derive(Debug, Clone)]
pub struct PgStore(sqlx::PgPool);

impl PgStore {
    /// Connect to the Postgres database at `url`.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        Ok(Self(sqlx::PgPool::connect(url).await?))
    }
}

impl From<sqlx::PgPool> for PgStore {
    fn from(value: sqlx::PgPool) -> Self {
        Self(value)
    }
}

impl super::DbRead for &PgStore {
    type Error = sqlx::Error;

    async fn get_bitcoin_block(
        self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Self::Error> {
        sqlx::query_as!(
            model::BitcoinBlock,
            "SELECT * FROM sbtc_signer.bitcoin_blocks WHERE block_hash = $1;",
            &block_hash
        )
        .fetch_optional(&self.0)
        .await
    }
}

impl super::DbWrite for &PgStore {
    type Error = sqlx::Error;

    async fn write_bitcoin_block(self, block: &model::BitcoinBlock) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.bitcoin_blocks VALUES ($1, $2, $3, $4, $5)",
            block.block_hash,
            block.block_height,
            block.parent_hash,
            block.confirms,
            block.created_at
        )
        .execute(&self.0)
        .await?;

        Ok(())
    }
}
