//! Postgres storage implementation.

use crate::storage::model;

/// A wrapper around a [`sqlx::PgPool`] which implements
/// [`crate::storage::DbRead`] and [`crate::storage::DbWrite`].
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

    async fn get_bitcoin_canonical_chain_tip(
        self,
    ) -> Result<Option<model::BitcoinBlockHash>, Self::Error> {
        todo!(); // TODO(244): Write query + integration test
    }

    async fn get_pending_deposit_requests(
        self,
        _chain_tip: &model::BitcoinBlockHash,
        _context_window: usize,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        todo!(); // TODO(244): Write query + integration test
    }

    async fn get_deposit_signers(
        self,
        _txid: &model::BitcoinTxId,
        _output_index: usize,
    ) -> Result<Vec<model::DepositSigner>, Self::Error> {
        todo!(); // TODO(244): Write query + integration test
    }

    async fn get_pending_withdraw_requests(
        self,
        _chain_tip: &model::BitcoinBlockHash,
        _context_window: usize,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        todo!(); // TODO(246): Write query + integration test
    }

    async fn get_bitcoin_blocks_with_transaction(
        self,
        _txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Self::Error> {
        todo!(); // TODO(244): write query + integration test
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

    async fn write_deposit_request(
        self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.deposit_requests VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            deposit_request.txid,
            deposit_request.output_index as i32,
            deposit_request.spend_script,
            deposit_request.reclaim_script,
            deposit_request.recipient,
            deposit_request.amount,
            deposit_request.max_fee,
            &deposit_request.sender_addresses,
            deposit_request.created_at,
        )
        .execute(&self.0)
        .await?;

        Ok(())
    }

    async fn write_withdraw_request(
        self,
        _withdraw_request: &model::WithdrawRequest,
    ) -> Result<(), Self::Error> {
        todo!(); // TODO(246): Write query + integration test
    }

    async fn write_deposit_signer_decision(
        self,
        _decision: &model::DepositSigner,
    ) -> Result<(), Self::Error> {
        todo!(); // TODO(244): Write query + integration test
    }

    async fn write_withdraw_signer_decision(
        self,
        _decision: &model::WithdrawSigner,
    ) -> Result<(), Self::Error> {
        todo!(); // TODO(246): Write query + integration test
    }

    async fn write_transaction(self, transaction: &model::Transaction) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.transactions VALUES ($1, $2, $3, $4)",
            transaction.txid,
            transaction.tx,
            transaction.tx_type.clone() as model::TransactionType,
            transaction.created_at,
        )
        .execute(&self.0)
        .await?;

        Ok(())
    }

    async fn write_bitcoin_transaction(
        self,
        bitcoin_transaction: &model::BitcoinTransaction,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.bitcoin_transactions VALUES ($1, $2)",
            bitcoin_transaction.txid,
            bitcoin_transaction.block_hash,
        )
        .execute(&self.0)
        .await?;

        Ok(())
    }
}
