//! A module with helper queryy functions.
//!

use crate::error::Error;
use crate::storage::model;
use crate::storage::postgres::PgStore;

impl PgStore {
    /// Get all deposit requests that have been confirmed within the
    /// context window.
    pub async fn get_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        sqlx::query_as::<_, model::DepositRequest>(
            r#"
            WITH RECURSIVE context_window AS (
                -- Anchor member: Initialize the recursion with the chain tip
                SELECT block_hash, block_height, parent_hash, created_at, 1 AS depth
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                -- Recursive member: Fetch the parent block using the last block's parent_hash
                SELECT parent.block_hash, parent.block_height, parent.parent_hash,
                       parent.created_at, last.depth + 1
                FROM sbtc_signer.bitcoin_blocks parent
                JOIN context_window last ON parent.block_hash = last.parent_hash
                WHERE last.depth < $2
            ),
            transactions_in_window AS (
                SELECT transactions.txid
                FROM context_window blocks_in_window
                JOIN sbtc_signer.bitcoin_transactions transactions ON
                    transactions.block_hash = blocks_in_window.block_hash
            )
            SELECT
                deposit_requests.txid
              , deposit_requests.output_index
              , deposit_requests.spend_script
              , deposit_requests.reclaim_script
              , deposit_requests.recipient
              , deposit_requests.amount
              , deposit_requests.max_fee
              , deposit_requests.lock_time
              , deposit_requests.signers_public_key
              , deposit_requests.sender_script_pub_keys
            FROM transactions_in_window transactions
            JOIN sbtc_signer.deposit_requests deposit_requests ON
                deposit_requests.txid = transactions.txid
            "#,
        )
        .bind(chain_tip)
        .bind(i32::from(context_window))
        .fetch_all(self.pool())
        .await
        .map_err(Error::SqlxQuery)
    }
}
