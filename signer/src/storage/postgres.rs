//! Postgres storage implementation.

use std::collections::HashMap;
use std::sync::OnceLock;

use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::Hash as _;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksBlockId;
use futures::StreamExt as _;
use sqlx::postgres::PgPoolOptions;
use sqlx::Executor as _;
use sqlx::PgExecutor;
use stacks_common::types::chainstate::StacksAddress;

use crate::bitcoin::utxo::SignerUtxo;
use crate::bitcoin::validation::DepositRequestReport;
use crate::bitcoin::validation::DepositRequestStatus;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey as _;
use crate::stacks::events::CompletedDepositEvent;
use crate::stacks::events::WithdrawalAcceptEvent;
use crate::stacks::events::WithdrawalCreateEvent;
use crate::stacks::events::WithdrawalRejectEvent;
use crate::storage::model;
use crate::storage::model::TransactionType;
use crate::DEPOSIT_LOCKTIME_BLOCK_BUFFER;

use super::util::get_utxo;

/// All migration scripts from the `signer/migrations` directory.
static PGSQL_MIGRATIONS: include_dir::Dir =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/migrations");

const CONTRACT_NAMES: [&str; 4] = [
    // The name of the Stacks smart contract used for minting sBTC after a
    // successful transaction moving BTC under the signers' control.
    "sbtc-deposit",
    // The name of the Stacks smart contract for recording or registering
    // successfully completed withdrawal and deposit requests.
    "sbtc-registry",
    // The name of the Stacks sBTC smart contract used by the signers for
    // managing the signer set and the associated keys for a PoX cycle.
    "sbtc-bootstrap-signers",
    // The name of the Stacks smart contract used for withdrawing sBTC as
    // BTC on chain.
    "sbtc-withdrawal",
];

#[rustfmt::skip]
const CONTRACT_FUNCTION_NAMES: [(&str, TransactionType); 5] = [
    ("initiate-withdrawal-request", TransactionType::WithdrawRequest),
    ("complete-deposit-wrapper", TransactionType::DepositAccept),
    ("accept-withdrawal-request", TransactionType::WithdrawAccept),
    ("reject-withdrawal-request", TransactionType::WithdrawReject),
    ("rotate-keys-wrapper", TransactionType::RotateKeys),
];

/// Returns the mapping between functions in a contract call and the
/// transaction type.
fn contract_transaction_kinds() -> &'static HashMap<&'static str, TransactionType> {
    static CONTRACT_FUNCTION_NAME_MAPPING: OnceLock<HashMap<&str, TransactionType>> =
        OnceLock::new();

    CONTRACT_FUNCTION_NAME_MAPPING.get_or_init(|| CONTRACT_FUNCTION_NAMES.into_iter().collect())
}

/// This function extracts the signer relevant sBTC related transactions
/// from the given blocks.
///
/// Here the deployer is the address that deployed the sBTC smart
/// contracts.
pub fn extract_relevant_transactions(
    blocks: &[NakamotoBlock],
    deployer: &StacksAddress,
) -> Vec<model::Transaction> {
    let transaction_kinds = contract_transaction_kinds();
    blocks
        .iter()
        .flat_map(|block| block.txs.iter().map(|tx| (tx, block.block_id())))
        .filter_map(|(tx, block_id)| match &tx.payload {
            TransactionPayload::ContractCall(x)
                if CONTRACT_NAMES.contains(&x.contract_name.as_str()) && &x.address == deployer =>
            {
                Some(model::Transaction {
                    txid: tx.txid().into_bytes(),
                    block_hash: block_id.into_bytes(),
                    tx: tx.serialize_to_vec(),
                    tx_type: *transaction_kinds.get(&x.function_name.as_str())?,
                })
            }
            _ => None,
        })
        .collect()
}

/// A convenience struct for retrieving a deposit request report
#[derive(sqlx::FromRow)]
struct StatusSummary {
    /// The current signer may not have a record of their vote for
    /// the deposit. When that happens the `is_accepted` and
    /// `can_sign` fields will be None.
    is_accepted: Option<bool>,
    /// Whether this signer is a member of the signing set that generated
    /// the public key locking the deposit.
    can_sign: Option<bool>,
    /// The height of the block that confirmed the deposit request
    /// transaction.
    block_height: Option<i64>,
    /// The block hash that confirmed the deposit request.
    block_hash: Option<model::BitcoinBlockHash>,
    /// The bitcoin consensus encoded locktime in the reclaim script.
    #[sqlx(try_from = "i64")]
    lock_time: u32,
    /// The amount associated with the deposit UTXO in sats.
    #[sqlx(try_from = "i64")]
    amount: u64,
}

/// A wrapper around a [`sqlx::PgPool`] which implements
/// [`crate::storage::DbRead`] and [`crate::storage::DbWrite`].
#[derive(Debug, Clone)]
pub struct PgStore(sqlx::PgPool);

impl PgStore {
    /// Connect to the Postgres database at `url`.
    pub async fn connect(url: &str) -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .after_connect(|conn, _meta| Box::pin(async move {
                conn.execute("SET application_name = 'sbtc-signer'; SET search_path = sbtc_signer,public;")
                    .await?;
                Ok(())
            }))
            .connect(url)
            .await
            .map_err(Error::SqlxConnect)?;

        Ok(Self(pool))
    }

    /// Apply the migrations to the database.
    pub async fn apply_migrations(&self) -> Result<(), Error> {
        // Related to https://github.com/stacks-network/sbtc/issues/411
        // TODO(537) - Revisit this prior to public launch
        //
        // Note 1: This could be generalized and moved up to the `storage` module, but
        // left that for a future exercise if we need to support other databases.
        //
        // Note 2: The `sqlx` "migration" feature results in dependency conflicts
        // with sqlite from the clarity crate.
        //
        // Note 3: The migration code paths have no explicit integration tests, but are
        // implicitly tested by all integration tests using `new_test_database()`.
        tracing::info!("Preparing to run database migrations");

        sqlx::raw_sql(
            r#"
                CREATE TABLE IF NOT EXISTS public.__sbtc_migrations (
                    key TEXT PRIMARY KEY
                );
            "#,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxMigrate)?;

        let mut trx = self
            .pool()
            .begin()
            .await
            .map_err(Error::SqlxBeginTransaction)?;

        // Collect all migration scripts and sort them by filename. It is important
        // that the migration scripts are named in a way that they are executed in
        // the correct order, i.e. the current naming of `0001__`, `0002__`, etc.
        let mut migrations = PGSQL_MIGRATIONS.files().collect::<Vec<_>>();
        migrations.sort_by_key(|file| file.path().file_name());
        for migration in migrations {
            let key = migration
                .path()
                .file_name()
                .expect("failed to get filename from migration script path")
                .to_string_lossy();

            // Just in-case we end up with a README.md or some other non-SQL file
            // in the migrations directory.
            if !key.ends_with(".sql") {
                tracing::debug!(migration = %key, "Skipping non-SQL migration file");
            }

            // Check if the migration has already been applied. If so, we should
            // be able to safely skip it.
            if self.check_migration_existence(&mut *trx, &key).await? {
                tracing::debug!(migration = %key, "Database migration already applied");
                continue;
            }

            // Attempt to apply the migration. If we encounter an error, we abort
            // the entire migration process.
            if let Some(script) = migration.contents_utf8() {
                tracing::info!(migration = %key, "Applying database migration");

                // Execute the migration.
                sqlx::raw_sql(script)
                    .execute(&mut *trx)
                    .await
                    .map_err(Error::SqlxMigrate)?;

                // Save the migration as applied.
                self.insert_migration(&key).await?;
            } else {
                // The trx should be rolled back on drop but let's be explicit.
                trx.rollback()
                    .await
                    .map_err(Error::SqlxRollbackTransaction)?;

                // We failed to read the migration script as valid UTF-8. This
                // shouldn't happen since it's our own migration scripts, but
                // just in case...
                return Err(Error::ReadSqlMigration(
                    migration.path().as_os_str().to_string_lossy(),
                ));
            }
        }

        trx.commit().await.map_err(Error::SqlxCommitTransaction)?;

        Ok(())
    }

    /// Check if a migration with the given `key` exists.
    async fn check_migration_existence(
        &self,
        executor: impl PgExecutor<'_>,
        key: &str,
    ) -> Result<bool, Error> {
        let result = sqlx::query_scalar::<_, i64>(
            // Note: db_name + key are PK so we can only get max 1 row.
            r#"
            SELECT COUNT(*) FROM public.__sbtc_migrations
                WHERE
                    key = $1
            ;
            "#,
        )
        .bind(key)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(result > 0)
    }

    /// Insert a migration with the given `key`.
    async fn insert_migration(&self, key: &str) -> Result<(), Error> {
        sqlx::query(
            r#"
            INSERT INTO public.__sbtc_migrations (key)
                VALUES ($1)
            "#,
        )
        .bind(key)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    /// Get a reference to the underlying pool.
    #[cfg(any(test, feature = "testing"))]
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.0
    }

    async fn write_transactions(
        &self,
        txs: Vec<model::Transaction>,
    ) -> Result<model::TransactionIds, Error> {
        if txs.is_empty() {
            return Ok(model::TransactionIds {
                tx_ids: Vec::new(),
                block_hashes: Vec::new(),
            });
        }

        let mut tx_ids = Vec::with_capacity(txs.len());
        let mut txs_bytes = Vec::with_capacity(txs.len());
        let mut tx_types = Vec::with_capacity(txs.len());
        let mut block_hashes = Vec::with_capacity(txs.len());

        for tx in txs {
            tx_ids.push(tx.txid);
            txs_bytes.push(tx.tx);
            tx_types.push(tx.tx_type.to_string());
            block_hashes.push(tx.block_hash)
        }

        sqlx::query(
            r#"
            WITH tx_ids AS (
                SELECT ROW_NUMBER() OVER (), txid
                FROM UNNEST($1::bytea[]) AS txid
            )
            , txs AS (
                SELECT ROW_NUMBER() OVER (), tx
                FROM UNNEST($2::bytea[]) AS tx
            )
            , transaction_types AS (
                SELECT ROW_NUMBER() OVER (), tx_type::sbtc_signer.transaction_type
                FROM UNNEST($3::VARCHAR[]) AS tx_type
            )
            INSERT INTO sbtc_signer.transactions (txid, tx, tx_type)
            SELECT
                txid
              , tx
              , tx_type
            FROM tx_ids
            JOIN txs USING (row_number)
            JOIN transaction_types USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(&tx_ids)
        .bind(txs_bytes)
        .bind(tx_types)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(model::TransactionIds { tx_ids, block_hashes })
    }

    async fn get_utxo_from_donation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        aggregate_key: &PublicKey,
        context_window: u16,
    ) -> Result<Option<SignerUtxo>, Error> {
        // TODO(585): once the new table is ready, check if it can be used to simplify this
        // TODO: currently returns the latest donation, we may want to return something else
        let script_pubkey = aggregate_key.signers_script_pubkey();
        let mut txs = sqlx::query_as::<_, model::Transaction>(
            r#"
            WITH RECURSIVE tx_block_chain AS (
                SELECT
                    block_hash
                  , parent_hash
                  , 1 AS depth
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.parent_hash
                  , child.depth + 1
                FROM sbtc_signer.bitcoin_blocks AS parent
                JOIN tx_block_chain AS child ON child.parent_hash = parent.block_hash
                WHERE child.depth < $2
            )
            SELECT
                txs.txid
              , txs.tx
              , txs.tx_type
              , tbc.block_hash
            FROM tx_block_chain AS tbc
            JOIN sbtc_signer.bitcoin_transactions AS bt ON tbc.block_hash = bt.block_hash
            JOIN sbtc_signer.transactions AS txs USING (txid)
            WHERE txs.tx_type = 'donation'
            ORDER BY tbc.depth ASC;
            "#,
        )
        .bind(chain_tip)
        .bind(context_window as i32)
        .fetch(&self.0);

        let mut utxo_block = None;
        while let Some(tx) = txs.next().await {
            let tx = tx.map_err(Error::SqlxQuery)?;
            let bt_tx = bitcoin::Transaction::consensus_decode(&mut tx.tx.as_slice())
                .map_err(Error::DecodeBitcoinTransaction)?;
            if !bt_tx
                .output
                .first()
                .is_some_and(|out| out.script_pubkey == script_pubkey)
            {
                continue;
            }
            utxo_block = Some(tx.block_hash);
            break;
        }

        // `utxo_block` is the highest block containing a valid utxo
        let Some(utxo_block) = utxo_block else {
            return Ok(None);
        };
        // Fetch all the sbtc txs in the same block
        let sbtc_txs = sqlx::query_as::<_, model::Transaction>(
            r#"
            SELECT
                txs.txid
              , txs.tx
              , txs.tx_type
              , bt.block_hash
            FROM sbtc_signer.transactions AS txs
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            WHERE txs.tx_type = 'donation' AND bt.block_hash = $1;
            "#,
        )
        .bind(utxo_block)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)?
        .iter()
        .map(|tx| {
            bitcoin::Transaction::consensus_decode(&mut tx.tx.as_slice())
                .map_err(Error::DecodeBitcoinTransaction)
        })
        .collect::<Result<Vec<bitcoin::Transaction>, _>>()?;

        get_utxo(aggregate_key, sbtc_txs)
    }

    /// Return the least height for which the deposit request was confirmed
    /// on a bitcoin blockchain.
    ///
    /// Transactions can be confirmed on more than one blockchain and this
    /// function returns the least height out of all bitcoin blocks for
    /// which the deposit has been confirmed.
    ///
    /// None is returned if we do not have a record of the deposit request.
    pub async fn get_deposit_request_least_height(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<i64>, Error> {
        // Before the deposit request is written a signer also stores the
        // bitcoin transaction and (after #731) the bitcoin block
        // confirming the deposit to the database. So this will return zero
        // rows only when we cannot find the deposit request.
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT block_height
            FROM sbtc_signer.deposit_requests AS dr
            JOIN sbtc_signer.bitcoin_transactions USING (txid)
            JOIN sbtc_signer.bitcoin_blocks USING (block_hash)
            WHERE dr.txid = $1
              AND dr.output_index = $2
            ORDER BY block_height
            LIMIT 1
            "#,
        )
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Return the txid of the bitcoin transaction that swept in the
    /// deposit UTXO. The sweep transaction must be confirmed on the
    /// blockchain identified by the given chain tip.
    ///
    /// This query only looks back at transactions that are confirmed at or
    /// after the given `min_block_height`.
    async fn get_deposit_sweep_txid(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        min_block_height: u64,
    ) -> Result<Option<model::BitcoinTxId>, Error> {
        sqlx::query_scalar::<_, model::BitcoinTxId>(
            r#"
            WITH RECURSIVE block_chain AS (
                SELECT 
                    block_hash
                  , block_height
                  , parent_hash
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    child.block_hash
                  , child.block_height
                  , child.parent_hash
                FROM sbtc_signer.bitcoin_blocks AS child
                JOIN block_chain AS parent
                  ON child.block_hash = parent.parent_hash
                WHERE child.block_height >= $2
            )
            SELECT sd.sweep_transaction_txid
            FROM sbtc_signer.swept_deposits AS sd
            JOIN sbtc_signer.bitcoin_transactions AS bt
              ON bt.txid = sd.sweep_transaction_txid
            JOIN block_chain USING (block_hash)
            WHERE sd.deposit_request_txid = $3
              AND sd.deposit_request_output_index = $4
            LIMIT 1
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(min_block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Fetch a status summary of a deposit request.
    ///
    /// In this query we list out the blockchain identified by the chain
    /// tip as far back as necessary. We then check if this signer accepted
    /// the deposit request, and whether it was confirmed on the blockchain
    /// that we just listed out.
    ///
    /// `None` is returned if deposit request in the database (we always
    /// write the associated transaction to the database for each deposit
    /// so that cannot be the reason for why the query here returns
    /// `None`).
    async fn get_deposit_request_status_summary(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<StatusSummary>, Error> {
        // We first get the least height for when the deposit request was
        // confirmed. This height serves as the stopping criteria for the
        // recursive part of the subsequent query.
        let min_block_height_fut = self.get_deposit_request_least_height(txid, output_index);
        // None is only returned if we do not have a record of the deposit
        // request or the deposit transaction.
        let Some(min_block_height) = min_block_height_fut.await? else {
            return Ok(None);
        };
        sqlx::query_as::<_, StatusSummary>(
            r#"
            WITH RECURSIVE block_chain AS (
                SELECT 
                    block_hash
                  , block_height
                  , parent_hash
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    child.block_hash
                  , child.block_height
                  , child.parent_hash
                FROM sbtc_signer.bitcoin_blocks AS child
                JOIN block_chain AS parent
                  ON child.block_hash = parent.parent_hash
                WHERE child.block_height >= $2
            )
            SELECT
                ds.is_accepted
              , ds.can_sign
              , dr.amount
              , dr.lock_time
              , bc.block_height
              , bc.block_hash
            FROM sbtc_signer.deposit_requests AS dr 
            JOIN sbtc_signer.bitcoin_transactions USING (txid)
            LEFT JOIN block_chain AS bc USING (block_hash)
            LEFT JOIN sbtc_signer.deposit_signers AS ds
              ON dr.txid = ds.txid
             AND dr.output_index = ds.output_index
             AND ds.signer_pub_key = $5
            WHERE dr.txid = $3
              AND dr.output_index = $4
            LIMIT 1
            "#,
        )
        .bind(chain_tip)
        .bind(min_block_height)
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(signer_public_key)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Attempts to retrieve an entire transaction package by id.
    ///
    /// TODO: This could be made more efficient and shorter by returning a table
    /// with all the necessary information in one query, and doing a custom
    /// `FromRow` implementation. I just didn't want to spend more time on it
    /// now.
    async fn get_sweep_transaction_by_txid(
        &self,
        sweep_txid: &model::BitcoinTxId,
    ) -> Result<Option<model::SweepTransaction>, Error> {
        let transaction: Option<model::SweepTransaction> = sqlx::query_as(
            "
            SELECT
                txid
              , signer_prevout_txid
              , signer_prevout_output_index
              , signer_prevout_amount
              , signer_prevout_script_pubkey
              , amount
              , fee
              , created_at_block_hash
              , market_fee_rate
            FROM
                sweep_transactions
            WHERE
                txid = $1;
        ",
        )
        .bind(sweep_txid)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        let Some(mut transaction) = transaction else {
            return Ok(None);
        };

        let swept_deposits = sqlx::query_as(
            "
            SELECT
                input_index
              , deposit_request_txid
              , deposit_request_output_index
            FROM
                swept_deposits
            WHERE
                sweep_transaction_txid = $1
            ORDER BY
                input_index ASC;
            ",
        )
        .bind(sweep_txid)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        let swept_withdrawals = sqlx::query_as(
            "
            SELECT
                output_index
              , withdrawal_request_id
              , withdrawal_request_block_hash
            FROM
                swept_withdrawals
            WHERE
                sweep_transaction_txid = $1
            ORDER BY
                output_index ASC;
        ",
        )
        .bind(sweep_txid)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        transaction.swept_deposits = swept_deposits;
        transaction.swept_withdrawals = swept_withdrawals;

        Ok(Some(transaction))
    }
}

impl From<sqlx::PgPool> for PgStore {
    fn from(value: sqlx::PgPool) -> Self {
        Self(value)
    }
}

impl super::DbRead for PgStore {
    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error> {
        sqlx::query_as::<_, model::BitcoinBlock>(
            "SELECT
                block_hash
              , block_height
              , parent_hash
            FROM sbtc_signer.bitcoin_blocks
            WHERE block_hash = $1;",
        )
        .bind(block_hash)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        sqlx::query_as::<_, model::StacksBlock>(
            "SELECT
                block_hash
              , block_height
              , parent_hash
              , bitcoin_anchor
            FROM sbtc_signer.stacks_blocks
            WHERE block_hash = $1;",
        )
        .bind(block_hash)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Error> {
        sqlx::query_as::<_, model::BitcoinBlock>(
            "SELECT
                block_hash
              , block_height
              , parent_hash
             FROM sbtc_signer.bitcoin_blocks
             ORDER BY block_height DESC, block_hash DESC
             LIMIT 1",
        )
        .fetch_optional(&self.0)
        .await
        .map(|maybe_block| maybe_block.map(|block| block.block_hash))
        .map_err(Error::SqlxQuery)
    }

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        // TODO: stop recursion after the first bitcoin block having stacks block anchored?
        // Note that in tests generated data we may get a taller stacks chain anchored to a
        // bitcoin block that may not be the first one we encounter having stacks block anchored
        sqlx::query_as::<_, model::StacksBlock>(
            r#"
            WITH RECURSIVE context_window AS (
                SELECT
                    block_hash
                  , block_height
                  , parent_hash
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.block_height
                  , parent.parent_hash
                FROM sbtc_signer.bitcoin_blocks AS parent
                JOIN context_window AS child
                  ON parent.block_hash = child.parent_hash
            )
            SELECT
                stacks_blocks.block_hash
              , stacks_blocks.block_height
              , stacks_blocks.parent_hash
              , stacks_blocks.bitcoin_anchor
            FROM context_window bitcoin_blocks
            JOIN sbtc_signer.stacks_blocks stacks_blocks
                ON bitcoin_blocks.block_hash = stacks_blocks.bitcoin_anchor
            ORDER BY block_height DESC, block_hash DESC
            LIMIT 1;
            "#,
        )
        .bind(bitcoin_chain_tip)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_deposit_requests(
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
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        // Add one to the acceptable unlock height because the chain tip is at height one less
        // than the height of the next block, which is the block for which we are assessing
        // the threshold.
        let minimum_acceptable_unlock_height = self
            .get_bitcoin_block(chain_tip)
            .await?
            .ok_or(Error::MissingBitcoinBlock(*chain_tip))?
            .block_height as i32
            + DEPOSIT_LOCKTIME_BLOCK_BUFFER as i32
            + 1;

        sqlx::query_as::<_, model::DepositRequest>(
            r#"
            WITH context_window AS (
                SELECT * FROM bitcoin_blockchain_of($1, $2)
            ),
            transactions_in_window AS (
                SELECT
                    transactions.txid
                  , blocks_in_window.block_height
                FROM context_window blocks_in_window
                JOIN sbtc_signer.bitcoin_transactions transactions ON
                    transactions.block_hash = blocks_in_window.block_hash
            ),
            -- First we get all the deposits that are accepted by enough signers
            accepted_deposits AS (
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
                JOIN sbtc_signer.deposit_requests deposit_requests USING(txid)
                JOIN sbtc_signer.deposit_signers signers USING(txid, output_index)
                WHERE
                    signers.is_accepted
                    AND (transactions.block_height + deposit_requests.lock_time) >= $4
                GROUP BY deposit_requests.txid, deposit_requests.output_index
                HAVING COUNT(signers.txid) >= $3
            )
            -- Then we only consider the ones not swept yet (in the canonical chain)
            SELECT accepted_deposits.*
            FROM accepted_deposits
            LEFT JOIN
                swept_deposits AS swept_deposit
                    ON swept_deposit.deposit_request_txid = accepted_deposits.txid
                    AND swept_deposit.deposit_request_output_index = accepted_deposits.output_index
            LEFT JOIN
                transactions_in_window
                    ON swept_deposit.sweep_transaction_txid = transactions_in_window.txid
            GROUP BY
                accepted_deposits.txid
              , accepted_deposits.output_index
              , accepted_deposits.spend_script
              , accepted_deposits.reclaim_script
              , accepted_deposits.recipient
              , accepted_deposits.amount
              , accepted_deposits.max_fee
              , accepted_deposits.lock_time
              , accepted_deposits.signers_public_key
              , accepted_deposits.sender_script_pub_keys
            HAVING
                COUNT(transactions_in_window.txid) = 0
            "#,
        )
        .bind(chain_tip)
        .bind(i32::from(context_window))
        .bind(i32::from(threshold))
        .bind(minimum_acceptable_unlock_height)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_deposit_request_signer_votes(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        sqlx::query_as::<_, model::SignerVote>(
            r#"
            WITH signer_set_rows AS (
                SELECT DISTINCT UNNEST(signer_set_public_keys) AS signer_public_key
                FROM sbtc_signer.dkg_shares
                WHERE aggregate_key = $1
            ),
            deposit_votes AS (
                SELECT
                    signer_pub_key AS signer_public_key
                  , is_accepted
                FROM sbtc_signer.deposit_signers AS ds
                WHERE TRUE
                  AND ds.txid = $2
                  AND ds.output_index = $3
            )
            SELECT
                signer_public_key
              , is_accepted
            FROM signer_set_rows AS ss
            LEFT JOIN deposit_votes AS ds USING(signer_public_key)
            "#,
        )
        .bind(aggregate_key)
        .bind(txid)
        .bind(i64::from(output_index))
        .fetch_all(&self.0)
        .await
        .map(model::SignerVotes::from)
        .map_err(Error::SqlxQuery)
    }

    async fn get_withdrawal_request_signer_votes(
        &self,
        id: &model::QualifiedRequestId,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        sqlx::query_as::<_, model::SignerVote>(
            r#"
            WITH signer_set_rows AS (
                SELECT DISTINCT UNNEST(signer_set_public_keys) AS signer_public_key
                FROM sbtc_signer.dkg_shares
                WHERE aggregate_key = $1
            ),
            withdrawal_votes AS (
                SELECT
                    signer_pub_key AS signer_public_key
                  , is_accepted
                FROM sbtc_signer.withdrawal_signers AS ws
                WHERE TRUE
                  AND ws.txid = $2
                  AND ws.block_hash = $3
                  AND ws.request_id = $4
            )
            SELECT
                signer_public_key
              , is_accepted
            FROM signer_set_rows AS ss
            LEFT JOIN withdrawal_votes AS wv USING(signer_public_key)
            "#,
        )
        .bind(aggregate_key)
        .bind(id.txid)
        .bind(id.block_hash)
        .bind(i64::try_from(id.request_id).map_err(Error::ConversionDatabaseInt)?)
        .fetch_all(&self.0)
        .await
        .map(model::SignerVotes::from)
        .map_err(Error::SqlxQuery)
    }

    async fn get_accepted_deposit_requests(
        &self,
        signer: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        sqlx::query_as::<_, model::DepositRequest>(
            r#"
            SELECT
                requests.txid
              , requests.output_index
              , requests.spend_script
              , requests.reclaim_script
              , requests.recipient
              , requests.amount
              , requests.max_fee
              , requests.lock_time
              , requests.signers_public_key
              , requests.sender_script_pub_keys
            FROM sbtc_signer.deposit_requests requests
                 JOIN sbtc_signer.deposit_signers signers
                   ON requests.txid = signers.txid
                  AND requests.output_index = signers.output_index
            WHERE
                signers.signer_pub_key = $1
            "#,
        )
        .bind(signer.serialize())
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_deposit_request_report(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<DepositRequestReport>, Error> {
        // Now fetch the deposit summary
        let summary_fut = self.get_deposit_request_status_summary(
            chain_tip,
            txid,
            output_index,
            signer_public_key,
        );
        let Some(summary) = summary_fut.await? else {
            return Ok(None);
        };

        // The block height and block hash are always None or not None at
        // the same time.
        let block_info = summary
            .block_height
            .map(u64::try_from)
            .zip(summary.block_hash);

        // Lastly we map the block_height variable to a status enum.
        let status = match block_info {
            // Now that we know that it has been confirmed, check to see if
            // it has been swept in a bitcoin transaction that has been
            // confirmed already. We use the height of when the deposit was
            // confirmed for the min height for when a sweep transaction
            // could be confirmed. We could also use block_height + 1.
            Some((Ok(block_height), block_hash)) => {
                let deposit_sweep_txid =
                    self.get_deposit_sweep_txid(chain_tip, txid, output_index, block_height);

                match deposit_sweep_txid.await? {
                    Some(txid) => DepositRequestStatus::Spent(txid),
                    None => DepositRequestStatus::Confirmed(block_height, block_hash),
                }
            }
            // If we didn't grab the block height in the above query, then
            // we know that the deposit transaction is not on the
            // blockchain identified by the chain tip.
            None => DepositRequestStatus::Unconfirmed,
            // Block heights are stored as BIGINTs after conversion from
            // u64s, so converting back to u64s is actually safe.
            Some((Err(error), _)) => return Err(Error::ConversionDatabaseInt(error)),
        };

        Ok(Some(DepositRequestReport {
            status,
            can_sign: summary.can_sign,
            is_accepted: summary.is_accepted,
            amount: summary.amount,
            lock_time: bitcoin::relative::LockTime::from_consensus(summary.lock_time)
                .map_err(Error::DisabledLockTime)?,
            outpoint: bitcoin::OutPoint::new((*txid).into(), output_index),
        }))
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        sqlx::query_as::<_, model::DepositSigner>(
            "SELECT
                txid
              , output_index
              , signer_pub_key
              , is_accepted
              , can_sign
            FROM sbtc_signer.deposit_signers
            WHERE txid = $1 AND output_index = $2",
        )
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn can_sign_deposit_tx(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<bool>, Error> {
        sqlx::query_scalar::<_, bool>(
            r#"
            WITH x_only_public_keys AS (
                -- These are the aggregate public keys that this signer is
                -- a party on. We lop off the first byte because we want
                -- x-only aggregate keys here.
                SELECT substring(aggregate_key FROM 2) AS signers_public_key
                FROM sbtc_signer.dkg_shares AS ds
                WHERE $3 = ANY(signer_set_public_keys)
            )
            SELECT xo.signers_public_key IS NOT NULL
            FROM sbtc_signer.deposit_requests AS dr
            LEFT JOIN x_only_public_keys AS xo USING (signers_public_key)
            WHERE dr.txid = $1
              AND dr.output_index = $2
            LIMIT 1
            "#,
        )
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(signer_public_key)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_withdrawal_signers(
        &self,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        sqlx::query_as::<_, model::WithdrawalSigner>(
            "SELECT
                request_id
              , txid
              , block_hash
              , signer_pub_key
              , is_accepted
              , created_at
            FROM sbtc_signer.withdrawal_signers
            WHERE request_id = $1 AND block_hash = $2",
        )
        .bind(i64::try_from(request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(block_hash)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(Vec::new());
        };
        sqlx::query_as::<_, model::WithdrawalRequest>(
            r#"
            WITH RECURSIVE extended_context_window AS (
                SELECT
                    block_hash
                  , parent_hash
                  , 1 AS depth
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.parent_hash
                  , last.depth + 1
                FROM sbtc_signer.bitcoin_blocks parent
                JOIN extended_context_window last ON parent.block_hash = last.parent_hash
                WHERE last.depth <= $3
            ),
            stacks_context_window AS (
                SELECT
                    stacks_blocks.block_hash
                  , stacks_blocks.block_height
                  , stacks_blocks.parent_hash
                FROM sbtc_signer.stacks_blocks stacks_blocks
                WHERE stacks_blocks.block_hash = $2

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.block_height
                  , parent.parent_hash
                FROM sbtc_signer.stacks_blocks parent
                JOIN stacks_context_window last
                        ON parent.block_hash = last.parent_hash
                JOIN extended_context_window block
                        ON block.block_hash = parent.bitcoin_anchor
            )
            SELECT
                wr.request_id
              , wr.txid
              , wr.block_hash
              , wr.recipient
              , wr.amount
              , wr.max_fee
              , wr.sender_address
            FROM sbtc_signer.withdrawal_requests wr
            JOIN stacks_context_window sc ON wr.block_hash = sc.block_hash
            "#,
        )
        .bind(chain_tip)
        .bind(stacks_chain_tip.block_hash)
        .bind(i32::from(context_window))
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_accepted_withdrawal_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(Vec::new());
        };
        sqlx::query_as::<_, model::WithdrawalRequest>(
            r#"
            WITH RECURSIVE extended_context_window AS (
                SELECT
                    block_hash
                  , parent_hash
                  , 1 AS depth
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.parent_hash
                  , last.depth + 1
                FROM sbtc_signer.bitcoin_blocks parent
                JOIN extended_context_window last ON parent.block_hash = last.parent_hash
                WHERE last.depth <= $3
            ),
            stacks_context_window AS (
                SELECT
                    stacks_blocks.block_hash
                  , stacks_blocks.block_height
                  , stacks_blocks.parent_hash
                FROM sbtc_signer.stacks_blocks stacks_blocks
                WHERE stacks_blocks.block_hash = $2

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.block_height
                  , parent.parent_hash
                FROM sbtc_signer.stacks_blocks parent
                JOIN stacks_context_window last
                        ON parent.block_hash = last.parent_hash
                JOIN extended_context_window block
                        ON block.block_hash = parent.bitcoin_anchor
            )
            SELECT
                wr.request_id
              , wr.txid
              , wr.block_hash
              , wr.recipient
              , wr.amount
              , wr.max_fee
              , wr.sender_address
            FROM sbtc_signer.withdrawal_requests wr
            JOIN stacks_context_window sc ON wr.block_hash = sc.block_hash
            JOIN sbtc_signer.withdrawal_signers signers ON
                wr.txid = signers.txid AND
                wr.request_id = signers.request_id AND
                wr.block_hash = signers.block_hash
            WHERE
                signers.is_accepted
            GROUP BY wr.request_id, wr.block_hash, wr.txid
            HAVING COUNT(wr.request_id) >= $4
            "#,
        )
        .bind(chain_tip)
        .bind(stacks_chain_tip.block_hash)
        .bind(i32::from(context_window))
        .bind(i64::from(threshold))
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Error> {
        sqlx::query_as::<_, model::BitcoinTxRef>(
            "SELECT txid, block_hash FROM sbtc_signer.bitcoin_transactions WHERE txid = $1",
        )
        .bind(txid)
        .fetch_all(&self.0)
        .await
        .map(|res| {
            res.into_iter()
                .map(|junction| junction.block_hash)
                .collect()
        })
        .map_err(Error::SqlxQuery)
    }

    async fn stacks_block_exists(&self, block_id: StacksBlockId) -> Result<bool, Error> {
        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT TRUE AS exists
            FROM sbtc_signer.stacks_blocks
            WHERE block_hash = $1;"#,
        )
        .bind(block_id.0)
        .fetch_optional(&self.0)
        .await
        .map(|row| row.is_some())
        .map_err(Error::SqlxQuery)
    }

    async fn get_encrypted_dkg_shares(
        &self,
        aggregate_key: &PublicKey,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        sqlx::query_as::<_, model::EncryptedDkgShares>(
            r#"
            SELECT
                aggregate_key
              , tweaked_aggregate_key
              , script_pubkey
              , encrypted_private_shares
              , public_shares
              , signer_set_public_keys
              , signature_share_threshold
            FROM sbtc_signer.dkg_shares
            WHERE aggregate_key = $1;
            "#,
        )
        .bind(aggregate_key)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_latest_encrypted_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        sqlx::query_as::<_, model::EncryptedDkgShares>(
            r#"
            SELECT
                aggregate_key
              , tweaked_aggregate_key
              , script_pubkey
              , encrypted_private_shares
              , public_shares
              , signer_set_public_keys
              , signature_share_threshold
            FROM sbtc_signer.dkg_shares
            ORDER BY created_at DESC
            LIMIT 1;
            "#,
        )
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Find the last key rotation by iterating backwards from the stacks
    /// chain tip scanning all transactions until we encounter a key
    /// rotation transactions.
    ///
    /// This might become quite inefficient for long chains with infrequent
    /// key rotations, so we might have to consider data model updates to
    /// allow more efficient querying of the last key rotation.
    async fn get_last_key_rotation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::RotateKeysTransaction>, Error> {
        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(None);
        };

        sqlx::query_as::<_, model::RotateKeysTransaction>(
            r#"
            WITH RECURSIVE stacks_blocks AS (
                SELECT
                    block_hash
                  , parent_hash
                  , block_height
                  , 1 AS depth
                FROM sbtc_signer.stacks_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.parent_hash
                  , parent.block_height
                  , last.depth + 1
                FROM sbtc_signer.stacks_blocks parent
                JOIN stacks_blocks last ON parent.block_hash = last.parent_hash
            )
            SELECT
                rkt.txid
              , rkt.aggregate_key
              , rkt.signer_set
              , rkt.signatures_required
            FROM sbtc_signer.rotate_keys_transactions rkt
            JOIN sbtc_signer.stacks_transactions st ON st.txid = rkt.txid
            JOIN stacks_blocks sb on st.block_hash = sb.block_hash
            ORDER BY sb.block_height DESC, sb.block_hash DESC, rkt.txid DESC
            LIMIT 1
            "#,
        )
        .bind(stacks_chain_tip.block_hash)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error> {
        sqlx::query_scalar::<_, model::Bytes>(
            r#"
            WITH last_script_pubkey AS (
                SELECT script_pubkey
                FROM sbtc_signer.dkg_shares
                ORDER BY created_at DESC
                LIMIT 1
            )
            SELECT script_pubkey
            FROM last_script_pubkey

            UNION

            SELECT script_pubkey
            FROM sbtc_signer.dkg_shares
            WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '365 DAYS';
            "#,
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        aggregate_key: &PublicKey,
        context_window: u16,
    ) -> Result<Option<SignerUtxo>, Error> {
        // TODO(585): once the new table is ready, check if it can be used to simplify this
        let script_pubkey = aggregate_key.signers_script_pubkey();
        let mut txs = sqlx::query_as::<_, model::Transaction>(
            r#"
            WITH RECURSIVE tx_block_chain AS (
                SELECT
                    block_hash
                  , parent_hash
                  , 1 AS depth
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.parent_hash
                  , child.depth + 1
                FROM sbtc_signer.bitcoin_blocks AS parent
                JOIN tx_block_chain AS child ON child.parent_hash = parent.block_hash
                WHERE child.depth < $2
            )
            SELECT
                txs.txid
              , txs.tx
              , txs.tx_type
              , tbc.block_hash
            FROM tx_block_chain AS tbc
            JOIN sbtc_signer.bitcoin_transactions AS bt ON tbc.block_hash = bt.block_hash
            JOIN sbtc_signer.transactions AS txs USING (txid)
            WHERE txs.tx_type = 'sbtc_transaction'
            ORDER BY tbc.depth ASC;
            "#,
        )
        .bind(chain_tip)
        .bind(context_window as i32)
        .fetch(&self.0);

        let mut utxo_block = None;
        while let Some(tx) = txs.next().await {
            let tx = tx.map_err(Error::SqlxQuery)?;
            let bt_tx = bitcoin::Transaction::consensus_decode(&mut tx.tx.as_slice())
                .map_err(Error::DecodeBitcoinTransaction)?;
            if !bt_tx
                .output
                .first()
                .is_some_and(|out| out.script_pubkey == script_pubkey)
            {
                continue;
            }
            utxo_block = Some(tx.block_hash);
            break;
        }

        // `utxo_block` is the highest block containing a valid utxo
        let Some(utxo_block) = utxo_block else {
            // if no sbtc tx exists, consider donations
            return self
                .get_utxo_from_donation(chain_tip, aggregate_key, context_window)
                .await;
        };
        // Fetch all the sbtc txs in the same block
        let sbtc_txs = sqlx::query_as::<_, model::Transaction>(
            r#"
            SELECT
                txs.txid
              , txs.tx
              , txs.tx_type
              , bt.block_hash
            FROM sbtc_signer.transactions AS txs
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            WHERE txs.tx_type = 'sbtc_transaction' AND bt.block_hash = $1;
            "#,
        )
        .bind(utxo_block)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)?
        .iter()
        .map(|tx| {
            bitcoin::Transaction::consensus_decode(&mut tx.tx.as_slice())
                .map_err(Error::DecodeBitcoinTransaction)
        })
        .collect::<Result<Vec<bitcoin::Transaction>, _>>()?;

        get_utxo(aggregate_key, sbtc_txs)
    }

    async fn in_canonical_bitcoin_blockchain(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        block_ref: &model::BitcoinBlockRef,
    ) -> Result<bool, Error> {
        let height_diff = chain_tip
            .block_height
            .saturating_sub(block_ref.block_height);

        sqlx::query_scalar::<_, bool>(
            r#"
            WITH RECURSIVE tx_block_chain AS (
                SELECT
                    block_hash
                  , block_height
                  , parent_hash
                  , 0 AS counter
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    child.block_hash
                  , child.block_height
                  , child.parent_hash
                  , parent.counter + 1
                FROM sbtc_signer.bitcoin_blocks AS child
                JOIN tx_block_chain AS parent
                  ON child.block_hash = parent.parent_hash
                WHERE parent.counter <= $3
            )
            SELECT EXISTS (
                SELECT TRUE
                FROM tx_block_chain AS tbc
                WHERE tbc.block_hash = $2
                  AND tbc.block_height = $4
            );
        "#,
        )
        .bind(chain_tip.block_hash)
        .bind(block_ref.block_hash)
        .bind(i64::try_from(height_diff).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(block_ref.block_height).map_err(Error::ConversionDatabaseInt)?)
        .fetch_one(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn is_signer_script_pub_key(&self, script: &model::ScriptPubKey) -> Result<bool, Error> {
        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT TRUE
                FROM sbtc_signer.dkg_shares AS ds
                WHERE ds.script_pubkey = $1
            );
        "#,
        )
        .bind(script)
        .fetch_one(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_bitcoin_tx(
        &self,
        txid: &model::BitcoinTxId,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinTx>, Error> {
        sqlx::query_scalar::<_, model::BitcoinTx>(
            r#"
            SELECT txs.tx
            FROM sbtc_signer.bitcoin_transactions AS bt
            JOIN sbtc_signer.transactions AS txs USING (txid)
            WHERE bt.block_hash = $1
              AND bt.txid = $2
        "#,
        )
        .bind(block_hash)
        .bind(txid)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_swept_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error> {
        // The following tests define the criteria for this query:
        // - [X] get_swept_deposit_requests_returns_swept_deposit_requests
        // - [X] get_swept_deposit_requests_does_not_return_unswept_deposit_requests
        // - [X] get_swept_deposit_requests_does_not_return_deposit_requests_with_responses
        // - [X] get_swept_deposit_requests_response_tx_reorged

        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(Vec::new());
        };

        sqlx::query_as::<_, model::SweptDepositRequest>(
            "
            SELECT
                bc_trx.txid AS sweep_txid
              , bc_trx.block_hash AS sweep_block_hash
              , bc_blocks.block_height AS sweep_block_height
              , deposit_req.txid
              , deposit_req.output_index
              , deposit_req.recipient
              , deposit_req.amount
              , deposit_req.max_fee
            FROM
                bitcoin_blockchain_of($1, $2) AS bc_blocks
            INNER JOIN
                bitcoin_transactions AS bc_trx
                    ON bc_trx.block_hash = bc_blocks.block_hash
            INNER JOIN
                sweep_transactions AS sweep_tx
                    ON bc_trx.txid = sweep_tx.txid
            INNER JOIN
                swept_deposits AS swept_deposit
                    ON swept_deposit.sweep_transaction_txid = sweep_tx.txid
            INNER JOIN
                deposit_requests AS deposit_req
                    ON deposit_req.txid = swept_deposit.deposit_request_txid
                    AND deposit_req.output_index = swept_deposit.deposit_request_output_index
            LEFT JOIN 
                completed_deposit_events AS cde
                    ON cde.bitcoin_txid = deposit_req.txid
                    AND cde.output_index = deposit_req.output_index
            LEFT JOIN
                stacks_blockchain_of($3, $1, $2) sb
                    ON sb.block_hash = cde.block_hash
            GROUP BY
                bc_trx.txid
              , bc_trx.block_hash
              , bc_blocks.block_height
              , deposit_req.txid
              , deposit_req.output_index
              , deposit_req.recipient
              , deposit_req.amount
            HAVING
                COUNT(sb.block_hash) = 0
        ",
        )
        .bind(chain_tip)
        .bind(i32::from(context_window))
        .bind(stacks_chain_tip.block_hash)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_swept_withdrawal_requests(
        &self,
        _chain_tip: &model::BitcoinBlockHash,
        _context_window: u16,
    ) -> Result<Vec<model::SweptWithdrawalRequest>, Error> {
        // TODO: This can use a similiar query to
        // `get_swept_deposit_requests()`, but using withdrawal tables instead
        // of deposit.
        unimplemented!()
    }

    async fn get_latest_sweep_transaction(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<Option<model::SweepTransaction>, Error> {
        let Some((txid,)): Option<(model::BitcoinTxId,)> = sqlx::query_as(
            "
            SELECT
                tx.txid
            FROM bitcoin_blockchain_of($1, $2) AS bitcoin
            JOIN sweep_transactions AS tx ON bitcoin.block_hash = tx.created_at_block_hash
            ORDER BY tx.created_at DESC",
        )
        .bind(chain_tip)
        .bind(context_window as i32)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)?
        else {
            return Ok(None);
        };

        self.get_sweep_transaction_by_txid(&txid).await
    }
}

impl super::DbWrite for PgStore {
    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.bitcoin_blocks
              ( block_hash
              , block_height
              , parent_hash
              )
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING",
        )
        .bind(block.block_hash)
        .bind(i64::try_from(block.block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(block.parent_hash)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.stacks_blocks
              ( block_hash
              , block_height
              , parent_hash
              , bitcoin_anchor
              )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING",
        )
        .bind(block.block_hash)
        .bind(i64::try_from(block.block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(block.parent_hash)
        .bind(block.bitcoin_anchor)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.deposit_requests
              ( txid
              , output_index
              , spend_script
              , reclaim_script
              , recipient
              , amount
              , max_fee
              , lock_time
              , signers_public_key
              , sender_script_pub_keys
              )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT DO NOTHING",
        )
        .bind(deposit_request.txid)
        .bind(i32::try_from(deposit_request.output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(&deposit_request.spend_script)
        .bind(&deposit_request.reclaim_script)
        .bind(&deposit_request.recipient)
        .bind(i64::try_from(deposit_request.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(deposit_request.max_fee).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::from(deposit_request.lock_time))
        .bind(deposit_request.signers_public_key)
        .bind(&deposit_request.sender_script_pub_keys)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Error> {
        if deposit_requests.is_empty() {
            return Ok(());
        }

        let mut txid = Vec::with_capacity(deposit_requests.len());
        let mut output_index = Vec::with_capacity(deposit_requests.len());
        let mut spend_script = Vec::with_capacity(deposit_requests.len());
        let mut reclaim_script = Vec::with_capacity(deposit_requests.len());
        let mut recipient = Vec::with_capacity(deposit_requests.len());
        let mut amount = Vec::with_capacity(deposit_requests.len());
        let mut max_fee = Vec::with_capacity(deposit_requests.len());
        let mut lock_time = Vec::with_capacity(deposit_requests.len());
        let mut signers_public_key = Vec::with_capacity(deposit_requests.len());
        let mut sender_script_pubkeys = Vec::with_capacity(deposit_requests.len());

        for req in deposit_requests {
            let vout = i32::try_from(req.output_index).map_err(Error::ConversionDatabaseInt)?;
            txid.push(req.txid);
            output_index.push(vout);
            spend_script.push(req.spend_script);
            reclaim_script.push(req.reclaim_script);
            recipient.push(req.recipient);
            amount.push(i64::try_from(req.amount).map_err(Error::ConversionDatabaseInt)?);
            max_fee.push(i64::try_from(req.max_fee).map_err(Error::ConversionDatabaseInt)?);
            lock_time.push(i64::from(req.lock_time));
            signers_public_key.push(req.signers_public_key);
            // We need to join the addresses like this (and later split
            // them), because handling of multidimensional arrays in
            // postgres is tough. The naive approach of doing
            // UNNEST($1::VARCHAR[][]) doesn't work, since that completely
            // flattens the array.
            let addresses: Vec<String> = req
                .sender_script_pub_keys
                .iter()
                .map(|x| x.to_hex_string())
                .collect();
            sender_script_pubkeys.push(addresses.join(","));
        }

        sqlx::query(
            r#"
            WITH tx_ids       AS (SELECT ROW_NUMBER() OVER (), txid FROM UNNEST($1::BYTEA[]) AS txid)
            , output_index    AS (SELECT ROW_NUMBER() OVER (), output_index FROM UNNEST($2::INTEGER[]) AS output_index)
            , spend_script    AS (SELECT ROW_NUMBER() OVER (), spend_script FROM UNNEST($3::BYTEA[]) AS spend_script)
            , reclaim_script  AS (SELECT ROW_NUMBER() OVER (), reclaim_script FROM UNNEST($4::BYTEA[]) AS reclaim_script)
            , recipient       AS (SELECT ROW_NUMBER() OVER (), recipient FROM UNNEST($5::TEXT[]) AS recipient)
            , amount          AS (SELECT ROW_NUMBER() OVER (), amount FROM UNNEST($6::BIGINT[]) AS amount)
            , max_fee         AS (SELECT ROW_NUMBER() OVER (), max_fee FROM UNNEST($7::BIGINT[]) AS max_fee)
            , lock_time       AS (SELECT ROW_NUMBER() OVER (), lock_time FROM UNNEST($8::BIGINT[]) AS lock_time)
            , signer_pub_keys AS (SELECT ROW_NUMBER() OVER (), signers_public_key FROM UNNEST($9::BYTEA[]) AS signers_public_key)
            , script_pub_keys AS (SELECT ROW_NUMBER() OVER (), senders FROM UNNEST($10::VARCHAR[]) AS senders)
            INSERT INTO sbtc_signer.deposit_requests (
                  txid
                , output_index
                , spend_script
                , reclaim_script
                , recipient
                , amount
                , max_fee
                , lock_time
                , signers_public_key
                , sender_script_pub_keys)
            SELECT
                txid
              , output_index
              , spend_script
              , reclaim_script
              , recipient
              , amount
              , max_fee
              , lock_time
              , signers_public_key
              , ARRAY(SELECT decode(UNNEST(regexp_split_to_array(senders, ',')), 'hex'))
            FROM tx_ids
            JOIN output_index USING (row_number)
            JOIN spend_script USING (row_number)
            JOIN reclaim_script USING (row_number)
            JOIN recipient USING (row_number)
            JOIN amount USING (row_number)
            JOIN max_fee USING (row_number)
            JOIN lock_time USING (row_number)
            JOIN signer_pub_keys USING (row_number)
            JOIN script_pub_keys USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(txid)
        .bind(output_index)
        .bind(spend_script)
        .bind(reclaim_script)
        .bind(recipient)
        .bind(amount)
        .bind(max_fee)
        .bind(lock_time)
        .bind(signers_public_key)
        .bind(sender_script_pubkeys)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_request(
        &self,
        request: &model::WithdrawalRequest,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.withdrawal_requests
              ( request_id
              , txid
              , block_hash
              , recipient
              , amount
              , max_fee
              , sender_address
              )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT DO NOTHING",
        )
        .bind(i64::try_from(request.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(request.txid)
        .bind(request.block_hash)
        .bind(&request.recipient)
        .bind(i64::try_from(request.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(request.max_fee).map_err(Error::ConversionDatabaseInt)?)
        .bind(&request.sender_address)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.deposit_signers
              ( txid
              , output_index
              , signer_pub_key
              , is_accepted
              , can_sign
              )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING",
        )
        .bind(decision.txid)
        .bind(i32::try_from(decision.output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(decision.signer_pub_key)
        .bind(decision.is_accepted)
        .bind(decision.can_sign)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_signer_decision(
        &self,
        decision: &model::WithdrawalSigner,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.withdrawal_signers
              ( request_id
              , txid
              , block_hash
              , signer_pub_key
              , is_accepted
              )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING",
        )
        .bind(i64::try_from(decision.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(decision.txid)
        .bind(decision.block_hash)
        .bind(decision.signer_pub_key)
        .bind(decision.is_accepted)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_transaction(&self, transaction: &model::Transaction) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.transactions
              ( txid
              , tx
              , tx_type
              )
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING",
        )
        .bind(transaction.txid)
        .bind(&transaction.tx)
        .bind(transaction.tx_type)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_bitcoin_transaction(&self, tx_ref: &model::BitcoinTxRef) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.bitcoin_transactions (txid, block_hash)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING",
        )
        .bind(tx_ref.txid)
        .bind(tx_ref.block_hash)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_bitcoin_transactions(&self, txs: Vec<model::Transaction>) -> Result<(), Error> {
        let summary = self.write_transactions(txs).await?;
        if summary.tx_ids.is_empty() {
            return Ok(());
        }
        sqlx::query(
            r#"
            WITH tx_ids AS (
                SELECT ROW_NUMBER() OVER (), txid
                FROM UNNEST($1::bytea[]) AS txid
            )
            , block_ids AS (
                SELECT ROW_NUMBER() OVER (), block_id
                FROM UNNEST($2::bytea[]) AS block_id
            )
            INSERT INTO sbtc_signer.bitcoin_transactions (txid, block_hash)
            SELECT
                txid
              , block_id
            FROM tx_ids
            JOIN block_ids USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(&summary.tx_ids)
        .bind(&summary.block_hashes)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_stacks_transaction(
        &self,
        stacks_transaction: &model::StacksTransaction,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.stacks_transactions (txid, block_hash)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING",
        )
        .bind(stacks_transaction.txid)
        .bind(stacks_transaction.block_hash)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_stacks_transactions(&self, txs: Vec<model::Transaction>) -> Result<(), Error> {
        let summary = self.write_transactions(txs).await?;
        if summary.tx_ids.is_empty() {
            return Ok(());
        }

        sqlx::query(
            r#"
            WITH tx_ids AS (
                SELECT ROW_NUMBER() OVER (), txid
                FROM UNNEST($1::bytea[]) AS txid
            )
            , block_ids AS (
                SELECT ROW_NUMBER() OVER (), block_id
                FROM UNNEST($2::bytea[]) AS block_id
            )
            INSERT INTO sbtc_signer.stacks_transactions (txid, block_hash)
            SELECT
                txid
              , block_id
            FROM tx_ids
            JOIN block_ids USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(&summary.tx_ids)
        .bind(&summary.block_hashes)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_stacks_block_headers(
        &self,
        blocks: Vec<model::StacksBlock>,
    ) -> Result<(), Error> {
        if blocks.is_empty() {
            return Ok(());
        }

        let mut block_ids = Vec::with_capacity(blocks.len());
        let mut parent_block_ids = Vec::with_capacity(blocks.len());
        let mut chain_lengths = Vec::<i64>::with_capacity(blocks.len());
        let mut bitcoin_anchors = Vec::with_capacity(blocks.len());

        for block in blocks {
            block_ids.push(block.block_hash);
            parent_block_ids.push(block.parent_hash);
            let block_height =
                i64::try_from(block.block_height).map_err(Error::ConversionDatabaseInt)?;
            chain_lengths.push(block_height);
            bitcoin_anchors.push(block.bitcoin_anchor);
        }

        sqlx::query(
            r#"
            WITH block_ids AS (
                SELECT ROW_NUMBER() OVER (), block_id
                FROM UNNEST($1::bytea[]) AS block_id
            )
            , parent_block_ids AS (
                SELECT ROW_NUMBER() OVER (), parent_block_id
                FROM UNNEST($2::bytea[]) AS parent_block_id
            )
            , chain_lengths AS (
                SELECT ROW_NUMBER() OVER (), chain_length
                FROM UNNEST($3::bigint[]) AS chain_length
            )
            , bitcoin_anchors AS (
                SELECT ROW_NUMBER() OVER (), bitcoin_anchor
                FROM UNNEST($4::bytea[]) AS bitcoin_anchor
            )
            INSERT INTO sbtc_signer.stacks_blocks (block_hash, block_height, parent_hash, bitcoin_anchor)
            SELECT
                block_id
              , chain_length
              , parent_block_id
              , bitcoin_anchor
            FROM block_ids
            JOIN parent_block_ids USING (row_number)
            JOIN chain_lengths USING (row_number)
            JOIN bitcoin_anchors USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(&block_ids)
        .bind(&parent_block_ids)
        .bind(&chain_lengths)
        .bind(&bitcoin_anchors)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Error> {
        sqlx::query(
            r#"
            INSERT INTO sbtc_signer.dkg_shares (
                aggregate_key
              , tweaked_aggregate_key
              , encrypted_private_shares
              , public_shares
              , script_pubkey
              , signer_set_public_keys
              , signature_share_threshold
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(shares.aggregate_key)
        .bind(shares.tweaked_aggregate_key)
        .bind(&shares.encrypted_private_shares)
        .bind(&shares.public_shares)
        .bind(&shares.script_pubkey)
        .bind(&shares.signer_set_public_keys)
        .bind(i32::from(shares.signature_share_threshold))
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::RotateKeysTransaction,
    ) -> Result<(), Error> {
        sqlx::query(
            r#"
            INSERT INTO sbtc_signer.rotate_keys_transactions (
                  txid
                , aggregate_key
                , signer_set
                , signatures_required)
            VALUES
                ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(key_rotation.txid)
        .bind(key_rotation.aggregate_key)
        .bind(&key_rotation.signer_set)
        .bind(i32::from(key_rotation.signatures_required))
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_completed_deposit_event(
        &self,
        event: &CompletedDepositEvent,
    ) -> Result<(), Error> {
        sqlx::query(
            "
        INSERT INTO sbtc_signer.completed_deposit_events (
            txid
          , block_hash
          , amount
          , bitcoin_txid
          , output_index
        )
        VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(event.txid.0)
        .bind(event.block_id.0)
        .bind(i64::try_from(event.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.outpoint.txid.to_byte_array())
        .bind(i64::from(event.outpoint.vout))
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_create_event(
        &self,
        event: &WithdrawalCreateEvent,
    ) -> Result<(), Error> {
        sqlx::query(
            "
        INSERT INTO sbtc_signer.withdrawal_create_events (
            txid
          , block_hash
          , request_id
          , amount
          , sender
          , recipient
          , max_fee
          , block_height
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(event.txid.0)
        .bind(event.block_id.0)
        .bind(i64::try_from(event.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(event.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.sender.to_string())
        .bind(event.recipient.as_bytes())
        .bind(i64::try_from(event.max_fee).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(event.block_height).map_err(Error::ConversionDatabaseInt)?)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_accept_event(
        &self,
        event: &WithdrawalAcceptEvent,
    ) -> Result<(), Error> {
        sqlx::query(
            "
        INSERT INTO sbtc_signer.withdrawal_accept_events (
            txid
          , block_hash
          , request_id
          , signer_bitmap
          , bitcoin_txid
          , output_index
          , fee
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(event.txid.0)
        .bind(event.block_id.0)
        .bind(i64::try_from(event.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.signer_bitmap.into_inner())
        .bind(event.outpoint.txid.to_byte_array())
        .bind(i64::from(event.outpoint.vout))
        .bind(i64::try_from(event.fee).map_err(Error::ConversionDatabaseInt)?)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdrawal_reject_event(
        &self,
        event: &WithdrawalRejectEvent,
    ) -> Result<(), Error> {
        sqlx::query(
            "
        INSERT INTO sbtc_signer.withdrawal_reject_events (
            txid
          , block_hash
          , request_id
          , signer_bitmap
        )
        VALUES ($1, $2, $3, $4)",
        )
        .bind(event.txid.0)
        .bind(event.block_id.0)
        .bind(i64::try_from(event.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(event.signer_bitmap.into_inner())
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_sweep_transaction(
        &self,
        transaction: &model::SweepTransaction,
    ) -> Result<(), Error> {
        // We're doing multiple inserts here so we wrap them in a transaction.
        let mut tx = self.0.begin().await.map_err(Error::SqlxBeginTransaction)?;

        sqlx::query(
            "
            INSERT INTO sweep_transactions (
                txid
              , signer_prevout_txid
              , signer_prevout_output_index
              , signer_prevout_amount
              , signer_prevout_script_pubkey
              , amount
              , fee
              , created_at_block_hash
              , market_fee_rate
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT DO NOTHING;
        ",
        )
        .bind(transaction.txid)
        .bind(transaction.signer_prevout_txid)
        .bind(
            i32::try_from(transaction.signer_prevout_output_index)
                .map_err(Error::ConversionDatabaseInt)?,
        )
        .bind(
            i64::try_from(transaction.signer_prevout_amount)
                .map_err(Error::ConversionDatabaseInt)?,
        )
        .bind(transaction.signer_prevout_script_pubkey.clone())
        .bind(i64::try_from(transaction.amount).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::try_from(transaction.fee).map_err(Error::ConversionDatabaseInt)?)
        .bind(transaction.created_at_block_hash)
        .bind(transaction.market_fee_rate)
        .execute(&mut *tx)
        .await
        .map_err(Error::SqlxQuery)?;

        // Insert the swept deposits.
        for deposit in transaction.swept_deposits.iter() {
            sqlx::query(
                "
                INSERT INTO swept_deposits (
                    sweep_transaction_txid
                  , input_index
                  , deposit_request_txid
                  , deposit_request_output_index
                )
                VALUES ($1, $2, $3, $4)
                ON CONFLICT DO NOTHING;
            ",
            )
            .bind(transaction.txid)
            .bind(i32::try_from(deposit.input_index).map_err(Error::ConversionDatabaseInt)?)
            .bind(deposit.deposit_request_txid)
            .bind(
                i32::try_from(deposit.deposit_request_output_index)
                    .map_err(Error::ConversionDatabaseInt)?,
            )
            .execute(&mut *tx)
            .await
            .map_err(Error::SqlxQuery)?;
        }

        // Insert the serviced withdrawals.
        for withdrawal in transaction.swept_withdrawals.iter() {
            sqlx::query(
                "
                INSERT INTO swept_withdrawals (
                    sweep_transaction_txid
                  , output_index
                  , withdrawal_request_id
                  , withdrawal_request_block_hash
                )
                VALUES ($1, $2, $3, $4)
                ON CONFLICT DO NOTHING;
            ",
            )
            .bind(transaction.txid)
            .bind(i32::try_from(withdrawal.output_index).map_err(Error::ConversionDatabaseInt)?)
            .bind(
                i64::try_from(withdrawal.withdrawal_request_id)
                    .map_err(Error::ConversionDatabaseInt)?,
            )
            .bind(withdrawal.withdrawal_request_block_hash)
            .execute(&mut *tx)
            .await
            .map_err(Error::SqlxQuery)?;
        }

        tx.commit().await.map_err(Error::SqlxCommitTransaction)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;

    use blockstack_lib::chainstate::stacks::TransactionContractCall;
    use blockstack_lib::clarity::vm::ClarityName;
    use blockstack_lib::clarity::vm::ContractName;
    use blockstack_lib::types::chainstate::StacksAddress;
    use blockstack_lib::util::hash::Hash160;
    use test_case::test_case;

    /// Test that we can extract the types of function calls that we care
    /// about
    #[test_case("sbtc-withdrawal", "initiate-withdrawal-request"; "initiate withdrawal request")]
    fn extract_transaction_type(contract_name: &str, function_name: &str) {
        let path = "tests/fixtures/tenure-blocks-0-e5fdeb1a51ba6eb297797a1c473e715c27dc81a58ba82c698f6a32eeccee9a5b.bin";
        let mut file = std::fs::File::open(path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let bytes: &mut &[u8] = &mut buf.as_ref();
        let mut blocks = Vec::new();

        while !bytes.is_empty() {
            blocks.push(NakamotoBlock::consensus_deserialize(bytes).unwrap());
        }

        let deployer = StacksAddress::burn_address(false);
        let txs = extract_relevant_transactions(&blocks, &deployer);
        assert!(txs.is_empty());

        let last_block = blocks.last_mut().unwrap();
        let mut tx = last_block.txs.last().unwrap().clone();

        let contract_call = TransactionContractCall {
            address: deployer,
            contract_name: ContractName::from(contract_name),
            function_name: ClarityName::from(function_name),
            function_args: Vec::new(),
        };
        tx.payload = TransactionPayload::ContractCall(contract_call);
        last_block.txs.push(tx);

        let txs = extract_relevant_transactions(&blocks, &deployer);
        assert_eq!(txs.len(), 1);

        // We've just seen that if the deployer supplied here matches the
        // address in the transaction, then we will consider it a relevant
        // transaction. Now what if someone tries to pull a fast one by
        // deploying their own modified version of the sBTC smart contracts
        // and creating contract calls against that? We'll the address of
        // these contract calls won't match the ones that we are interested
        // in and we will filter them out. We test that now,
        let contract_call = TransactionContractCall {
            // This is the address of the poser that deployed their own
            // versions of the sBTC smart contracts.
            address: StacksAddress::new(2, Hash160([1; 20])),
            contract_name: ContractName::from(contract_name),
            function_name: ClarityName::from(function_name),
            function_args: Vec::new(),
        };
        // The last transaction in the last nakamoto block is a legit
        // transaction. Let's remove it and replace it with a non-legit
        // one.
        let last_block = blocks.last_mut().unwrap();
        let mut tx = last_block.txs.pop().unwrap();
        tx.payload = TransactionPayload::ContractCall(contract_call);
        last_block.txs.push(tx);

        // Now there aren't any relevant transactions in the block
        let txs = extract_relevant_transactions(&blocks, &deployer);
        assert!(txs.is_empty());
    }
}
