use std::collections::BTreeSet;

use bitcoin::OutPoint;

use crate::{
    DEPOSIT_LOCKTIME_BLOCK_BUFFER, MAX_MEMPOOL_PACKAGE_TX_COUNT, MAX_REORG_BLOCK_COUNT,
    WITHDRAWAL_BLOCKS_EXPIRY,
    bitcoin::{
        utxo::SignerUtxo,
        validation::{
            DepositConfirmationStatus, DepositRequestReport, WithdrawalRequestReport,
            WithdrawalRequestStatus,
        },
    },
    error::Error,
    keys::{PublicKey, PublicKeyXOnly},
    storage::{
        DbRead,
        model::{
            self, BitcoinBlockHash, BitcoinBlockHeight, BitcoinBlockRef, StacksBlockHash,
            StacksBlockHeight,
        },
    },
};

use super::{PgStore, PgTransaction};

/// A convenience struct for retrieving a deposit request report
#[derive(sqlx::FromRow)]
struct DepositStatusSummary {
    /// The current signer may not have a record of their vote for
    /// the deposit. When that happens the `can_accept` and
    /// `can_sign` fields will be None.
    can_accept: Option<bool>,
    /// Whether this signer is a member of the signing set that generated
    /// the public key locking the deposit.
    can_sign: Option<bool>,
    /// The height of the block that confirmed the deposit request
    /// transaction.
    block_height: Option<BitcoinBlockHeight>,
    /// The block hash that confirmed the deposit request.
    block_hash: Option<model::BitcoinBlockHash>,
    /// The bitcoin consensus encoded locktime in the reclaim script.
    #[sqlx(try_from = "i64")]
    lock_time: u32,
    /// The amount associated with the deposit UTXO in sats.
    #[sqlx(try_from = "i64")]
    amount: u64,
    /// The maximum amount to spend for the bitcoin miner fee when sweeping
    /// in the funds.
    max_fee: [u8; 8],
    /// The deposit script used so that the signers' can spend funds.
    deposit_script: model::ScriptPubKey,
    /// The hash of reclaim script for the deposit.
    reclaim_script_hash: model::TaprootScriptHash,
    /// The public key used in the deposit script.
    signers_public_key: PublicKeyXOnly,
}

/// A convenience struct for retrieving a withdrawal request report
#[derive(sqlx::FromRow)]
struct WithdrawalStatusSummary {
    /// The current signer may not have a record of their vote for the
    /// withdrawal. When that happens the `is_accepted` field will be
    /// [`None`].
    is_accepted: Option<bool>,
    /// The height of the bitcoin chain tip during the execution of the
    /// contract call that generated the withdrawal request.
    bitcoin_block_height: BitcoinBlockHeight,
    /// The amount associated with the deposit UTXO in sats.
    #[sqlx(try_from = "i64")]
    amount: u64,
    /// The maximum amount to spend for the bitcoin miner fee when sweeping
    /// in the funds.
    #[sqlx(try_from = "i64")]
    max_fee: u64,
    /// The recipient scriptPubKey of the withdrawn funds.
    recipient: model::ScriptPubKey,
    /// Stacks block ID of the block that includes the transaction
    /// associated with this withdrawal request.
    stacks_block_hash: model::StacksBlockHash,
    /// Stacks block ID of the block that includes the transaction
    /// associated with this withdrawal request.
    stacks_block_height: StacksBlockHeight,
}

// A convenience struct for retrieving the signers' UTXO
#[derive(sqlx::FromRow)]
struct PgSignerUtxo {
    txid: model::BitcoinTxId,
    #[sqlx(try_from = "i32")]
    output_index: u32,
    #[sqlx(try_from = "i64")]
    amount: u64,
    aggregate_key: PublicKey,
}

impl From<PgSignerUtxo> for SignerUtxo {
    fn from(pg_txo: PgSignerUtxo) -> Self {
        SignerUtxo {
            outpoint: OutPoint::new(pg_txo.txid.into(), pg_txo.output_index),
            amount: pg_txo.amount,
            public_key: pg_txo.aggregate_key.into(),
        }
    }
}
/// Read-accessors to the Postgres database.
pub struct PgRead;

impl PgRead {
    /// This function returns the bitcoin block height of the first
    /// confirmed sweep that happened on or after the given minimum block
    /// height.
    async fn get_least_txo_height<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        min_block_height: BitcoinBlockHeight,
    ) -> Result<Option<BitcoinBlockHeight>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, BitcoinBlockHeight>(
            r#"
            SELECT bb.block_height
            FROM sbtc_signer.bitcoin_tx_inputs AS bi
            JOIN sbtc_signer.bitcoin_tx_outputs AS bo
              ON bo.txid = bi.txid
            JOIN sbtc_signer.bitcoin_transactions AS bt
              ON bt.txid = bi.txid
            JOIN bitcoin_blockchain_until($1, $2) AS bb
              ON bb.block_hash = bt.block_hash
            WHERE bo.output_type = 'signers_output'
              AND bi.prevout_type = 'signers_input'
            ORDER BY bb.block_height ASC
            LIMIT 1;
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(min_block_height).map_err(Error::ConversionDatabaseInt)?)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_utxo<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        output_type: model::TxOutputType,
        min_block_height: BitcoinBlockHeight,
    ) -> Result<Option<SignerUtxo>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        let pg_utxo = sqlx::query_as::<_, PgSignerUtxo>(
            r#"
            WITH bitcoin_blockchain AS (
                SELECT block_hash
                FROM bitcoin_blockchain_until($1, $2)
            ),
            confirmed_sweeps AS (
                SELECT
                    prevout_txid
                  , prevout_output_index
                FROM sbtc_signer.bitcoin_tx_inputs
                JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
                JOIN bitcoin_blockchain AS bb USING (block_hash)
                WHERE prevout_type = 'signers_input'
            )
            SELECT
                bo.txid
              , bo.output_index
              , bo.amount
              , ds.aggregate_key
            FROM sbtc_signer.bitcoin_tx_outputs AS bo
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            JOIN bitcoin_blockchain AS bb USING (block_hash)
            JOIN sbtc_signer.dkg_shares AS ds USING (script_pubkey)
            LEFT JOIN confirmed_sweeps AS cs
              ON cs.prevout_txid = bo.txid
              AND cs.prevout_output_index = bo.output_index
            WHERE cs.prevout_txid IS NULL
              AND bo.output_type = $3
            ORDER BY bo.amount DESC
            LIMIT 1;
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(min_block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(output_type)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(pg_utxo.map(SignerUtxo::from))
    }

    /// Return the height of the earliest block in which a donation UTXO
    /// has been confirmed.
    ///
    /// # Notes
    ///
    /// This function does not check whether the donation output has been
    /// spent.
    async fn minimum_donation_txo_height<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<BitcoinBlockHeight>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, BitcoinBlockHeight>(
            r#"
            SELECT bb.block_height
            FROM sbtc_signer.bitcoin_tx_outputs AS bo
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            JOIN sbtc_signer.bitcoin_blocks AS bb USING (block_hash)
            WHERE bo.output_type = 'donation'
            ORDER BY bb.block_height ASC
            LIMIT 1;
            "#,
        )
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Return a donation UTXO with minimum height.
    async fn get_donation_utxo<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<SignerUtxo>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        let Some(min_block_height) = Self::minimum_donation_txo_height(executor).await? else {
            return Ok(None);
        };
        let output_type = model::TxOutputType::Donation;
        Self::get_utxo(executor, chain_tip, output_type, min_block_height).await
    }

    /// Fetch the bitcoin transaction ID that swept the withdrawal along
    /// with the block hash that confirmed the transaction.
    ///
    /// `None` is returned if there is no transaction sweeping out the
    /// funds that has been confirmed on the blockchain identified by the
    /// given chain-tip.
    async fn get_withdrawal_sweep_info<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        id: &model::QualifiedRequestId,
    ) -> Result<Option<model::BitcoinTxRef>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::BitcoinTxRef>(
            r#"
            -- get_withdrawal_sweep_info
            WITH potential_transactions AS (
                SELECT
                    bwo.bitcoin_txid AS txid
                  , bt.block_hash
                  , wr.bitcoin_block_height
                FROM sbtc_signer.withdrawal_requests AS wr
                JOIN sbtc_signer.bitcoin_withdrawals_outputs AS bwo
                  ON bwo.request_id = wr.request_id
                  AND bwo.stacks_block_hash = wr.block_hash
                JOIN sbtc_signer.bitcoin_transactions AS bt
                  ON bt.txid = bwo.bitcoin_txid
                WHERE wr.request_id = $2
                  AND wr.block_hash = $3

                UNION

                SELECT
                    bwto.txid
                  , bt.block_hash
                  , wr.bitcoin_block_height
                FROM sbtc_signer.withdrawal_requests AS wr
                JOIN sbtc_signer.bitcoin_withdrawal_tx_outputs AS bwto
                  ON bwto.request_id = wr.request_id
                JOIN sbtc_signer.bitcoin_transactions AS bt
                  ON bt.txid = bwto.txid
                WHERE wr.request_id = $2
                  AND wr.block_hash = $3
            )
            SELECT 
                pt.txid
              , pt.block_hash
            FROM potential_transactions AS pt
            JOIN sbtc_signer.bitcoin_blockchain_until($1, pt.bitcoin_block_height) AS bbu
              ON bbu.block_hash = pt.block_hash
            LIMIT 1
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(id.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(id.block_hash)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Fetch a status summary of a withdrawal request.
    ///
    /// In this query we fetch the raw withdrawal request and add some
    /// information about whether this signer accepted the request.
    ///
    /// `None` is returned if withdrawal request is not in the database or
    /// if the withdrawal request is not associated with a stacks block in
    /// the database.
    async fn get_withdrawal_request_status_summary<'e, E>(
        executor: &'e mut E,
        id: &model::QualifiedRequestId,
        signer_public_key: &PublicKey,
    ) -> Result<Option<WithdrawalStatusSummary>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, WithdrawalStatusSummary>(
            r#"
            SELECT
                ws.is_accepted
              , wr.amount
              , wr.max_fee
              , wr.recipient
              , wr.bitcoin_block_height
              , wr.block_hash   AS stacks_block_hash
              , sb.block_height AS stacks_block_height
            FROM sbtc_signer.withdrawal_requests AS wr
            JOIN sbtc_signer.stacks_blocks AS sb
              ON sb.block_hash = wr.block_hash
            LEFT JOIN sbtc_signer.withdrawal_signers AS ws
              ON ws.request_id = wr.request_id
             AND ws.block_hash = wr.block_hash
             AND ws.signer_pub_key = $1
            WHERE wr.request_id = $2
              AND wr.block_hash = $3
            LIMIT 1
            "#,
        )
        .bind(signer_public_key)
        .bind(i64::try_from(id.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(id.block_hash)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Return the least height for which the deposit request was confirmed
    /// on a bitcoin blockchain.
    ///
    /// Transactions can be confirmed on more than one blockchain and this
    /// function returns the least height out of all bitcoin blocks for
    /// which the deposit has been confirmed.
    ///
    /// None is returned if we do not have a record of the deposit request.
    async fn get_deposit_request_least_height<'e, E>(
        executor: &'e mut E,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<BitcoinBlockHeight>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        // Before the deposit request is written a signer also stores the
        // bitcoin transaction and (after #731) the bitcoin block
        // confirming the deposit to the database. So this will return zero
        // rows only when we cannot find the deposit request.
        sqlx::query_scalar::<_, BitcoinBlockHeight>(
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
        .fetch_optional(executor)
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
    /// `None` is returned if no deposit request is in the database (we
    /// always write the associated transaction to the database for each
    /// deposit so that cannot be the reason for why the query here returns
    /// `None`).
    async fn get_deposit_request_status_summary<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<DepositStatusSummary>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        // We first get the least height for when the deposit request was
        // confirmed. This height serves as the stopping criteria for the
        // recursive part of the subsequent query.
        let min_block_height_fut =
            Self::get_deposit_request_least_height(executor, txid, output_index);
        // None is only returned if we do not have a record of the deposit
        // request or the deposit transaction.
        let Some(min_block_height) = min_block_height_fut.await? else {
            return Ok(None);
        };
        sqlx::query_as::<_, DepositStatusSummary>(
            r#"
            SELECT
                ds.can_accept
              , ds.can_sign
              , dr.amount
              , dr.max_fee
              , dr.lock_time
              , dr.spend_script AS deposit_script
              , dr.reclaim_script_hash
              , dr.signers_public_key
              , bc.block_height
              , bc.block_hash
            FROM sbtc_signer.deposit_requests AS dr
            JOIN sbtc_signer.bitcoin_transactions USING (txid)
            LEFT JOIN sbtc_signer.bitcoin_blockchain_until($1, $2) AS bc USING (block_hash)
            LEFT JOIN sbtc_signer.deposit_signers AS ds
              ON dr.txid = ds.txid
             AND dr.output_index = ds.output_index
             AND ds.signer_pub_key = $5
            WHERE dr.txid = $3
              AND dr.output_index = $4
            -- Always prefer a transaction's occurrence on the selected Bitcoin chain
            ORDER BY (bc.block_hash IS NOT NULL) DESC
            LIMIT 1
            "#,
        )
        .bind(chain_tip)
        .bind(min_block_height)
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .bind(signer_public_key)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Return the txid of the bitcoin transaction that swept in the
    /// deposit UTXO. The sweep transaction must be confirmed on the
    /// blockchain identified by the given chain tip.
    ///
    /// This query only looks back at transactions that are confirmed at or
    /// after the given `min_block_height`.
    async fn get_deposit_sweep_txid<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        min_block_height: BitcoinBlockHeight,
    ) -> Result<Option<model::BitcoinTxId>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, model::BitcoinTxId>(
            r#"
            SELECT bti.txid
            FROM sbtc_signer.bitcoin_tx_inputs AS bti
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            JOIN sbtc_signer.bitcoin_blockchain_until($1, $2) USING (block_hash)
            WHERE bti.prevout_txid = $3
              AND bti.prevout_output_index = $4
            LIMIT 1
            "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(min_block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Return a block height that is less than or equal to the block that
    /// confirms the signers' UTXO.
    ///
    /// # Notes
    ///
    /// * This function only returns `Ok(None)` if there have been no
    ///   confirmed sweep transactions.
    /// * As the signers sweep funds between BTC and sBTC, they leave a
    ///   chain of transactions, where each transaction spends the signers'
    ///   sole UTXO and creates a new one. This function "crawls" the chain
    ///   of transactions, starting at the most recently confirmed one,
    ///   until it goes back at least [`MAX_REORG_BLOCK_COUNT`] blocks
    ///   worth of transactions. A block with height greater than or equal
    ///   to the height returned here should contain the transaction with
    ///   the signers' UTXO, and won't if there is a reorg spanning more
    ///   than [`MAX_REORG_BLOCK_COUNT`] blocks.
    async fn minimum_utxo_height<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<BitcoinBlockHeight>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        #[derive(sqlx::FromRow)]
        struct PgCandidateUtxo {
            txid: model::BitcoinTxId,
            block_height: BitcoinBlockHeight,
        }

        // Get the block height of the unspent transaction that was most
        // recently confirmed. Note that we are not filtering by the
        // blockchain identified by a chain tip, we just want the UTXO with
        // maximum height, even if it has been reorged.
        let utxo_candidate = sqlx::query_as::<_, PgCandidateUtxo>(
            r#"
            WITH confirmed_sweeps AS (
                SELECT
                    prevout_txid
                  , prevout_output_index
                FROM sbtc_signer.bitcoin_tx_inputs
                JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
                WHERE prevout_type = 'signers_input'
            )
            SELECT
                bo.txid
              , bb.block_height
            FROM sbtc_signer.bitcoin_tx_outputs AS bo
            JOIN sbtc_signer.bitcoin_transactions AS bt USING (txid)
            JOIN sbtc_signer.bitcoin_blocks AS bb USING (block_hash)
            LEFT JOIN confirmed_sweeps AS cs
              ON cs.prevout_txid = bo.txid
              AND cs.prevout_output_index = bo.output_index
            WHERE cs.prevout_txid IS NULL
              AND bo.output_type = 'signers_output'
            ORDER BY bb.block_height DESC
            LIMIT 1;
            "#,
        )
        .fetch_optional(&mut *executor)
        .await
        .map_err(Error::SqlxQuery)?;

        // If such a UTXO candidate doesn't exist then we know that there is no
        // UTXO at all the given transaction output type.
        let Some(utxo_candidate) = utxo_candidate else {
            return Ok(None);
        };

        // Now we want the max block height[1] of all sweep transactions
        // that occurred more than MAX_REORG_BLOCK_COUNT blocks ago, because
        // this sweep transaction is considered fully confirmed.
        //
        // [1]: The sweep transaction that occurred more than
        //      MAX_REORG_BLOCK_COUNT blocks ago may have been confirmed
        //      more than once. If this is the case, we want the min height
        //      of all of them.

        // Given the utxo candidate above, this is our best guess of the
        // minimum UTXO height. It might be wrong, we'll find out shortly.
        let min_block_height_candidate = utxo_candidate
            .block_height
            .saturating_sub(MAX_REORG_BLOCK_COUNT);

        // We want to go back at least MAX_REORG_BLOCK_COUNT blocks worth
        // of transactions. The number here is the maximum number of
        // transactions that the signers could get confirmed in
        // MAX_REORG_BLOCK_COUNT bitcoin blocks, plus one. We add the one
        // because we want the transaction right after
        // MAX_REORG_BLOCK_COUNT worth of transactions.
        let max_transactions =
            i64::try_from(MAX_MEMPOOL_PACKAGE_TX_COUNT * MAX_REORG_BLOCK_COUNT + 1)
                .map_err(Error::ConversionDatabaseInt)?;

        // Find the block height of the sweep transaction that occurred at
        // or before block "best candidate block height" minus
        // MAX_REORG_BLOCK_COUNT.
        //
        // We do this because the block that confirmed the UTXO with max
        // height need not be the signers' UTXO; it does not need to be on
        // the best blockchain. But if we go back at least
        // `MAX_REORG_BLOCK_COUNT` bitcoin blocks then that UTXO is assumed
        // to still be confirmed.
        let prev_confirmed_height_candidate = sqlx::query_scalar::<_, BitcoinBlockHeight>(
            r#"
            WITH RECURSIVE signer_inputs AS (
                SELECT
                    bti.txid
                  , bti.prevout_txid
                  , MIN(bb.block_height) AS block_height
                FROM sbtc_signer.bitcoin_tx_inputs AS bti
                JOIN sbtc_signer.bitcoin_transactions USING (txid)
                JOIN sbtc_signer.bitcoin_blocks AS bb USING (block_hash)
                WHERE bti.prevout_type = 'signers_input'
                  AND bb.block_height <= $1
                GROUP BY bti.txid, bti.prevout_txid
            ),
            tx_chain AS (
                SELECT
                    si.txid
                  , si.prevout_txid
                  , si.block_height
                  , 1 AS tx_count
                FROM signer_inputs AS si
                WHERE si.txid = $3

                UNION ALL

                SELECT
                    si.txid
                  , si.prevout_txid
                  , si.block_height
                  , tc.tx_count + 1
                FROM signer_inputs AS si
                JOIN tx_chain AS tc
                  ON tc.prevout_txid = si.txid
                WHERE tc.tx_count < $2
            )
            SELECT block_height
            FROM tx_chain
            WHERE block_height <= $4
            ORDER BY block_height DESC
            LIMIT 1;
            "#,
        )
        .bind(utxo_candidate.block_height)
        .bind(max_transactions)
        .bind(utxo_candidate.txid)
        .bind(min_block_height_candidate)
        .fetch_optional(&mut *executor)
        .await
        .map_err(Error::SqlxQuery)?;

        // We need to go back at least MAX_REORG_BLOCK_COUNT blocks before
        // the confirmation height of our best candidate height. If there
        // were no sweeps at least MAX_REORG_BLOCK_COUNT blocks ago, then
        // we can use min_block_height_candidate.
        let min_block_height =
            prev_confirmed_height_candidate.unwrap_or(min_block_height_candidate);

        Ok(Some(min_block_height))
    }

    /// Check whether the given block hash is a part of the stacks
    /// blockchain identified by the given chain-tip.
    pub async fn in_canonical_stacks_blockchain<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::StacksBlockHash,
        block_hash: &model::StacksBlockHash,
        block_height: StacksBlockHeight,
    ) -> Result<bool, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>(
            r#"
            WITH RECURSIVE tx_block_chain AS (
                SELECT
                    block_hash
                  , block_height
                  , parent_hash
                FROM sbtc_signer.stacks_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.block_height
                  , parent.parent_hash
                FROM sbtc_signer.stacks_blocks AS parent
                JOIN tx_block_chain AS child
                  ON parent.block_hash = child.parent_hash
                WHERE child.block_height > $2
            )
            SELECT EXISTS (
                SELECT TRUE
                FROM tx_block_chain AS tbc
                WHERE tbc.block_hash = $3
            );
        "#,
        )
        .bind(chain_tip)
        .bind(i64::try_from(block_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(block_hash)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    pub async fn get_bitcoin_block<'e, E>(
        executor: &'e mut E,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::BitcoinBlock>(
            "SELECT
                block_hash
              , block_height
              , parent_hash
            FROM sbtc_signer.bitcoin_blocks
            WHERE block_hash = $1;",
        )
        .bind(block_hash)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    pub async fn get_stacks_block<'e, E>(
        executor: &'e mut E,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    #[cfg(any(test, feature = "testing"))]
    pub async fn get_bitcoin_canonical_chain_tip<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<model::BitcoinBlockHash>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::BitcoinBlock>(
            "SELECT
                block_hash
              , block_height
              , parent_hash
             FROM sbtc_signer.bitcoin_blocks
             ORDER BY block_height DESC, block_hash DESC
             LIMIT 1",
        )
        .fetch_optional(executor)
        .await
        .map(|maybe_block| maybe_block.map(|block| block.block_hash))
        .map_err(Error::SqlxQuery)
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_bitcoin_canonical_chain_tip_ref<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<model::BitcoinBlockRef>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::BitcoinBlockRef>(
            "SELECT
                block_hash
              , block_height
             FROM sbtc_signer.bitcoin_blocks
             ORDER BY block_height DESC, block_hash DESC
             LIMIT 1",
        )
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    #[cfg(any(test, feature = "testing"))]
    pub async fn get_stacks_chain_tip<'e, E>(
        executor: &'e mut E,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    pub async fn get_pending_deposit_requests<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
              , deposit_requests.reclaim_script_hash
              , deposit_requests.recipient
              , deposit_requests.amount
              , deposit_requests.max_fee
              , deposit_requests.lock_time
              , deposit_requests.signers_public_key
              , deposit_requests.sender_script_pub_keys
            FROM transactions_in_window transactions
            JOIN sbtc_signer.deposit_requests AS deposit_requests USING (txid)
            LEFT JOIN sbtc_signer.deposit_signers AS ds
              ON ds.txid = deposit_requests.txid
             AND ds.output_index = deposit_requests.output_index
             AND ds.signer_pub_key = $3
            WHERE ds.txid IS NULL
            "#,
        )
        .bind(chain_tip)
        .bind(i32::from(context_window))
        .bind(signer_public_key)
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    pub async fn get_pending_accepted_deposit_requests<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockRef,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::DepositRequest>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        // We only consider deposits where the confirmation height plus
        // their locktime is greater than the value below. We add one to
        // the acceptable unlock height because the chain tip is at height
        // one less than the height of the next block, which is the block
        // for which we are assessing the threshold.
        let minimum_acceptable_unlock_height =
            *chain_tip.block_height as i32 + DEPOSIT_LOCKTIME_BLOCK_BUFFER as i32 + 1;

        sqlx::query_as::<_, model::DepositRequest>(
            r#"
            WITH transactions_in_window AS (
                SELECT
                    transactions.txid
                  , blocks_in_window.block_height
                FROM bitcoin_blockchain_of($1, $2) AS blocks_in_window
                JOIN sbtc_signer.bitcoin_transactions transactions ON
                    transactions.block_hash = blocks_in_window.block_hash
            ),
            -- First we get all the deposits that are accepted by enough signers
            accepted_deposits AS (
                SELECT
                    deposit_requests.txid
                  , deposit_requests.output_index
                  , deposit_requests.spend_script
                  , deposit_requests.reclaim_script_hash
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
                    signers.can_accept
                    AND signers.can_sign
                    AND (transactions.block_height + deposit_requests.lock_time) >= $4
                GROUP BY deposit_requests.txid, deposit_requests.output_index
                HAVING COUNT(signers.txid) >= $3
            )
            -- Then we only consider the ones not swept yet (in the canonical chain)
            SELECT accepted_deposits.*
            FROM accepted_deposits
            LEFT JOIN sbtc_signer.bitcoin_tx_inputs AS bti
              ON bti.prevout_txid = accepted_deposits.txid
             AND bti.prevout_output_index = accepted_deposits.output_index
            LEFT JOIN transactions_in_window
              ON bti.txid = transactions_in_window.txid
            GROUP BY
                accepted_deposits.txid
              , accepted_deposits.output_index
              , accepted_deposits.spend_script
              , accepted_deposits.reclaim_script_hash
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
        .bind(chain_tip.block_hash)
        .bind(i32::from(context_window))
        .bind(i32::from(threshold))
        .bind(minimum_acceptable_unlock_height)
        .fetch_all(&mut *executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    pub async fn get_deposit_request_signer_votes<'e, E>(
        executor: &'e mut E,
        txid: &model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
                  , can_accept AND can_sign AS is_accepted
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
        .fetch_all(executor)
        .await
        .map(model::SignerVotes::from)
        .map_err(Error::SqlxQuery)
    }

    async fn get_withdrawal_request_signer_votes<'e, E>(
        executor: &'e mut E,
        id: &model::QualifiedRequestId,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
        .fetch_all(executor)
        .await
        .map(model::SignerVotes::from)
        .map_err(Error::SqlxQuery)
    }

    pub async fn get_deposit_request_report<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<DepositRequestReport>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        // Now fetch the deposit summary
        let summary_fut = Self::get_deposit_request_status_summary(
            executor,
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
        let block_info = summary.block_height.zip(summary.block_hash);

        // Lastly we map the block_height variable to a status enum.
        let status = match block_info {
            // Now that we know that it has been confirmed, check to see if
            // it has been swept in a bitcoin transaction that has been
            // confirmed already. We use the height of when the deposit was
            // confirmed for the min height for when a sweep transaction
            // could be confirmed. We could also use block_height + 1.
            Some((block_height, block_hash)) => {
                let deposit_sweep_txid = Self::get_deposit_sweep_txid(
                    executor,
                    chain_tip,
                    txid,
                    output_index,
                    block_height,
                );

                match deposit_sweep_txid.await? {
                    Some(txid) => DepositConfirmationStatus::Spent(txid),
                    None => DepositConfirmationStatus::Confirmed(block_height, block_hash),
                }
            }
            // If we didn't grab the block height in the above query, then
            // we know that the deposit transaction is not on the
            // blockchain identified by the chain tip.
            None => DepositConfirmationStatus::Unconfirmed,
        };

        let dkg_shares =
            Self::get_encrypted_dkg_shares(executor, summary.signers_public_key).await?;

        Ok(Some(DepositRequestReport {
            status,
            can_sign: summary.can_sign,
            can_accept: summary.can_accept,
            amount: summary.amount,
            max_fee: u64::from_be_bytes(summary.max_fee),
            lock_time: bitcoin::relative::LockTime::from_consensus(summary.lock_time)
                .map_err(Error::DisabledLockTime)?,
            outpoint: bitcoin::OutPoint::new((*txid).into(), output_index),
            deposit_script: summary.deposit_script.into(),
            reclaim_script_hash: summary.reclaim_script_hash,
            signers_public_key: summary.signers_public_key.into(),
            dkg_shares_status: dkg_shares.map(|shares| shares.dkg_shares_status),
        }))
    }

    pub async fn get_deposit_signers<'e, E>(
        executor: &'e mut E,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<model::DepositSigner>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::DepositSigner>(
            "SELECT
                txid
              , output_index
              , signer_pub_key
              , can_accept
              , can_sign
            FROM sbtc_signer.deposit_signers
            WHERE txid = $1 AND output_index = $2",
        )
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn can_sign_deposit_tx<'e, E>(
        executor: &'e mut E,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<bool>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn deposit_request_exists<'e, E>(
        executor: &'e mut E,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<bool, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT TRUE
                FROM sbtc_signer.deposit_requests AS dr
                WHERE dr.txid = $1
                  AND dr.output_index = $2
            )
            "#,
        )
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_withdrawal_signers<'e, E>(
        executor: &'e mut E,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawalSigner>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_withdrawal_requests<'e, E>(
        executor: &'e mut E,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalRequest>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
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
              , wr.bitcoin_block_height
            FROM sbtc_signer.withdrawal_requests wr
            JOIN stacks_context_window sc USING (block_hash)
            LEFT JOIN sbtc_signer.withdrawal_signers AS ws
              ON ws.request_id = wr.request_id
             AND ws.block_hash = wr.block_hash
             AND ws.signer_pub_key = $4
            WHERE ws.request_id IS NULL
            "#,
        )
        .bind(bitcoin_chain_tip)
        .bind(stacks_chain_tip)
        .bind(i32::from(context_window))
        .bind(signer_public_key)
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_accepted_withdrawal_requests<'e, E>(
        executor: &'e mut E,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        min_bitcoin_height: BitcoinBlockHeight,
        signature_threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::WithdrawalRequest>(
            r#"
            -- get_pending_accepted_withdrawal_requests
            WITH RECURSIVE

            -- Get all withdrawal requests which have a bitcoin block height
            -- of at least minimum height provided.
            requests AS (
                SELECT
                    wr.request_id
                  , wr.txid
                  , wr.block_hash
                  , wr.recipient
                  , wr.amount
                  , wr.max_fee
                  , wr.sender_address
                  , wr.bitcoin_block_height
                  , bt.block_hash as sweep_block_hash
                  , wre.block_hash as reject_block_hash
                FROM sbtc_signer.withdrawal_requests wr

                -- Join in any sweep transactions we know about.
                LEFT JOIN sbtc_signer.bitcoin_withdrawals_outputs bwo
                    ON bwo.request_id = wr.request_id
                    AND bwo.stacks_block_hash = wr.block_hash

                LEFT JOIN sbtc_signer.bitcoin_withdrawal_tx_outputs bwto
                    ON bwto.request_id = wr.request_id

                LEFT JOIN sbtc_signer.bitcoin_transactions bt
                    ON bt.txid = bwo.bitcoin_txid
                    OR bt.txid = bwto.txid

                -- Join in any rejection events we know about.
                LEFT JOIN sbtc_signer.withdrawal_reject_events AS wre
                    ON wre.request_id = wr.request_id

                -- Only requests where the bitcoin height is >= than the minimum.
                WHERE wr.bitcoin_block_height >= $3
            ),

            -- Fetch the canonical bitcoin blockchain from the chain tip back
            -- to the lowest bitcoin block height of the requests.
            bitcoin_blockchain AS (
                SELECT
                    block_hash
                  , block_height
                FROM bitcoin_blockchain_until($1, $3 - 1)
            ),

            -- Fetch the canonical stacks blockchain from the chain tip back
            -- to the anchor block with the lowest bitcoin block height of all of
            -- the requests.
            stacks_blockchain AS (
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
                JOIN stacks_blockchain last
                    ON parent.block_hash = last.parent_hash
                JOIN bitcoin_blockchain anchor
                    ON anchor.block_hash = parent.bitcoin_anchor
            )

            -- Main select clause (what we're returning).
            SELECT
                wr.request_id
              , wr.txid
              , wr.block_hash
              , wr.recipient
              , wr.amount
              , wr.max_fee
              , wr.sender_address
              , wr.bitcoin_block_height

            -- We start the query from the `requests` CTE.
            FROM requests wr

            -- Return a row for each signer vote.
            JOIN sbtc_signer.withdrawal_signers signers ON
                wr.request_id = signers.request_id
                AND wr.block_hash = signers.block_hash
                AND signers.is_accepted = TRUE

            -- Ensure the request is confirmed on the canonical stacks chain
            JOIN stacks_blockchain canonical_confirmed
                ON wr.block_hash = canonical_confirmed.block_hash

            -- Are there any confirmed sweep transactions?
            LEFT JOIN bitcoin_blockchain AS canonical_sweep
                ON wr.sweep_block_hash = canonical_sweep.block_hash

            -- Are there any confirmed reject transactions?
            LEFT JOIN stacks_blockchain AS canonical_reject
                ON wr.reject_block_hash = canonical_reject.block_hash

            GROUP BY
                wr.request_id
              , wr.block_hash
              , wr.txid
              , wr.recipient
              , wr.amount
              , wr.max_fee
              , wr.sender_address
              , wr.bitcoin_block_height

            HAVING
                -- Ensure there are enough 'yes' votes.
                COUNT(wr.request_id) >= $4
                -- Ensure there are no confirmed sweep transactions.
                AND COUNT(canonical_sweep.block_hash) = 0
                -- Ensure there are no confirmed reject contract-calls.
                AND COUNT(canonical_reject.block_hash) = 0

            ORDER BY
                wr.request_id ASC
            "#,
        )
        .bind(bitcoin_chain_tip)
        .bind(stacks_chain_tip)
        .bind(i64::try_from(min_bitcoin_height).map_err(Error::ConversionDatabaseInt)?)
        .bind(i64::from(signature_threshold))
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_rejected_withdrawal_requests<'e, E>(
        executor: &'e mut E,
        bitcoin_chain_tip: &BitcoinBlockRef,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        let expiration_height = bitcoin_chain_tip
            .block_height
            .saturating_sub(WITHDRAWAL_BLOCKS_EXPIRY);

        sqlx::query_as::<_, model::WithdrawalRequest>(
            r#"
            -- get_pending_rejected_withdrawal_requests
            WITH RECURSIVE bitcoin_blockchain AS (
                SELECT
                    block_hash
                  , block_height
                FROM bitcoin_blockchain_of($1, $2)
            ),
            stacks_context_window AS (
                SELECT
                    stacks_blocks.block_hash
                  , stacks_blocks.block_height
                  , stacks_blocks.parent_hash
                FROM sbtc_signer.stacks_blocks stacks_blocks
                WHERE stacks_blocks.block_hash = $3

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.block_height
                  , parent.parent_hash
                FROM sbtc_signer.stacks_blocks parent
                JOIN stacks_context_window last
                  ON parent.block_hash = last.parent_hash
                -- Limit the recursion to the bitcoin context window height. We
                -- are not joining directly on `bitcoin_blockchain` as once we
                -- get the stacks chain tip considering its anchor block, then
                -- we can just walk backwards.
                JOIN sbtc_signer.bitcoin_blocks block
                  ON block.block_hash = parent.bitcoin_anchor
                WHERE block.block_height >= (SELECT MIN(block_height) FROM bitcoin_blockchain)
            )
            SELECT
                wr.request_id
              , wr.txid
              , wr.block_hash
              , wr.recipient
              , wr.amount
              , wr.max_fee
              , wr.sender_address
              , wr.bitcoin_block_height
            FROM sbtc_signer.withdrawal_requests wr
            -- Request confirmed on stacks chain
            JOIN stacks_context_window sc ON wr.block_hash = sc.block_hash
            -- Request not accepted
            LEFT JOIN sbtc_signer.bitcoin_withdrawals_outputs AS bwo
                ON bwo.request_id = wr.request_id
                AND bwo.stacks_block_hash = wr.block_hash
            LEFT JOIN sbtc_signer.bitcoin_withdrawal_tx_outputs bwto
                ON bwto.request_id = wr.request_id
            LEFT JOIN bitcoin_transactions AS bc_trx
                ON bc_trx.txid = bwo.bitcoin_txid
                OR bc_trx.txid = bwto.txid
            LEFT JOIN bitcoin_blockchain
                ON bc_trx.block_hash = bitcoin_blockchain.block_hash
            -- Request not rejected
            LEFT JOIN withdrawal_reject_events AS wre
                ON wre.request_id = wr.request_id
            LEFT JOIN stacks_context_window sc2
                ON wre.block_hash = sc2.block_hash
            -- Request is expired
            WHERE wr.bitcoin_block_height < $4

            -- we need to group since we could have multiple withdrawals
            -- outputs for a single request, and some of them may not be in
            -- the canonical chain, resulting in a NULL bc_trx.block_hash;
            -- so we group and check that all the rows have NULL
            GROUP BY
                wr.request_id
              , wr.txid
              , wr.block_hash
              , wr.recipient
              , wr.amount
              , wr.max_fee
              , wr.sender_address
              , wr.bitcoin_block_height
            HAVING
                -- Request not accepted (cont'd)
                COUNT(bitcoin_blockchain.block_height) = 0
                -- Request not rejected (cont'd)
            AND COUNT(sc2.block_hash) = 0
            "#,
        )
        .bind(bitcoin_chain_tip.block_hash)
        .bind(i32::from(context_window))
        .bind(stacks_chain_tip)
        .bind(i64::try_from(expiration_height).map_err(Error::ConversionDatabaseInt)?)
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_withdrawal_request_report<'e, E>(
        executor: &'e mut E,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        id: &model::QualifiedRequestId,
        signer_public_key: &PublicKey,
    ) -> Result<Option<WithdrawalRequestReport>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        let summary_fut =
            Self::get_withdrawal_request_status_summary(executor, id, signer_public_key);
        let Some(summary) = summary_fut.await? else {
            return Ok(None);
        };

        let sweep_info_fut = Self::get_withdrawal_sweep_info(executor, bitcoin_chain_tip, id);
        let status = match sweep_info_fut.await? {
            Some(tx_ref) => WithdrawalRequestStatus::Fulfilled(tx_ref),
            None => {
                let in_canonical_stacks_blockchain_fut = Self::in_canonical_stacks_blockchain(
                    executor,
                    stacks_chain_tip,
                    &summary.stacks_block_hash,
                    summary.stacks_block_height,
                );
                if in_canonical_stacks_blockchain_fut.await? {
                    WithdrawalRequestStatus::Confirmed
                } else {
                    WithdrawalRequestStatus::Unconfirmed
                }
            }
        };

        Ok(Some(WithdrawalRequestReport {
            id: id.clone(), // TODO: Should probably take `id` by value since we're cloning it anyway
            amount: summary.amount,
            max_fee: summary.max_fee,
            is_accepted: summary.is_accepted,
            recipient: summary.recipient.into(),
            status,
            bitcoin_block_height: summary.bitcoin_block_height,
        }))
    }

    async fn compute_withdrawn_total<'e, E>(
        executor: &'e mut E,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<u64, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        let total_amount = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT SUM(bto.amount)::BIGINT
            FROM sbtc_signer.bitcoin_tx_outputs AS bto
            JOIN sbtc_signer.bitcoin_transactions AS bt
              ON bt.txid = bto.txid
            JOIN bitcoin_blockchain_of($1, $2) AS bbo
              ON bbo.block_hash = bt.block_hash
            WHERE bto.output_type = 'withdrawal'
            "#,
        )
        .bind(bitcoin_chain_tip)
        .bind(i32::from(context_window))
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        // Amounts are always positive in the database, so this conversion
        // is always fine.
        u64::try_from(total_amount.unwrap_or(0)).map_err(|_| Error::TypeConversion)
    }

    async fn get_bitcoin_blocks_with_transaction<'e, E>(
        executor: &'e mut E,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::BitcoinTxRef>(
            "SELECT txid, block_hash FROM sbtc_signer.bitcoin_transactions WHERE txid = $1",
        )
        .bind(txid)
        .fetch_all(executor)
        .await
        .map(|res| {
            res.into_iter()
                .map(|junction| junction.block_hash)
                .collect()
        })
        .map_err(Error::SqlxQuery)
    }

    async fn stacks_block_exists<'e, E>(
        executor: &'e mut E,
        block_id: &StacksBlockHash,
    ) -> Result<bool, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT TRUE AS exists
            FROM sbtc_signer.stacks_blocks
            WHERE block_hash = $1;"#,
        )
        .bind(block_id)
        .fetch_optional(executor)
        .await
        .map(|row| row.is_some())
        .map_err(Error::SqlxQuery)
    }

    async fn get_encrypted_dkg_shares<'e, X, E>(
        executor: &'e mut E,
        aggregate_key: X,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        X: Into<PublicKeyXOnly>,
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        // The aggregate_key column stores compressed public keys, which
        // always include a parity byte. Since the input here is an x-only
        // public key we don't have a parity byte, so we lop it off when
        // filtering.
        let key: PublicKeyXOnly = aggregate_key.into();
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
              , dkg_shares_status
              , started_at_bitcoin_block_hash
              , started_at_bitcoin_block_height
            FROM sbtc_signer.dkg_shares
            WHERE substring(aggregate_key FROM 2) = $1;
            "#,
        )
        .bind(key)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_latest_encrypted_dkg_shares<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
              , dkg_shares_status
              , started_at_bitcoin_block_hash
              , started_at_bitcoin_block_height
            FROM sbtc_signer.dkg_shares
            ORDER BY created_at DESC
            LIMIT 1;
            "#,
        )
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_latest_verified_dkg_shares<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
              , dkg_shares_status
              , started_at_bitcoin_block_hash
              , started_at_bitcoin_block_height
            FROM sbtc_signer.dkg_shares
            WHERE dkg_shares_status = 'verified'
            ORDER BY created_at DESC
            LIMIT 1;
            "#,
        )
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_latest_non_failed_dkg_shares<'e, E>(
        executor: &'e mut E,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
              , dkg_shares_status
              , started_at_bitcoin_block_hash
              , started_at_bitcoin_block_height
            FROM sbtc_signer.dkg_shares
            WHERE dkg_shares_status != 'failed'
            ORDER BY created_at DESC
            LIMIT 1;
            "#,
        )
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    /// Returns the number of non-failed rows in the `dkg_shares` table.
    async fn get_encrypted_dkg_shares_count<'e, E>(executor: &'e mut E) -> Result<u32, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sbtc_signer.dkg_shares WHERE dkg_shares_status != 'failed';",
        )
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)?;

        u32::try_from(count).map_err(Error::ConversionDatabaseInt)
    }

    /// Find the last key rotation by iterating backwards from the stacks
    /// chain tip scanning all transactions until we encounter a key
    /// rotation transactions.
    ///
    /// This might become quite inefficient for long chains with infrequent
    /// key rotations, so we might have to consider data model updates to
    /// allow more efficient querying of the last key rotation.
    #[cfg(any(test, feature = "testing"))]
    async fn get_last_key_rotation<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::KeyRotationEvent>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        let Some(stacks_chain_tip) = Self::get_stacks_chain_tip(executor, chain_tip).await? else {
            return Ok(None);
        };

        sqlx::query_as::<_, model::KeyRotationEvent>(
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
              , rkt.block_hash
              , rkt.address
              , rkt.aggregate_key
              , rkt.signer_set
              , rkt.signatures_required
            FROM sbtc_signer.rotate_keys_transactions rkt
            JOIN stacks_blocks AS sb
              ON rkt.block_hash = sb.block_hash
            ORDER BY sb.block_height DESC, sb.block_hash DESC, rkt.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(stacks_chain_tip.block_hash)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn key_rotation_exists<'e, E>(
        executor: &'e mut E,
        stacks_chain_tip: &model::StacksBlockHash,
        signer_set: &BTreeSet<PublicKey>,
        aggregate_key: &PublicKey,
        signatures_required: u16,
    ) -> Result<bool, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        sqlx::query_scalar::<_, bool>(
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
            SELECT EXISTS (
                SELECT TRUE
                FROM sbtc_signer.rotate_keys_transactions AS rkt
                JOIN stacks_blocks AS sb 
                  ON rkt.block_hash = sb.block_hash
                WHERE rkt.signer_set = $2
                  AND rkt.aggregate_key = $3
                  AND rkt.signatures_required = $4
            )
            "#,
        )
        .bind(stacks_chain_tip)
        .bind(signer_set.iter().collect::<Vec<_>>())
        .bind(aggregate_key)
        .bind(i32::from(signatures_required))
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_signers_script_pubkeys<'e, E>(
        executor: &'e mut E,
    ) -> Result<Vec<model::Bytes>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
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
            WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '365 DAYS'

            UNION

            SELECT script_pubkey
            FROM sbtc_signer.bitcoin_tx_outputs
            WHERE output_type = 'signers_output'
              AND created_at > CURRENT_TIMESTAMP - INTERVAL '365 DAYS'
            "#,
        )
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_signer_utxo<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<SignerUtxo>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        // If we've swept funds before, then will have a signer output and
        // a minimum UTXO height, so let's try that first.
        let Some(min_block_height) = Self::minimum_utxo_height(executor).await? else {
            // If the above function returns None then we know that there
            // have been no confirmed sweep transactions thus far, so let's
            // try looking for a donation UTXO.
            return Self::get_donation_utxo(executor, chain_tip).await;
        };
        // Okay, so we know that there has been at least one sweep
        // transaction. Let's look for the UTXO in a block after our
        // min_block_height. Note that `Self::get_utxo` returns `None` only
        // when a reorg has affected all sweep transactions. If this
        // happens we try searching for a donation.
        let output_type = model::TxOutputType::SignersOutput;
        let fut = Self::get_utxo(executor, chain_tip, output_type, min_block_height);
        match fut.await? {
            res @ Some(_) => Ok(res),
            None => Self::get_donation_utxo(executor, chain_tip).await,
        }
    }

    async fn is_known_bitcoin_block_hash<'e, E>(
        executor: &'e mut E,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<bool, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT TRUE
                FROM sbtc_signer.bitcoin_blocks AS bb
                WHERE bb.block_hash = $1
            );
        "#,
        )
        .bind(block_hash)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn in_canonical_bitcoin_blockchain<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockRef,
        block_ref: &model::BitcoinBlockRef,
    ) -> Result<bool, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        let height_diff: u64 = *chain_tip
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
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn is_signer_script_pub_key<'e, E>(
        executor: &'e mut E,
        script: &model::ScriptPubKey,
    ) -> Result<bool, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT 
                EXISTS (
                    SELECT TRUE
                    FROM sbtc_signer.dkg_shares AS ds
                    WHERE ds.script_pubkey = $1
                )
                
                OR

                EXISTS (
                    SELECT TRUE
                    FROM sbtc_signer.bitcoin_tx_outputs
                    WHERE output_type = 'signers_output'
                    AND script_pubkey = $1
                )
        "#,
        )
        .bind(script)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn is_withdrawal_inflight<'e, E>(
        executor: &'e mut E,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<bool, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        let Some(signer_utxo) = Self::get_signer_utxo(executor, bitcoin_chain_tip).await? else {
            return Ok(false);
        };
        let txid: model::BitcoinTxId = signer_utxo.outpoint.txid.into();

        // This should execute quite quickly, since the recursive part of
        // this query should be limited to 25 transactions when the most
        // recent signer UTXO hasn't been reorged. When a reorg affects
        // sweep transactions, this recursive part of the query is bounded
        // by the reorg depth length multiplied by 25.
        sqlx::query_scalar::<_, bool>(
            r#"
            WITH RECURSIVE proposed_transactions AS (
                SELECT
                    bts.txid
                  , bts.prevout_txid
                FROM sbtc_signer.bitcoin_tx_sighashes AS bts
                WHERE bts.prevout_txid = $1

                UNION ALL

                SELECT
                    bts.txid
                  , bts.prevout_txid
                FROM sbtc_signer.bitcoin_tx_sighashes AS bts
                JOIN proposed_transactions AS parent
                  ON bts.prevout_txid = parent.txid
                WHERE bts.prevout_type = 'signers_input'
            )
            SELECT EXISTS (
                SELECT TRUE
                FROM sbtc_signer.bitcoin_withdrawals_outputs AS bwo
                JOIN proposed_transactions AS pt
                  ON pt.txid = bwo.bitcoin_txid
                WHERE bwo.request_id = $2
                  AND bwo.stacks_block_hash = $3
            )"#,
        )
        .bind(txid)
        .bind(i64::try_from(id.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(id.block_hash)
        .fetch_one(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn is_withdrawal_active<'e, E>(
        executor: &'e mut E,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        min_confirmations: u64,
    ) -> Result<bool, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        // We want to find the first sweep transaction that happened
        // *after* the last time the signers considered sweeping the
        // withdrawal request. We do this in two stages:
        // 1. Find the block height of the last time that the signers
        //    considered the withdrawal request (the query right below this
        //    comment).
        // 2. Find the least height of any sweep transaction confirmed in a
        //    block with height greater than the height returned from (1).
        let last_considered_height = sqlx::query_scalar::<_, Option<BitcoinBlockHeight>>(
            r#"
            SELECT MAX(bb.block_height)
            FROM sbtc_signer.bitcoin_withdrawals_outputs AS bwo
            JOIN sbtc_signer.bitcoin_blocks AS bb
              ON bb.block_hash = bwo.bitcoin_chain_tip
            WHERE bwo.request_id = $1
              AND bwo.stacks_block_hash = $2
            "#,
        )
        .bind(i64::try_from(id.request_id).map_err(Error::ConversionDatabaseInt)?)
        .bind(id.block_hash)
        .fetch_one(&mut *executor)
        .await
        .map_err(Error::SqlxQuery)?;

        // We add one because we are interested in sweeps that were
        // confirmed after the signers last considered the withdrawal.
        let Some(min_block_height) = last_considered_height.map(|height| height + 1) else {
            // This means that there are no rows associated with the ID in the
            // `bitcoin_withdrawals_outputs` table.
            return Ok(false);
        };

        // We now know that the signers considered this withdrawal request
        // at least once. We now try to find the height of the oldest
        // signer TXO whose height is greater than the height from above.
        let chain_tip_hash = &bitcoin_chain_tip.block_hash;
        let least_txo_height =
            Self::get_least_txo_height(executor, chain_tip_hash, min_block_height).await?;
        // If this returns None, then the sweep itself could be in the
        // mempool. If that's the case then this is definitely active.
        let Some(least_txo_height) = least_txo_height else {
            return Ok(true);
        };
        // We test whether the TXO height has a minimum number of
        // confirmations. If it doesn't have enough confirmations, then it
        // is considered active since a fork could put it into the mempool
        // again.
        let txo_confirmations = bitcoin_chain_tip
            .block_height
            .saturating_sub(least_txo_height);
        Ok(txo_confirmations <= min_confirmations.into())
    }

    async fn get_swept_deposit_requests<'e, E>(
        executor: &'e mut E,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        // The following tests define the criteria for this query:
        // - [X] get_swept_deposit_requests_returns_swept_deposit_requests
        // - [X] get_swept_deposit_requests_does_not_return_unswept_deposit_requests
        // - [X] get_swept_deposit_requests_does_not_return_deposit_requests_with_responses
        // - [X] get_swept_deposit_requests_response_tx_reorged
        //
        // Note that this query may return completed requests if the stacks
        // event is anchored to a bitcoin block that is outside the context
        // window, while the sweep is still inside it.

        sqlx::query_as::<_, model::SweptDepositRequest>(
            "
            WITH RECURSIVE bitcoin_blockchain AS (
                SELECT
                    block_hash
                  , block_height
                FROM bitcoin_blockchain_of($1, $2)
            ),
            stacks_blockchain AS (
                SELECT
                    stacks_blocks.block_hash
                  , stacks_blocks.block_height
                  , stacks_blocks.parent_hash
                FROM sbtc_signer.stacks_blocks stacks_blocks
                JOIN bitcoin_blockchain as bb
                    ON bb.block_hash = stacks_blocks.bitcoin_anchor
                WHERE stacks_blocks.block_hash = $3

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.block_height
                  , parent.parent_hash
                FROM sbtc_signer.stacks_blocks parent
                JOIN stacks_blockchain last
                  ON parent.block_hash = last.parent_hash
                JOIN bitcoin_blockchain AS bb
                  ON bb.block_hash = parent.bitcoin_anchor
            )
            SELECT
                bc_trx.txid AS sweep_txid
              , bc_trx.block_hash AS sweep_block_hash
              , bc_blocks.block_height AS sweep_block_height
              , deposit_req.txid
              , deposit_req.output_index
              , deposit_req.recipient
              , deposit_req.amount
            FROM bitcoin_blockchain AS bc_blocks
            INNER JOIN bitcoin_transactions AS bc_trx USING (block_hash)
            INNER JOIN bitcoin_tx_inputs AS bti USING (txid)
            INNER JOIN deposit_requests AS deposit_req
              ON deposit_req.txid = bti.prevout_txid
             AND deposit_req.output_index = bti.prevout_output_index
            LEFT JOIN completed_deposit_events AS cde
              ON cde.bitcoin_txid = deposit_req.txid
             AND cde.output_index = deposit_req.output_index
            LEFT JOIN stacks_blockchain AS sb
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
        .bind(bitcoin_chain_tip)
        .bind(i32::from(context_window))
        .bind(stacks_chain_tip)
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_swept_withdrawal_requests<'e, E>(
        executor: &'e mut E,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptWithdrawalRequest>, Error>
    where
        E: 'static,
        for<'c> &'c mut E: sqlx::PgExecutor<'c>,
    {
        // The following tests define the criteria for this query:
        // - [X] get_swept_withdrawal_requests_returns_swept_withdrawal_requests
        // - [X] get_swept_withdrawal_requests_does_not_return_unswept_withdrawal_requests
        // - [X] get_swept_withdrawal_requests_does_not_return_withdrawal_requests_with_responses
        // - [X] get_swept_withdrawal_requests_response_tx_reorged
        //
        // Note that this query may return completed requests if the stacks
        // event is anchored to a bitcoin block that is outside the context
        // window, while the sweep is still inside it.

        sqlx::query_as::<_, model::SweptWithdrawalRequest>(
            r#"
                -- get_swept_withdrawal_requests
                WITH RECURSIVE bitcoin_blockchain AS (
                    SELECT
                        block_hash
                      , block_height
                    FROM bitcoin_blockchain_of($1, $2)
                ),
                stacks_blockchain AS (
                    SELECT
                        stacks_blocks.block_hash
                      , stacks_blocks.block_height
                      , stacks_blocks.parent_hash
                    FROM sbtc_signer.stacks_blocks stacks_blocks
                    JOIN bitcoin_blockchain AS bb
                        ON bb.block_hash = stacks_blocks.bitcoin_anchor
                    WHERE stacks_blocks.block_hash = $3
                    UNION ALL
                    SELECT
                        parent.block_hash
                      , parent.block_height
                      , parent.parent_hash
                    FROM sbtc_signer.stacks_blocks parent
                    JOIN stacks_blockchain last
                        ON parent.block_hash = last.parent_hash
                    JOIN bitcoin_blockchain AS bb
                        ON bb.block_hash = parent.bitcoin_anchor
                ),
                swept_withdrawals AS (
                    SELECT
                        bwto.output_index
                      , bwto.txid         AS sweep_txid
                      , bb.block_hash     AS sweep_block_hash
                      , bb.block_height   AS sweep_block_height
                      , bwto.request_id
                    FROM sbtc_signer.bitcoin_withdrawal_tx_outputs AS bwto
                    JOIN sbtc_signer.bitcoin_transactions AS bt
                      ON bt.txid = bwto.txid
                    JOIN bitcoin_blockchain AS bb
                      ON bb.block_hash = bt.block_hash

                    UNION

                    SELECT
                        bwo.output_index
                      , bwo.bitcoin_txid AS sweep_txid
                      , bb.block_hash    AS sweep_block_hash
                      , bb.block_height  AS sweep_block_height
                      , bwo.request_id
                    FROM sbtc_signer.bitcoin_withdrawals_outputs AS bwo
                    JOIN sbtc_signer.bitcoin_transactions AS bt
                      ON bt.txid = bwo.bitcoin_txid
                    JOIN bitcoin_blockchain AS bb
                      ON bb.block_hash = bt.block_hash
                ),
                completed_withdrawals AS (
                    SELECT wae.request_id
                    FROM sbtc_signer.withdrawal_accept_events AS wae
                    JOIN stacks_blockchain AS sb
                      ON sb.block_hash = wae.block_hash
                )
                SELECT
                    sw.output_index
                  , sw.sweep_txid
                  , sw.sweep_block_hash
                  , sw.sweep_block_height
                  , sw.request_id
                  , wr.txid
                  , wr.block_hash
                  , wr.recipient
                  , wr.amount
                  , wr.max_fee
                  , wr.sender_address
                FROM swept_withdrawals AS sw
                JOIN sbtc_signer.withdrawal_requests AS wr
                  ON wr.request_id = sw.request_id
                JOIN stacks_blockchain AS sb
                  ON sb.block_hash = wr.block_hash
                LEFT JOIN completed_withdrawals AS cw
                  ON cw.request_id = sw.request_id
                WHERE cw.request_id IS NULL
        "#,
        )
        .bind(bitcoin_chain_tip)
        .bind(i32::from(context_window))
        .bind(stacks_chain_tip)
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_deposit_request<'e, E>(
        executor: &'e mut E,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<model::DepositRequest>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::DepositRequest>(
            r#"
            SELECT txid
                 , output_index
                 , spend_script
                 , reclaim_script_hash
                 , recipient
                 , amount
                 , max_fee
                 , lock_time
                 , signers_public_key
                 , sender_script_pub_keys
            FROM sbtc_signer.deposit_requests
            WHERE txid = $1
              AND output_index = $2
            "#,
        )
        .bind(txid)
        .bind(i32::try_from(output_index).map_err(Error::ConversionDatabaseInt)?)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn will_sign_bitcoin_tx_sighash<'e, E>(
        executor: &'e mut E,
        sighash: &model::SigHash,
    ) -> Result<Option<(bool, PublicKeyXOnly, model::TxPrevoutType)>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, (bool, PublicKeyXOnly, model::TxPrevoutType)>(
            r#"
            SELECT
                will_sign
              , x_only_public_key
              , prevout_type
            FROM sbtc_signer.bitcoin_tx_sighashes
            WHERE sighash = $1
            "#,
        )
        .bind(sighash)
        .fetch_optional(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_withdrawal_signer_decisions<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalSigner>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::WithdrawalSigner>(
            r#"
            WITH target_block AS (
                SELECT blocks.block_hash, blocks.created_at
                FROM sbtc_signer.bitcoin_blockchain_of($1, $2) chain
                JOIN sbtc_signer.bitcoin_blocks blocks USING (block_hash)
                ORDER BY chain.block_height ASC
                LIMIT 1
            )
            SELECT
                ws.request_id
              , ws.txid
              , ws.block_hash
              , ws.signer_pub_key
              , ws.is_accepted

            FROM sbtc_signer.withdrawal_signers ws
            WHERE ws.signer_pub_key = $3
              AND ws.created_at >= (SELECT created_at FROM target_block)
            "#,
        )
        .bind(chain_tip)
        .bind(i32::from(context_window))
        .bind(signer_public_key)
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_deposit_signer_decisions<'e, E>(
        executor: &'e mut E,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositSigner>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::DepositSigner>(
            r#"
            WITH target_block AS (
                SELECT blocks.block_hash, blocks.created_at
                FROM sbtc_signer.bitcoin_blockchain_of($1, $2) chain
                JOIN sbtc_signer.bitcoin_blocks blocks USING (block_hash)
                ORDER BY chain.block_height ASC
                LIMIT 1
            )
            SELECT
                ds.txid
              , ds.output_index
              , ds.signer_pub_key
              , ds.can_sign
              , ds.can_accept
            FROM sbtc_signer.deposit_signers ds
            WHERE ds.signer_pub_key = $3
              AND ds.created_at >= (SELECT created_at FROM target_block)
            "#,
        )
        .bind(chain_tip)
        .bind(i32::from(context_window))
        .bind(signer_public_key)
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_p2p_peers<'e, E>(executor: &'e mut E) -> Result<Vec<model::P2PPeer>, Error>
    where
        &'e mut E: sqlx::PgExecutor<'e>,
    {
        sqlx::query_as::<_, model::P2PPeer>(
            r#"
            SELECT 
                peer_id
              , public_key
              , address
              , last_dialed_at
            FROM 
                sbtc_signer.p2p_peers
            "#,
        )
        .fetch_all(executor)
        .await
        .map_err(Error::SqlxQuery)
    }
}

impl DbRead for PgStore {
    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error> {
        PgRead::get_bitcoin_block(self.get_connection().await?.as_mut(), block_hash).await
    }

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        PgRead::get_stacks_block(self.get_connection().await?.as_mut(), block_hash).await
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Error> {
        PgRead::get_bitcoin_canonical_chain_tip(self.get_connection().await?.as_mut()).await
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_bitcoin_canonical_chain_tip_ref(
        &self,
    ) -> Result<Option<model::BitcoinBlockRef>, Error> {
        PgRead::get_bitcoin_canonical_chain_tip_ref(self.get_connection().await?.as_mut()).await
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        PgRead::get_stacks_chain_tip(self.get_connection().await?.as_mut(), bitcoin_chain_tip).await
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        PgRead::get_pending_deposit_requests(
            self.get_connection().await?.as_mut(),
            chain_tip,
            context_window,
            signer_public_key,
        )
        .await
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        context_window: u16,
        threshold: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        PgRead::get_pending_accepted_deposit_requests(
            self.get_connection().await?.as_mut(),
            chain_tip,
            context_window,
            threshold,
        )
        .await
    }

    async fn get_deposit_request_signer_votes(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        PgRead::get_deposit_request_signer_votes(
            self.get_connection().await?.as_mut(),
            txid,
            output_index,
            aggregate_key,
        )
        .await
    }

    async fn get_withdrawal_request_signer_votes(
        &self,
        id: &model::QualifiedRequestId,
        aggregate_key: &PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        PgRead::get_withdrawal_request_signer_votes(
            self.get_connection().await?.as_mut(),
            id,
            aggregate_key,
        )
        .await
    }

    async fn get_deposit_request_report(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<DepositRequestReport>, Error> {
        PgRead::get_deposit_request_report(
            self.get_connection().await?.as_mut(),
            chain_tip,
            txid,
            output_index,
            signer_public_key,
        )
        .await
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        PgRead::get_deposit_signers(self.get_connection().await?.as_mut(), txid, output_index).await
    }

    async fn can_sign_deposit_tx(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &PublicKey,
    ) -> Result<Option<bool>, Error> {
        PgRead::can_sign_deposit_tx(
            self.get_connection().await?.as_mut(),
            txid,
            output_index,
            signer_public_key,
        )
        .await
    }

    async fn deposit_request_exists(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<bool, Error> {
        PgRead::deposit_request_exists(self.get_connection().await?.as_mut(), txid, output_index)
            .await
    }

    async fn get_withdrawal_signers(
        &self,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        PgRead::get_withdrawal_signers(
            self.get_connection().await?.as_mut(),
            request_id,
            block_hash,
        )
        .await
    }

    async fn get_pending_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        PgRead::get_pending_withdrawal_requests(
            self.get_connection().await?.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            context_window,
            signer_public_key,
        )
        .await
    }

    async fn get_pending_accepted_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        min_bitcoin_height: BitcoinBlockHeight,
        signature_threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        PgRead::get_pending_accepted_withdrawal_requests(
            self.get_connection().await?.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            min_bitcoin_height,
            signature_threshold,
        )
        .await
    }

    async fn get_pending_rejected_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockRef,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        PgRead::get_pending_rejected_withdrawal_requests(
            self.get_connection().await?.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            context_window,
        )
        .await
    }

    async fn get_withdrawal_request_report(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        id: &model::QualifiedRequestId,
        signer_public_key: &PublicKey,
    ) -> Result<Option<WithdrawalRequestReport>, Error> {
        PgRead::get_withdrawal_request_report(
            self.get_connection().await?.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            id,
            signer_public_key,
        )
        .await
    }

    async fn compute_withdrawn_total(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<u64, Error> {
        PgRead::compute_withdrawn_total(
            self.get_connection().await?.as_mut(),
            bitcoin_chain_tip,
            context_window,
        )
        .await
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Error> {
        PgRead::get_bitcoin_blocks_with_transaction(self.get_connection().await?.as_mut(), txid)
            .await
    }

    async fn stacks_block_exists(&self, block_id: &StacksBlockHash) -> Result<bool, Error> {
        PgRead::stacks_block_exists(self.get_connection().await?.as_mut(), block_id).await
    }

    async fn get_encrypted_dkg_shares<X>(
        &self,
        aggregate_key: X,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        X: Into<PublicKeyXOnly>,
    {
        PgRead::get_encrypted_dkg_shares(self.get_connection().await?.as_mut(), aggregate_key).await
    }

    async fn get_latest_encrypted_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        PgRead::get_latest_encrypted_dkg_shares(self.get_connection().await?.as_mut()).await
    }

    async fn get_latest_verified_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        PgRead::get_latest_verified_dkg_shares(self.get_connection().await?.as_mut()).await
    }

    async fn get_latest_non_failed_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        PgRead::get_latest_non_failed_dkg_shares(self.get_connection().await?.as_mut()).await
    }

    async fn get_encrypted_dkg_shares_count(&self) -> Result<u32, Error> {
        PgRead::get_encrypted_dkg_shares_count(self.get_connection().await?.as_mut()).await
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_last_key_rotation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::KeyRotationEvent>, Error> {
        PgRead::get_last_key_rotation(self.get_connection().await?.as_mut(), chain_tip).await
    }

    async fn key_rotation_exists(
        &self,
        stacks_chain_tip: &StacksBlockHash,
        signer_set: &BTreeSet<PublicKey>,
        aggregate_key: &PublicKey,
        signatures_required: u16,
    ) -> Result<bool, Error> {
        PgRead::key_rotation_exists(
            self.get_connection().await?.as_mut(),
            stacks_chain_tip,
            signer_set,
            aggregate_key,
            signatures_required,
        )
        .await
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error> {
        PgRead::get_signers_script_pubkeys(self.get_connection().await?.as_mut()).await
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<SignerUtxo>, Error> {
        PgRead::get_signer_utxo(self.get_connection().await?.as_mut(), chain_tip).await
    }

    async fn is_known_bitcoin_block_hash(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        PgRead::is_known_bitcoin_block_hash(self.get_connection().await?.as_mut(), block_hash).await
    }

    async fn in_canonical_bitcoin_blockchain(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        block_ref: &model::BitcoinBlockRef,
    ) -> Result<bool, Error> {
        PgRead::in_canonical_bitcoin_blockchain(
            self.get_connection().await?.as_mut(),
            chain_tip,
            block_ref,
        )
        .await
    }

    async fn is_signer_script_pub_key(&self, script: &model::ScriptPubKey) -> Result<bool, Error> {
        PgRead::is_signer_script_pub_key(self.get_connection().await?.as_mut(), script).await
    }

    async fn is_withdrawal_inflight(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        PgRead::is_withdrawal_inflight(self.get_connection().await?.as_mut(), id, bitcoin_chain_tip)
            .await
    }

    async fn is_withdrawal_active(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        min_confirmations: u64,
    ) -> Result<bool, Error> {
        PgRead::is_withdrawal_active(
            self.get_connection().await?.as_mut(),
            id,
            bitcoin_chain_tip,
            min_confirmations,
        )
        .await
    }

    async fn get_swept_deposit_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error> {
        PgRead::get_swept_deposit_requests(
            self.get_connection().await?.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            context_window,
        )
        .await
    }

    async fn get_swept_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptWithdrawalRequest>, Error> {
        PgRead::get_swept_withdrawal_requests(
            self.get_connection().await?.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            context_window,
        )
        .await
    }

    async fn get_deposit_request(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<model::DepositRequest>, Error> {
        PgRead::get_deposit_request(self.get_connection().await?.as_mut(), txid, output_index).await
    }

    async fn will_sign_bitcoin_tx_sighash(
        &self,
        sighash: &model::SigHash,
    ) -> Result<Option<(bool, PublicKeyXOnly, model::TxPrevoutType)>, Error> {
        PgRead::will_sign_bitcoin_tx_sighash(self.get_connection().await?.as_mut(), sighash).await
    }

    async fn get_withdrawal_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        PgRead::get_withdrawal_signer_decisions(
            self.get_connection().await?.as_mut(),
            chain_tip,
            context_window,
            signer_public_key,
        )
        .await
    }

    async fn get_deposit_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &PublicKey,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        PgRead::get_deposit_signer_decisions(
            self.get_connection().await?.as_mut(),
            chain_tip,
            context_window,
            signer_public_key,
        )
        .await
    }

    async fn get_p2p_peers(&self) -> Result<Vec<model::P2PPeer>, Error> {
        PgRead::get_p2p_peers(self.get_connection().await?.as_mut()).await
    }
}

impl DbRead for PgTransaction<'_> {
    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_bitcoin_block(tx.as_mut(), block_hash).await
    }

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        PgRead::get_stacks_block(self.tx.lock().await.as_mut(), block_hash).await
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_bitcoin_canonical_chain_tip(tx.as_mut()).await
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_bitcoin_canonical_chain_tip_ref(
        &self,
    ) -> Result<Option<model::BitcoinBlockRef>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_bitcoin_canonical_chain_tip_ref(tx.as_mut()).await
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlock>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_stacks_chain_tip(tx.as_mut(), bitcoin_chain_tip).await
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_pending_deposit_requests(
            tx.as_mut(),
            chain_tip,
            context_window,
            signer_public_key,
        )
        .await
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        context_window: u16,
        signatures_required: u16,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        PgRead::get_pending_accepted_deposit_requests(
            self.tx.lock().await.as_mut(),
            chain_tip,
            context_window,
            signatures_required,
        )
        .await
    }

    async fn deposit_request_exists(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<bool, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::deposit_request_exists(tx.as_mut(), txid, output_index).await
    }

    async fn get_deposit_request_report(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Option<crate::bitcoin::validation::DepositRequestReport>, Error> {
        PgRead::get_deposit_request_report(
            self.tx.lock().await.as_mut(),
            chain_tip,
            txid,
            output_index,
            signer_public_key,
        )
        .await
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_deposit_signers(tx.as_mut(), txid, output_index).await
    }

    async fn get_deposit_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Vec<model::DepositSigner>, Error> {
        PgRead::get_deposit_signer_decisions(
            self.tx.lock().await.as_mut(),
            chain_tip,
            context_window,
            signer_public_key,
        )
        .await
    }

    async fn get_withdrawal_signer_decisions(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        PgRead::get_withdrawal_signer_decisions(
            self.tx.lock().await.as_mut(),
            chain_tip,
            context_window,
            signer_public_key,
        )
        .await
    }

    async fn can_sign_deposit_tx(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Option<bool>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::can_sign_deposit_tx(tx.as_mut(), txid, output_index, signer_public_key).await
    }

    async fn get_withdrawal_signers(
        &self,
        request_id: u64,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawalSigner>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_withdrawal_signers(tx.as_mut(), request_id, block_hash).await
    }

    async fn get_pending_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        PgRead::get_pending_withdrawal_requests(
            self.tx.lock().await.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            context_window,
            signer_public_key,
        )
        .await
    }

    async fn get_pending_accepted_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        min_bitcoin_height: BitcoinBlockHeight,
        signature_threshold: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        PgRead::get_pending_accepted_withdrawal_requests(
            self.tx.lock().await.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            min_bitcoin_height,
            signature_threshold,
        )
        .await
    }

    async fn get_pending_rejected_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockRef,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        PgRead::get_pending_rejected_withdrawal_requests(
            self.tx.lock().await.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            context_window,
        )
        .await
    }

    async fn get_withdrawal_request_report(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        stacks_chain_tip: &model::StacksBlockHash,
        id: &model::QualifiedRequestId,
        signer_public_key: &crate::keys::PublicKey,
    ) -> Result<Option<crate::bitcoin::validation::WithdrawalRequestReport>, Error> {
        PgRead::get_withdrawal_request_report(
            self.tx.lock().await.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            id,
            signer_public_key,
        )
        .await
    }

    async fn compute_withdrawn_total(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        context_window: u16,
    ) -> Result<u64, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::compute_withdrawn_total(tx.as_mut(), bitcoin_chain_tip, context_window).await
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_bitcoin_blocks_with_transaction(tx.as_mut(), txid).await
    }

    async fn stacks_block_exists(&self, block_id: &StacksBlockHash) -> Result<bool, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::stacks_block_exists(tx.as_mut(), block_id).await
    }

    async fn get_encrypted_dkg_shares<X>(
        &self,
        aggregate_key: X,
    ) -> Result<Option<model::EncryptedDkgShares>, Error>
    where
        X: Into<crate::keys::PublicKeyXOnly>,
    {
        let mut tx = self.tx.lock().await;
        PgRead::get_encrypted_dkg_shares(tx.as_mut(), aggregate_key).await
    }

    async fn get_latest_encrypted_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_latest_encrypted_dkg_shares(tx.as_mut()).await
    }

    async fn get_latest_verified_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_latest_verified_dkg_shares(tx.as_mut()).await
    }

    async fn get_latest_non_failed_dkg_shares(
        &self,
    ) -> Result<Option<model::EncryptedDkgShares>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_latest_non_failed_dkg_shares(tx.as_mut()).await
    }

    async fn get_encrypted_dkg_shares_count(&self) -> Result<u32, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_encrypted_dkg_shares_count(tx.as_mut()).await
    }

    #[cfg(any(test, feature = "testing"))]
    async fn get_last_key_rotation(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::KeyRotationEvent>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_last_key_rotation(tx.as_mut(), chain_tip).await
    }

    async fn key_rotation_exists(
        &self,
        stacks_chain_tip: &model::StacksBlockHash,
        signer_set: &std::collections::BTreeSet<crate::keys::PublicKey>,
        aggregate_key: &crate::keys::PublicKey,
        signatures_required: u16,
    ) -> Result<bool, Error> {
        PgRead::key_rotation_exists(
            self.tx.lock().await.as_mut(),
            stacks_chain_tip,
            signer_set,
            aggregate_key,
            signatures_required,
        )
        .await
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_signers_script_pubkeys(tx.as_mut()).await
    }

    async fn get_signer_utxo(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<crate::bitcoin::utxo::SignerUtxo>, Error> {
        PgRead::get_signer_utxo(self.tx.lock().await.as_mut(), chain_tip).await
    }

    async fn get_deposit_request_signer_votes(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
        aggregate_key: &crate::keys::PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        PgRead::get_deposit_request_signer_votes(
            self.tx.lock().await.as_mut(),
            txid,
            output_index,
            aggregate_key,
        )
        .await
    }

    async fn get_withdrawal_request_signer_votes(
        &self,
        id: &model::QualifiedRequestId,
        aggregate_key: &crate::keys::PublicKey,
    ) -> Result<model::SignerVotes, Error> {
        PgRead::get_withdrawal_request_signer_votes(
            self.tx.lock().await.as_mut(),
            id,
            aggregate_key,
        )
        .await
    }

    async fn is_known_bitcoin_block_hash(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::is_known_bitcoin_block_hash(tx.as_mut(), block_hash).await
    }

    async fn in_canonical_bitcoin_blockchain(
        &self,
        chain_tip: &model::BitcoinBlockRef,
        block_ref: &model::BitcoinBlockRef,
    ) -> Result<bool, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::in_canonical_bitcoin_blockchain(tx.as_mut(), chain_tip, block_ref).await
    }

    async fn is_signer_script_pub_key(&self, script: &model::ScriptPubKey) -> Result<bool, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::is_signer_script_pub_key(tx.as_mut(), script).await
    }

    async fn is_withdrawal_inflight(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        PgRead::is_withdrawal_inflight(self.tx.lock().await.as_mut(), id, bitcoin_chain_tip).await
    }

    async fn is_withdrawal_active(
        &self,
        id: &model::QualifiedRequestId,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        min_confirmations: u64,
    ) -> Result<bool, Error> {
        PgRead::is_withdrawal_active(
            self.tx.lock().await.as_mut(),
            id,
            bitcoin_chain_tip,
            min_confirmations,
        )
        .await
    }

    async fn get_swept_deposit_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptDepositRequest>, Error> {
        PgRead::get_swept_deposit_requests(
            self.tx.lock().await.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            context_window,
        )
        .await
    }

    async fn get_swept_withdrawal_requests(
        &self,
        bitcoin_chain_tip: &BitcoinBlockHash,
        stacks_chain_tip: &StacksBlockHash,
        context_window: u16,
    ) -> Result<Vec<model::SweptWithdrawalRequest>, Error> {
        PgRead::get_swept_withdrawal_requests(
            self.tx.lock().await.as_mut(),
            bitcoin_chain_tip,
            stacks_chain_tip,
            context_window,
        )
        .await
    }

    async fn get_deposit_request(
        &self,
        txid: &model::BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<model::DepositRequest>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_deposit_request(tx.as_mut(), txid, output_index).await
    }

    async fn will_sign_bitcoin_tx_sighash(
        &self,
        sighash: &model::SigHash,
    ) -> Result<Option<(bool, crate::keys::PublicKeyXOnly, model::TxPrevoutType)>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::will_sign_bitcoin_tx_sighash(tx.as_mut(), sighash).await
    }

    async fn get_p2p_peers(&self) -> Result<Vec<model::P2PPeer>, Error> {
        let mut tx = self.tx.lock().await;
        PgRead::get_p2p_peers(tx.as_mut()).await
    }
}
