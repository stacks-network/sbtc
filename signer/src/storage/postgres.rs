//! Postgres storage implementation.

use std::collections::HashMap;
use std::sync::OnceLock;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksBlockId;

use crate::error::Error;
use crate::keys::PublicKey;
use crate::storage::model;
use crate::storage::model::TransactionType;

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
pub fn extract_relevant_transactions(blocks: &[NakamotoBlock]) -> Vec<model::Transaction> {
    let transaction_kinds = contract_transaction_kinds();
    blocks
        .iter()
        .flat_map(|block| block.txs.iter().map(|tx| (tx, block.block_id())))
        .filter_map(|(tx, block_id)| match &tx.payload {
            TransactionPayload::ContractCall(x)
                if CONTRACT_NAMES.contains(&x.contract_name.as_str()) =>
            {
                Some(model::Transaction {
                    txid: tx.txid().to_bytes().to_vec(),
                    block_hash: block_id.to_bytes().to_vec(),
                    tx: tx.serialize_to_vec(),
                    tx_type: *transaction_kinds.get(&x.function_name.as_str())?,
                })
            }
            _ => None,
        })
        .collect()
}

/// A wrapper around a [`sqlx::PgPool`] which implements
/// [`crate::storage::DbRead`] and [`crate::storage::DbWrite`].
#[derive(Debug, Clone)]
pub struct PgStore(sqlx::PgPool);

impl TryFrom<&NakamotoBlock> for model::StacksBlock {
    type Error = Error;
    fn try_from(block: &NakamotoBlock) -> Result<Self, Self::Error> {
        let block_height = block
            .header
            .chain_length
            .try_into()
            .map_err(|_| Error::TypeConversion)?;

        Ok(Self {
            block_hash: block.block_id().to_bytes().to_vec(),
            block_height,
            parent_hash: block.header.parent_block_id.to_bytes().to_vec(),
            created_at: time::OffsetDateTime::now_utc(),
        })
    }
}

impl PgStore {
    /// Connect to the Postgres database at `url`.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        Ok(Self(sqlx::PgPool::connect(url).await?))
    }

    async fn get_stacks_chain_tip(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Option<model::StacksBlockHash>, Error> {
        sqlx::query_as!(
            model::StacksBlock,
            r#"
             SELECT
                 stacks_blocks.block_hash
               , stacks_blocks.block_height
               , stacks_blocks.parent_hash
               , stacks_blocks.created_at
             FROM sbtc_signer.stacks_blocks stacks_blocks
             JOIN sbtc_signer.bitcoin_blocks bitcoin_blocks
                 ON bitcoin_blocks.confirms @> ARRAY[stacks_blocks.block_hash]
             WHERE bitcoin_blocks.block_hash = $1
            ORDER BY block_height DESC, block_hash DESC
            LIMIT 1;
            "#,
            bitcoin_chain_tip
        )
        .fetch_optional(&self.0)
        .await
        .map(|maybe_block| maybe_block.map(|block| block.block_hash))
        .map_err(Error::SqlxQuery)
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

        sqlx::query!(
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
            INSERT INTO sbtc_signer.transactions (txid, tx, tx_type, created_at)
            SELECT
                txid
              , tx
              , tx_type
              , CURRENT_TIMESTAMP
            FROM tx_ids 
            JOIN txs USING (row_number)
            JOIN transaction_types USING (row_number)
            ON CONFLICT DO NOTHING"#,
            &tx_ids,
            &txs_bytes,
            &tx_types,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(model::TransactionIds { tx_ids, block_hashes })
    }
}

impl From<sqlx::PgPool> for PgStore {
    fn from(value: sqlx::PgPool) -> Self {
        Self(value)
    }
}

impl super::DbRead for PgStore {
    type Error = Error;

    async fn get_bitcoin_block(
        &self,
        block_hash: &model::BitcoinBlockHash,
    ) -> Result<Option<model::BitcoinBlock>, Self::Error> {
        sqlx::query_as!(
            model::BitcoinBlock,
            "SELECT
                block_hash
              , block_height
              , parent_hash
              , confirms
              , created_at
            FROM sbtc_signer.bitcoin_blocks
            WHERE block_hash = $1;",
            &block_hash
        )
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_stacks_block(
        &self,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Option<model::StacksBlock>, Self::Error> {
        sqlx::query_as!(
            model::StacksBlock,
            "SELECT
                block_hash
              , block_height
              , parent_hash
              , created_at
            FROM sbtc_signer.stacks_blocks
            WHERE block_hash = $1;",
            &block_hash
        )
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Self::Error> {
        sqlx::query_as!(
            model::BitcoinBlock,
            "SELECT
                block_hash
              , block_height
              , parent_hash
              , confirms
              , created_at
             FROM sbtc_signer.bitcoin_blocks
             ORDER BY block_height DESC, block_hash DESC"
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
        sqlx::query_as!(
            model::StacksBlock,
            r#"
             SELECT
                 stacks_blocks.block_hash
               , stacks_blocks.block_height
               , stacks_blocks.parent_hash
               , stacks_blocks.created_at
             FROM sbtc_signer.stacks_blocks stacks_blocks
             JOIN sbtc_signer.bitcoin_blocks bitcoin_blocks
                 ON bitcoin_blocks.confirms @> ARRAY[stacks_blocks.block_hash]
             WHERE bitcoin_blocks.block_hash = $1
            ORDER BY block_height DESC, block_hash DESC
            LIMIT 1;
            "#,
            bitcoin_chain_tip
        )
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        sqlx::query_as!(
            model::DepositRequest,
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
              , deposit_requests.sender_addresses
              , deposit_requests.created_at
            FROM transactions_in_window transactions
            JOIN sbtc_signer.deposit_requests deposit_requests ON
                deposit_requests.txid = transactions.txid
            "#,
            chain_tip,
            context_window,
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_accepted_deposit_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
        threshold: i64,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        sqlx::query_as!(
            model::DepositRequest,
            r#"
            WITH RECURSIVE context_window AS (
                -- Anchor member: Initialize the recursion with the chain tip
                SELECT block_hash, block_height, parent_hash, created_at, 1 AS depth
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1
                
                UNION ALL
                
                -- Recursive member: Fetch the parent block using the last block's parent_hash
                SELECT
                    parent.block_hash
                  , parent.block_height
                  , parent.parent_hash
                  , parent.created_at
                  , last.depth + 1
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
              , deposit_requests.sender_addresses
              , deposit_requests.created_at
            FROM transactions_in_window transactions
            JOIN sbtc_signer.deposit_requests deposit_requests USING(txid)
            JOIN sbtc_signer.deposit_signers signers USING(txid, output_index)
            WHERE
                signers.is_accepted
            GROUP BY deposit_requests.txid, deposit_requests.output_index
            HAVING COUNT(signers.txid) >= $3
            "#,
            chain_tip,
            context_window,
            threshold,
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_accepted_deposit_requests(
        &self,
        signer: &PublicKey,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        let key = signer.serialize();
        sqlx::query_as!(
            model::DepositRequest,
            r#"
            SELECT
                requests.txid
              , requests.output_index
              , requests.spend_script
              , requests.reclaim_script
              , requests.recipient
              , requests.amount
              , requests.max_fee
              , requests.sender_addresses
              , requests.created_at
            FROM sbtc_signer.deposit_requests requests
                 JOIN sbtc_signer.deposit_signers signers
                   ON requests.txid = signers.txid
                  AND requests.output_index = signers.output_index
            WHERE
                signers.signer_pub_key = $1
            "#,
            key.as_slice(),
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_deposit_signers(
        &self,
        txid: &model::BitcoinTxId,
        output_index: i32,
    ) -> Result<Vec<model::DepositSigner>, Self::Error> {
        sqlx::query_as::<_, model::DepositSigner>(
            "SELECT
                txid
              , output_index
              , signer_pub_key
              , is_accepted
              , created_at
            FROM sbtc_signer.deposit_signers 
            WHERE txid = $1 AND output_index = $2",
        )
        .bind(txid)
        .bind(output_index)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_withdraw_signers(
        &self,
        request_id: i32,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawSigner>, Self::Error> {
        sqlx::query_as::<_, model::WithdrawSigner>(
            "SELECT
                request_id
              , block_hash
              , signer_pub_key
              , is_accepted
              , created_at
            FROM sbtc_signer.withdraw_signers
            WHERE request_id = $1 AND block_hash = $2",
        )
        .bind(request_id)
        .bind(block_hash)
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(Vec::new());
        };
        sqlx::query_as!(
            model::WithdrawRequest,
            r#"
            WITH RECURSIVE extended_context_window AS (
                SELECT 
                    block_hash
                  , parent_hash
                  , confirms
                  , 1 AS depth
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.parent_hash
                  , parent.confirms
                  , last.depth + 1
                FROM sbtc_signer.bitcoin_blocks parent
                JOIN extended_context_window last ON parent.block_hash = last.parent_hash
                WHERE last.depth <= $3
            ),
            last_bitcoin_block AS (
                SELECT
                    block_hash
                  , confirms
                FROM extended_context_window
                ORDER BY depth DESC
                LIMIT 1
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
                LEFT JOIN last_bitcoin_block block
                        ON block.confirms @> ARRAY[parent.block_hash]
                WHERE block.block_hash IS NULL
            )
            SELECT
                wr.request_id
              , wr.block_hash
              , wr.recipient
              , wr.amount
              , wr.max_fee
              , wr.sender_address
              , wr.created_at
            FROM sbtc_signer.withdraw_requests wr
            JOIN stacks_context_window sc ON wr.block_hash = sc.block_hash
            "#,
            chain_tip,
            stacks_chain_tip,
            context_window,
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_accepted_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
        threshold: i64,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        let Some(stacks_chain_tip) = self.get_stacks_chain_tip(chain_tip).await? else {
            return Ok(Vec::new());
        };
        sqlx::query_as!(
            model::WithdrawRequest,
            r#"
            WITH RECURSIVE extended_context_window AS (
                SELECT 
                    block_hash
                  , parent_hash
                  , confirms
                  , 1 AS depth
                FROM sbtc_signer.bitcoin_blocks
                WHERE block_hash = $1

                UNION ALL

                SELECT
                    parent.block_hash
                  , parent.parent_hash
                  , parent.confirms
                  , last.depth + 1
                FROM sbtc_signer.bitcoin_blocks parent
                JOIN extended_context_window last ON parent.block_hash = last.parent_hash
                WHERE last.depth <= $3
            ),
            last_bitcoin_block AS (
                SELECT
                    block_hash
                  , confirms
                FROM extended_context_window
                ORDER BY depth DESC
                LIMIT 1
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
                LEFT JOIN last_bitcoin_block block
                        ON block.confirms @> ARRAY[parent.block_hash]
                WHERE block.block_hash IS NULL
            )
            SELECT
                wr.request_id
              , wr.block_hash
              , wr.recipient
              , wr.amount
              , wr.max_fee
              , wr.sender_address
              , wr.created_at
            FROM sbtc_signer.withdraw_requests wr
            JOIN stacks_context_window sc ON wr.block_hash = sc.block_hash
            JOIN sbtc_signer.withdraw_signers signers ON
                wr.request_id = signers.request_id AND
                wr.block_hash = signers.block_hash
            WHERE
                signers.is_accepted
            GROUP BY wr.request_id, wr.block_hash
            HAVING COUNT(wr.request_id) >= $4
            "#,
            chain_tip,
            stacks_chain_tip,
            context_window,
            threshold,
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Self::Error> {
        sqlx::query_as!(
            model::BitcoinTransaction,
            "SELECT txid, block_hash FROM sbtc_signer.bitcoin_transactions WHERE txid = $1",
            txid,
        )
        .fetch_all(&self.0)
        .await
        .map(|res| {
            res.into_iter()
                .map(|junction| junction.block_hash)
                .collect()
        })
        .map_err(Error::SqlxQuery)
    }

    async fn stacks_block_exists(&self, block_id: StacksBlockId) -> Result<bool, Self::Error> {
        sqlx::query!(
            r#"
            SELECT 1 AS exists
            FROM sbtc_signer.stacks_blocks
            WHERE block_hash = $1;"#,
            &block_id.0
        )
        .fetch_optional(&self.0)
        .await
        .map(|row| row.is_some())
        .map_err(Error::SqlxQuery)
    }

    async fn get_encrypted_dkg_shares(
        &self,
        aggregate_key: &PublicKey,
    ) -> Result<Option<model::EncryptedDkgShares>, Self::Error> {
        sqlx::query_as::<_, model::EncryptedDkgShares>(
            r#"
            SELECT
                aggregate_key
              , tweaked_aggregate_key
              , script_pubkey
              , encrypted_private_shares
              , public_shares
              , created_at
            FROM sbtc_signer.dkg_shares
            WHERE aggregate_key = $1;
            "#,
        )
        .bind(aggregate_key)
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
    ) -> Result<Option<model::RotateKeysTransaction>, Self::Error> {
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
            ORDER BY sb.block_height DESC, sb.block_hash DESC
            LIMIT 1
            "#,
        )
        .bind(stacks_chain_tip)
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_signers_script_pubkeys(&self) -> Result<Vec<model::Bytes>, Self::Error> {
        sqlx::query_scalar::<_, model::Bytes>(
            r#"
            SELECT script_pubkey
            FROM sbtc_signer.dkg_shares
            WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '365 DAYS';
            "#,
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }
}

impl super::DbWrite for PgStore {
    type Error = Error;

    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.bitcoin_blocks
              ( block_hash
              , block_height
              , parent_hash
              , confirms
              , created_at
              )
            VALUES ($1, $2, $3, $4, $5)",
            block.block_hash,
            block.block_height,
            block.parent_hash,
            &block.confirms,
            block.created_at
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_stacks_block(&self, block: &model::StacksBlock) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.stacks_blocks
              ( block_hash
              , block_height
              , parent_hash
              , created_at
              )
            VALUES ($1, $2, $3, $4)",
            block.block_hash,
            block.block_height,
            block.parent_hash,
            block.created_at
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_deposit_request(
        &self,
        deposit_request: &model::DepositRequest,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.deposit_requests
              ( txid
              , output_index
              , spend_script
              , reclaim_script
              , recipient
              , amount
              , max_fee
              , sender_addresses
              , created_at
              )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            deposit_request.txid,
            deposit_request.output_index,
            deposit_request.spend_script,
            deposit_request.reclaim_script,
            deposit_request.recipient,
            deposit_request.amount,
            deposit_request.max_fee,
            &deposit_request.sender_addresses,
            deposit_request.created_at,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_deposit_requests(
        &self,
        deposit_requests: Vec<model::DepositRequest>,
    ) -> Result<(), Self::Error> {
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
        let mut sender_addresses = Vec::with_capacity(deposit_requests.len());

        for req in deposit_requests {
            txid.push(req.txid);
            output_index.push(req.output_index);
            spend_script.push(req.spend_script);
            reclaim_script.push(req.reclaim_script);
            recipient.push(req.recipient);
            amount.push(req.amount);
            max_fee.push(req.max_fee);
            // We need to join the addresses like this (and later split
            // them), because handling of multidimensional arrays in
            // postgres is tough. The naive approach of doing
            // UNNEST($1::VARCHAR[][]) doesn't work, since that completely
            // flattens the array.
            sender_addresses.push(req.sender_addresses.join(","));
        }

        sqlx::query(
            r#"
            WITH tx_ids       AS (SELECT ROW_NUMBER() OVER (), txid FROM UNNEST($1::BYTEA[]) AS txid)
            , output_index    AS (SELECT ROW_NUMBER() OVER (), output_index FROM UNNEST($2::INTEGER[]) AS output_index)
            , spend_script    AS (SELECT ROW_NUMBER() OVER (), spend_script FROM UNNEST($3::BYTEA[]) AS spend_script)
            , reclaim_script  AS (SELECT ROW_NUMBER() OVER (), reclaim_script FROM UNNEST($4::BYTEA[]) AS reclaim_script)
            , recipient       AS (SELECT ROW_NUMBER() OVER (), recipient FROM UNNEST($5::BYTEA[]) AS recipient)
            , amount          AS (SELECT ROW_NUMBER() OVER (), amount FROM UNNEST($6::BIGINT[]) AS amount)
            , max_fee         AS (SELECT ROW_NUMBER() OVER (), max_fee FROM UNNEST($7::BIGINT[]) AS max_fee)
            , sender_address  AS (SELECT ROW_NUMBER() OVER (), sender_address FROM UNNEST($8::VARCHAR[]) AS sender_address)
            INSERT INTO sbtc_signer.deposit_requests (
                  txid
                , output_index
                , spend_script
                , reclaim_script
                , recipient
                , amount
                , max_fee
                , sender_addresses
                , created_at)
            SELECT
                txid
              , output_index
              , spend_script
              , reclaim_script
              , recipient
              , amount
              , max_fee
              , regexp_split_to_array(sender_address, ',')
              , CURRENT_TIMESTAMP
            FROM tx_ids
            JOIN output_index USING (row_number)
            JOIN spend_script USING (row_number)
            JOIN reclaim_script USING (row_number)
            JOIN recipient USING (row_number)
            JOIN amount USING (row_number)
            JOIN max_fee USING (row_number)
            JOIN sender_address USING (row_number)
            ON CONFLICT DO NOTHING"#,
        )
        .bind(txid)
        .bind(output_index)
        .bind(spend_script)
        .bind(reclaim_script)
        .bind(recipient)
        .bind(amount)
        .bind(max_fee)
        .bind(sender_addresses)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdraw_request(
        &self,
        withdraw_request: &model::WithdrawRequest,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.withdraw_requests
              ( request_id
              , block_hash
              , recipient
              , amount
              , max_fee
              , sender_address
              , created_at
              )
            VALUES ($1, $2, $3, $4, $5, $6, $7)",
            withdraw_request.request_id,
            &withdraw_request.block_hash,
            &withdraw_request.recipient,
            withdraw_request.amount,
            withdraw_request.max_fee,
            withdraw_request.sender_address,
            withdraw_request.created_at,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn write_deposit_signer_decision(
        &self,
        decision: &model::DepositSigner,
    ) -> Result<(), Self::Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.deposit_signers
              ( txid
              , output_index
              , signer_pub_key
              , is_accepted
              , created_at
              )
            VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&decision.txid)
        .bind(decision.output_index)
        .bind(decision.signer_pub_key)
        .bind(decision.is_accepted)
        .bind(decision.created_at)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdraw_signer_decision(
        &self,
        decision: &model::WithdrawSigner,
    ) -> Result<(), Self::Error> {
        sqlx::query(
            "INSERT INTO sbtc_signer.withdraw_signers
              ( request_id
              , block_hash
              , signer_pub_key
              , is_accepted
              , created_at
              )
            VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(decision.request_id)
        .bind(&decision.block_hash)
        .bind(decision.signer_pub_key)
        .bind(decision.is_accepted)
        .bind(decision.created_at)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_transaction(&self, transaction: &model::Transaction) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.transactions
              ( txid
              , tx
              , tx_type
              , created_at
              )
            VALUES ($1, $2, $3, CURRENT_TIMESTAMP)",
            transaction.txid,
            transaction.tx,
            transaction.tx_type as TransactionType,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_bitcoin_transaction(
        &self,
        bitcoin_transaction: &model::BitcoinTransaction,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.bitcoin_transactions (txid, block_hash) VALUES ($1, $2)",
            bitcoin_transaction.txid,
            bitcoin_transaction.block_hash,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_bitcoin_transactions(
        &self,
        txs: Vec<model::Transaction>,
    ) -> Result<(), Self::Error> {
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
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.stacks_transactions (txid, block_hash) VALUES ($1, $2)",
            stacks_transaction.txid,
            stacks_transaction.block_hash,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_stacks_transactions(
        &self,
        txs: Vec<model::Transaction>,
    ) -> Result<(), Self::Error> {
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
    ) -> Result<(), Self::Error> {
        if blocks.is_empty() {
            return Ok(());
        }

        let mut block_ids = Vec::with_capacity(blocks.len());
        let mut parent_block_ids = Vec::with_capacity(blocks.len());
        let mut chain_lengths = Vec::<i64>::with_capacity(blocks.len());

        for block in blocks {
            block_ids.push(block.block_hash);
            parent_block_ids.push(block.parent_hash);
            chain_lengths.push(block.block_height);
        }

        sqlx::query!(
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
            INSERT INTO sbtc_signer.stacks_blocks (block_hash, block_height, parent_hash, created_at)
            SELECT
                block_id
              , chain_length
              , parent_block_id
              , CURRENT_TIMESTAMP
            FROM block_ids 
            JOIN parent_block_ids USING (row_number)
            JOIN chain_lengths USING (row_number)
            ON CONFLICT DO NOTHING"#,
            &block_ids,
            &parent_block_ids,
            &chain_lengths,
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO sbtc_signer.dkg_shares (
                aggregate_key
              , tweaked_aggregate_key
              , encrypted_private_shares
              , public_shares
              , script_pubkey
              , created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(shares.aggregate_key)
        .bind(shares.tweaked_aggregate_key)
        .bind(&shares.encrypted_private_shares)
        .bind(&shares.public_shares)
        .bind(&shares.script_pubkey)
        .bind(shares.created_at)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_rotate_keys_transaction(
        &self,
        key_rotation: &model::RotateKeysTransaction,
    ) -> Result<(), Self::Error> {
        sqlx::query(
            r#"
            INSERT INTO sbtc_signer.rotate_keys_transactions (
                  txid
                , aggregate_key
                , signer_set
                , signatures_required)
            VALUES
                ($1, $2, $3, $4)
            "#,
        )
        .bind(&key_rotation.txid)
        .bind(key_rotation.aggregate_key)
        .bind(&key_rotation.signer_set)
        .bind(key_rotation.signatures_required as i32)
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

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
        let path = "tests/fixtures/tenure-blocks-0-1ed91e0720129bda5072540ee7283dd5345d0f6de0cf5b982c6de3943b6e3291.bin";
        let mut file = std::fs::File::open(path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let bytes: &mut &[u8] = &mut buf.as_ref();
        let mut blocks = Vec::new();

        while !bytes.is_empty() {
            blocks.push(NakamotoBlock::consensus_deserialize(bytes).unwrap());
        }

        let txs = extract_relevant_transactions(&blocks);
        assert!(txs.is_empty());

        let last_block = blocks.last_mut().unwrap();
        let mut tx = last_block.txs.last().unwrap().clone();

        let contract_call = TransactionContractCall {
            address: StacksAddress::new(2, Hash160([0u8; 20])),
            contract_name: ContractName::from(contract_name),
            function_name: ClarityName::from(function_name),
            function_args: Vec::new(),
        };
        tx.payload = TransactionPayload::ContractCall(contract_call);
        last_block.txs.push(tx);

        let txs = extract_relevant_transactions(&blocks);
        assert_eq!(txs.len(), 1);
    }
}
