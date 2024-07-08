//! Postgres storage implementation.

use std::collections::HashMap;
use std::sync::OnceLock;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksBlockId;
use blockstack_lib::util::hash::to_hex;

use crate::error::Error;
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
/// TODO(250): Update once we settle on all of the relevant function names.
const CONTRACT_FUNCTION_NAMES: [(&str, TransactionType); 1] = [(
    "initiate-withdrawal-request",
    TransactionType::WithdrawAccept,
)];

/// Returns the mapping between functions in a contract call and the
/// transaction type.
fn contract_transaction_kinds() -> &'static HashMap<&'static str, TransactionType> {
    static CONTRACT_FUNCTION_NAME_MAPPING: OnceLock<HashMap<&str, TransactionType>> =
        OnceLock::new();

    CONTRACT_FUNCTION_NAME_MAPPING.get_or_init(|| CONTRACT_FUNCTION_NAMES.into_iter().collect())
}

/// A type used for storing transactions in the stacks_transactions table
#[derive(Debug, serde::Serialize)]
struct StacksTx {
    /// The transaction id for the transaction
    txid: String,
    /// The block id for the nakamoto block that this transaction was
    /// included in.
    block_id: String,
    /// The raw transaction binary
    tx: String,
    /// The type of sBTC transaction on the stacks blockchain
    tx_type: TransactionType,
}

/// A type used for storing transactions in the stacks_transactions table
#[derive(Debug, serde::Serialize)]
struct StacksBlockSummary {
    /// The block id for the nakamoto block that this transaction was
    /// included in.
    block_id: String,
    /// The height of the block
    chain_length: i64,
    /// The block id of the block immediately prior to this one in the
    /// blockchain.
    parent_block_id: String,
}

/// This function extracts the signer relevant sBTC related transactions
/// from the given blocks.
fn extract_relevant_transactions(blocks: &[NakamotoBlock]) -> Vec<StacksTx> {
    let transaction_kinds = contract_transaction_kinds();
    blocks
        .iter()
        .flat_map(|block| block.txs.iter().map(|tx| (tx, block.block_id())))
        .filter_map(|(tx, block_id)| match &tx.payload {
            TransactionPayload::ContractCall(x)
                if CONTRACT_NAMES.contains(&x.contract_name.as_str()) =>
            {
                Some(StacksTx {
                    tx_type: *transaction_kinds.get(&x.function_name.as_str())?,
                    txid: tx.txid().to_hex(),
                    block_id: block_id.to_hex(),
                    tx: to_hex(&tx.serialize_to_vec()),
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

impl PgStore {
    /// Connect to the Postgres database at `url`.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        Ok(Self(sqlx::PgPool::connect(url).await?))
    }

    /// Write parts of the Stacks Nakamoto block headers to the database.
    async fn write_stacks_block_header(&self, blocks: &[NakamotoBlock]) -> Result<(), Error> {
        let block_summaries: Vec<StacksBlockSummary> = blocks
            .iter()
            .map(|block| StacksBlockSummary {
                block_id: block.block_id().to_hex(),
                chain_length: block.header.chain_length as i64,
                parent_block_id: block.header.parent_block_id.to_hex(),
            })
            .collect();

        if block_summaries.is_empty() {
            return Ok(());
        }

        sqlx::query!(
            r#"
            INSERT INTO sbtc_signer.stacks_blocks (block_hash, block_height, parent_hash, created_at)
            SELECT
                decode(block_id, 'hex')
              , chain_length
              , decode(parent_block_id, 'hex')
              , CURRENT_TIMESTAMP
            FROM JSONB_TO_RECORDSET($1::JSONB) AS x(
                block_id        CHAR(64)
              , chain_length    BIGINT
              , parent_block_id CHAR(64)
            )
            ON CONFLICT DO NOTHING"#,
            serde_json::to_value(&block_summaries).map_err(Error::JsonSerialize)?
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    /// Write sBTC related transactions in the given blocks to the
    /// database.
    async fn write_stacks_sbtc_txs(&self, blocks: &[NakamotoBlock]) -> Result<(), Error> {
        let block_txs: Vec<StacksTx> = extract_relevant_transactions(blocks);

        if block_txs.is_empty() {
            return Ok(());
        }

        let block_txs_json = serde_json::to_value(&block_txs).map_err(Error::JsonSerialize)?;
        sqlx::query!(
            r#"
            INSERT INTO sbtc_signer.transactions (txid, tx, tx_type, created_at)
            SELECT
                decode(txid, 'hex')
              , decode(tx, 'hex')
              , tx_type::sbtc_signer.transaction_type
              , CURRENT_TIMESTAMP
            FROM JSONB_TO_RECORDSET($1::JSONB) AS x(
                txid      CHAR(64)
              , tx        VARCHAR
              , tx_type   VARCHAR
            )
            ON CONFLICT DO NOTHING"#,
            &block_txs_json
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        sqlx::query!(
            r#"
            INSERT INTO sbtc_signer.stacks_transactions (txid, block_hash)
            SELECT
                decode(txid, 'hex')
              , decode(block_id, 'hex')
            FROM JSONB_TO_RECORDSET($1::JSONB) AS x(
                txid        CHAR(64)
              , block_id    CHAR(64)
            )
            ON CONFLICT DO NOTHING"#,
            &block_txs_json
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
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

    async fn get_accepted_deposit_requests(
        &self,
        signer: &model::PubKey,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
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
            signer,
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
        sqlx::query_as!(
            model::DepositSigner,
            "SELECT
                txid
              , output_index
              , signer_pub_key
              , is_accepted
              , created_at
            FROM sbtc_signer.deposit_signers 
            WHERE txid = $1 AND output_index = $2",
            txid,
            output_index,
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_withdraw_signers(
        &self,
        request_id: i32,
        block_hash: &model::StacksBlockHash,
    ) -> Result<Vec<model::WithdrawSigner>, Self::Error> {
        sqlx::query_as!(
            model::WithdrawSigner,
            "SELECT
                request_id
              , block_hash
              , signer_pub_key
              , is_accepted
              , created_at
            FROM sbtc_signer.withdraw_signers
            WHERE request_id = $1 AND block_hash = $2",
            request_id,
            block_hash,
        )
        .fetch_all(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_pending_withdraw_requests(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        context_window: i32,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        let stacks_chain_tip = self.get_stacks_chain_tip(chain_tip).await?;
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
        aggregate_key: &model::PubKey,
    ) -> Result<Option<model::EncryptedDkgShares>, Self::Error> {
        sqlx::query_as!(
            model::EncryptedDkgShares,
            r#"
            SELECT
                aggregate_key
              , tweaked_aggregate_key
              , encrypted_shares
              , created_at
            FROM sbtc_signer.dkg_shares
            WHERE aggregate_key = $1;
            "#,
            aggregate_key,
        )
        .fetch_optional(&self.0)
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
        sqlx::query!(
            "INSERT INTO sbtc_signer.deposit_signers
              ( txid
              , output_index
              , signer_pub_key
              , is_accepted
              , created_at
              )
            VALUES ($1, $2, $3, $4, $5)",
            decision.txid,
            decision.output_index,
            decision.signer_pub_key,
            decision.is_accepted,
            decision.created_at
        )
        .execute(&self.0)
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdraw_signer_decision(
        &self,
        decision: &model::WithdrawSigner,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.withdraw_signers
              ( request_id
              , block_hash
              , signer_pub_key
              , is_accepted
              , created_at
              )
            VALUES ($1, $2, $3, $4, $5)",
            decision.request_id,
            decision.block_hash,
            decision.signer_pub_key,
            decision.is_accepted,
            decision.created_at
        )
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
            VALUES ($1, $2, $3, $4)",
            transaction.txid,
            transaction.tx,
            transaction.tx_type as TransactionType,
            transaction.created_at,
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

    async fn write_stacks_blocks(&self, blocks: &[NakamotoBlock]) -> Result<(), Self::Error> {
        self.write_stacks_block_header(blocks).await?;
        self.write_stacks_sbtc_txs(blocks).await
    }

    async fn write_encrypted_dkg_shares(
        &self,
        shares: &model::EncryptedDkgShares,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            INSERT INTO sbtc_signer.dkg_shares
                (aggregate_key, tweaked_aggregate_key, encrypted_shares, created_at)
            VALUES
                ($1, $2, $3, $4)
            "#,
            shares.aggregate_key,
            shares.tweaked_aggregate_key,
            shares.encrypted_shares,
            shares.created_at,
        )
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
