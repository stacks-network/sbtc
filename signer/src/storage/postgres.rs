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
            "SELECT * FROM sbtc_signer.bitcoin_blocks WHERE block_hash = $1;",
            &block_hash
        )
        .fetch_optional(&self.0)
        .await
        .map_err(Error::SqlxQuery)
    }

    async fn get_bitcoin_canonical_chain_tip(
        &self,
    ) -> Result<Option<model::BitcoinBlockHash>, Self::Error> {
        todo!(); // TODO(244): Write query + integration test
    }

    async fn get_pending_deposit_requests(
        &self,
        _chain_tip: &model::BitcoinBlockHash,
        _context_window: usize,
    ) -> Result<Vec<model::DepositRequest>, Self::Error> {
        todo!(); // TODO(244): Write query + integration test
    }

    async fn get_deposit_signers(
        &self,
        _txid: &model::BitcoinTxId,
        _output_index: usize,
    ) -> Result<Vec<model::DepositSigner>, Self::Error> {
        todo!(); // TODO(244): Write query + integration test
    }

    async fn get_pending_withdraw_requests(
        &self,
        _chain_tip: &model::BitcoinBlockHash,
        _context_window: usize,
    ) -> Result<Vec<model::WithdrawRequest>, Self::Error> {
        todo!(); // TODO(246): Write query + integration test
    }

    async fn get_bitcoin_blocks_with_transaction(
        &self,
        _txid: &model::BitcoinTxId,
    ) -> Result<Vec<model::BitcoinBlockHash>, Self::Error> {
        todo!(); // TODO(244): write query + integration test
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
}

impl super::DbWrite for PgStore {
    type Error = Error;

    async fn write_bitcoin_block(&self, block: &model::BitcoinBlock) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.bitcoin_blocks VALUES ($1, $2, $3, $4, $5)",
            block.block_hash,
            block.block_height,
            block.parent_hash,
            block.confirms,
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
        .await
        .map_err(Error::SqlxQuery)?;

        Ok(())
    }

    async fn write_withdraw_request(
        &self,
        _withdraw_request: &model::WithdrawRequest,
    ) -> Result<(), Self::Error> {
        todo!(); // TODO(246): Write query + integration test
    }

    async fn write_deposit_signer_decision(
        &self,
        _decision: &model::DepositSigner,
    ) -> Result<(), Self::Error> {
        todo!(); // TODO(244): Write query + integration test
    }

    async fn write_withdraw_signer_decision(
        &self,
        _decision: &model::WithdrawSigner,
    ) -> Result<(), Self::Error> {
        todo!(); // TODO(246): Write query + integration test
    }

    async fn write_transaction(&self, transaction: &model::Transaction) -> Result<(), Self::Error> {
        sqlx::query!(
            "INSERT INTO sbtc_signer.transactions VALUES ($1, $2, $3, $4)",
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
            "INSERT INTO sbtc_signer.bitcoin_transactions VALUES ($1, $2)",
            bitcoin_transaction.txid,
            bitcoin_transaction.block_hash,
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
