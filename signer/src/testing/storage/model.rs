//! Test data generation utilities

use fake::Fake;

use crate::storage::model;
use crate::storage::DbWrite;

use rand::seq::SliceRandom;

/// Collection of related data usable for database tests.
///
/// Right now this is only a chain of bitcoin blocks,
/// but this struct is intended to grow to encompass
/// items of all of the types in the storage model.
#[derive(Debug, Clone)]
pub struct TestData {
    /// Bitcoin blocks
    pub bitcoin_blocks: Vec<model::BitcoinBlock>,

    /// Deposit requests
    pub deposit_requests: Vec<model::DepositRequest>,

    /// Raw transaction data
    pub transactions: Vec<model::Transaction>,

    /// Connection between bitcoin blocks and transactions
    pub bitcoin_transactions: Vec<model::BitcoinTransaction>,
}

impl TestData {
    /// Generate random test data with the given parameters.
    pub fn generate(rng: &mut impl rand::RngCore, params: &Params) -> Self {
        let bitcoin_block_generator: BlockGenerator = match params.chain_type {
            ChainType::Idealistic => Box::new(idealistic_bitcoin_chain(rng)),
            ChainType::Realistic => Box::new(realistic_bitcoin_chain(rng)),
            ChainType::Chaotic => Box::new(chaotic_bitcoin_chain(rng)),
        };

        let bitcoin_blocks: Vec<_> = (0..params.num_bitcoin_blocks)
            .scan(Vec::new(), bitcoin_block_generator)
            .collect();

        let deposit_requests: Vec<_> = (0..params.num_deposit_requests)
            .map(|_| fake::Faker.fake_with_rng(rng))
            .collect();

        let transactions = hallucinate_raw_transactions(rng, &deposit_requests);

        let bitcoin_transactions =
            idealistic_assign_deposit_requests(rng, &deposit_requests, &bitcoin_blocks);

        Self {
            bitcoin_blocks,
            deposit_requests,
            bitcoin_transactions,
            transactions,
        }
    }

    /// Write the test data to the given store
    pub async fn write_to<Db>(&self, storage: &mut Db)
    where
        Db: DbWrite,
    {
        for block in self.bitcoin_blocks.iter() {
            storage
                .write_bitcoin_block(block)
                .await
                .expect("Failed to write bitcoin block");
        }

        for tx in self.transactions.iter() {
            storage
                .write_transaction(tx)
                .await
                .expect("Failed to write transaction");
        }

        for req in self.deposit_requests.iter() {
            storage
                .write_deposit_request(req)
                .await
                .expect("Failed to write deposit request");
        }

        for bitcoin_tx in self.bitcoin_transactions.iter() {
            storage
                .write_bitcoin_transaction(bitcoin_tx)
                .await
                .expect("Failed to write bitcoin transaction");
        }
    }
}

/// Parameters for test data generation.
#[derive(Debug, Clone)]
pub struct Params {
    /// The number of bitcoin blocks to generate.
    pub num_bitcoin_blocks: usize,
    /// The type of characteristics for the generated blockchain.
    pub chain_type: ChainType,
    /// The number of deposit requests,
    pub num_deposit_requests: usize,
}

/// Enum repredenting different strategies for how to connect blocks.
#[derive(Debug, Clone)]
pub enum ChainType {
    /// A single chain without any forks.
    Idealistic,
    /// A chain with some forking but no orphans.
    Realistic,
    /// A chain with plenty of forks and orphans.
    Chaotic,
}

type BlockGenerator<'a> =
    Box<dyn FnMut(&mut Vec<BlockSummary>, usize) -> Option<model::BitcoinBlock> + 'a>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BlockSummary {
    block_hash: model::BitcoinBlockHash,
    block_height: i64,
}

impl BlockSummary {
    fn summarize(block: &model::BitcoinBlock) -> Self {
        Self {
            block_hash: block.block_hash.clone(),
            block_height: block.block_height,
        }
    }

    fn hallucinate_parent(block: &model::BitcoinBlock) -> Self {
        Self {
            block_hash: block.parent_hash.clone(),
            block_height: 1337, // Arbitrary number
        }
    }
}

fn idealistic_bitcoin_chain(
    rng: &mut impl rand::RngCore,
) -> impl FnMut(&mut Vec<BlockSummary>, usize) -> Option<model::BitcoinBlock> + '_ {
    |block_summaries, _| {
        let mut block: model::BitcoinBlock = fake::Faker.fake_with_rng(rng);
        let parent_block_summary = block_summaries
            .last()
            .cloned()
            .unwrap_or_else(|| BlockSummary::hallucinate_parent(&block));

        block.parent_hash = parent_block_summary.block_hash;
        block.block_height = parent_block_summary.block_height + 1;

        block_summaries.push(BlockSummary::summarize(&block));
        Some(block)
    }
}

fn realistic_bitcoin_chain(
    rng: &mut impl rand::RngCore,
) -> impl FnMut(&mut Vec<BlockSummary>, usize) -> Option<model::BitcoinBlock> + '_ {
    |block_summaries, _| {
        let mut block: model::BitcoinBlock = fake::Faker.fake_with_rng(rng);
        let parent_block_summary = block_summaries
            .choose(rng)
            .cloned()
            .unwrap_or_else(|| BlockSummary::hallucinate_parent(&block));

        block.parent_hash = parent_block_summary.block_hash;
        block.block_height = parent_block_summary.block_height + 1;

        block_summaries.push(BlockSummary::summarize(&block));
        Some(block)
    }
}

fn chaotic_bitcoin_chain(
    rng: &mut impl rand::RngCore,
) -> impl FnMut(&mut Vec<BlockSummary>, usize) -> Option<model::BitcoinBlock> + '_ {
    |block_summaries, _| {
        let mut block: model::BitcoinBlock = fake::Faker.fake_with_rng(rng);
        block_summaries.push(BlockSummary::hallucinate_parent(&block));
        let parent_block_summary = block_summaries.choose(rng).unwrap().clone();

        block.parent_hash = parent_block_summary.block_hash;
        block.block_height = parent_block_summary.block_height + 1;

        block_summaries.push(BlockSummary::summarize(&block));
        Some(block)
    }
}

/// Creates random transactions associated with the given requests
fn hallucinate_raw_transactions(
    rng: &mut impl rand::RngCore,
    deposit_requests: &[model::DepositRequest],
) -> Vec<model::Transaction> {
    deposit_requests
        .iter()
        .map(|req| {
            let mut tx: model::Transaction = fake::Faker.fake_with_rng(rng);
            tx.txid = req.txid.clone();
            tx.tx_type = model::TransactionType::DepositRequest;
            tx
        })
        .collect()
}

/// Assigns every deposit request exactly once to a random
/// bitcoin block.
fn idealistic_assign_deposit_requests(
    rng: &mut impl rand::RngCore,
    deposit_requests: &[model::DepositRequest],
    bitcoin_blocks: &[model::BitcoinBlock],
) -> Vec<model::BitcoinTransaction> {
    deposit_requests
        .iter()
        .filter_map(|req| {
            let txid = req.txid.clone();
            let block_hash = bitcoin_blocks
                .choose(rng)
                .map(|block| block.block_hash.clone())?;

            Some(model::BitcoinTransaction { txid, block_hash })
        })
        .collect()
}
