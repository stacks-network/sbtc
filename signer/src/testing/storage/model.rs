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
#[derive(Debug, Clone, Default)]
pub struct TestData {
    /// Bitcoin blocks
    pub bitcoin_blocks: Vec<model::BitcoinBlock>,

    /// Stacks blocks
    pub stacks_blocks: Vec<model::StacksBlock>,

    /// Deposit requests
    pub deposit_requests: Vec<model::DepositRequest>,

    /// Deposit requests
    pub withdraw_requests: Vec<model::WithdrawRequest>,

    /// Raw transaction data
    pub transactions: Vec<model::Transaction>,

    /// Connection between bitcoin blocks and transactions
    pub bitcoin_transactions: Vec<model::BitcoinTransaction>,

    /// Connection between bitcoin blocks and transactions
    pub stacks_transactions: Vec<model::StacksTransaction>,
}

impl TestData {
    fn new() -> Self {
        Self::default()
    }
    /// Generate random test data with the given parameters.
    pub fn generate(rng: &mut impl rand::RngCore, params: &Params) -> Self {
        let mut test_data = Self::new();

        for _ in 0..params.num_bitcoin_blocks {
            let next_chunk = test_data.new_block(rng, params);
            test_data.push(next_chunk);
        }

        test_data
    }

    /// Generate a new bitcoin block with associated data on top of
    /// the current model.
    pub fn new_block(&self, rng: &mut impl rand::RngCore, params: &Params) -> Self {
        let mut block = self.generate_bitcoin_block(rng);

        let stacks_blocks =
            self.generate_stacks_blocks(rng, &block, params.num_stacks_blocks_per_bitcoin_block);

        block
            .confirms
            .push(stacks_blocks.last().unwrap().block_hash.clone());

        let deposit_data =
            DepositData::generate(rng, &block, params.num_deposit_requests_per_block);

        let withdraw_data = WithdrawData::generate(
            rng,
            &stacks_blocks,
            &self.withdraw_requests,
            params.num_withdraw_requests_per_block,
        );

        let transactions = deposit_data
            .transactions
            .into_iter()
            .chain(withdraw_data.transactions)
            .collect();

        let bitcoin_blocks = vec![block.clone()];

        Self {
            bitcoin_blocks,
            stacks_blocks,
            deposit_requests: deposit_data.deposit_requests,
            withdraw_requests: withdraw_data.withdraw_requests,
            bitcoin_transactions: deposit_data.bitcoin_transactions,
            stacks_transactions: withdraw_data.stacks_transactions,
            transactions,
        }
    }

    /// Add newly generated data to the current model.
    pub fn push(&mut self, new_data: Self) {
        self.bitcoin_blocks.extend(new_data.bitcoin_blocks);
        self.stacks_blocks.extend(new_data.stacks_blocks);
        self.deposit_requests.extend(new_data.deposit_requests);
        self.withdraw_requests.extend(new_data.withdraw_requests);
        self.bitcoin_transactions
            .extend(new_data.bitcoin_transactions);
        self.stacks_transactions
            .extend(new_data.stacks_transactions);
        self.transactions.extend(new_data.transactions);
    }

    /// Write the test data to the given store.
    pub async fn write_to<Db>(&self, storage: &mut Db)
    where
        Db: DbWrite,
    {
        for block in self.bitcoin_blocks.iter() {
            storage
                .write_bitcoin_block(block)
                .await
                .expect("failed to write bitcoin block");
        }

        for block in self.stacks_blocks.iter() {
            storage
                .write_stacks_block(block)
                .await
                .expect("failed to write bitcoin block");
        }

        for tx in self.transactions.iter() {
            storage
                .write_transaction(tx)
                .await
                .expect("failed to write transaction");
        }

        for req in self.deposit_requests.iter() {
            storage
                .write_deposit_request(req)
                .await
                .expect("failed to write deposit request");
        }

        for req in self.withdraw_requests.iter() {
            storage
                .write_withdraw_request(req)
                .await
                .expect("failed to write withdraw request");
        }

        for bitcoin_tx in self.bitcoin_transactions.iter() {
            storage
                .write_bitcoin_transaction(bitcoin_tx)
                .await
                .expect("failed to write bitcoin transaction");
        }

        for stacks_tx in self.stacks_transactions.iter() {
            storage
                .write_stacks_transaction(stacks_tx)
                .await
                .expect("failed to write stacks transaction");
        }
    }

    fn generate_bitcoin_block(&self, rng: &mut impl rand::RngCore) -> model::BitcoinBlock {
        let mut block: model::BitcoinBlock = fake::Faker.fake_with_rng(rng);
        let parent_block_summary = self
            .bitcoin_blocks
            .choose(rng)
            .map(BlockSummary::summarize)
            .unwrap_or_else(|| BlockSummary::hallucinate_parent(&block));

        block.parent_hash = parent_block_summary.block_hash;
        block.block_height = parent_block_summary.block_height + 1;

        block
    }

    fn generate_stacks_blocks(
        &self,
        rng: &mut impl rand::RngCore,
        new_bitcoin_block: &model::BitcoinBlock,
        num_stacks_blocks: usize,
    ) -> Vec<model::StacksBlock> {
        let mut stacks_block: model::StacksBlock = fake::Faker.fake_with_rng(rng);

        let stacks_parent_block_summary = self
            .bitcoin_blocks
            .iter()
            .find(|b| b.block_hash == new_bitcoin_block.parent_hash)
            .and_then(|b| b.confirms.choose(rng))
            .and_then(|block_hash| {
                self.stacks_blocks
                    .iter()
                    .find(|b| &b.block_hash == block_hash)
            })
            .map(StacksBlockSummary::summarize)
            .unwrap_or_else(|| StacksBlockSummary::hallucinate_parent(&stacks_block));

        stacks_block.parent_hash = stacks_parent_block_summary.block_hash;
        stacks_block.block_height = stacks_parent_block_summary.block_height + 1;

        let stacks_blocks = (1..num_stacks_blocks).fold(vec![stacks_block], |mut blocks, _| {
            let parent = blocks.last().unwrap(); // Guaranteed to be at least one block

            let mut stacks_block: model::StacksBlock = fake::Faker.fake_with_rng(rng);
            stacks_block.parent_hash = parent.block_hash.clone();
            stacks_block.block_height = parent.block_height + 1;

            blocks.push(stacks_block);

            blocks
        });

        stacks_blocks
    }
}

#[derive(Debug, Clone, Default)]
struct DepositData {
    pub deposit_requests: Vec<model::DepositRequest>,
    pub transactions: Vec<model::Transaction>,
    pub bitcoin_transactions: Vec<model::BitcoinTransaction>,
}

impl DepositData {
    fn new() -> Self {
        Self::default()
    }

    fn generate(
        rng: &mut impl rand::RngCore,
        bitcoin_block: &model::BitcoinBlock,
        num_deposit_requests: usize,
    ) -> Self {
        (0..num_deposit_requests).fold(Self::new(), |mut deposit_data, _| {
            let deposit_request: model::DepositRequest = fake::Faker.fake_with_rng(rng);

            let mut raw_transaction: model::Transaction = fake::Faker.fake_with_rng(rng);
            raw_transaction.txid = deposit_request.txid.clone();
            raw_transaction.tx_type = model::TransactionType::DepositRequest;

            let bitcoin_transaction = model::BitcoinTransaction {
                txid: raw_transaction.txid.clone(),
                block_hash: bitcoin_block.block_hash.clone(),
            };

            deposit_data.bitcoin_transactions.push(bitcoin_transaction);
            deposit_data.deposit_requests.push(deposit_request);
            deposit_data.transactions.push(raw_transaction);

            deposit_data
        })
    }
}

#[derive(Debug, Clone, Default)]
struct WithdrawData {
    pub withdraw_requests: Vec<model::WithdrawRequest>,
    pub transactions: Vec<model::Transaction>,
    pub stacks_transactions: Vec<model::StacksTransaction>,
}

impl WithdrawData {
    fn new() -> Self {
        Self::default()
    }

    fn generate(
        rng: &mut impl rand::RngCore,
        stacks_blocks: &[model::StacksBlock],
        withdraw_requests: &[model::WithdrawRequest],
        num_withdraw_requests: usize,
    ) -> Self {
        let next_withdraw_request_id = withdraw_requests
            .iter()
            .map(|req| req.request_id)
            .max()
            .unwrap_or(0)
            + 1;

        (0..num_withdraw_requests)
            .fold(
                (Self::new(), next_withdraw_request_id),
                |(mut withdraw_requests, next_withdraw_request_id), _| {
                    let stacks_block_hash = stacks_blocks.choose(rng).unwrap().block_hash.clone(); // Guaranteed to be non-empty

                    let mut withdraw_request: model::WithdrawRequest =
                        fake::Faker.fake_with_rng(rng);

                    withdraw_request.block_hash = stacks_block_hash.clone();
                    withdraw_request.request_id = next_withdraw_request_id;

                    let mut raw_transaction: model::Transaction = fake::Faker.fake_with_rng(rng);
                    raw_transaction.tx_type = model::TransactionType::WithdrawRequest;

                    let stacks_transaction = model::StacksTransaction {
                        txid: raw_transaction.txid.clone(),
                        block_hash: stacks_block_hash,
                    };

                    withdraw_requests
                        .stacks_transactions
                        .push(stacks_transaction);
                    withdraw_requests.withdraw_requests.push(withdraw_request);
                    withdraw_requests.transactions.push(raw_transaction);

                    (withdraw_requests, next_withdraw_request_id + 1)
                },
            )
            .0
    }
}

/// Parameters for test data generation.
#[derive(Debug, Clone)]
pub struct Params {
    /// The number of bitcoin blocks to generate.
    pub num_bitcoin_blocks: usize,
    /// The number of stacks blocks to generate per bitcoin block.
    pub num_stacks_blocks_per_bitcoin_block: usize,
    /// The number of deposit requests to generate per bitcoin block,
    pub num_deposit_requests_per_block: usize,
    /// The number of withdraw requests to generate per bitcoin block,
    pub num_withdraw_requests_per_block: usize,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StacksBlockSummary {
    block_hash: model::StacksBlockHash,
    block_height: i64,
}

impl StacksBlockSummary {
    fn summarize(block: &model::StacksBlock) -> Self {
        Self {
            block_hash: block.block_hash.clone(),
            block_height: block.block_height,
        }
    }

    fn hallucinate_parent(block: &model::StacksBlock) -> Self {
        Self {
            block_hash: block.parent_hash.clone(),
            block_height: 1337, // Arbitrary number
        }
    }
}
