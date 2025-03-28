//! Test data generation utilities

use std::collections::HashSet;

use bitcoin::consensus::Encodable as _;
use bitcoin::hashes::Hash as _;
use fake::Fake;

use crate::keys::PublicKey;
use crate::storage::DbWrite;
use crate::storage::model;
use crate::storage::model::BitcoinBlock;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinBlockRef;
use crate::testing::dummy::DepositTxConfig;

use rand::seq::SliceRandom;

/// Collection of related data usable for database tests.
///
/// The primary use case of this type is to load a database
/// with mocked data.
#[derive(Debug, Clone, Default)]
pub struct TestData {
    /// Bitcoin blocks
    pub bitcoin_blocks: Vec<model::BitcoinBlock>,

    /// Stacks blocks
    pub stacks_blocks: Vec<model::StacksBlock>,

    /// Deposit requests
    pub deposit_requests: Vec<model::DepositRequest>,

    /// Deposit requests
    pub withdraw_requests: Vec<model::WithdrawalRequest>,

    /// Raw transaction data
    pub transactions: Vec<model::Transaction>,

    /// Connection between bitcoin blocks and transactions
    pub bitcoin_transactions: Vec<model::BitcoinTxRef>,

    /// Connection between bitcoin blocks and transactions
    pub stacks_transactions: Vec<model::StacksTransaction>,

    /// Deposit signers
    pub deposit_signers: Vec<model::DepositSigner>,

    /// Withdraw signers
    pub withdraw_signers: Vec<model::WithdrawalSigner>,

    /// transaction outputs
    pub tx_outputs: Vec<model::TxOutput>,
}

impl TestData {
    fn new() -> Self {
        Self::default()
    }

    /// Generate random test data with the given parameters.
    pub fn generate<R>(rng: &mut R, signer_keys: &[PublicKey], params: &Params) -> Self
    where
        R: rand::RngCore,
    {
        let mut test_data = Self::new();
        let mut parent: Option<BitcoinBlockRef> = None;
        for _ in 0..params.num_bitcoin_blocks {
            let (next_chunk, block_ref) =
                test_data.new_block(rng, signer_keys, params, parent.as_ref());
            test_data.push(next_chunk);
            if params.consecutive_blocks {
                parent = Some(block_ref);
            }
        }

        test_data
    }

    /// Generate a new bitcoin block with associated data on top of
    /// the current model.
    pub fn new_block<R>(
        &self,
        rng: &mut R,
        signer_keys: &[PublicKey],
        params: &Params,
        parent: Option<&BitcoinBlockRef>,
    ) -> (Self, BitcoinBlockRef)
    where
        R: rand::RngCore,
    {
        let block = self.generate_bitcoin_block(rng, parent);

        let stacks_blocks =
            self.generate_stacks_blocks(rng, &block, params.num_stacks_blocks_per_bitcoin_block);

        let deposit_data = DepositData::generate(
            rng,
            signer_keys,
            &block,
            params.num_deposit_requests_per_block,
            params.num_signers_per_request,
        );

        let withdraw_data = WithdrawData::generate(
            rng,
            signer_keys,
            &block,
            &stacks_blocks,
            &self.withdraw_requests,
            params.num_withdraw_requests_per_block,
            params.num_signers_per_request,
        );

        let transactions = deposit_data
            .transactions
            .into_iter()
            .chain(withdraw_data.transactions)
            .collect();

        let bitcoin_blocks = vec![block.clone()];
        (
            Self {
                bitcoin_blocks,
                stacks_blocks,
                deposit_requests: deposit_data.deposit_requests,
                deposit_signers: deposit_data.deposit_signers,
                withdraw_requests: withdraw_data.withdraw_requests,
                withdraw_signers: withdraw_data.withdraw_signers,
                bitcoin_transactions: deposit_data.bitcoin_transactions,
                stacks_transactions: withdraw_data.stacks_transactions,
                transactions,
                tx_outputs: Vec::new(),
            },
            block.into(),
        )
    }

    /// Add newly generated data to the current model.
    pub fn push(&mut self, new_data: Self) {
        self.bitcoin_blocks.extend(new_data.bitcoin_blocks);
        self.stacks_blocks.extend(new_data.stacks_blocks);
        self.deposit_requests.extend(new_data.deposit_requests);
        self.deposit_signers.extend(new_data.deposit_signers);
        self.withdraw_requests.extend(new_data.withdraw_requests);
        self.withdraw_signers.extend(new_data.withdraw_signers);
        self.bitcoin_transactions
            .extend(new_data.bitcoin_transactions);
        self.stacks_transactions
            .extend(new_data.stacks_transactions);
        self.transactions.extend(new_data.transactions);
        self.tx_outputs.extend(new_data.tx_outputs);
    }

    /// Remove data in `other` present in the current model.
    pub fn remove(&mut self, other: Self) {
        vec_diff(&mut self.bitcoin_blocks, &other.bitcoin_blocks);
        vec_diff(&mut self.stacks_blocks, &other.stacks_blocks);
        vec_diff(&mut self.deposit_requests, &other.deposit_requests);
        vec_diff(&mut self.deposit_signers, &other.deposit_signers);
        vec_diff(&mut self.withdraw_requests, &other.withdraw_requests);
        vec_diff(&mut self.withdraw_signers, &other.withdraw_signers);
        vec_diff(&mut self.bitcoin_transactions, &other.bitcoin_transactions);
        vec_diff(&mut self.stacks_transactions, &other.stacks_transactions);
        vec_diff(&mut self.transactions, &other.transactions);
        vec_diff(&mut self.tx_outputs, &other.tx_outputs);
    }

    /// Push bitcoin txs to a specific bitcoin block
    pub fn push_bitcoin_txs(
        &mut self,
        block: &BitcoinBlockRef,
        sbtc_txs: Vec<(model::TransactionType, bitcoin::Transaction)>,
    ) {
        let mut bitcoin_transactions = vec![];
        let mut transactions = vec![];
        let mut tx_outputs = Vec::new();

        for (tx_type, tx) in sbtc_txs {
            let mut tx_bytes = Vec::new();
            tx.consensus_encode(&mut tx_bytes).unwrap();

            let model_tx = model::Transaction {
                txid: tx.compute_txid().to_byte_array(),
                tx: tx_bytes,
                tx_type,
                block_hash: block.block_hash.into_bytes(),
            };

            let bitcoin_transaction = model::BitcoinTxRef {
                txid: model_tx.txid.into(),
                block_hash: block.block_hash,
            };

            transactions.push(model_tx);
            bitcoin_transactions.push(bitcoin_transaction);

            let output_type = match tx_type {
                model::TransactionType::SbtcTransaction => model::TxOutputType::SignersOutput,
                model::TransactionType::Donation => model::TxOutputType::Donation,
                _ => continue,
            };
            if let Some(tx_out) = tx.output.first() {
                // In our tests we always happen to put the first output as
                // the signers UTXO, even if it is a donation.
                let tx_output = model::TxOutput {
                    txid: tx.compute_txid().into(),
                    output_index: 0,
                    script_pubkey: tx_out.script_pubkey.clone().into(),
                    amount: tx_out.value.to_sat(),
                    output_type,
                };
                tx_outputs.push(tx_output);
            }
        }

        self.push(Self {
            bitcoin_transactions,
            transactions,
            tx_outputs,
            ..Self::default()
        });
    }

    /// Write the test data to the given store.
    pub async fn write_to<Db>(&self, storage: &Db)
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
                .write_withdrawal_request(req)
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

        for decision in self.deposit_signers.iter() {
            storage
                .write_deposit_signer_decision(decision)
                .await
                .expect("failed to write signer decision");
        }

        for decision in self.withdraw_signers.iter() {
            storage
                .write_withdrawal_signer_decision(decision)
                .await
                .expect("failed to write signer decision");
        }

        for tx_output in self.tx_outputs.iter() {
            storage.write_tx_output(tx_output).await.unwrap();
        }
    }

    fn generate_bitcoin_block(
        &self,
        rng: &mut impl rand::RngCore,
        parent: Option<&BitcoinBlockRef>,
    ) -> model::BitcoinBlock {
        let mut block: model::BitcoinBlock = fake::Faker.fake_with_rng(rng);
        let parent_block_summary = match parent {
            Some(block) => block,
            None => &self
                .bitcoin_blocks
                .choose(rng)
                .map(BitcoinBlockRef::summarize)
                .unwrap_or_else(|| BitcoinBlockRef::hallucinate_parent(&block)),
        };

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
        stacks_block.bitcoin_anchor = new_bitcoin_block.parent_hash;

        let stacks_parent_block_summary = self
            .bitcoin_blocks
            .iter()
            .find(|b| b.block_hash == new_bitcoin_block.parent_hash)
            .and_then(|b| {
                let cands = self
                    .stacks_blocks
                    .iter()
                    .filter(|stacks_block| stacks_block.bitcoin_anchor == b.parent_hash)
                    .collect::<Vec<_>>();
                cands.choose(rng).cloned()
            })
            .map(StacksBlockSummary::summarize)
            .unwrap_or_else(|| StacksBlockSummary::hallucinate_parent(&stacks_block));

        stacks_block.parent_hash = stacks_parent_block_summary.block_hash;
        stacks_block.block_height = stacks_parent_block_summary.block_height + 1;

        let stacks_blocks = (1..num_stacks_blocks).fold(vec![stacks_block], |mut blocks, _| {
            let parent = blocks.last().unwrap(); // Guaranteed to be at least one block

            let mut stacks_block: model::StacksBlock = fake::Faker.fake_with_rng(rng);
            stacks_block.parent_hash = parent.block_hash;
            stacks_block.block_height = parent.block_height + 1;
            stacks_block.bitcoin_anchor = parent.bitcoin_anchor;

            blocks.push(stacks_block);

            blocks
        });

        stacks_blocks
    }

    /// Fetch the parent block given the hash.
    pub fn get_bitcoin_block(&self, block_hash: &BitcoinBlockHash) -> Option<BitcoinBlock> {
        self.bitcoin_blocks
            .iter()
            .find(|x| &x.block_hash == block_hash)
            .cloned()
    }
}

#[derive(Debug, Clone, Default)]
struct DepositData {
    pub deposit_requests: Vec<model::DepositRequest>,
    pub deposit_signers: Vec<model::DepositSigner>,
    pub transactions: Vec<model::Transaction>,
    pub bitcoin_transactions: Vec<model::BitcoinTxRef>,
}

impl DepositData {
    fn new() -> Self {
        Self::default()
    }

    fn generate(
        rng: &mut impl rand::RngCore,
        signer_keys: &[PublicKey],
        bitcoin_block: &model::BitcoinBlock,
        num_deposit_requests: usize,
        num_signers_per_request: usize,
    ) -> Self {
        (0..num_deposit_requests).fold(Self::new(), |mut deposit_data, _| {
            let mut deposit_request: model::DepositRequest = fake::Faker.fake_with_rng(rng);

            let deposit_config = DepositTxConfig {
                aggregate_key: PublicKey::combine_keys(signer_keys)
                    .unwrap_or_else(|_| fake::Faker.fake_with_rng(rng)),
                ..fake::Faker.fake_with_rng(rng)
            };

            let mut raw_transaction: model::Transaction = deposit_config.fake_with_rng(rng);
            raw_transaction.block_hash = *bitcoin_block.block_hash.as_ref();
            deposit_request.txid = raw_transaction.txid.into();
            deposit_request.signers_public_key = deposit_config.aggregate_key.into();

            let deposit_signers: Vec<_> = signer_keys
                .iter()
                .take(num_signers_per_request)
                .copied()
                .map(|signer_pub_key| model::DepositSigner {
                    txid: deposit_request.txid,
                    output_index: deposit_request.output_index,
                    signer_pub_key,
                    can_accept: fake::Faker.fake_with_rng(rng),
                    can_sign: true,
                })
                .collect();

            let bitcoin_transaction = model::BitcoinTxRef {
                txid: raw_transaction.txid.into(),
                block_hash: bitcoin_block.block_hash,
            };

            deposit_data.bitcoin_transactions.push(bitcoin_transaction);
            deposit_data.deposit_requests.push(deposit_request);
            deposit_data.transactions.push(raw_transaction);
            deposit_data.deposit_signers.extend(deposit_signers);

            deposit_data
        })
    }
}

#[derive(Debug, Clone, Default)]
struct WithdrawData {
    pub withdraw_requests: Vec<model::WithdrawalRequest>,
    pub withdraw_signers: Vec<model::WithdrawalSigner>,
    pub transactions: Vec<model::Transaction>,
    pub stacks_transactions: Vec<model::StacksTransaction>,
}

impl WithdrawData {
    fn new() -> Self {
        Self::default()
    }

    fn generate(
        rng: &mut impl rand::RngCore,
        signer_keys: &[PublicKey],
        bitcoin_block: &model::BitcoinBlock,
        stacks_blocks: &[model::StacksBlock],
        withdraw_requests: &[model::WithdrawalRequest],
        num_withdraw_requests: usize,
        num_signers_per_request: usize,
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
                    let stacks_block_hash = stacks_blocks.choose(rng).unwrap().block_hash; // Guaranteed to be non-empty

                    let mut withdraw_request: model::WithdrawalRequest =
                        fake::Faker.fake_with_rng(rng);

                    withdraw_request.block_hash = stacks_block_hash;
                    withdraw_request.request_id = next_withdraw_request_id;
                    withdraw_request.recipient = fake::Faker.fake_with_rng(rng);
                    withdraw_request.bitcoin_block_height = bitcoin_block.block_height;

                    let mut raw_transaction: model::Transaction = fake::Faker.fake_with_rng(rng);
                    raw_transaction.tx_type = model::TransactionType::WithdrawRequest;

                    let stacks_transaction = model::StacksTransaction {
                        txid: raw_transaction.txid.into(),
                        block_hash: stacks_block_hash,
                    };

                    let withdraw_signers: Vec<_> = signer_keys
                        .iter()
                        .take(num_signers_per_request)
                        .copied()
                        .map(|signer_pub_key| model::WithdrawalSigner {
                            request_id: withdraw_request.request_id,
                            block_hash: withdraw_request.block_hash,
                            txid: withdraw_request.txid,
                            signer_pub_key,
                            is_accepted: fake::Faker.fake_with_rng(rng),
                        })
                        .collect();

                    withdraw_requests
                        .stacks_transactions
                        .push(stacks_transaction);
                    withdraw_requests.withdraw_requests.push(withdraw_request);
                    withdraw_requests.transactions.push(raw_transaction);
                    withdraw_requests.withdraw_signers.extend(withdraw_signers);

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
    /// The number of signers to hallucinate per request
    pub num_signers_per_request: usize,
    /// Wheter to generate consecutive blocks or not
    pub consecutive_blocks: bool,
}

impl BitcoinBlockRef {
    fn summarize(block: &model::BitcoinBlock) -> Self {
        Self {
            block_hash: block.block_hash,
            block_height: block.block_height,
        }
    }

    fn hallucinate_parent(block: &model::BitcoinBlock) -> Self {
        Self {
            block_hash: block.parent_hash,
            block_height: 1337, // Arbitrary number
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StacksBlockSummary {
    block_hash: model::StacksBlockHash,
    block_height: u64,
}

impl StacksBlockSummary {
    fn summarize(block: &model::StacksBlock) -> Self {
        Self {
            block_hash: block.block_hash,
            block_height: block.block_height,
        }
    }

    fn hallucinate_parent(block: &model::StacksBlock) -> Self {
        Self {
            block_hash: block.parent_hash,
            block_height: 1337, // Arbitrary number
        }
    }
}

fn vec_diff<T: std::cmp::Eq + std::hash::Hash>(subtrahend: &mut Vec<T>, minuend: &[T]) {
    let minuend_set = minuend.iter().collect::<HashSet<_>>();
    subtrahend.retain(|v| !minuend_set.contains(v));
}

impl From<&bitcoin::Block> for crate::storage::model::BitcoinBlockRef {
    fn from(value: &bitcoin::Block) -> Self {
        Self {
            block_hash: value.block_hash().into(),
            block_height: value.bip34_block_height().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use more_asserts::assert_ge;
    use rand::SeedableRng as _;

    use crate::{
        storage::{self, DbRead as _},
        testing,
    };

    use super::*;

    #[tokio::test]
    async fn check_simple_chain() {
        let mut store = storage::in_memory::Store::new_shared();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let test_model_params = Params {
            num_bitcoin_blocks: 10,
            num_stacks_blocks_per_bitcoin_block: 5,
            num_deposit_requests_per_block: 0,
            num_withdraw_requests_per_block: 0,
            num_signers_per_request: 0,
            consecutive_blocks: true,
        };
        let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, 7);

        let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
        test_data.write_to(&mut store).await;

        let bitcoin_chain_tip = store
            .get_bitcoin_canonical_chain_tip()
            .await
            .unwrap()
            .unwrap();
        let tip = store
            .get_stacks_chain_tip(&bitcoin_chain_tip)
            .await
            .unwrap()
            .unwrap();

        let mut walk = vec![tip];
        while let Some(current) = store
            .get_stacks_block(&walk.last().unwrap().parent_hash)
            .await
            .unwrap()
        {
            // Check the stacks heights increment as expected
            assert_eq!(current.block_height, walk.last().unwrap().block_height - 1);
            walk.push(current);
        }

        // Check that we walked at least `num_bitcoin_blocks` stacks blocks:
        // TestData connects the first stacks block of a bitcoin block to a
        // random stacks block of the parent bitcoin block, so the stacks chain
        // will have at least one stacks block in each bitcoin block; the
        // bitcoin chain itself will be fork-less because of consecutive_blocks
        assert_ge!(walk.len(), 10);
    }
}
