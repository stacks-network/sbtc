//! Test data generation utilities

use fake::Fake;
use time::OffsetDateTime;

use crate::storage::model;

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
}

impl TestData {
    /// Generate random test data with the given parameters
    pub fn generate(rng: &mut impl rand::RngCore, params: &Params) -> Self {
        let bitcoin_block_generator: BlockGenerator = match params.chain_type {
            ChainType::Idealistic => Box::new(idealistic_bitcoin_chain(rng)),
            ChainType::Realistic => Box::new(realistic_bitcoin_chain(rng)),
            ChainType::Chaotic => Box::new(chaotic_bitcoin_chain(rng)),
        };

        let bitcoin_blocks = (0..params.num_bitcoin_blocks)
            .scan(Vec::new(), bitcoin_block_generator)
            .collect();

        Self { bitcoin_blocks }
    }
}

/// Parameters for test data generation
#[derive(Debug, Clone)]
pub struct Params {
    /// The number of bitcoin blocks to generate
    pub num_bitcoin_blocks: usize,
    /// The type of characteristics for the generated blockchain
    pub chain_type: ChainType,
}

/// Enum repredenting different strategies for how to connect blocks
#[derive(Debug, Clone)]
pub enum ChainType {
    /// A single chain without any forks
    Idealistic,
    /// A chain with some forking but no orphans
    Realistic,
    /// A chain with plenty of forks and orphans
    Chaotic,
}

type BlockGenerator<'a> =
    Box<dyn FnMut(&mut Vec<model::BitcoinBlockHash>, usize) -> Option<model::BitcoinBlock> + 'a>;

fn idealistic_bitcoin_chain(
    rng: &mut impl rand::RngCore,
) -> impl FnMut(&mut Vec<model::BitcoinBlockHash>, usize) -> Option<model::BitcoinBlock> + '_ {
    |block_hashes, _| {
        let mut block: model::BitcoinBlock = fake::Faker.fake_with_rng(rng);
        let block_hash: [u8; 32] = fake::Faker.fake_with_rng(rng);
        block.block_hash = block_hash.to_vec();
        block.created_at = block.created_at.max(OffsetDateTime::UNIX_EPOCH);
        block.created_at = block.created_at.replace_nanosecond(0).unwrap();
        block.parent_hash = block_hashes.last().unwrap_or(&block.parent_hash).clone();
        block_hashes.push(block.block_hash.clone());
        Some(block)
    }
}

fn realistic_bitcoin_chain(
    rng: &mut impl rand::RngCore,
) -> impl FnMut(&mut Vec<model::BitcoinBlockHash>, usize) -> Option<model::BitcoinBlock> + '_ {
    |block_hashes, _| {
        let mut block: model::BitcoinBlock = fake::Faker.fake_with_rng(rng);
        let block_hash: [u8; 32] = fake::Faker.fake_with_rng(rng);
        block.block_hash = block_hash.to_vec();
        block.created_at = block.created_at.max(OffsetDateTime::UNIX_EPOCH);
        block.created_at = block.created_at.replace_nanosecond(0).unwrap();
        block.parent_hash = block_hashes
            .choose(rng)
            .unwrap_or(&block.parent_hash)
            .clone();
        block_hashes.push(block.block_hash.clone());
        Some(block)
    }
}

fn chaotic_bitcoin_chain(
    rng: &mut impl rand::RngCore,
) -> impl FnMut(&mut Vec<model::BitcoinBlockHash>, usize) -> Option<model::BitcoinBlock> + '_ {
    |block_hashes, _| {
        let mut block: model::BitcoinBlock = fake::Faker.fake_with_rng(rng);
        let block_hash: [u8; 32] = fake::Faker.fake_with_rng(rng);
        block.block_hash = block_hash.to_vec();
        block.created_at = block.created_at.max(OffsetDateTime::UNIX_EPOCH);
        block.created_at = block.created_at.replace_nanosecond(0).unwrap();
        block_hashes.push(block.parent_hash.clone());
        block.parent_hash = block_hashes.choose(rng).unwrap().clone();
        block_hashes.push(block.block_hash.clone());
        Some(block)
    }
}
