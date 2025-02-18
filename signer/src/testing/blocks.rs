//! Block helpers

use fake::Fake;
use fake::Faker;

use crate::storage::model::BitcoinBlock;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::StacksBlock;
use crate::storage::model::StacksBlockHash;

impl BitcoinBlock {
    /// Create a new bitcoin block with the following properties:
    /// - block_hash: random
    /// - block_height: 0
    /// - parent_hash: all zeroes
    pub fn new_genesis() -> Self {
        Self {
            block_hash: Faker.fake(),
            block_height: 0,
            parent_hash: BitcoinBlockHash::from([0; 32]),
        }
    }

    /// Create a new [`BitcoinBlock`] with the following properties:
    /// - block_hash: random
    /// - block_height: this block's height + 1
    /// - parent_hash: this block's hash
    pub fn new_child(&self) -> Self {
        Self {
            block_hash: Faker.fake(),
            block_height: self.block_height + 1,
            parent_hash: self.block_hash,
        }
    }
}

impl StacksBlock {
    /// Create a new stacks block with the following properties:
    /// - block_hash: random
    /// - block_height: 0
    /// - parent_hash: all zeroes
    pub fn new_genesis() -> Self {
        Self {
            block_hash: Faker.fake(),
            block_height: 0,
            parent_hash: StacksBlockHash::from([0; 32]),
            bitcoin_anchor: BitcoinBlockHash::from([0; 32]),
        }
    }

    /// Anchor this block to a specific bitcoin block.
    pub fn anchored_to(mut self, bitcoin_block: &BitcoinBlock) -> Self {
        self.bitcoin_anchor = bitcoin_block.block_hash;
        self
    }

    /// Create a new [`StacksBlock`] with the following properties:
    /// - block_hash: random
    /// - block_height: this block's height + 1
    /// - parent_hash: this block's hash
    pub fn new_child(&self) -> Self {
        Self {
            block_hash: Faker.fake(),
            block_height: self.block_height + 1,
            parent_hash: self.block_hash,
            bitcoin_anchor: self.bitcoin_anchor,
        }
    }
}
