//! Block helpers

use std::borrow::Cow;

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

    /// Generate a new chain of bitcoin blocks with the given length.
    ///
    /// The first block is created with [`Self::new_genesis()`] and will have a
    /// height of 0 and a parent hash of all zeroes. Each subsequent block will
    /// have a height one greater than the previous block and a parent hash
    /// equal to the hash of the previous block.
    pub fn new_chain(length: usize) -> Vec<Self> {
        let genesis = Self::new_genesis();
        genesis.generate_descendant_chain(length)
    }

    /// Generate a chain of bitcoin blocks with the given length, descending
    /// from this block. The chain will start with this block as the genesis
    /// block and each subsequent block will be a child of the previous block
    /// with its height incremented by one.
    pub fn generate_descendant_chain(&self, length: usize) -> Vec<BitcoinBlock> {
        let mut chain = vec![self.clone()];
        for _ in 0..length {
            chain.push(chain.last().unwrap().new_child());
        }
        chain
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
    pub fn anchored_to<B>(mut self, bitcoin_block: B) -> Self
    where
        B: AsRef<BitcoinBlockHash>,
    {
        self.bitcoin_anchor = *bitcoin_block.as_ref();
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

    /// Generate a new chain of stacks blocks of the same length as the given
    /// bitcoin chain.
    ///
    /// The first block is created with [`Self::new_genesis()`] and will have a
    /// height of 0 and a parent hash of all zeroes.
    ///
    /// Each subsequent block will have a height one greater than the previous
    /// block and a parent hash equal to the hash of the previous block.
    ///
    /// Each block will be anchored to the corresponding bitcoin block index in
    /// the provided bitcoin chain.
    pub fn new_anchored_chain<I, B>(bitcoin_chain: I) -> Vec<StacksBlock>
    where
        B: AsRef<BitcoinBlockHash>,
        I: IntoIterator<Item = B>,
    {
        let mut chain: Vec<StacksBlock> = vec![];
        for bitcoin_block in bitcoin_chain {
            let block = if chain.is_empty() {
                StacksBlock::new_genesis()
            } else {
                chain.last().unwrap().new_child()
            };
            chain.push(block.anchored_to(&bitcoin_block));
        }
        chain
    }

    /// Generate a chain of stacks blocks with a length equal to `1 +
    /// bitcoin_chain.len()`, descending from this block.
    ///
    /// The chain will start with this block as the genesis block and each
    /// subsequent block will be a child of the previous block with its height
    /// incremented by one.
    ///
    /// Each block will be anchored to the corresponding bitcoin block index in
    /// the provided bitcoin chain.
    pub fn generate_descendant_chain<I, B>(&self, bitcoin_chain: I) -> Vec<Cow<'_, StacksBlock>>
    where
        B: AsRef<BitcoinBlockHash>,
        I: IntoIterator<Item = B>,
    {
        let mut chain = vec![Cow::Borrowed(self)];
        for bitcoin_block in bitcoin_chain {
            chain.push(Cow::Owned(
                chain.last().unwrap().new_child().anchored_to(bitcoin_block),
            ));
        }
        chain
    }
}
