//! Various utilities for generating and manipulating chains of bitcoin and
//! stacks blocks for testing purposes.

use fake::Fake;
use fake::Faker;

use crate::storage::model::BitcoinBlock;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::StacksBlock;
use crate::storage::model::StacksBlockHash;

/// Represents a naive, sequential chain of bitcoin blocks and provides basic
/// functionality for manipulation. Does not handle forks/branches.
pub struct BitcoinChain(Vec<BitcoinBlock>);

impl<'a> IntoIterator for &'a BitcoinChain {
    type Item = &'a BitcoinBlock;
    type IntoIter = std::slice::Iter<'a, BitcoinBlock>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Note: the `Default` derive generates `BitcoinChain(vec![])`, which is
/// not a valid state.
impl Default for BitcoinChain {
    fn default() -> Self {
        Self::new()
    }
}

impl BitcoinChain {
    /// Generate a new chain of bitcoin blocks with a single genesis block.
    ///
    /// The first block is created with [`BitcoinBlock::new_genesis()`] and will
    /// have a height of 0 and a parent hash of all zeroes. Each subsequent
    /// block will have a height one greater than the previous block and a
    /// parent hash equal to the hash of the previous block.
    pub fn new() -> Self {
        Self(vec![BitcoinBlock::new_genesis()])
    }

    /// Generate a new chain of bitcoin blocks with a length equal to `length`.
    ///
    /// See [`Self::new()`] for more information on how the blocks are
    /// generated.
    pub fn new_with_length(length: usize) -> Self {
        let mut chain = Self::new();
        chain.generate_blocks(length.saturating_sub(1));
        chain
    }

    /// Generate a chain of `length` bitcoin blocks, descending from the last
    /// block in the chain.
    ///
    /// Each block will have a height one greater than the previous block and a
    /// parent hash equal to the hash of the previous block.
    ///
    /// Returns a vector of references to the newly generated blocks.
    pub fn generate_blocks(&mut self, length: usize) -> Vec<&BitcoinBlock> {
        for _ in 0..length {
            let new_block = self.chain_tip().new_child();
            self.0.push(new_block);
        }

        self.0[(self.0.len() - length)..].iter().collect()
    }

    /// Gets the first block in the chain.
    pub fn first_block(&self) -> &BitcoinBlock {
        self.0.first().unwrap()
    }

    /// Gets the last block in the chain.
    pub fn chain_tip(&self) -> &BitcoinBlock {
        self.0.last().unwrap()
    }

    /// Gets the nth block in the chain, if it exists.
    pub fn nth_block_checked(&self, height: usize) -> Option<&BitcoinBlock> {
        self.0.get(height)
    }

    /// Gets the nth block in the chain, panicking if it does not exist.
    pub fn nth_block(&self, height: usize) -> &BitcoinBlock {
        self.nth_block_checked(height)
            .expect("no nth bitcoin block (index out of range)")
    }
}

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

/// Represents a naive, sequential chain of stacks blocks and provides basic
/// functionality for manipulation.
pub struct StacksChain(Vec<StacksBlock>);

impl<'a> IntoIterator for &'a StacksChain {
    type Item = &'a StacksBlock;
    type IntoIter = std::slice::Iter<'a, StacksBlock>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl StacksChain {
    /// Generates a new chain of stacks blocks where each block is anchored to
    /// the corresponding bitcoin block in the provided bitcoin block list. Does
    /// not handle forks/branches.
    pub fn new_anchored<I, B>(anchors: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: AsRef<BitcoinBlockHash>,
    {
        let mut chain = Self(vec![]);
        for anchor in anchors {
            chain.new_block(anchor);
        }
        chain
    }

    /// Adds a new block to the chain, anchored to the given bitcoin block.
    pub fn new_block<B>(&mut self, anchor: B) -> &StacksBlock
    where
        B: AsRef<BitcoinBlockHash>,
    {
        if self.0.is_empty() {
            self.0.push(StacksBlock::new_genesis().anchored_to(anchor));
        } else {
            let new_block = self.chain_tip().new_child().anchored_to(anchor);
            self.0.push(new_block);
        }
        self.chain_tip()
    }

    /// Gets the first block in the chain.
    pub fn first_block(&self) -> &StacksBlock {
        self.0.first().unwrap()
    }

    /// Gets the last block in the chain.
    pub fn chain_tip(&self) -> &StacksBlock {
        self.0.last().unwrap()
    }

    /// Gets the nth block in the chain, if it exists.
    pub fn nth_block_checked(&self, height: usize) -> Option<&StacksBlock> {
        self.0.get(height)
    }

    /// Gets the nth block in the chain, panicking if it does not exist.
    pub fn nth_block(&self, height: usize) -> &StacksBlock {
        self.0
            .get(height)
            .expect("no nth bitcoin block (index out of range)")
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
}
