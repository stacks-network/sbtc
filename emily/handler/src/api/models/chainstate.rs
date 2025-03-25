//! Request structures for chainstate api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Chainstate.
#[derive(
    Clone,
    Default,
    Debug,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct Chainstate {
    /// Stacks block height.
    pub stacks_block_height: u64,
    /// Stacks block hash at the height.
    pub stacks_block_hash: String,
    /// Bitcoin block height
    pub bitcoin_block_height: u64,
}

// We manually implement this traits, ignoring `bitcoin_block_height` to
// not trigger reorg in cases where only this field is different.
// Also, we assume that there is no situation where only this 

impl PartialEq for Chainstate {
    fn eq(&self, other: &Self) -> bool {
        self.stacks_block_height == other.stacks_block_height
            && self.stacks_block_hash == other.stacks_block_hash
    }
}

impl Eq for Chainstate {}

impl PartialOrd for Chainstate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Chainstate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.stacks_block_height
            .cmp(&other.stacks_block_height)
            .then(self.stacks_block_hash.cmp(&other.stacks_block_hash))
    }
}
