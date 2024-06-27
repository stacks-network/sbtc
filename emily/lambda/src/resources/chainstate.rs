use serde::{Deserialize, Serialize};

/// Chainstate table entry.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ChainstateBlock {
    /// Block height of the block.
    pub block_height: u64,

    /// Block hash at that height.
    pub block_hash: String,
}
