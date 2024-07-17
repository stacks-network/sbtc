//! Entries into the chainstate table.

use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::api::models::{
    chainstate::Chainstate,
    common::{BlockHeight, StacksBlockHash},
};

// Chainstate entry ---------------------------------------------------------------

/// Chainstate table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChainstateEntryKey {
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub hash: StacksBlockHash,
    /// Bitcoin transaction id.
    pub height: BlockHeight,
}

/// Chainstate table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChainstateEntry {
    /// Chainstate entry key.
    #[serde(flatten)]
    pub key: ChainstateEntryKey,
}

impl From<ChainstateEntry> for Chainstate {
    fn from(chainstate_entry: ChainstateEntry) -> Self {
        Chainstate {
            stacks_block_hash: chainstate_entry.key.hash,
            stacks_block_height: chainstate_entry.key.height,
        }
    }
}
