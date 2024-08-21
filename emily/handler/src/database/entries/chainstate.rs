//! Entries into the chainstate table.

use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::api::models::{
    chainstate::Chainstate,
    common::{BlockHeight, StacksBlockHash},
};

use super::{EntryTrait, KeyTrait, PrimaryIndex, PrimaryIndexTrait, VersionedEntryTrait};

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

/// Convert from entry to its corresponding chainstate.
impl From<ChainstateEntry> for Chainstate {
    fn from(chainstate_entry: ChainstateEntry) -> Self {
        Chainstate {
            stacks_block_hash: chainstate_entry.key.hash,
            stacks_block_height: chainstate_entry.key.height,
        }
    }
}

/// Convert from chainstate to its corresponding entry.
impl From<Chainstate> for ChainstateEntry {
    fn from(chainstate_entry: Chainstate) -> Self {
        ChainstateEntry {
            key: ChainstateEntryKey {
                hash: chainstate_entry.stacks_block_hash,
                height: chainstate_entry.stacks_block_height,
            },
        }
    }
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for ChainstateEntryKey {
    /// The type of the partition key.
    type PartitionKey = BlockHeight;
    /// the type of the sort key.
    type SortKey = StacksBlockHash;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "Height";
    /// The table field name of the sort key.
    const _SORT_KEY_NAME: &'static str = "Hash";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for ChainstateEntry {
    /// The type of the key for this entry type.
    type Key = ChainstateEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        ChainstateEntryKey {
            height: self.key.height,
            hash: self.key.hash.clone(),
        }
    }
}

/// Primary index struct.
pub struct ChainstateTablePrimaryIndexInner;
/// Withdrawal table primary index type.
pub type ChainstateTablePrimaryIndex = PrimaryIndex<ChainstateTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for ChainstateTablePrimaryIndexInner {
    type Entry = ChainstateEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.chainstate_table_name
    }
}

// Api State Entry -------------------------------------------------------------

/// Special hash value for the chainstate entry that stores information about the
/// whole API state.
const API_STATE_HASH_TOKEN: &str = "API_STATE";

/// Special height value for the chainstate entry that stores information about the
/// whole API state.
const API_STATE_HEIGHT_TOKEN: i32 = -1;

/// A special api state key definition that redefines the height type to be
/// an i32 so that it can be negative one. Using a constant hash and a negative
/// height where the height is regularly represented as a u64 make accessing this
/// special entry nearly impossible for any regular access path.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SpecialApiStateKey {
    /// Special token that takes the place of the hash field. Constant fields
    /// are set in the `Default` function for this struct.
    #[serde(rename = "Hash")]
    api_state_token: String,
    /// Special token that takes the place of the height field. Constant fields
    /// are set in the `Default` function for this struct.
    #[serde(rename = "Height")]
    negative_one: i32,
}

/// Implementation of default for SpecialApiStateKey.
impl Default for SpecialApiStateKey {
    /// Implementation of default that set constant specific values that
    /// cannot be changed for the SpecialApiStateKey.
    fn default() -> Self {
        SpecialApiStateKey {
            api_state_token: API_STATE_HASH_TOKEN.to_string(),
            negative_one: API_STATE_HEIGHT_TOKEN,
        }
    }
}

/// Api status that indicates the overall state of the API.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ApiStatus {
    /// The API is currently stable.
    #[default]
    Stable,
    /// The API state is currently being reorganized and should be assumed to
    /// be unsafe to modify.
    Reorg,
}

/// API state struct.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ApiStateEntry {
    /// Special immutable table entry key that will always point to the status
    /// of the whole API.
    #[serde(flatten)]
    special_api_state_key: SpecialApiStateKey,
    /// Version field to prevent race conditions in updating the entry. If this field
    /// increments once a nanosecond it will overflow in ~ 584.94 years.
    pub version: u64,
    /// Current chain tip.
    pub chaintip: ChainstateEntry,
    /// Api Status.
    pub api_status: ApiStatus,
}

impl ApiStateEntry {
    /// Get the special key.
    pub fn key() -> SpecialApiStateKey {
        SpecialApiStateKey {
            api_state_token: API_STATE_HASH_TOKEN.to_string(),
            negative_one: API_STATE_HEIGHT_TOKEN,
        }
    }
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for SpecialApiStateKey {
    /// The type of the partition key.
    type PartitionKey = i32;
    /// the type of the sort key.
    type SortKey = String;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "Height";
    /// The table field name of the sort key.
    const _SORT_KEY_NAME: &'static str = "Hash";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for ApiStateEntry {
    /// The type of the key for this entry type.
    type Key = SpecialApiStateKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        ApiStateEntry::key()
    }
}

/// Implement versioned entry trait for the api state entry.
impl VersionedEntryTrait for ApiStateEntry {
    /// Version field.
    const VERSION_FIELD: &'static str = "Version";
    /// Get version.
    fn get_version(&self) -> u64 {
        self.version
    }
    /// Increment version.
    fn increment_version(&mut self) {
        self.version += 1;
    }
}

/// Primary index struct.
pub struct SpecialApiStateIndexInner;
/// Withdrawal table primary index type.
pub type SpecialApiStateIndex = PrimaryIndex<SpecialApiStateIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for SpecialApiStateIndexInner {
    type Entry = ApiStateEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.chainstate_table_name
    }
}
