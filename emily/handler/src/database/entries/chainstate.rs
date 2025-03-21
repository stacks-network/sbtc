//! Entries into the chainstate table.

use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::{api::models::chainstate::Chainstate, common::error::Error};

use super::{EntryTrait, KeyTrait, PrimaryIndex, PrimaryIndexTrait, VersionedEntryTrait};

// Chainstate entry ---------------------------------------------------------------

/// Chainstate table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChainstateEntryKey {
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub hash: String,
    /// Bitcoin transaction id.
    pub height: u64,
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
    type PartitionKey = u64;
    /// the type of the sort key.
    type SortKey = String;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "Height";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "Hash";
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
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ApiStatus {
    /// The API is currently stable.
    Stable(ChainstateEntry),
    /// The API state is currently being reorganized and should be assumed to
    /// be unsafe to modify.
    Reorg(ChainstateEntry),
}

/// Implement default for ApiStatus.
impl Default for ApiStatus {
    fn default() -> Self {
        ApiStatus::Stable(ChainstateEntry::default())
    }
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
    /// Api Status.
    pub api_status: ApiStatus,
}

/// Api state entry implementation.
impl ApiStateEntry {
    /// Get the special key.
    pub fn key() -> SpecialApiStateKey {
        SpecialApiStateKey {
            api_state_token: API_STATE_HASH_TOKEN.to_string(),
            negative_one: API_STATE_HEIGHT_TOKEN,
        }
    }
    /// Gets the current chain tip.
    pub fn chaintip(&self) -> ChainstateEntry {
        match &self.api_status {
            ApiStatus::Stable(chaintip) => chaintip.clone(),
            ApiStatus::Reorg(chaintip) => chaintip.clone(),
        }
    }
    /// Create the appropriate error if the API is reorganizing.
    pub fn error_if_reorganizing(&self) -> Result<(), Error> {
        if let ApiStatus::Reorg(chaintip) = &self.api_status {
            Err(Error::Reorganizing(chaintip.clone().into()))
        } else {
            Ok(())
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
    const SORT_KEY_NAME: &'static str = "Hash";
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

// HeightsMapping entry ---------------------------------------------------------------

/// Deposit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HeightsMappingEntryKey {
    /// Bitcoin block height.
    pub bitcoin_height: u64,
}

/// Deposit table entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HeightsMappingEntry {
    /// Deposit table entry key.
    #[serde(flatten)]
    pub key: HeightsMappingEntryKey,
    /// Table entry version. Updated on each alteration.
    pub version: u64,
    /// First anchored stacks block height
    pub first_ancored_stacks_height: u64,
}

/// Implements versioned entry trait for the deposit entry.
impl VersionedEntryTrait for HeightsMappingEntry {
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

/// Implements the key trait for the deposit entry key.
impl KeyTrait for HeightsMappingEntryKey {
    /// The type of the partition key.
    type PartitionKey = u64;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "BitcoinHeight";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "BitcoinHeight2";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for HeightsMappingEntry {
    /// The type of the key for this entry type.
    type Key = HeightsMappingEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        HeightsMappingEntryKey {
            bitcoin_height: self.key.bitcoin_height,
        }
    }
}

/// Primary index struct.
pub struct HeightsMappingTablePrimaryIndexInner;
/// Deposit table primary index type.
pub type HeightsMappingTablePrimaryIndex = PrimaryIndex<HeightsMappingTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for HeightsMappingTablePrimaryIndexInner {
    type Entry = HeightsMappingEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.heights_mapping_table_name
    }
}

/// Implementation of deposit entry.
impl HeightsMappingEntry {
    /// Implement validate.
    pub fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

// BitcoinChainstate entry ---------------------------------------------------------------

/// BitcoinChainstate table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BitcoinChainstateEntryKey {
    /// Bitcoin tip hash
    pub dummy: String,
}

/// Chainstate table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BitcoinChainstateEntry {
    /// Chainstate entry key.
    #[serde(flatten)]
    pub key: BitcoinChainstateEntryKey,
    /// Bitcoin tip height.
    pub height: u64,
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for BitcoinChainstateEntryKey {
    /// The type of the partition key.
    type PartitionKey = String;
    /// the type of the sort key.
    type SortKey = String;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "Dummy";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "Dummy2";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for BitcoinChainstateEntry {
    /// The type of the key for this entry type.
    type Key = BitcoinChainstateEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        BitcoinChainstateEntryKey { dummy: self.key.dummy.clone() }
    }
}

/// Primary index struct.
pub struct BitcoinChainstateTablePrimaryIndexInner;
/// Withdrawal table primary index type.
pub type BitcoinChainstateTablePrimaryIndex = PrimaryIndex<BitcoinChainstateTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for BitcoinChainstateTablePrimaryIndexInner {
    type Entry = BitcoinChainstateEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.bitcoin_chainstate_table_name
    }
}
