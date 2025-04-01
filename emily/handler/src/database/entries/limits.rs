//! Entries into the limit table.

use std::{hash::Hash, time::SystemTime};

use serde::{Deserialize, Serialize};

use crate::api::models::limits::AccountLimits;

use super::{EntryTrait, KeyTrait, PrimaryIndex, PrimaryIndexTrait};

// Limit entry ---------------------------------------------------------------

/// The special account name for the global cap.
pub(crate) const GLOBAL_CAP_ACCOUNT: &str = "GLOBAL";

/// Limit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LimitEntryKey {
    /// The account for the limit.
    pub account: String,
    /// The timestamp of the given update.
    pub timestamp: u64,
}

/// Limit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LimitEntry {
    /// Limit entry key.
    #[serde(flatten)]
    pub key: LimitEntryKey,
    /// Represents the current sBTC limits.
    pub peg_cap: Option<u64>,
    /// Per deposit minimum. If none then there is no minimum.
    pub per_deposit_minimum: Option<u64>,
    /// Per deposit cap. If none then the cap is the same as the global per deposit cap.
    pub per_deposit_cap: Option<u64>,
    /// Per withdrawal cap. If none then the cap is the same as the global per withdrawal cap.
    pub per_withdrawal_cap: Option<u64>,
    /// Number of blocks that define the rolling withdrawal window.
    pub rolling_withdrawal_blocks: Option<u64>,
    /// Maximum total sBTC that can be withdrawn within the rolling withdrawal window.
    pub rolling_withdrawal_cap: Option<u64>,
}

/// Convert from entry to its corresponding limit.
impl From<LimitEntry> for AccountLimits {
    fn from(limit_entry: LimitEntry) -> Self {
        AccountLimits {
            peg_cap: limit_entry.peg_cap,
            per_deposit_minimum: limit_entry.per_deposit_minimum,
            per_deposit_cap: limit_entry.per_deposit_cap,
            per_withdrawal_cap: limit_entry.per_withdrawal_cap,
            rolling_withdrawal_blocks: limit_entry.rolling_withdrawal_blocks,
            rolling_withdrawal_cap: limit_entry.rolling_withdrawal_cap,
        }
    }
}

impl LimitEntry {
    /// Create a new limit entry from an account limit and the chosen time.
    pub fn from_account_limit(
        account: String,
        now: SystemTime,
        account_limit: &AccountLimits,
    ) -> Self {
        LimitEntry {
            key: LimitEntryKey {
                account,
                timestamp: now
                    .duration_since(std::time::UNIX_EPOCH)
                    // It's impossible for this to fail.
                    .expect("Error making timestamp during limit entry creation.")
                    .as_secs(),
            },
            peg_cap: account_limit.peg_cap,
            per_deposit_minimum: account_limit.per_deposit_minimum,
            per_deposit_cap: account_limit.per_deposit_cap,
            per_withdrawal_cap: account_limit.per_withdrawal_cap,
            rolling_withdrawal_blocks: account_limit.rolling_withdrawal_blocks,
            rolling_withdrawal_cap: account_limit.rolling_withdrawal_cap,
        }
    }
    /// Returns true if the limit entry has no limits set.
    pub fn is_empty(&self) -> bool {
        self.peg_cap.is_none()
            && self.per_deposit_cap.is_none()
            && self.per_withdrawal_cap.is_none()
    }
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for LimitEntryKey {
    /// The type of the partition key.
    type PartitionKey = String;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "Account";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "Timestamp";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for LimitEntry {
    /// The type of the key for this entry type.
    type Key = LimitEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

/// Primary index struct.
pub struct LimitTablePrimaryIndexInner;
/// Withdrawal table primary index type.
pub type LimitTablePrimaryIndex = PrimaryIndex<LimitTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for LimitTablePrimaryIndexInner {
    type Entry = LimitEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.limit_table_name
    }
}
