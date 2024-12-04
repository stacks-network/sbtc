//! Entries into the limit table.

use std::hash::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;

use super::EntryTrait;
use super::KeyTrait;
use super::PrimaryIndex;
use super::PrimaryIndexTrait;
use super::SecondaryIndex;
use super::SecondaryIndexTrait;
use crate::api::models::signer::Signer;
use crate::api::models::signer::SignerHealth;
use crate::api::models::signer::SignerInfo;
use crate::api::models::{self};

// Limit entry ---------------------------------------------------------------

/// Signer health entry.
#[derive(
    Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "PascalCase")]
pub enum SignerHeatlhEntry {
    /// Signer is healthy.
    Healthy,
    /// Signer is unhealthy.
    Unhealthy(String),
    /// Signer is dead.
    Dead(String),
    /// The state of the signer is unknown.
    #[default]
    Unknown,
}

/// Limit table entry key. This is the primary index key.
#[derive(
    Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "PascalCase")]
pub struct SignerEntryKey {
    /// The account for the limit.
    pub api_key_hash: String,
    /// The timestamp of the given update.
    pub timestamp: u64,
}

/// Implementation of SignerEntryKey.
impl SignerEntryKey {
    /// Create a new signer entry key from an api key and the chosen time.
    pub fn new(api_key: String, now: SystemTime) -> Self {
        let mut api_key_hasher = DefaultHasher::new();
        api_key.hash(&mut api_key_hasher);
        SignerEntryKey {
            api_key_hash: api_key_hasher.finish().to_string(),
            timestamp: now
                .duration_since(std::time::UNIX_EPOCH)
                // It's impossible for this to fail.
                .expect(
                    "Error making timestamp during signer entry key creation.",
                )
                .as_secs(),
        }
    }
}

/// Signer table entry key. This is the primary index key.
#[derive(
    Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "PascalCase")]
pub struct SignerEntry {
    /// Limit entry key.
    #[serde(flatten)]
    pub key: SignerEntryKey,
    /// The name of the signer.
    pub name: String,
    /// The compressed public key of the signer.
    pub public_key: String,
    /// Approximate location of the signer.
    pub location: String,
    /// Signer's health assessment.
    pub health: SignerHeatlhEntry,
    /// The contact information for the signer.
    pub contact: String,
    /// Whether the signer is currently active.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_active: bool,
}

impl SignerEntry {
    /// Create a new signer entry from the registration.
    pub fn from_full_signer(
        api_key: String, full_signer: Signer, now: SystemTime,
    ) -> Self {
        SignerEntry {
            key: SignerEntryKey::new(api_key, now),
            name: full_signer.name,
            public_key: full_signer.public_key,
            location: full_signer.location,
            health: SignerHeatlhEntry::Unknown,
            contact: full_signer.contact,
            // When registering a signer it will always be active.
            is_active: true,
        }
    }
}

/// Convert from entry to its corresponding signer representation.
impl From<SignerEntry> for Signer {
    fn from(signer_entry: SignerEntry) -> Self {
        Signer {
            name: signer_entry.name,
            public_key: signer_entry.public_key,
            location: signer_entry.location,
            health: signer_entry.health.into(),
            contact: signer_entry.contact,
        }
    }
}

/// Implement from for SignerHeatlhEntry, allowing it to easily be converted to
/// the API model type.
impl From<SignerHeatlhEntry> for SignerHealth {
    fn from(signer_health_entry: SignerHeatlhEntry) -> Self {
        match signer_health_entry {
            SignerHeatlhEntry::Healthy => SignerHealth::Healthy,
            SignerHeatlhEntry::Unhealthy(reason) => {
                SignerHealth::Unhealthy(reason)
            },
            SignerHeatlhEntry::Dead(reason) => SignerHealth::Dead(reason),
            SignerHeatlhEntry::Unknown => SignerHealth::Unknown,
        }
    }
}

/// Implement from for SignerHealth, allowing it to easily be converted to the
/// database model type from the API model type.
impl From<SignerHealth> for SignerHeatlhEntry {
    fn from(signer_health: SignerHealth) -> Self {
        match signer_health {
            SignerHealth::Healthy => SignerHeatlhEntry::Healthy,
            SignerHealth::Unhealthy(reason) => {
                SignerHeatlhEntry::Unhealthy(reason)
            },
            SignerHealth::Dead(reason) => SignerHeatlhEntry::Dead(reason),
            SignerHealth::Unknown => SignerHeatlhEntry::Unknown,
        }
    }
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for SignerEntryKey {
    /// The type of the partition key.
    type PartitionKey = String;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "ApiKeyHash";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "Timestamp";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for SignerEntry {
    /// The type of the key for this entry type.
    type Key = SignerEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key { self.key.clone() }
}

/// Primary index struct.
pub struct SignerTablePrimaryIndexInner;
/// Withdrawal table primary index type.
pub type SignerTablePrimaryIndex = PrimaryIndex<SignerTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for SignerTablePrimaryIndexInner {
    type Entry = SignerEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.signer_table_name
    }
}

/// Key for signer info entry.
#[derive(
    Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "PascalCase")]
pub struct SignerInfoEntryKey {
    /// Whether the signer is active.
    pub is_active: u32,
    /// Public key.
    pub public_key: String,
}

impl SignerInfoEntryKey {
    /// Create a new signer info entry key.
    pub fn new(public_key: String) -> Self {
        SignerInfoEntryKey {
            is_active: 1,
            public_key,
        }
    }
}

/// Signer table entry key. This is the primary index key.
#[derive(
    Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "PascalCase")]
pub struct SignerInfoEntry {
    /// Gsi key data.
    pub key: SignerInfoEntryKey,
    /// Primary index key.
    #[serde(flatten)]
    pub primary_index_key: SignerEntryKey,
    /// Signer location.
    pub location: String,
    /// Signer name.
    pub name: String,
    /// Signer health.
    pub health: SignerHeatlhEntry,
}

impl From<SignerInfoEntry> for SignerInfo {
    fn from(signer_info_entry: SignerInfoEntry) -> Self {
        SignerInfo {
            name: signer_info_entry.name,
            public_key: signer_info_entry.key.public_key,
            location: signer_info_entry.location,
            health: signer_info_entry.health.into(),
        }
    }
}

impl KeyTrait for SignerInfoEntryKey {
    type PartitionKey = u32;
    type SortKey = String;
    const PARTITION_KEY_NAME: &'static str = "IsActive";
    const SORT_KEY_NAME: &'static str = "PublicKey";
}

/// Entry trait for the signer info entry.
impl EntryTrait for SignerInfoEntry {
    /// Key type.
    type Key = SignerInfoEntryKey;
    /// Extract the key from the entry.
    fn key(&self) -> Self::Key { self.key.clone() }
}

/// Secondary index struct.
pub struct SignerTableSecondaryIndexInner;
/// Deposit table secondary index type.
pub type SignerTableSecondaryIndex =
    SecondaryIndex<SignerTableSecondaryIndexInner>;
/// Definition of secondary index trait.
impl SecondaryIndexTrait for SignerTableSecondaryIndexInner {
    type PrimaryIndex = SignerTablePrimaryIndex;
    type Entry = SignerInfoEntry;
    const INDEX_NAME: &'static str = "ActiveSigners";
}
