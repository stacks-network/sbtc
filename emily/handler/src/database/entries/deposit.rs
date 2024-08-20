//! Entries into the deposit table.

use serde::{Deserialize, Serialize};

use crate::{
    api::models::{
        common::{
            BitcoinScript, BitcoinTransactionId, BitcoinTransactionOutputIndex, BlockHeight,
            Fulfillment, Satoshis, StacksBlockHash, StacksPrinciple, Status,
        },
        deposit::{
            requests::{DepositUpdate, UpdateDepositsRequestBody},
            Deposit, DepositInfo, DepositParameters,
        },
    },
    common::error::{Error, Inconsistency},
};

use super::{
    EntryTrait, KeyTrait, PrimaryIndex, PrimaryIndexTrait, SecondaryIndex, SecondaryIndexTrait,
    StatusEntry, VersionedEntryTrait,
};

// Deposit entry ---------------------------------------------------------------

/// Deposit table entry key. This is the primary index key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositEntryKey {
    /// Bitcoin transaction id.
    pub bitcoin_txid: BitcoinTransactionId,
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub bitcoin_tx_output_index: BitcoinTransactionOutputIndex,
}

/// Deposit table entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositEntry {
    /// Deposit table entry key.
    #[serde(flatten)]
    pub key: DepositEntryKey,
    /// Table entry version. Updated on each alteration.
    pub version: u64,
    /// Stacks address to received the deposited sBTC.
    pub recipient: StacksPrinciple,
    /// Amount of BTC being deposited.
    pub amount: Satoshis,
    /// Deposit parameters.
    #[serde(flatten)]
    pub parameters: DepositParametersEntry,
    /// The status of the deposit.
    #[serde(rename = "OpStatus")]
    pub status: Status,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: BlockHeight,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: StacksBlockHash,
    /// Data about the fulfillment of the sBTC Operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
    /// History of this deposit transaction.
    pub history: Vec<DepositEvent>,
}

/// Implements versioned entry trait for the deposit entry.
impl VersionedEntryTrait for DepositEntry {
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
impl KeyTrait for DepositEntryKey {
    /// The type of the partition key.
    type PartitionKey = BitcoinTransactionId;
    /// the type of the sort key.
    type SortKey = BitcoinTransactionOutputIndex;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "BitcoinTxid";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "BitcoinTxOutputIndex";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for DepositEntry {
    /// The type of the key for this entry type.
    type Key = DepositEntryKey;
    /// Extract the key from the deposit entry.
    fn key(&self) -> Self::Key {
        DepositEntryKey {
            bitcoin_txid: self.key.bitcoin_txid.clone(),
            bitcoin_tx_output_index: self.key.bitcoin_tx_output_index,
        }
    }
}

/// Primary index struct.
pub struct DepositTablePrimaryIndexInner;
/// Deposit table primary index type.
pub type DepositTablePrimaryIndex = PrimaryIndex<DepositTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for DepositTablePrimaryIndexInner {
    type Entry = DepositEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.deposit_table_name
    }
}

/// Implementation of deposit entry.
impl DepositEntry {
    /// Implement validate.
    pub fn validate(&self) -> Result<(), Error> {
        let stringy_self = serde_json::to_string(self)?;

        // Get latest event.
        let latest_event: &DepositEvent = self.history.last().ok_or(Error::Debug(format!(
            "Failed getting the last history element for deposit. {stringy_self:?}"
        )))?;

        // Verify that the latest event is the current one shown in the entry.
        if self.last_update_block_hash != latest_event.stacks_block_hash {
            return Err(Error::Debug(
                format!("last update block hash is inconsistent between history and top level data. {stringy_self:?}")
            ));
        }
        if self.last_update_height != latest_event.stacks_block_height {
            return Err(Error::Debug(
                format!("last update block height is inconsistent between history and top level data. {stringy_self:?}")
            ));
        }
        if self.status != (&latest_event.status).into() {
            return Err(Error::Debug(
                format!("most recent status is inconsistent between history and top level data. {stringy_self:?}")
            ));
        }
        Ok(())
    }

    /// Gets the latest event.
    pub fn latest_event(&self) -> Result<&DepositEvent, Error> {
        self.history.last().ok_or(Error::Debug(format!(
            "Deposit entry must always have at least one event, but entry with id {:?} did not.",
            self.key(),
        )))
    }
}

impl TryFrom<DepositEntry> for Deposit {
    type Error = Error;
    fn try_from(deposit_entry: DepositEntry) -> Result<Self, Self::Error> {
        // Ensure entry is valid.
        deposit_entry.validate()?;

        // Extract data from the latest event.
        let latest_event = deposit_entry.latest_event()?;
        let status_message = latest_event.message.clone();
        let status: Status = (&latest_event.status).into();
        let fulfillment = match &latest_event.status {
            StatusEntry::Accepted(fulfillment) => Some(fulfillment.clone()),
            _ => None,
        };

        // Create deposit from table entry.
        Ok(Deposit {
            bitcoin_txid: deposit_entry.key.bitcoin_txid,
            bitcoin_tx_output_index: deposit_entry.key.bitcoin_tx_output_index,
            recipient: deposit_entry.recipient,
            amount: deposit_entry.amount,
            last_update_height: deposit_entry.last_update_height,
            last_update_block_hash: deposit_entry.last_update_block_hash,
            status,
            status_message,
            parameters: DepositParameters {
                max_fee: deposit_entry.parameters.max_fee,
                lock_time: deposit_entry.parameters.lock_time,
                reclaim_script: deposit_entry.parameters.reclaim_script,
            },
            fulfillment,
        })
    }
}

/// Deposit parameters entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositParametersEntry {
    /// Maximum fee the signers are allowed to take from the deposit to facilitate
    /// the transaction.
    pub max_fee: Satoshis,
    /// Bitcoin block height at which the reclaim script becomes executable.
    pub lock_time: BlockHeight,
    /// Raw reclaim script.
    pub reclaim_script: BitcoinScript,
}

/// Event in the history of a deposit.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositEvent {
    /// Status code.
    #[serde(rename = "OpStatus")]
    pub status: StatusEntry,
    /// Status message.
    pub message: String,
    /// Stacks block heigh at the time of this update.
    pub stacks_block_height: BlockHeight,
    /// Stacks block hash associated with the height of this update.
    pub stacks_block_hash: StacksBlockHash,
}

/// Implementation of deposit event.
impl DepositEvent {
    /// Errors if the next event provided could not follow the current one.
    pub fn ensure_following_event_is_valid(&self, next_event: &DepositEvent) -> Result<(), Error> {
        // Determine if event is valid.
        if self.stacks_block_height > next_event.stacks_block_height {
            return Err(Error::InconsistentState(Inconsistency::ItemUpdate(
                "Attempting to update a deposit with a block height earlier than it should be."
                    .into(),
            )));
        } else if self.stacks_block_height == next_event.stacks_block_height
            && self.stacks_block_hash != next_event.stacks_block_hash
        {
            return Err(Error::InconsistentState(Inconsistency::ItemUpdate(
                "Attempting to update a deposit with a block height and hash that conflicts with the current history."
                    .into(),
            )));
        }

        Ok(())
    }
}

// Deposit info entry ----------------------------------------------------------

/// Search token for GSI.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositInfoEntrySearchToken {
    /// Primary index key.
    #[serde(flatten)]
    pub primary_index_key: DepositEntryKey,
    /// Global secondary index key.
    #[serde(flatten)]
    pub secondary_index_key: DepositInfoEntryKey,
}

/// Key for deposit info entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositInfoEntryKey {
    /// The status of the deposit.
    #[serde(rename = "OpStatus")]
    pub status: Status,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: BlockHeight,
}

/// Reduced version of the deposit data.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositInfoEntry {
    /// Gsi key data.
    #[serde(flatten)]
    pub key: DepositInfoEntryKey,
    /// Primary index key data.
    #[serde(flatten)]
    pub primary_index_key: DepositEntryKey,
    /// Stacks address to received the deposited sBTC.
    pub recipient: StacksPrinciple,
    /// Amount of BTC being deposited.
    pub amount: Satoshis,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: StacksBlockHash,
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for DepositInfoEntryKey {
    /// The type of the partition key.
    type PartitionKey = Status;
    /// the type of the sort key.
    type SortKey = BlockHeight;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "OpStatus";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "LastUpdateHeight";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for DepositInfoEntry {
    /// The type of the key for this entry type.
    type Key = DepositInfoEntryKey;
    /// Extract the key from the deposit info entry.
    fn key(&self) -> Self::Key {
        DepositInfoEntryKey {
            status: self.key.status.clone(),
            last_update_height: self.key.last_update_height,
        }
    }
}

/// Primary index struct.
pub struct DepositTableSecondaryIndexInner;
/// Deposit table primary index type.
pub type DepositTableSecondaryIndex = SecondaryIndex<DepositTableSecondaryIndexInner>;
/// Definition of Primary index trait.
impl SecondaryIndexTrait for DepositTableSecondaryIndexInner {
    type PrimaryIndex = DepositTablePrimaryIndex;
    type Entry = DepositInfoEntry;
    const INDEX_NAME: &'static str = "DepositStatus";
}

impl From<DepositInfoEntry> for DepositInfo {
    fn from(deposit_info_entry: DepositInfoEntry) -> Self {
        // Create deposit info resource from deposit info table entry.
        DepositInfo {
            bitcoin_txid: deposit_info_entry.primary_index_key.bitcoin_txid,
            bitcoin_tx_output_index: deposit_info_entry.primary_index_key.bitcoin_tx_output_index,
            recipient: deposit_info_entry.recipient,
            amount: deposit_info_entry.amount,
            last_update_height: deposit_info_entry.key.last_update_height,
            last_update_block_hash: deposit_info_entry.last_update_block_hash,
            status: deposit_info_entry.key.status,
        }
    }
}

/// Validated version of the update deposit request.
pub struct ValidatedUpdateDepositsRequest {
    /// Validated deposit update requests.
    pub deposits: Vec<ValidatedDepositUpdate>,
}

/// Implement try from for the validated depoit requests.
impl TryFrom<UpdateDepositsRequestBody> for ValidatedUpdateDepositsRequest {
    type Error = Error;
    fn try_from(update_request: UpdateDepositsRequestBody) -> Result<Self, Self::Error> {
        // Validate all the depoit updates.
        let deposits = update_request
            .deposits
            .into_iter()
            .map(|i| i.try_into())
            .collect::<Result<_, Error>>()?;
        Ok(ValidatedUpdateDepositsRequest { deposits })
    }
}

/// Validated deposit update.
pub struct ValidatedDepositUpdate {
    /// Key.
    pub key: DepositEntryKey,
    /// Deposit event.
    pub event: DepositEvent,
}

impl TryFrom<DepositUpdate> for ValidatedDepositUpdate {
    type Error = Error;
    fn try_from(update: DepositUpdate) -> Result<Self, Self::Error> {
        // Make key.
        let key = DepositEntryKey {
            bitcoin_tx_output_index: update.bitcoin_tx_output_index,
            bitcoin_txid: update.bitcoin_txid,
        };
        // Make status entry.
        let status_entry: StatusEntry = match update.status {
            Status::Accepted => {
                let fulfillment = update.fulfillment.ok_or(Error::InternalServer)?;
                StatusEntry::Accepted(fulfillment)
            }
            Status::Confirmed => StatusEntry::Confirmed,
            Status::Pending => StatusEntry::Pending,
            Status::Reprocessing => StatusEntry::Reprocessing,
            Status::Failed => StatusEntry::Failed,
        };
        // Make the new event.
        let event = DepositEvent {
            status: status_entry,
            message: update.status_message,
            stacks_block_height: update.last_update_height,
            stacks_block_hash: update.last_update_block_hash,
        };
        // Return the validated update.
        Ok(ValidatedDepositUpdate { key, event })
    }
}

/// Packaged deposit update.
pub struct DepositUpdatePackage {
    /// Key.
    pub key: DepositEntryKey,
    /// Version.
    pub version: u64,
    /// Deposit event.
    pub event: DepositEvent,
}

/// Implementation of deposit update package.
impl DepositUpdatePackage {
    /// Implements from.
    pub fn try_from(entry: &DepositEntry, update: ValidatedDepositUpdate) -> Result<Self, Error> {
        // Ensure the keys are equal.
        if update.key != entry.key {
            return Err(Error::Debug(
                "Attempted to update deposit txid + output index combo".into(),
            ));
        }
        // Ensure that this event is valid if it follows the current latest event.
        entry
            .latest_event()?
            .ensure_following_event_is_valid(&update.event)?;
        // Create the deposit update package.
        Ok(DepositUpdatePackage {
            key: entry.key.clone(),
            version: entry.version,
            event: update.event,
        })
    }
}
