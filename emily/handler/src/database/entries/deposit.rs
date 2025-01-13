//! Entries into the deposit table.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    api::models::{
        chainstate::Chainstate,
        common::{Fulfillment, Status},
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
    pub bitcoin_txid: String,
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub bitcoin_tx_output_index: u32,
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
    pub recipient: String,
    /// Amount of BTC being deposited in satoshis.
    pub amount: u64,
    /// Deposit parameters.
    #[serde(flatten)]
    pub parameters: DepositParametersEntry,
    /// The status of the deposit.
    #[serde(rename = "OpStatus")]
    pub status: Status,
    /// The raw reclaim script.
    pub reclaim_script: String,
    /// The raw deposit script.
    pub deposit_script: String,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: u64,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
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
    type PartitionKey = String;
    /// the type of the sort key.
    type SortKey = u32;
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

    /// Reorgs around a given chainstate.
    /// TODO(TBD): Remove duplicate code around deposits and withdrawals if possible.
    pub fn reorganize_around(&mut self, chainstate: &Chainstate) -> Result<(), Error> {
        // Update the history to have the histories wiped after the reorg.
        self.history.retain(|event| {
            // The event is younger than the reorg...
            (chainstate.stacks_block_height > event.stacks_block_height)
                // Or the event is as old as the reorg and has the same block hash...
                || ((chainstate.stacks_block_height == event.stacks_block_height)
                    && (chainstate.stacks_block_hash == event.stacks_block_hash))
        });
        // If the history is empty, just say that the deposit is pending again where its
        // latest update is the point at which the reorg happened.
        if self.history.is_empty() {
            self.history = vec![DepositEvent {
                status: StatusEntry::Pending,
                message: "Reprocessing deposit status after reorg.".to_string(),
                stacks_block_height: chainstate.stacks_block_height,
                stacks_block_hash: chainstate.stacks_block_hash.clone(),
            }]
        }
        // Synchronize self with the new history.
        self.synchronize_with_history()?;
        // Return.
        Ok(())
    }

    /// Synchronizes the entry with its history.
    ///
    /// These entries contain an internal vector of history entries in chronological order.
    /// The last entry in the history vector is the latest entry, meaning the most up-to-date data.
    /// Within this last history are some fields that we want to be able to index into the
    /// table with; at the moment of writing this it's `status` and `last_update_height`.
    ///
    /// DynamoDB can only be sorted and indexed by top level fields, so in order to allow the table
    /// to be searchable by `status`` or ordered by `last_update_height`` there needs to be a top
    /// level field for it.
    ///
    /// This function takes the entry and then synchronizes the top level fields that should
    /// reflect the latest data in the history vector with the latest entry in the history vector.
    pub fn synchronize_with_history(&mut self) -> Result<(), Error> {
        // Get latest event.
        let latest_event: DepositEvent = self.latest_event()?.clone();
        // Calculate the new values.
        let new_status: Status = (&latest_event.status).into();
        let new_last_update_height: u64 = latest_event.stacks_block_height;

        // Set variables.
        if new_status == Status::Confirmed {
            self.fulfillment = match &latest_event.status {
                StatusEntry::Confirmed(fulfillment) => Some(fulfillment.clone()),
                _ => None,
            };
        } else {
            self.fulfillment = None;
        }
        self.status = new_status;
        self.last_update_height = new_last_update_height;
        self.last_update_block_hash = latest_event.stacks_block_hash;

        // Return.
        Ok(())
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
            StatusEntry::Confirmed(fulfillment) => Some(fulfillment.clone()),
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
            },
            reclaim_script: deposit_entry.reclaim_script,
            deposit_script: deposit_entry.deposit_script,
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
    pub max_fee: u64,
    /// Bitcoin block height at which the reclaim script becomes executable.
    pub lock_time: u32,
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
    pub stacks_block_height: u64,
    /// Stacks block hash associated with the height of this update.
    pub stacks_block_hash: String,
}

/// Implementation of deposit event.
impl DepositEvent {
    /// Errors if the next event provided could not follow the current one.
    pub fn ensure_following_event_is_valid(&self, next_event: &DepositEvent) -> Result<(), Error> {
        // Determine if event is valid.
        if self.stacks_block_height > next_event.stacks_block_height {
            let err_msg = format!(
                "Attempting to update a deposit with a block height earlier than it should be.\n
                latest_existing_event:\n{self:?}\n
                newest_event:\n{next_event:?}"
            );
            return Err(Error::InconsistentState(Inconsistency::ItemUpdate(err_msg)));
        } else if self.stacks_block_height == next_event.stacks_block_height
            && self.stacks_block_hash != next_event.stacks_block_hash
        {
            let err_msg = format!(
                "Attempting to update a deposit with a block height and hash that conflicts with its current history.\n
                latest_existing_event:\n{self:?}\n
                newest_event:\n{next_event:?}"
            );
            return Err(Error::InconsistentState(Inconsistency::ItemUpdate(err_msg)));
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
    pub last_update_height: u64,
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
    pub recipient: String,
    /// Amount of BTC being deposited in satoshis.
    pub amount: u64,
    /// The raw reclaim script.
    pub reclaim_script: String,
    /// The raw deposit script.
    pub deposit_script: String,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for DepositInfoEntryKey {
    /// The type of the partition key.
    type PartitionKey = Status;
    /// the type of the sort key.
    type SortKey = u64;
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
            reclaim_script: deposit_info_entry.reclaim_script,
            deposit_script: deposit_info_entry.deposit_script,
        }
    }
}

// Deposit info by recipient entry ---------------------------------------------

/// Search token for recipient GSI.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositInfoByRecipientEntrySearchToken {
    /// Primary index key.
    #[serde(flatten)]
    pub primary_index_key: DepositEntryKey,
    /// Global secondary index key.
    #[serde(flatten)]
    pub secondary_index_key: DepositInfoByRecipientEntryKey,
}

/// Key for deposit info entry that's indexed by recipient.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositInfoByRecipientEntryKey {
    /// The recipient of the deposit.
    pub recipient: String,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: u64,
}

/// Reduced version of the deposit data that is indexed by recipient.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DepositInfoByRecipientEntry {
    /// Gsi key data.
    #[serde(flatten)]
    pub key: DepositInfoByRecipientEntryKey,
    /// Primary index key data.
    #[serde(flatten)]
    pub primary_index_key: DepositEntryKey,
    /// The status of the entry.
    #[serde(rename = "OpStatus")]
    pub status: Status,
    /// Amount of BTC being deposited in satoshis.
    pub amount: u64,
    /// The raw reclaim script.
    pub reclaim_script: String,
    /// The raw deposit script.
    pub deposit_script: String,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
}

/// Implements the key trait for the deposit entry key.
impl KeyTrait for DepositInfoByRecipientEntryKey {
    /// The type of the partition key.
    type PartitionKey = String;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "Recipient";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "LastUpdateHeight";
}

/// Implements the entry trait for the deposit entry.
impl EntryTrait for DepositInfoByRecipientEntry {
    /// The type of the key for this entry type.
    type Key = DepositInfoByRecipientEntryKey;
    /// Extract the key from the deposit info entry.
    fn key(&self) -> Self::Key {
        DepositInfoByRecipientEntryKey {
            recipient: self.key.recipient.clone(),
            last_update_height: self.key.last_update_height,
        }
    }
}

/// Primary index struct.
pub struct DepositTableByRecipientSecondaryIndexInner;
/// Deposit table primary index type.
pub type DepositTableByRecipientSecondaryIndex =
    SecondaryIndex<DepositTableByRecipientSecondaryIndexInner>;
/// Definition of Primary index trait.
impl SecondaryIndexTrait for DepositTableByRecipientSecondaryIndexInner {
    type PrimaryIndex = DepositTablePrimaryIndex;
    type Entry = DepositInfoByRecipientEntry;
    const INDEX_NAME: &'static str = "DepositRecipient";
}

impl From<DepositInfoByRecipientEntry> for DepositInfo {
    fn from(deposit_info_entry: DepositInfoByRecipientEntry) -> Self {
        // Create deposit info resource from deposit info table entry.
        DepositInfo {
            bitcoin_txid: deposit_info_entry.primary_index_key.bitcoin_txid,
            bitcoin_tx_output_index: deposit_info_entry.primary_index_key.bitcoin_tx_output_index,
            recipient: deposit_info_entry.key.recipient,
            amount: deposit_info_entry.amount,
            last_update_height: deposit_info_entry.key.last_update_height,
            last_update_block_hash: deposit_info_entry.last_update_block_hash,
            status: deposit_info_entry.status,
            reclaim_script: deposit_info_entry.reclaim_script,
            deposit_script: deposit_info_entry.deposit_script,
        }
    }
}

// -----------------------------------------------------------------------------

/// Validated version of the update deposit request.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct ValidatedUpdateDepositsRequest {
    /// Validated deposit update requests where each update request is in chronoloical order
    /// of when the update should have occurred, but where the first value of the tuple is the
    /// index of the update in the original request.
    ///
    /// This allows the updates to be executed in chronological order but returned in the order
    /// that the client sent them.
    pub deposits: Vec<(usize, ValidatedDepositUpdate)>,
}

/// Implement try from for the validated deposit requests.
impl TryFrom<UpdateDepositsRequestBody> for ValidatedUpdateDepositsRequest {
    type Error = Error;
    fn try_from(update_request: UpdateDepositsRequestBody) -> Result<Self, Self::Error> {
        // Validate all the depoit updates.
        let mut deposits: Vec<(usize, ValidatedDepositUpdate)> = update_request
            .deposits
            .into_iter()
            .enumerate()
            .map(|(index, update)| {
                update
                    .try_into()
                    .map(|validated_update| (index, validated_update))
            })
            .collect::<Result<_, Error>>()?;

        // Order the updates by order of when they occur so that it's as though we got them in
        // chronological order.
        deposits.sort_by_key(|(_, update)| update.event.stacks_block_height);

        Ok(ValidatedUpdateDepositsRequest { deposits })
    }
}

impl ValidatedUpdateDepositsRequest {
    /// Infers all chainstates that need to be present in the API for the
    /// deposit updates to be valid.
    pub fn inferred_chainstates(&self) -> Result<Vec<Chainstate>, Error> {
        // TODO(TBD): Error if the inferred chainstates have conflicting block hashes
        // for a the same block height.
        let mut inferred_chainstates = self
            .deposits
            .clone()
            .into_iter()
            .map(|(_, update)| Chainstate {
                stacks_block_hash: update.event.stacks_block_hash,
                stacks_block_height: update.event.stacks_block_height,
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        // Sort the chainsates in the order that they should come in.
        inferred_chainstates.sort_by_key(|chainstate| chainstate.stacks_block_height);

        // Return.
        Ok(inferred_chainstates)
    }
}

/// Validated deposit update.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash)]
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
            Status::Confirmed => {
                let fulfillment = update.fulfillment.ok_or(Error::InternalServer)?;
                StatusEntry::Confirmed(fulfillment)
            }
            Status::Accepted => StatusEntry::Accepted,
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

impl ValidatedDepositUpdate {
    /// Returns true if the update is not necessary.
    pub fn is_unnecessary(&self, entry: &DepositEntry) -> bool {
        entry
            .history
            .iter()
            .rev()
            .take_while(|event| event.stacks_block_height >= self.event.stacks_block_height)
            .any(|event| event == &self.event)
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

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test]
    fn deposit_update_should_be_unnecessary_when_event_is_present() {
        let pending = DepositEvent {
            status: StatusEntry::Pending,
            message: "".to_string(),
            stacks_block_height: 0,
            stacks_block_hash: "".to_string(),
        };

        let accepted = DepositEvent {
            status: StatusEntry::Accepted,
            message: "".to_string(),
            stacks_block_height: 1,
            stacks_block_hash: "".to_string(),
        };

        let deposit = DepositEntry {
            key: Default::default(),
            version: 0,
            recipient: "".to_string(),
            amount: 0,
            parameters: Default::default(),
            status: Status::Pending,
            reclaim_script: "".to_string(),
            deposit_script: "".to_string(),
            last_update_height: 0,
            last_update_block_hash: "".to_string(),
            fulfillment: None,
            history: vec![pending, accepted.clone()],
        };

        let update = ValidatedDepositUpdate {
            key: Default::default(),
            event: accepted,
        };

        assert!(update.is_unnecessary(&deposit));
    }

    #[test]
    fn deposit_update_should_be_necessary_when_event_is_not_present() {
        let pending = DepositEvent {
            status: StatusEntry::Pending,
            message: "".to_string(),
            stacks_block_height: 0,
            stacks_block_hash: "".to_string(),
        };

        let accepted = DepositEvent {
            status: StatusEntry::Accepted,
            message: "".to_string(),
            stacks_block_height: 1,
            stacks_block_hash: "".to_string(),
        };

        let deposit = DepositEntry {
            key: Default::default(),
            version: 0,
            recipient: "".to_string(),
            amount: 0,
            parameters: Default::default(),
            status: Status::Pending,
            reclaim_script: "".to_string(),
            deposit_script: "".to_string(),
            last_update_height: 0,
            last_update_block_hash: "".to_string(),
            fulfillment: None,
            history: vec![pending.clone()],
        };

        let update = ValidatedDepositUpdate {
            key: Default::default(),
            event: accepted,
        };

        assert!(!update.is_unnecessary(&deposit));
    }

    #[test_case(0, "hash0", 0, "hash0", StatusEntry::Pending; "reorg around genesis sets status to pending at genesis")]
    #[test_case(5, "hash5", 4, "hash4", StatusEntry::Accepted; "reorg goes to earliest canonical event 1")]
    #[test_case(4, "hash4", 4, "hash4", StatusEntry::Accepted; "reorg setting a height consistent with an event keeps it")]
    #[test_case(4, "hash4-1", 2, "hash2", StatusEntry::Pending; "reorg setting a height inconsistent with an event removes it")]
    #[test_case(3, "hash3", 2, "hash2", StatusEntry::Pending; "reorg  goes to earliest canonical event 2")]
    fn reorganizing_around_a_new_chainstate_results_in_valid_deposit(
        reorg_height: u64,
        reorg_hash: &str,
        expected_height: u64,
        expected_hash: &str,
        expected_status: StatusEntry,
    ) {
        let pending = DepositEvent {
            status: StatusEntry::Pending,
            message: "initial test pending".to_string(),
            stacks_block_height: 2,
            stacks_block_hash: "hash2".to_string(),
        };

        let accepted = DepositEvent {
            status: StatusEntry::Accepted,
            message: "accepted".to_string(),
            stacks_block_height: 4,
            stacks_block_hash: "hash4".to_string(),
        };

        let fulfillment: Fulfillment = Default::default();
        let confirmed = DepositEvent {
            status: StatusEntry::Confirmed(fulfillment.clone()),
            message: "confirmed".to_string(),
            stacks_block_height: 6,
            stacks_block_hash: "hash6".to_string(),
        };

        let mut deposit = DepositEntry {
            key: Default::default(),
            version: 3,
            recipient: "test-recipient".to_string(),
            amount: 100,
            parameters: Default::default(),
            status: (&confirmed.status).into(),
            reclaim_script: "test-reclaim".to_string(),
            deposit_script: "test-deposit".to_string(),
            last_update_height: 6,
            last_update_block_hash: "hash6".to_string(),
            fulfillment: Some(fulfillment.clone()),
            history: vec![pending.clone(), accepted.clone(), confirmed.clone()],
        };

        // Ensure the deposit is valid.
        assert!(
            deposit.validate().is_ok(),
            "Test deposit must be valid before reorg.",
        );

        // Reorganize around a new chainstate.
        let chainstate = Chainstate {
            stacks_block_height: reorg_height,
            stacks_block_hash: reorg_hash.to_string(),
        };
        deposit.reorganize_around(&chainstate).unwrap();

        // Ensure the deposit is valid.
        assert!(
            deposit.validate().is_ok(),
            "Deposit must be valid after reorg.",
        );

        // Check latest height.
        assert_eq!(deposit.last_update_height, expected_height);
        assert_eq!(deposit.last_update_block_hash, expected_hash);
        assert_eq!(deposit.status, (&expected_status).into());

        let latest_event = deposit
            .latest_event()
            .expect("must have latest event")
            .clone();
        assert_eq!(latest_event.stacks_block_height, expected_height);
        assert_eq!(latest_event.stacks_block_hash, expected_hash);
        assert_eq!(latest_event.status, expected_status);
    }
}
