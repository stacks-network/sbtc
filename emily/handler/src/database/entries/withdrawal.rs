//! Entries into the withdrawal table.

use serde::{Deserialize, Serialize};

use crate::{
    api::models::{
        common::{BitcoinAddress, BlockHeight, Satoshis, StacksBlockHash, StacksPrinciple, Status},
        withdrawal::{
            requests::{UpdateWithdrawalsRequestBody, WithdrawalUpdate},
            Withdrawal, WithdrawalId, WithdrawalInfo, WithdrawalParameters,
        },
    },
    common::error::{Error, Inconsistency},
};

use super::{
    EntryTrait, KeyTrait, PrimaryIndex, PrimaryIndexTrait, SecondaryIndex, SecondaryIndexTrait,
    StatusEntry, VersionedEntryTrait,
};

// Withdrawal entry ---------------------------------------------------------------

/// Withdrawal table entry key. This is the root table key.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalEntryKey {
    /// The request id of the withdrawal.
    pub request_id: WithdrawalId,
    /// The stacks block hash of the block in which this withdrawal was initiated.
    pub stacks_block_hash: StacksBlockHash,
}

/// Withdrawal table entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalEntry {
    /// Withdrawal table entry key.
    #[serde(flatten)]
    pub key: WithdrawalEntryKey,
    /// The height of the Stacks block in which this request id was initiated.
    pub stacks_block_height: BlockHeight,
    /// Table entry version. Updated on each alteration.
    pub version: u64,
    /// Stacks address to received the withdrawn sBTC.
    pub recipient: BitcoinAddress,
    /// Amount of BTC being withdrawn.
    pub amount: Satoshis,
    /// Withdrawal parameters.
    #[serde(flatten)]
    pub parameters: WithdrawalParametersEntry,
    /// The status of the withdrawal.
    #[serde(rename = "OpStatus")]
    pub status: Status,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: BlockHeight,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: StacksBlockHash,
    /// History of this withdrawal transaction.
    pub history: Vec<WithdrawalEvent>,
}

/// Implements versioned entry trait for the deposit entry.
impl VersionedEntryTrait for WithdrawalEntry {
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

/// Implementation of withdrawal entry.
impl WithdrawalEntry {
    /// Implement validate.
    pub fn validate(&self) -> Result<(), Error> {
        let stringy_self = serde_json::to_string(self)?;

        // Get latest event.
        let latest_event: &WithdrawalEvent = self.history.last().ok_or(Error::Debug(format!(
            "Failed getting the last history element for withdrawal. {stringy_self:?}"
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
    pub fn latest_event(&self) -> Result<&WithdrawalEvent, Error> {
        self.history.last().ok_or(Error::Debug(format!(
            "Withdrawal entry must always have at least one event, but entry with id {:?} did not.",
            self.key(),
        )))
    }
}

impl TryFrom<WithdrawalEntry> for Withdrawal {
    type Error = Error;
    fn try_from(withdrawal_entry: WithdrawalEntry) -> Result<Self, Self::Error> {
        // Ensure entry is valid.
        withdrawal_entry.validate()?;

        // Extract data from the latest event.
        let latest_event = withdrawal_entry.latest_event()?;
        let status_message = latest_event.message.clone();
        let status: Status = (&latest_event.status).into();
        let fulfillment = match &latest_event.status {
            StatusEntry::Accepted(fulfillment) => Some(fulfillment.clone()),
            _ => None,
        };

        // Create withdrawal from table entry.
        Ok(Withdrawal {
            request_id: withdrawal_entry.key.request_id,
            stacks_block_hash: withdrawal_entry.key.stacks_block_hash,
            stacks_block_height: withdrawal_entry.stacks_block_height,
            recipient: withdrawal_entry.recipient,
            amount: withdrawal_entry.amount,
            last_update_height: withdrawal_entry.last_update_height,
            last_update_block_hash: withdrawal_entry.last_update_block_hash,
            status,
            status_message,
            parameters: WithdrawalParameters {
                max_fee: withdrawal_entry.parameters.max_fee,
            },
            fulfillment,
        })
    }
}

/// Withdrawal parameters entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalParametersEntry {
    /// Maximum fee the signers are allowed to take from the withdrawal to facilitate
    /// the transaction.
    pub max_fee: Satoshis,
}

/// Event in the history of a withdrawal.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalEvent {
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

/// Implementation of withdrawal event.
impl WithdrawalEvent {
    /// Errors if the next event provided could not follow the current one.
    pub fn ensure_following_event_is_valid(
        &self,
        next_event: &WithdrawalEvent,
    ) -> Result<(), Error> {
        // Determine if event is valid.
        if self.stacks_block_height > next_event.stacks_block_height {
            return Err(Error::InconsistentState(Inconsistency::ItemUpdate(
                "Attempting to update a withdrawal with a block height earlier than it should be."
                    .into(),
            )));
        } else if self.stacks_block_height == next_event.stacks_block_height
            && self.stacks_block_hash != next_event.stacks_block_hash
        {
            return Err(Error::InconsistentState(Inconsistency::ItemUpdate(
                "Attempting to update a withdrawal with a block height and hash that conflicts with the current history."
                    .into(),
            )));
        }

        Ok(())
    }
}

/// Implements the key trait for the withdrawal entry key.
impl KeyTrait for WithdrawalEntryKey {
    /// The type of the partition key.
    type PartitionKey = u64;
    /// the type of the sort key.
    type SortKey = StacksBlockHash;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "RequestId";
    /// The table field name of the sort key.
    const _SORT_KEY_NAME: &'static str = "StacksBlockHash";
}

/// Implements the entry trait for the withdrawal entry.
impl EntryTrait for WithdrawalEntry {
    /// The type of the key for this entry type.
    type Key = WithdrawalEntryKey;
    /// Extract the key from the withdrawal entry.
    fn key(&self) -> Self::Key {
        WithdrawalEntryKey {
            request_id: self.key.request_id,
            stacks_block_hash: self.key.stacks_block_hash.clone(),
        }
    }
}

/// Primary index struct.
pub struct WithdrawalTablePrimaryIndexInner;
/// Withdrawal table primary index type.
pub type WithdrawalTablePrimaryIndex = PrimaryIndex<WithdrawalTablePrimaryIndexInner>;
/// Definition of Primary index trait.
impl PrimaryIndexTrait for WithdrawalTablePrimaryIndexInner {
    type Entry = WithdrawalEntry;
    fn table_name(settings: &crate::context::Settings) -> &str {
        &settings.withdrawal_table_name
    }
}

// Withdrawal info entry ----------------------------------------------------------

/// Search token for GSI.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalInfoEntrySearchToken {
    /// Primary index key.
    #[serde(flatten)]
    pub primary_index_key: WithdrawalEntryKey,
    /// Global secondary index key.
    #[serde(flatten)]
    pub secondary_index_key: WithdrawalInfoEntryKey,
}

/// Key for withdrawal info entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalInfoEntryKey {
    /// The status of the withdrawal.
    #[serde(rename = "OpStatus")]
    pub status: Status,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: BlockHeight,
}

/// Reduced version of the withdrawal data.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalInfoEntry {
    /// Secondary index key. This is what's used to search for this particular item.
    #[serde(flatten)]
    pub key: WithdrawalInfoEntryKey,
    /// Primary index key. This is what's used to search the main table.
    #[serde(flatten)]
    pub primary_index_key: WithdrawalEntryKey,
    /// The height of the Stacks block in which this request id was initiated.
    pub stacks_block_height: BlockHeight,
    /// Stacks address to received the withdrawn sBTC.
    pub recipient: StacksPrinciple,
    /// Amount of BTC being withdrawn.
    pub amount: Satoshis,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: StacksBlockHash,
}

/// Implements the key trait for the withdrawal info entry key.
impl KeyTrait for WithdrawalInfoEntryKey {
    /// The type of the partition key.
    type PartitionKey = Status;
    /// the type of the sort key.
    type SortKey = BlockHeight;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "OpStatus";
    /// The table field name of the sort key.
    const _SORT_KEY_NAME: &'static str = "LastUpdateHeight";
}

/// Implements the entry trait for the withdrawal info entry.
impl EntryTrait for WithdrawalInfoEntry {
    /// The type of the key for this entry type.
    type Key = WithdrawalInfoEntryKey;
    /// Extract the key from the withdrawal info entry.
    fn key(&self) -> Self::Key {
        WithdrawalInfoEntryKey {
            status: self.key.status.clone(),
            last_update_height: self.key.last_update_height,
        }
    }
}

/// Primary index struct.
pub struct WithdrawalTableSecondaryIndexInner;
/// Withdrawal table primary index type.
pub type WithdrawalTableSecondaryIndex = SecondaryIndex<WithdrawalTableSecondaryIndexInner>;
/// Definition of Primary index trait.
impl SecondaryIndexTrait for WithdrawalTableSecondaryIndexInner {
    type PrimaryIndex = WithdrawalTablePrimaryIndex;
    type Entry = WithdrawalInfoEntry;
    const INDEX_NAME: &'static str = "WithdrawalStatus";
}

impl From<WithdrawalInfoEntry> for WithdrawalInfo {
    fn from(withdrawal_info_entry: WithdrawalInfoEntry) -> Self {
        // Create withdrawal info resource from withdrawal info table entry.
        WithdrawalInfo {
            request_id: withdrawal_info_entry.primary_index_key.request_id,
            stacks_block_hash: withdrawal_info_entry.primary_index_key.stacks_block_hash,
            stacks_block_height: withdrawal_info_entry.stacks_block_height,
            recipient: withdrawal_info_entry.recipient,
            amount: withdrawal_info_entry.amount,
            last_update_height: withdrawal_info_entry.key.last_update_height,
            last_update_block_hash: withdrawal_info_entry.last_update_block_hash,
            status: withdrawal_info_entry.key.status,
        }
    }
}

/// Validated version of the update withdrawal request.
pub struct ValidatedUpdateWithdrawalRequest {
    /// Validated withdrawal update requests.
    pub withdrawals: Vec<ValidatedWithdrawalUpdate>,
}

/// Implement try from for the validated depoit requests.
impl TryFrom<UpdateWithdrawalsRequestBody> for ValidatedUpdateWithdrawalRequest {
    type Error = Error;
    fn try_from(update_request: UpdateWithdrawalsRequestBody) -> Result<Self, Self::Error> {
        // Validate all the depoit updates.
        let withdrawals = update_request
            .withdrawals
            .into_iter()
            .map(|i| i.try_into())
            .collect::<Result<_, Error>>()?;
        Ok(ValidatedUpdateWithdrawalRequest { withdrawals })
    }
}

/// Validated withdrawal update.
pub struct ValidatedWithdrawalUpdate {
    /// Key.
    pub request_id: WithdrawalId,
    /// Withdrawal event.
    pub event: WithdrawalEvent,
}

impl TryFrom<WithdrawalUpdate> for ValidatedWithdrawalUpdate {
    type Error = Error;
    fn try_from(update: WithdrawalUpdate) -> Result<Self, Self::Error> {
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
        let event = WithdrawalEvent {
            status: status_entry,
            message: update.status_message,
            stacks_block_height: update.last_update_height,
            stacks_block_hash: update.last_update_block_hash,
        };
        // Return the validated update.
        Ok(ValidatedWithdrawalUpdate {
            request_id: update.request_id,
            event,
        })
    }
}

/// Packaged withdrawal update.
pub struct WithdrawalUpdatePackage {
    /// Key.
    pub key: WithdrawalEntryKey,
    /// Version.
    pub version: u64,
    /// Withdrawal event.
    pub event: WithdrawalEvent,
}

/// Implementation of withdrawal update package.
impl WithdrawalUpdatePackage {
    /// Implements from.
    pub fn try_from(
        entry: &WithdrawalEntry,
        update: ValidatedWithdrawalUpdate,
    ) -> Result<Self, Error> {
        // Ensure the keys are equal.
        if update.request_id != entry.key.request_id {
            return Err(Error::Debug(
                "Attempted to update withdrawal request_id combo.".into(),
            ));
        }
        // Ensure that this event is valid if it follows the current latest event.
        entry
            .latest_event()?
            .ensure_following_event_is_valid(&update.event)?;
        // Create the withdrawal update package.
        Ok(WithdrawalUpdatePackage {
            key: entry.key.clone(),
            version: entry.version,
            event: update.event,
        })
    }
}
