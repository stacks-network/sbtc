//! Entries into the withdrawal table.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    api::models::{
        chainstate::Chainstate,
        common::Status,
        withdrawal::{
            requests::{UpdateWithdrawalsRequestBody, WithdrawalUpdate},
            Withdrawal, WithdrawalInfo, WithdrawalParameters,
        },
    },
    common::error::{Error, Inconsistency, ValidationError},
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
    pub request_id: u64,
    /// The stacks block hash of the block in which this withdrawal was initiated.
    pub stacks_block_hash: String,
}

/// Withdrawal table entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalEntry {
    /// Withdrawal table entry key.
    #[serde(flatten)]
    pub key: WithdrawalEntryKey,
    /// The height of the Stacks block in which this request id was initiated.
    pub stacks_block_height: u64,
    /// Table entry version. Updated on each alteration.
    pub version: u64,
    /// The recipient's Bitcoin hex-encoded scriptPubKey.
    pub recipient: String,
    /// Amount of BTC being withdrawn in satoshis.
    pub amount: u64,
    /// Withdrawal parameters.
    #[serde(flatten)]
    pub parameters: WithdrawalParametersEntry,
    /// The status of the withdrawal.
    #[serde(rename = "OpStatus")]
    pub status: Status,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: u64,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
    /// History of this withdrawal transaction.
    pub history: Vec<WithdrawalEvent>,
}

/// Implements versioned entry trait for the withdrawal entry.
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

    /// Reorgs around a given chainstate.
    /// TODO(TBD): Remove duplicate code around withdrawals and withdrawals if possible.
    pub fn reorganize_around(&mut self, chainstate: &Chainstate) -> Result<(), Error> {
        // Update the history to have the histories wiped after the reorg.
        self.history.retain(|event| {
            // The event is younger than the reorg...
            (chainstate.stacks_block_height > event.stacks_block_height)
                // Or the event is as old as the reorg and has the same block hash...
                || ((chainstate.stacks_block_height == event.stacks_block_height)
                    && (chainstate.stacks_block_hash == event.stacks_block_hash))
        });
        // If the history is empty, just say that the withdrawal is pending again where its
        // latest update is the point at which the reorg happened.
        if self.history.is_empty() {
            self.history = vec![WithdrawalEvent {
                status: StatusEntry::Pending,
                message: "Reprocessing withdrawal status after reorg.".to_string(),
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
    /// to be searchable by `status` or ordered by `last_update_height` there needs to be a top
    /// level field for it.
    ///
    /// This function takes the entry and then synchronizes the top level fields that should
    /// reflect the latest data in the history vector with the latest entry in the history vector.
    pub fn synchronize_with_history(&mut self) -> Result<(), Error> {
        // Get latest event.
        let latest_event = self.latest_event()?.clone();
        // Calculate the new values.
        let new_status: Status = (&latest_event.status).into();
        let new_last_update_height: u64 = latest_event.stacks_block_height;
        // Set variables.
        self.status = new_status;
        self.last_update_height = new_last_update_height;
        self.last_update_block_hash = latest_event.stacks_block_hash.clone();
        // Return.
        Ok(())
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
            StatusEntry::Confirmed(fulfillment) => Some(fulfillment.clone()),
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
    pub max_fee: u64,
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
    /// Stacks block height at the time of this update.
    pub stacks_block_height: u64,
    /// Stacks block hash associated with the height of this update.
    pub stacks_block_hash: String,
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
    type SortKey = String;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "RequestId";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "StacksBlockHash";
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

/// Secondary index struct.
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
    pub last_update_height: u64,
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
    pub stacks_block_height: u64,
    /// The recipient's Bitcoin hex-encoded scriptPubKey.
    pub recipient: String,
    /// Amount of BTC being withdrawn in satoshis.
    pub amount: u64,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
}

/// Implements the key trait for the withdrawal info entry key.
impl KeyTrait for WithdrawalInfoEntryKey {
    /// The type of the partition key.
    type PartitionKey = Status;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "OpStatus";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "LastUpdateHeight";
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

/// Secondary index struct.
pub struct WithdrawalTableSecondaryIndexInner;
/// Withdrawal table secondary index type.
pub type WithdrawalTableSecondaryIndex = SecondaryIndex<WithdrawalTableSecondaryIndexInner>;
/// Definition of secondary index trait.
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

/// Search token for WithdrawalRecipient GSI.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalInfoByRecipientEntrySearchToken {
    /// Primary index key.
    #[serde(flatten)]
    pub primary_index_key: WithdrawalEntryKey,
    /// Global secondary index key.
    #[serde(flatten)]
    pub secondary_index_key: WithdrawalInfoByRecipientEntryKey,
}

/// Key for withdrawal info entry that's indexed by recipient.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalInfoByRecipientEntryKey {
    /// The recipient's Bitcoin hex-encoded scriptPubKey.
    pub recipient: String,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: u64,
}

/// Reduced version of the withdrawal data.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithdrawalInfoByRecipientEntry {
    /// Secondary index key. This is what's used to search for this particular item.
    #[serde(flatten)]
    pub key: WithdrawalInfoByRecipientEntryKey,
    /// Primary index key. This is what's used to search the main table.
    #[serde(flatten)]
    pub primary_index_key: WithdrawalEntryKey,
    /// The height of the Stacks block in which this request id was initiated.
    pub stacks_block_height: u64,
    /// The status of the entry.
    #[serde(rename = "OpStatus")]
    pub status: Status,
    /// Amount of BTC being withdrawn in satoshis.
    pub amount: u64,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
}

/// Implements the key trait for the withdrawal info entry key.
impl KeyTrait for WithdrawalInfoByRecipientEntryKey {
    /// The type of the partition key.
    type PartitionKey = String;
    /// the type of the sort key.
    type SortKey = u64;
    /// The table field name of the partition key.
    const PARTITION_KEY_NAME: &'static str = "Recipient";
    /// The table field name of the sort key.
    const SORT_KEY_NAME: &'static str = "LastUpdateHeight";
}

/// Implements the entry trait for the withdrawal info entry.
impl EntryTrait for WithdrawalInfoByRecipientEntry {
    /// The type of the key for this entry type.
    type Key = WithdrawalInfoByRecipientEntryKey;
    /// Extract the key from the withdrawal info entry.
    fn key(&self) -> Self::Key {
        WithdrawalInfoByRecipientEntryKey {
            recipient: self.key.recipient.clone(),
            last_update_height: self.key.last_update_height,
        }
    }
}

/// Secondary index struct.
pub struct WithdrawalTableByRecipientSecondaryIndexInner;
/// Withdrawal table secondary index type.
pub type WithdrawalTableByRecipientSecondaryIndex =
    SecondaryIndex<WithdrawalTableByRecipientSecondaryIndexInner>;
/// Definition of secondary index trait.
impl SecondaryIndexTrait for WithdrawalTableByRecipientSecondaryIndexInner {
    type PrimaryIndex = WithdrawalTablePrimaryIndex;
    type Entry = WithdrawalInfoByRecipientEntry;
    const INDEX_NAME: &'static str = "WithdrawalRecipient";
}

impl From<WithdrawalInfoByRecipientEntry> for WithdrawalInfo {
    fn from(withdrawal_info_entry: WithdrawalInfoByRecipientEntry) -> Self {
        // Create withdrawal info resource from withdrawal info table entry.
        WithdrawalInfo {
            request_id: withdrawal_info_entry.primary_index_key.request_id,
            stacks_block_hash: withdrawal_info_entry.primary_index_key.stacks_block_hash,
            stacks_block_height: withdrawal_info_entry.stacks_block_height,
            recipient: withdrawal_info_entry.key.recipient,
            amount: withdrawal_info_entry.amount,
            last_update_height: withdrawal_info_entry.key.last_update_height,
            last_update_block_hash: withdrawal_info_entry.last_update_block_hash,
            status: withdrawal_info_entry.status,
        }
    }
}

/// Validated version of the update withdrawal request.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct ValidatedUpdateWithdrawalRequest {
    /// Validated withdrawal update requests where each update request is in chronological order
    /// of when the update should have occurred, but where the first value of the tuple is the
    /// index of the update in the original request.
    ///
    /// This allows the updates to be executed in chronological order but returned in the order
    /// that the client sent them.
    pub withdrawals: Vec<(usize, ValidatedWithdrawalUpdate)>,
}

/// Implement try from for the validated withdrawal requests.
impl TryFrom<UpdateWithdrawalsRequestBody> for ValidatedUpdateWithdrawalRequest {
    type Error = Error;
    fn try_from(update_request: UpdateWithdrawalsRequestBody) -> Result<Self, Self::Error> {
        // Validate all the withdrawal updates.
        let mut withdrawals: Vec<(usize, ValidatedWithdrawalUpdate)> = vec![];
        let mut failed_ids: Vec<u64> = vec![];

        for (index, update) in update_request.withdrawals.into_iter().enumerate() {
            match update.clone().try_into() {
                Ok(validated_update) => withdrawals.push((index, validated_update)),
                Err(_) => failed_ids.push(update.request_id),
            }
        }

        // If there are failed conversion, return an error.
        if !failed_ids.is_empty() {
            return Err(ValidationError::WithdrawalsMissingFulfillment(failed_ids).into());
        }

        // Order the updates by order of when they occur so that it's as though we got them in
        // chronological order.
        withdrawals.sort_by_key(|(_, update)| update.event.stacks_block_height);

        Ok(ValidatedUpdateWithdrawalRequest { withdrawals })
    }
}

impl ValidatedUpdateWithdrawalRequest {
    /// Infers all chainstates that need to be present in the API for the
    /// withdrawal updates to be valid.
    pub fn inferred_chainstates(&self) -> Vec<Chainstate> {
        // TODO(TBD): Error if the inferred chainstates have conflicting block hashes
        // for a the same block height.
        let mut inferred_chainstates = self
            .withdrawals
            .clone()
            .into_iter()
            .map(|(_, update)| Chainstate {
                stacks_block_hash: update.event.stacks_block_hash,
                stacks_block_height: update.event.stacks_block_height,
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        // Sort the chainstates in the order that they should come in.
        inferred_chainstates.sort_by_key(|chainstate| chainstate.stacks_block_height);

        // Return.
        inferred_chainstates
    }
}

/// Validated withdrawal update.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct ValidatedWithdrawalUpdate {
    /// Key.
    pub request_id: u64,
    /// Withdrawal event.
    pub event: WithdrawalEvent,
}

impl TryFrom<WithdrawalUpdate> for ValidatedWithdrawalUpdate {
    type Error = ValidationError;

    fn try_from(update: WithdrawalUpdate) -> Result<Self, Self::Error> {
        // Make status entry.
        let status_entry: StatusEntry = match update.status {
            Status::Confirmed => {
                let fulfillment =
                    update
                        .fulfillment
                        .ok_or(ValidationError::WithdrawalMissingFulfillment(
                            update.request_id,
                        ))?;
                StatusEntry::Confirmed(fulfillment)
            }
            Status::Accepted => StatusEntry::Accepted,
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

impl ValidatedWithdrawalUpdate {
    /// Returns true if the update is not necessary.
    pub fn is_unnecessary(&self, entry: &WithdrawalEntry) -> bool {
        entry
            .history
            .iter()
            .rev()
            .take_while(|event| event.stacks_block_height >= self.event.stacks_block_height)
            .any(|event| event == &self.event)
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

#[cfg(test)]
mod tests {
    use crate::api::models::chainstate::Chainstate;
    use crate::api::models::common::Fulfillment;
    use crate::database::entries::StatusEntry;
    use crate::{
        api::models::common::Status,
        database::entries::withdrawal::{
            ValidatedWithdrawalUpdate, WithdrawalEntry, WithdrawalEntryKey, WithdrawalEvent,
            WithdrawalParametersEntry,
        },
    };
    use test_case::test_case;

    #[test]
    fn withdrawal_update_should_be_unnecessary_when_event_is_present() {
        // Arrange
        let pending = WithdrawalEvent {
            status: StatusEntry::Pending,
            message: "message".to_string(),
            stacks_block_height: 1,
            stacks_block_hash: "hash".to_string(),
        };

        let failed = WithdrawalEvent {
            status: StatusEntry::Failed,
            message: "message".to_string(),
            stacks_block_height: 2,
            stacks_block_hash: "hash".to_string(),
        };

        let withdrawal_entry = WithdrawalEntry {
            key: WithdrawalEntryKey {
                request_id: 1,
                stacks_block_hash: "hash".to_string(),
            },
            stacks_block_height: 1,
            version: 1,
            recipient: "recipient".to_string(),
            amount: 1,
            parameters: WithdrawalParametersEntry { max_fee: 1 },
            status: Status::Pending,
            last_update_height: 1,
            last_update_block_hash: "hash".to_string(),
            history: vec![pending, failed.clone()],
        };

        let withdrawal_update = ValidatedWithdrawalUpdate { request_id: 1, event: failed };

        // Act
        let is_unnecessary = withdrawal_update.is_unnecessary(&withdrawal_entry);

        // Assert
        assert!(is_unnecessary);
    }

    #[test]
    fn withdrawal_update_should_be_necessary_when_event_is_not_present() {
        // Arrange
        let pending = WithdrawalEvent {
            status: StatusEntry::Pending,
            message: "message".to_string(),
            stacks_block_height: 1,
            stacks_block_hash: "hash".to_string(),
        };

        let failed = WithdrawalEvent {
            status: StatusEntry::Failed,
            message: "message".to_string(),
            stacks_block_height: 2,
            stacks_block_hash: "hash".to_string(),
        };

        let withdrawal_entry = WithdrawalEntry {
            key: WithdrawalEntryKey {
                request_id: 1,
                stacks_block_hash: "hash".to_string(),
            },
            stacks_block_height: 1,
            version: 1,
            recipient: "recipient".to_string(),
            amount: 1,
            parameters: WithdrawalParametersEntry { max_fee: 1 },
            status: Status::Pending,
            last_update_height: 1,
            last_update_block_hash: "hash".to_string(),
            history: vec![pending.clone()],
        };

        let withdrawal_update = ValidatedWithdrawalUpdate { request_id: 1, event: failed };

        // Act
        let is_unnecessary = withdrawal_update.is_unnecessary(&withdrawal_entry);

        // Assert
        assert!(!is_unnecessary);
    }

    #[test_case(0, "hash0", 0, "hash0", StatusEntry::Pending; "reorg around genesis sets status to pending at genesis")]
    #[test_case(5, "hash5", 4, "hash4", StatusEntry::Accepted; "reorg goes to earliest canonical event 1")]
    #[test_case(4, "hash4", 4, "hash4", StatusEntry::Accepted; "reorg setting a height consistent with an event keeps it")]
    #[test_case(4, "hash4-1", 2, "hash2", StatusEntry::Pending; "reorg setting a height inconsistent with an event removes it")]
    #[test_case(3, "hash3", 2, "hash2", StatusEntry::Pending; "reorg  goes to earliest canonical event 2")]
    fn reorganizing_around_a_new_chainstate_results_in_valid_withdrawal(
        reorg_height: u64,
        reorg_hash: &str,
        expected_height: u64,
        expected_hash: &str,
        expected_status: StatusEntry,
    ) {
        let pending = WithdrawalEvent {
            status: StatusEntry::Pending,
            message: "initial test pending".to_string(),
            stacks_block_height: 2,
            stacks_block_hash: "hash2".to_string(),
        };

        let accepted = WithdrawalEvent {
            status: StatusEntry::Accepted,
            message: "accepted".to_string(),
            stacks_block_height: 4,
            stacks_block_hash: "hash4".to_string(),
        };

        let fulfillment: Fulfillment = Default::default();
        let confirmed = WithdrawalEvent {
            status: StatusEntry::Confirmed(fulfillment.clone()),
            message: "confirmed".to_string(),
            stacks_block_height: 6,
            stacks_block_hash: "hash6".to_string(),
        };

        let mut withdrawal_entry = WithdrawalEntry {
            key: WithdrawalEntryKey {
                request_id: 1,
                stacks_block_hash: "hash".to_string(),
            },
            stacks_block_height: 1,
            version: 1,
            recipient: "test-recipient".to_string(),
            amount: 1,
            parameters: WithdrawalParametersEntry { max_fee: 1 },
            status: Status::Confirmed,
            last_update_height: 6,
            last_update_block_hash: "hash6".to_string(),
            history: vec![pending.clone(), accepted.clone(), confirmed.clone()],
        };

        // Ensure the withdrawal is valid.
        assert!(
            withdrawal_entry.validate().is_ok(),
            "Test withdrawal must be valid before reorg.",
        );

        // Reorganize around a new chainstate.
        let chainstate = Chainstate {
            stacks_block_height: reorg_height,
            stacks_block_hash: reorg_hash.to_string(),
        };
        withdrawal_entry.reorganize_around(&chainstate).unwrap();

        // Ensure the withdrawal is valid.
        assert!(
            withdrawal_entry.validate().is_ok(),
            "Withdrawal must be valid after reorg.",
        );

        // Check latest height.
        assert_eq!(withdrawal_entry.last_update_height, expected_height);
        assert_eq!(withdrawal_entry.last_update_block_hash, expected_hash);
        assert_eq!(withdrawal_entry.status, (&expected_status).into());

        let latest_event = withdrawal_entry
            .latest_event()
            .expect("must have latest event")
            .clone();
        assert_eq!(latest_event.stacks_block_height, expected_height);
        assert_eq!(latest_event.stacks_block_hash, expected_hash);
        assert_eq!(latest_event.status, expected_status);
    }
}
