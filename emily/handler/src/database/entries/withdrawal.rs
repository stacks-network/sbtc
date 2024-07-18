//! Entries into the withdrawal table.

use serde::{Deserialize, Serialize};

use crate::{
    api::models::{
        common::{
            BitcoinAddress, BlockHeight, Fulfillment, Satoshis, StacksBlockHash, StacksPrinciple,
            Status,
        },
        withdrawal::{Withdrawal, WithdrawalId, WithdrawalInfo, WithdrawalParameters},
    },
    common::error::Error,
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
    /// Data about the fulfillment of the sBTC Operation.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
    /// History of this withdrawal transaction.
    pub history: Vec<WithdrawalEvent>,
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
        if self.status != latest_event.status {
            return Err(Error::Debug(
                format!("most recent status is inconsistent between history and top level data. {stringy_self:?}")
            ));
        }
        Ok(())
    }
}

impl TryFrom<WithdrawalEntry> for Withdrawal {
    type Error = Error;
    fn try_from(withdrawal_entry: WithdrawalEntry) -> Result<Self, Self::Error> {
        // Ensure entry is valid.
        withdrawal_entry.validate()?;
        // Get the latest event.
        let latest_event: &WithdrawalEvent = withdrawal_entry
            .history
            .last()
            .expect("Withdrawal history is invalid but was just validate.");
        // Create withdrawal from table entry.
        Ok(Withdrawal {
            request_id: withdrawal_entry.key.request_id,
            stacks_block_hash: withdrawal_entry.key.stacks_block_hash,
            stacks_block_height: withdrawal_entry.stacks_block_height,
            recipient: withdrawal_entry.recipient,
            amount: withdrawal_entry.amount,
            last_update_height: withdrawal_entry.last_update_height,
            last_update_block_hash: withdrawal_entry.last_update_block_hash,
            status: withdrawal_entry.status,
            status_message: latest_event.message.clone(),
            parameters: WithdrawalParameters {
                max_fee: withdrawal_entry.parameters.max_fee,
            },
            fulfillment: withdrawal_entry.fulfillment,
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
    pub status: Status,
    /// Status message.
    pub message: String,
    /// Stacks block heigh at the time of this update.
    pub stacks_block_height: BlockHeight,
    /// Stacks block hash associated with the height of this update.
    pub stacks_block_hash: StacksBlockHash,
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
