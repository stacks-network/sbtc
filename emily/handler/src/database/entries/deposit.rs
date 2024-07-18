//! Entries into the deposit table.

use serde::{Deserialize, Serialize};

use crate::{
    api::models::{
        common::{
            BitcoinScript, BitcoinTransactionId, BitcoinTransactionOutputIndex, BlockHeight,
            Fulfillment, Satoshis, StacksBlockHash, StacksPrinciple, Status,
        },
        deposit::{Deposit, DepositInfo, DepositParameters},
    },
    common::error::Error,
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
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
    /// History of this deposit transaction.
    pub history: Vec<DepositEvent>,
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
        if self.status != latest_event.status {
            return Err(Error::Debug(
                format!("most recent status is inconsistent between history and top level data. {stringy_self:?}")
            ));
        }
        Ok(())
    }
}

impl TryFrom<DepositEntry> for Deposit {
    type Error = Error;
    fn try_from(deposit_entry: DepositEntry) -> Result<Self, Self::Error> {
        // Ensure entry is valid.
        deposit_entry.validate()?;
        // Get the latest event.
        let latest_event: &DepositEvent = deposit_entry
            .history
            .last()
            .expect("Deposit history is invalid but was just validate.");
        // Create deposit from table entry.
        Ok(Deposit {
            bitcoin_txid: deposit_entry.key.bitcoin_txid,
            bitcoin_tx_output_index: deposit_entry.key.bitcoin_tx_output_index,
            recipient: deposit_entry.recipient,
            amount: deposit_entry.amount,
            last_update_height: deposit_entry.last_update_height,
            last_update_block_hash: deposit_entry.last_update_block_hash,
            status: deposit_entry.status,
            status_message: latest_event.message.clone(),
            parameters: DepositParameters {
                max_fee: deposit_entry.parameters.max_fee,
                lock_time: deposit_entry.parameters.lock_time,
                reclaim_script: deposit_entry.parameters.reclaim_script,
            },
            fulfillment: deposit_entry.fulfillment,
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
    pub status: Status,
    /// Status message.
    pub message: String,
    /// Stacks block heigh at the time of this update.
    pub stacks_block_height: BlockHeight,
    /// Stacks block hash associated with the height of this update.
    pub stacks_block_hash: StacksBlockHash,
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
