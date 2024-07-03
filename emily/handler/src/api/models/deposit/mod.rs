//! Request structures for deposit api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

use crate::api::models::common::*;

/// Requests.
pub mod requests;
/// Responses.
pub mod responses;

/// Deposit.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct Deposit {
    /// Bitcoin transaction id.
    pub bitcoin_txid: BitcoinTransactionId,
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub bitcoin_tx_output_index: BitcoinTransactionOutputIndex,
    /// Stacks address to received the deposited sBTC.
    pub recipient: StacksPrinciple,
    /// Amount of BTC being deposited.
    pub amount: Satoshis,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: BlockHeight,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: StacksBlockHash,
    /// The status of the deposit.
    pub status: Status,
    /// The status message of the deposit.
    pub status_message: String,
    /// Deposit parameters
    pub parameters: DepositParameters,
    /// Details about the on chain artifacts that fulfilled the deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
}

/// Deposit parameters.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct DepositParameters {
    /// Maximum fee the signers are allowed to take from the deposit to facilitate
    /// the transaction.
    pub max_fee: Satoshis,
    /// Bitcoin block height at which the reclaim script becomes executable.
    pub lock_time: BlockHeight,
    /// Raw reclaim script.
    pub reclaim_script: BitcoinScript,
}

/// Reduced version of the Deposit data.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct DepositInfo {
    /// Bitcoin transaction id.
    pub bitcoin_txid: BitcoinTransactionId,
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub bitcoin_tx_output_index: BitcoinTransactionOutputIndex,
    /// Stacks address to received the deposited sBTC.
    pub recipient: StacksPrinciple,
    /// Amount of BTC being deposited.
    pub amount: Satoshis,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: BlockHeight,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: StacksBlockHash,
    /// The status of the deposit.
    pub status: Status,
}
