//! Structures for withdrawal api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

use crate::api::models::common::*;

/// Requests.
pub mod requests;
/// Responses.
pub mod responses;

/// Type used to represent a withdrawal identifier.
pub type WithdrawalId = u64;

/// Withdrawal.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: WithdrawalId,
    /// The stacks block hash in which this request id was initiated.
    pub stacks_block_hash: StacksBlockHash,
    /// The height of the Stacks block in which this request id was initiated.
    pub stacks_block_height: BlockHeight,
    /// The recipient Bitcoin address.
    pub recipient: BitcoinAddress,
    /// Amount of BTC being withdrawn.
    pub amount: Satoshis,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: BlockHeight,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: StacksBlockHash,
    /// The status of the withdrawal.
    pub status: Status,
    /// The status message of the withdrawal.
    pub status_message: String,
    /// Withdrawal request parameters.
    pub parameters: WithdrawalParameters,
    /// Details about the on chain artifacts that fulfilled the withdrawal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
}

/// Withdrawal parameters.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalParameters {
    /// Maximum fee the signers are allowed to take from the withdrawal to facilitate
    /// the inclusion of the transaction onto the Bitcoin blockchain.
    pub max_fee: Satoshis,
}

/// Reduced version of the Withdrawal.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalInfo {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: WithdrawalId,
    /// The stacks block hash in which this request id was initiated.
    pub stacks_block_hash: StacksBlockHash,
    /// The height of the Stacks block in which this request id was initiated.
    pub stacks_block_height: BlockHeight,
    /// The recipient Bitcoin address.
    pub recipient: BitcoinAddress,
    /// Amount of BTC being withdrawn.
    pub amount: Satoshis,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: BlockHeight,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: StacksBlockHash,
    /// The status of the withdrawal.
    pub status: Status,
}

/// Create a WithdrawalInfo, which has a subset of the data within a Withdrawal, from a Withdrawal.
impl From<Withdrawal> for WithdrawalInfo {
    fn from(withdrawal: Withdrawal) -> Self {
        WithdrawalInfo {
            request_id: withdrawal.request_id,
            stacks_block_hash: withdrawal.stacks_block_hash,
            stacks_block_height: withdrawal.stacks_block_height,
            recipient: withdrawal.recipient,
            amount: withdrawal.amount,
            last_update_height: withdrawal.last_update_height,
            last_update_block_hash: withdrawal.last_update_block_hash,
            status: withdrawal.status,
        }
    }
}
