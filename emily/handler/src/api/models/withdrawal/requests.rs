//! Requests for withdrawal api calls.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::models::common::*;
use super::{WithdrawalId, WithdrawalParameters};

/// Query structure for the get withdrawals request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetWithdrawalsQuery {
    /// Operation status.
    status: Status,
    /// Pagination data.
    #[serde(flatten)]
    pagination_data: requests::PaginatedQuery<String>,
}

/// Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateWithdrawalRequestBody {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: WithdrawalId,
    /// The stacks block hash in which this request id was initiated.
    pub block_hash: StacksBlockHash,
    /// The height of the Stacks block in which this request id was initiated.
    pub block_height: BlockHeight,
    /// The recipient Bitcoin address.
    pub recipient: BitcoinAddress,
    /// Amount of BTC being withdrawn.
    pub amount: Satoshis,
    /// Withdrawal request parameters.
    pub parameters: WithdrawalParameters,
}

/// Withdrawals where only the fields to update are defined.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalUpdate {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<WithdrawalId>,
    /// The stacks block hash in which this request id was initiated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<StacksBlockHash>,
    /// The height of the Stacks block in which this request id was initiated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<BlockHeight>,
    /// The recipient Bitcoin address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<BitcoinAddress>,
    /// Amount of BTC being withdrawn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<Satoshis>,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update_height: Option<BlockHeight>,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update_block_hash: Option<StacksBlockHash>,
    /// The status of the withdrawal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// The status message of the withdrawal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// Withdrawal request parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<WithdrawalParameters>,
    /// Details about the on chain artifacts that fulfilled the withdrawal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Option<Fulfillment>>,
}

/// Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWithdrawalsRequestBody {
    /// Withdrawal updates to execute.
    withdrawals: Vec<WithdrawalUpdate>
}
