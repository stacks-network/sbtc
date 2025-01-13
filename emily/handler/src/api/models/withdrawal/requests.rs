//! Requests for withdrawal api calls.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::models::common::{Fulfillment, Status};
use crate::api::models::withdrawal::WithdrawalParameters;

/// Query structure for the get withdrawals request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetWithdrawalsQuery {
    /// Operation status.
    pub status: Status,
    /// Next token for the search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    /// Maximum number of results to show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u16>,
}

/// Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateWithdrawalRequestBody {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: u64,
    /// The stacks block hash in which this request id was initiated.
    pub stacks_block_hash: String,
    /// The stacks block hash in which this request id was initiated.
    pub stacks_block_height: u64,
    /// The recipient Bitcoin address.
    pub recipient: String,
    /// Amount of BTC being withdrawn in satoshis.
    pub amount: u64,
    /// Withdrawal request parameters.
    pub parameters: WithdrawalParameters,
}

/// A singlular Withdrawal update that contains only the fields pertinent
/// to updating the status of a withdrawal. This includes the key related
/// data in addition to status history related data.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalUpdate {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: u64,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: u64,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
    /// The status of the withdrawal.
    pub status: Status,
    /// The status message of the withdrawal.
    pub status_message: String,
    /// Details about the on chain artifacts that fulfilled the withdrawal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
}

/// Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWithdrawalsRequestBody {
    /// Withdrawal updates to execute.
    pub withdrawals: Vec<WithdrawalUpdate>,
}
