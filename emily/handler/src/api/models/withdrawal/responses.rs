//! Responses for withdrawal api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Response to get withdrawal request.
pub type GetWithdrawalResponse = super::Withdrawal;

/// Response to create withdrawal request.
pub type CreateWithdrawalResponse = super::Withdrawal;

/// Response to get withdrawals request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct GetWithdrawalsResponse {
    /// Next token for the search.
    pub next_token: Option<String>,
    /// Withdrawal infos: withdrawals with a little less data.
    pub withdrawals: Vec<super::WithdrawalInfo>,
}

/// Response to update withdrawals request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWithdrawalsResponse {
    /// Updated withdrawals.
    pub withdrawals: Vec<super::Withdrawal>,
}
