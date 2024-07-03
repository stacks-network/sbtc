//! Response structures for deposit api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Response to get deposit request.
pub type GetDepositResponse = super::Deposit;

/// Response to create deposit request.
pub type CreateDepositResponse = super::Deposit;

/// Response to get deposits for transaction request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct GetDepositsForTransactionResponse {
    /// Next token for the search.
    pub next_token: Option<String>,
    /// Deposits.
    pub deposits: Vec<super::Deposit>,
}

/// Response to get deposits request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct GetDepositsResponse {
    /// Next token for the search.
    pub next_token: Option<String>,
    /// Deposit infos: deposits with a little less data.
    pub deposits: Vec<super::DepositInfo>,
}

/// Response to update deposits request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDepositsResponse {
    /// Deposit infos: deposits with a little less data.
    pub deposits: Vec<super::Deposit>,
}
