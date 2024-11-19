//! Request structures for limits api calls.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

/// Represents the current sBTC limits.
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// Represents the total cap for all pegged-in BTC/sBTC.
    pub peg_cap: Option<u64>,
    /// Per deposit cap. If none then there is no cap.
    pub per_deposit_cap: Option<u64>,
    /// Per withdrawal cap. If none then there is no cap.
    pub per_withdrawal_cap: Option<u64>,
    /// Represents the individual limits for requests coming from different accounts.
    pub account_caps: HashMap<String, AccountLimits>,
}

/// The representation of a limit for a specific account.
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
pub struct AccountLimits {
    /// Represents the current sBTC limits.
    pub peg_cap: Option<u64>,
    /// Per deposit cap. If none then the cap is the same as the global per deposit cap.
    pub per_deposit_cap: Option<u64>,
    /// Per withdrawal cap. If none then the cap is the same as the global per withdrawal cap.
    pub per_withdrawal_cap: Option<u64>,
}
