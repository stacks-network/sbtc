//! Request structures for limits api calls.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

use crate::common::error::ValidationError;

/// Represents the current sBTC limits.
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// Represents the total cap for all pegged-in BTC/sBTC.
    pub peg_cap: Option<u64>,
    /// Per deposit minimum. If none then there is no minimum.
    pub per_deposit_minimum: Option<u64>,
    /// Per deposit cap. If none then there is no cap.
    pub per_deposit_cap: Option<u64>,
    /// Per withdrawal cap. If none then there is no cap.
    pub per_withdrawal_cap: Option<u64>,
    /// Number of blocks that define the rolling withdrawal window.
    pub rolling_withdrawal_blocks: Option<u64>,
    /// Maximum total sBTC that can be withdrawn within the rolling withdrawal window.
    pub rolling_withdrawal_cap: Option<u64>,
    /// Total amount sBTC still available for withdrawals in current window. All withdrawals except rejected
    /// counted here
    pub available_to_withdraw: Option<u64>,
    /// Represents the individual limits for requests coming from different accounts.
    pub account_caps: HashMap<String, AccountLimits>,
}

impl Limits {
    /// Validates the withdrawal limit configuration.
    ///
    /// This function checks if both `rolling_withdrawal_blocks` and `rolling_withdrawal_cap` are provided together.
    /// If one is provided without the other, it returns an error indicating that the configuration is incomplete.
    ///
    /// # Returns
    ///
    /// - `Ok(())`: If both `rolling_withdrawal_blocks` and `rolling_withdrawal_cap` are provided together.
    /// - `Err(ValidationError::IncompleteWithdrawalLimitConfig)`: If one of the fields is missing while the other is set.
    ///
    /// # Errors
    ///
    /// See [`ValidationError::IncompleteWithdrawalLimitConfig`].
    pub fn validate(&self) -> Result<(), ValidationError> {
        match (self.rolling_withdrawal_blocks, self.rolling_withdrawal_cap) {
            (Some(_), None) | (None, Some(_)) => {
                Err(ValidationError::IncompleteWithdrawalLimitConfig)
            }
            _ => Ok(()),
        }
    }
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
    /// Per deposit minimum. If none then there is no minimum.
    pub per_deposit_minimum: Option<u64>,
    /// Per deposit cap. If none then the cap is the same as the global per deposit cap.
    pub per_deposit_cap: Option<u64>,
    /// Per withdrawal cap. If none then the cap is the same as the global per withdrawal cap.
    pub per_withdrawal_cap: Option<u64>,
    /// Number of blocks that define the rolling withdrawal window.
    pub rolling_withdrawal_blocks: Option<u64>,
    /// Maximum total sBTC that can be withdrawn within the rolling withdrawal window.
    pub rolling_withdrawal_cap: Option<u64>,
}
