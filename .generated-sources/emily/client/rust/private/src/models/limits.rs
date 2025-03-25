/*
 * emily-openapi-spec
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 0.1.0
 *
 * Generated by: https://openapi-generator.tech
 */

use crate::models;
use serde::{Deserialize, Serialize};

/// Limits : Represents the current sBTC limits.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    /// Represents the individual limits for requests coming from different accounts.
    #[serde(rename = "accountCaps")]
    pub account_caps: std::collections::HashMap<String, models::AccountLimits>,
    /// Total amount sBTC still available for withdrawals in current window. All withdrawals except rejected counted here
    #[serde(
        rename = "availableToWithdraw",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub available_to_withdraw: Option<Option<u64>>,
    /// Represents the total cap for all pegged-in BTC/sBTC.
    #[serde(
        rename = "pegCap",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub peg_cap: Option<Option<u64>>,
    /// Per deposit cap. If none then there is no cap.
    #[serde(
        rename = "perDepositCap",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub per_deposit_cap: Option<Option<u64>>,
    /// Per deposit minimum. If none then there is no minimum.
    #[serde(
        rename = "perDepositMinimum",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub per_deposit_minimum: Option<Option<u64>>,
    /// Per withdrawal cap. If none then there is no cap.
    #[serde(
        rename = "perWithdrawalCap",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub per_withdrawal_cap: Option<Option<u64>>,
    /// Number of blocks that define the rolling withdrawal window.
    #[serde(
        rename = "rollingWithdrawalBlocks",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub rolling_withdrawal_blocks: Option<Option<u64>>,
    /// Maximum total sBTC that can be withdrawn within the rolling withdrawal window.
    #[serde(
        rename = "rollingWithdrawalCap",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub rolling_withdrawal_cap: Option<Option<u64>>,
}

impl Limits {
    /// Represents the current sBTC limits.
    pub fn new(account_caps: std::collections::HashMap<String, models::AccountLimits>) -> Limits {
        Limits {
            account_caps,
            available_to_withdraw: None,
            peg_cap: None,
            per_deposit_cap: None,
            per_deposit_minimum: None,
            per_withdrawal_cap: None,
            rolling_withdrawal_blocks: None,
            rolling_withdrawal_cap: None,
        }
    }
}
