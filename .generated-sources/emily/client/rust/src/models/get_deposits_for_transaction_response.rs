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

/// GetDepositsForTransactionResponse : Response to get deposits for transaction request.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct GetDepositsForTransactionResponse {
    /// Deposits.
    #[serde(rename = "deposits")]
    pub deposits: Vec<models::Deposit>,
    /// Next token for the search.
    #[serde(
        rename = "nextToken",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_token: Option<Option<String>>,
}

impl GetDepositsForTransactionResponse {
    /// Response to get deposits for transaction request.
    pub fn new(deposits: Vec<models::Deposit>) -> GetDepositsForTransactionResponse {
        GetDepositsForTransactionResponse { deposits, next_token: None }
    }
}
