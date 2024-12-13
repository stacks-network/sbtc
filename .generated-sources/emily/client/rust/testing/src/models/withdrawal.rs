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

/// Withdrawal : Withdrawal.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct Withdrawal {
    /// Amount of BTC being withdrawn in satoshis.
    #[serde(rename = "amount")]
    pub amount: u64,
    #[serde(
        rename = "fulfillment",
        default,
        with = "::serde_with::rust::double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub fulfillment: Option<Option<Box<models::Fulfillment>>>,
    /// The most recent Stacks block hash the API was aware of when the withdrawal was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this hash is the Stacks block hash that contains that artifact.
    #[serde(rename = "lastUpdateBlockHash")]
    pub last_update_block_hash: String,
    /// The most recent Stacks block height the API was aware of when the withdrawal was last updated. If the most recent update is tied to an artifact on the Stacks blockchain then this height is the Stacks block height that contains that artifact.
    #[serde(rename = "lastUpdateHeight")]
    pub last_update_height: u64,
    #[serde(rename = "parameters")]
    pub parameters: Box<models::WithdrawalParameters>,
    /// The recipient Bitcoin address.
    #[serde(rename = "recipient")]
    pub recipient: String,
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    #[serde(rename = "requestId")]
    pub request_id: u64,
    /// The stacks block hash in which this request id was initiated.
    #[serde(rename = "stacksBlockHash")]
    pub stacks_block_hash: String,
    /// The height of the Stacks block in which this request id was initiated.
    #[serde(rename = "stacksBlockHeight")]
    pub stacks_block_height: u64,
    #[serde(rename = "status")]
    pub status: models::Status,
    /// The status message of the withdrawal.
    #[serde(rename = "statusMessage")]
    pub status_message: String,
}

impl Withdrawal {
    /// Withdrawal.
    pub fn new(
        amount: u64,
        last_update_block_hash: String,
        last_update_height: u64,
        parameters: models::WithdrawalParameters,
        recipient: String,
        request_id: u64,
        stacks_block_hash: String,
        stacks_block_height: u64,
        status: models::Status,
        status_message: String,
    ) -> Withdrawal {
        Withdrawal {
            amount,
            fulfillment: None,
            last_update_block_hash,
            last_update_height,
            parameters: Box::new(parameters),
            recipient,
            request_id,
            stacks_block_hash,
            stacks_block_height,
            status,
            status_message,
        }
    }
}
