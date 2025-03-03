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

/// CreateWithdrawalRequestBody : Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateWithdrawalRequestBody {
    /// Amount of BTC being withdrawn in satoshis.
    #[serde(rename = "amount")]
    pub amount: u64,
    #[serde(rename = "parameters")]
    pub parameters: Box<models::WithdrawalParameters>,
    /// The recipient Bitcoin hex-encoded scriptPubKey.
    #[serde(rename = "recipient")]
    pub recipient: String,
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    #[serde(rename = "requestId")]
    pub request_id: u64,
    /// The stacks block hash in which this request id was initiated.
    #[serde(rename = "stacksBlockHash")]
    pub stacks_block_hash: String,
    /// The stacks block hash in which this request id was initiated.
    #[serde(rename = "stacksBlockHeight")]
    pub stacks_block_height: u64,
}

impl CreateWithdrawalRequestBody {
    /// Request structure for the create withdrawal request.
    pub fn new(
        amount: u64,
        parameters: models::WithdrawalParameters,
        recipient: String,
        request_id: u64,
        stacks_block_hash: String,
        stacks_block_height: u64,
    ) -> CreateWithdrawalRequestBody {
        CreateWithdrawalRequestBody {
            amount,
            parameters: Box::new(parameters),
            recipient,
            request_id,
            stacks_block_hash,
            stacks_block_height,
        }
    }
}
