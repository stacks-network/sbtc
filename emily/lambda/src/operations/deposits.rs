//! Handlers for sBTC deposit API operations

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use emily::models::{self, DepositData, OpStatus};
use serde::{Deserialize, Serialize};
use serde_dynamo::Item;
use crate::{common, utils};
use crate::config::LambdaContext;
use crate::errors::{self, EmilyApiError};
use crate::resources::deposits::{ DepositHistoryEntry, DepositRequest, DepositRequestBasicInfo, DepositRequestBasicInfoKey, DepositRequestKey};

/// Handles the creation of a deposit request
pub async fn handle_create_deposit(
    body: Option<String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    let request: models::CreateDepositRequestContent = common::deserialize_request(body)?;

    // TODO: [ticket link here once PR is approved]
    // Change "reclaim script" phrasing to be "deposit script" in consistent locations.
    let reclaim_script = request.reclaim;
    let deposit_script_fields: FieldsExtractedFromDepositScript = extract_fields_from_reclaim_script(reclaim_script.clone())?;

    // TODO: [ticket link here once PR is approved]
    // Get current latest stacks block from chainstate table.
    let stacks_block_hash: String = "DUMMY_BLOCK_HASH".to_string();
    let stacks_block_height: u64 = 44444;

    // Create table entry.
    let op_status: OpStatus = OpStatus::Pending;
    let deposit_request: DepositRequest = DepositRequest {
        bitcoin_txid: request.bitcoin_txid.clone(),
        bitcoin_tx_output_index: request.bitcoin_tx_output_index as u16,
        recipient: deposit_script_fields.recipient,
        amount: deposit_script_fields.amount,
        last_update_block_hash: stacks_block_hash.clone(),
        last_update_height: stacks_block_height,
        op_status,
        history: vec![
            DepositHistoryEntry {
                op_status,
                message: "Waiting for pickup by sBTC Bootstrap Signers.".to_string(),
                stacks_block_height,
                stacks_block_hash,
            }
        ],
        max_fee: deposit_script_fields.max_fee,
        lock_time: deposit_script_fields.lock_time,
        reclaim_script,
        ..DepositRequest::default()
    };

    // Make the item representation.
    let dynamodb_item: Item = serde_dynamo::to_item(&deposit_request)
        .map_err(errors::to_emily_api_error)?;

    // Put entry into table.
    //
    // TODO: [ticket link here once PR is approved]
    // Emplace collision logic.
    context.dynamodb_client
        .put_item()
        .table_name(context.settings.deposit_table_name.clone())
        .set_item(Some(dynamodb_item.into()))
        .send()
        .await
        .map_err(errors::to_emily_api_error)?;

    // Convert table entry to API like data.
    let deposit_data: models::DepositData = deposit_request.into();

    // Return API response.
    common::package_response(models::CreateDepositResponseContent {
        bitcoin_txid: deposit_data.bitcoin_txid,
        bitcoin_tx_output_index: deposit_data.bitcoin_tx_output_index,
        recipient: deposit_data.recipient,
        amount: deposit_data.amount,
        // Last update block hash is important to the table entry because it indicates what
        // the API was aware of when the entry was created, but at this stage in the process
        // the pending deposit is not tied to any block state so the resource won't provide it.
        last_update_block_hash: deposit_data.last_update_block_hash,
        last_update_height: deposit_data.last_update_height,
        status: deposit_data.status,
        status_message: deposit_data.status_message,
        parameters: deposit_data.parameters,
        fulfillment: deposit_data.fulfillment,
    }, 201)

}

/// Private "get transaction deposits" parameter representation to simplify deserialization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetTxnDepositsParameters {
    txid: String,
}

/// Handles the retrieval of deposit transactions
pub async fn handle_get_txn_deposits(
    path_parameters: HashMap<String, String>,
    query_parameters: aws_lambda_events::query_map::QueryMap,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    //
    // TODO: [ticket link here once PR is approved]
    // Refine extraction procedure for both query and path parameters.
    let exclusive_start_key = match query_parameters.first("nextToken") {
        Some(token) => Some(utils::deserialize_token_to_key::<DepositRequestKey>(token)?),
        None => None,
    };
    let limit: Option<i32> = match query_parameters.first("maxResults") {
        Some(max_results) => Some(max_results.parse::<i32>()
            .map_err(errors::to_emily_api_error)?),
        None => None,
    };
    let parameters = serde_json::to_string(&path_parameters)
        .and_then(|param_string| serde_json::from_str::<GetTxnDepositsParameters>(&param_string))
        .map_err(errors::to_emily_api_error)?;

    // Query the table.
    //
    // TODO: [ticket link here once PR is approved]
    // Move to DynamoDB table accessor utility.
    let response: aws_sdk_dynamodb::operation::query::QueryOutput = context
        .dynamodb_client
        .query()
        .table_name(&context.settings.deposit_table_name)
        .set_limit(limit)
        .set_exclusive_start_key(exclusive_start_key)
        .key_condition_expression("#pk = :v")
        .expression_attribute_names("#pk", "BitcoinTxid")
        .expression_attribute_values(":v", AttributeValue::S(parameters.txid))
        .send()
        .await
        .map_err(errors::to_emily_api_error)?;

    let items: Vec<DepositRequest> = serde_dynamo::from_items(response.items().to_vec())
        .map_err(errors::to_emily_api_error)?;

    let deposit_datas: Vec<DepositData> = items.into_iter()
        .map(|deposit_request| deposit_request.into())
        .collect();

    let next_token: Option<String> = match response.last_evaluated_key {
        Some(key) => Some(utils::serialize_key_to_token::<DepositRequestKey>(key)?),
        None => None
    };

    common::package_response(models::GetTxnDepositsResponseContent {
        next_token,
        deposits: Some(deposit_datas)
    }, 200)

}

/// Private "get deposit" parameter representation to simplify deserialization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetTxnDepositParameters {
    /// Bitcoin txid.
    txid: String,

    /// Output index on the bitcoin txid that corresponds to the deposit.
    #[serde(deserialize_with = "crate::utils::deserialize_string_to_number")]
    output_index: u16,
}

/// Handles the retrieval of a single deposit transaction
pub async fn handle_get_deposit(
    path_parameters: HashMap<String, String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    //
    // TODO: [ticket link here once PR is approved]
    // Refine extraction procedure for both query and path parameters.
    let parameters = serde_json::to_string(&path_parameters)
        .and_then(|param_string| serde_json::from_str::<GetTxnDepositParameters>(&param_string))
        .map_err(errors::to_emily_api_error)?;

    // Get table entry.
    let key = DepositRequestKey {
        bitcoin_txid: parameters.txid,
        bitcoin_tx_output_index: parameters.output_index,
    };

    let key_item: Item = serde_dynamo::to_item(&key)
        .map_err(errors::to_emily_api_error)?;

    let deposit_request: DepositRequest = context
        .dynamodb_client
        .get_item()
        .table_name(&context.settings.deposit_table_name)
        .set_key(Some(key_item.into()))
        .send()
        .await
        .map_err(errors::to_emily_api_error)?
        .item
        .ok_or(EmilyApiError::NotFound(format!("Deposit {:?} not found.", key)))
        .and_then(|item| {
            let maybe_deposit_request: Result<DepositRequest, errors::EmilyApiError> = serde_dynamo::from_item(item)
                // TODO: Reduce propagated error details.
                .map_err(errors::to_emily_api_error);
            maybe_deposit_request
        })?;

    // Convert deposit table entry to usable data.
    let deposit_data: models::DepositData = deposit_request.into();

    // Package response.
    common::package_response(models::GetDepositResponseContent {
        bitcoin_txid: deposit_data.bitcoin_txid,
        bitcoin_tx_output_index: deposit_data.bitcoin_tx_output_index,
        recipient: deposit_data.recipient,
        amount: deposit_data.amount,
        last_update_block_hash: deposit_data.last_update_block_hash,
        last_update_height: deposit_data.last_update_height,
        status: deposit_data.status,
        status_message: deposit_data.status_message,
        parameters: deposit_data.parameters,
        fulfillment: deposit_data.fulfillment,
    }, 200)

}

/// Handles the retrieval of multiple deposit transactions
pub async fn handle_get_deposits(
    query_parameters: aws_lambda_events::query_map::QueryMap,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    //
    // TODO: [ticket link here once PR is approved]
    // Refine extraction procedure for both query and path parameters.
    let exclusive_start_key = match query_parameters.first("nextToken") {
        Some(token) => Some(utils::deserialize_token_to_key::<DepositRequestBasicInfoKey>(token)?),
        None => None,
    };
    let page_size: Option<i32> = match query_parameters.first("maxResults") {
        Some(max_results) => Some(max_results.parse::<i32>().map_err(errors::to_emily_api_error)?),
        None => None,
    };
    let status: OpStatus = query_parameters.first("status")
        .ok_or(EmilyApiError::BadRequest("Missing \"status\" query parameter.".to_string()))
        .and_then(|status_string| {
            // TODO: Find a better way to do this.
            serde_json::from_str::<models::OpStatus>(format!("\"{}\"", status_string.replace("\"", "\\\"")).as_str())
                .map_err(errors::to_emily_api_error)
        })?;

    // Build DynamoDB Request.
    let response: aws_sdk_dynamodb::operation::query::QueryOutput = context
        .dynamodb_client
        .query()
        .table_name(&context.settings.deposit_table_name)
        .set_exclusive_start_key(exclusive_start_key)
        .set_limit(page_size)
        .index_name("DepositStatus".to_string())
        .key_condition_expression("#pk = :v")
        .expression_attribute_names("#pk", "OpStatus")
        .expression_attribute_values(":v", AttributeValue::S(status.to_string()))
        .send()
        .await
        .map_err(errors::to_emily_api_error)?;

    let items: Vec<DepositRequestBasicInfo> = serde_dynamo::from_items(response.items().to_vec())
        .map_err(errors::to_emily_api_error)?;

    let deposit_basic_info_list: Vec<models::DepositBasicInfo> = items.into_iter()
        .map(|deposit_request| deposit_request.into())
        .collect();

    let next_token: Option<String> = match response.last_evaluated_key {
        Some(key) => Some(utils::serialize_key_to_token::<DepositRequestBasicInfoKey>(key)?),
        None => None
    };

    common::package_response(models::GetDepositsResponseContent {
        next_token,
        deposits: Some(deposit_basic_info_list)
    }, 200)

}

/// Handles the update of deposit transactions
///
/// TODO: [ticket link here once PR is approved]
/// Handle update deposit.
pub async fn handle_update_deposits(
    _body: Option<String>,
    _context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    Err(EmilyApiError::NotImplemented("API endpoint not implemented".to_string()))
}

/// Represents the fields that can be extracted from the deposit script in a bundle.
///
/// TODO: [ticket link here once PR is approved]
/// Use transaction library function instead of this debug setup.
struct FieldsExtractedFromDepositScript {
    recipient: String,
    amount: u64,
    lock_time: u64,
    max_fee: u64,
}

/// Extracts fields from the reclaim script.
fn extract_fields_from_reclaim_script(
    _reclaim_script: String,
) -> Result<FieldsExtractedFromDepositScript, EmilyApiError> {
    Ok(FieldsExtractedFromDepositScript {
        recipient: "DUMMY_RECIPIENT".to_string(),
        amount: 11111,
        lock_time: 22222,
        max_fee: 33333,
    })
}

