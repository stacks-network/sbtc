//! Handlers for sBTC deposit API operations

use std::collections::HashMap;

use futures::future::try_join_all;

use aws_sdk_dynamodb::types::{AttributeAction, AttributeValue, AttributeValueUpdate, ExpectedAttributeValue, KeysAndAttributes};
use emily::models;
use crate::common;
use crate::config::LambdaContext;
use crate::errors::{self, EmilyApiError};
use crate::resources::deposits::{status_to_id, DepositBasicInfoResource, DepositHistoryEntry, DepositResource, DepositTableEntry, DepositTableEntryKey};

/// Handles the creation of a deposit request
pub async fn handle_create_deposit(
    body: Option<String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    let request: models::CreateDepositRequestContent =
        common::deserialize_request::<models::CreateDepositRequestContent>(body)?;

    // TODO:
    // Change "reclaim script" phrasing to be "deposit script" in consistent locations.
    let reclaim_script = request.reclaim.clone();
    let deposit_script_fields: FieldsExtractedFromDepositScript = extract_fields_from_reclaim_script(reclaim_script.clone())?;

    // TODO:
    // Get current latest stacks block from chainstate table.
    let stacks_block_hash: String = "DUMMY_BLOCK_HASH".to_string();
    let stacks_block_height: u64 = 44444;

    // Create table entry.
    let op_status: models::OpStatus = models::OpStatus::Pending;
    let message: String = "Waiting for pickup by sBTC Bootstrap Signers.".to_string();

    let deposit_table_entry: DepositTableEntry = DepositTableEntry {
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
                message,
                stacks_block_height,
                stacks_block_hash,
            }
        ],
        version: 0,
        max_fee: deposit_script_fields.max_fee,
        lock_time: deposit_script_fields.lock_time,
        reclaim_script,
        fulfillment_bitcoin_txid: None,
        fulfillment_bitcoin_tx_index: None,
        fulfillment_btc_fee: None,
        stacks_txid: None,
    };

    // Put entry into table.
    context.dynamodb_client
        .put_item()
        .table_name(context.settings.deposit_table_name.clone())
        .set_item(Some((&deposit_table_entry).into()))
        .send()
        .await
        .map_err(|e| EmilyApiError::InternalService(
            format!("Failed to create deposit: {:?}", e)))?;

    // Convert table entry to usable data.
    let deposit_resource: DepositResource = (&deposit_table_entry).into();

    common::package_response(models::CreateDepositResponseContent {
        bitcoin_txid: deposit_resource.bitcoin_txid,
        bitcoin_tx_output_index: deposit_resource.bitcoin_tx_output_index as f64,
        recipient: deposit_resource.recipient,
        amount: deposit_resource.amount as f64,
        // Last update block hash is important to the table entry because it indicates what
        // the API was aware of when the entry was created, but at this stage in the process
        // the pending deposit is not tied to any block state so the resource won't provide it.
        last_update_block_hash: None,
        last_update_height: None,
        status: deposit_resource.op_status,
        status_message: deposit_resource.status_message,
        parameters: deposit_resource.parameters.into(),
        fulfillment: None,
    }, 201)

}

/// Handles the retrieval of deposit transactions
pub async fn handle_get_txn_deposits(
    path_parameters:  HashMap<String, String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    let bitcoin_txid = path_parameters.get("txid").unwrap().clone();

    // TODO:
    // Move to DynamoDB table accessor utility.
    let response: aws_sdk_dynamodb::operation::query::QueryOutput = context
        .dynamodb_client
        .query()
        .table_name(&context.settings.deposit_table_name)
        .key_condition_expression("#pk = :v")
        .expression_attribute_names("#pk", "BitcoinTxid")
        .expression_attribute_values(":v", AttributeValue::S(bitcoin_txid.clone()))
        .send()
        .await
        .map_err(|e| EmilyApiError::InternalService(
            format!("failed at dynamodb call with parameters {:?}: {:?}", path_parameters, e)))?;

    let deposit_data_list: Vec<models::DepositData> = response.items()
        .iter()
        .map(|item| {
            let deposit_table_entry: Result<DepositTableEntry, EmilyApiError> = item.try_into();
            deposit_table_entry.and_then(|entry| {
                let deposit_resource: DepositResource = entry.into();
                Ok(models::DepositData {
                    bitcoin_txid: deposit_resource.bitcoin_txid,
                    bitcoin_tx_output_index: deposit_resource.bitcoin_tx_output_index as f64,
                    recipient: deposit_resource.recipient,
                    amount: deposit_resource.amount as f64,
                    last_update_height: Some(deposit_resource.last_update_height as f64),
                    last_update_block_hash: Some(deposit_resource.last_update_block_hash),
                    status: deposit_resource.op_status,
                    status_message: deposit_resource.status_message,
                    parameters: deposit_resource.parameters.into(),
                    // TODO!
                    // fulfillment: deposit_resource.fulfillment,
                    fulfillment: None,
                })
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let next_token: Option<String> = response.last_evaluated_key
        .map(token_from_last_evaluated_key);

    common::package_response(models::GetTxnDepositsResponseContent {
        next_token,
        deposits: Some(deposit_data_list)
    }, 200)

}

/// Handles the retrieval of a single deposit transaction
pub async fn handle_get_deposit(
    path_parameters: HashMap<String, String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    let bitcoin_txid = path_parameters.get("txid").unwrap().clone();
    let bitcoin_tx_output_index = path_parameters
        .get("outputIndex")
        .ok_or(EmilyApiError::BadRequest(
            "Missing output index field from request".to_string()
        ))?
        .parse::<u16>()
        .map_err(|e| EmilyApiError::BadRequest(
            format!("Malformed output index {}", e)
        ))?;

    // Get table entry.
    let deposit_table_entry: DepositTableEntry = get_deposit_table_entry(
        DepositTableEntryKey {
            bitcoin_txid,
            bitcoin_tx_output_index,
        },
        context,
    ).await?;

    // Convert deposit table entry to usable data.
    let deposit_resource: DepositResource = (&deposit_table_entry).into();

    // Package response.
    common::package_response(models::GetDepositResponseContent {
        bitcoin_txid: deposit_resource.bitcoin_txid,
        bitcoin_tx_output_index: deposit_resource.bitcoin_tx_output_index as f64,
        recipient: deposit_resource.recipient,
        amount: deposit_resource.amount as f64,
        last_update_block_hash: Some(deposit_resource.last_update_block_hash),
        last_update_height: Some(deposit_resource.last_update_height as f64),
        status: deposit_resource.op_status,
        status_message: deposit_resource.status_message,
        parameters: deposit_resource.parameters.into(),
        fulfillment: None,
    }, 200)

}

/// Handles the retrieval of multiple deposit transactions
pub async fn handle_get_deposits(
    path_parameters: HashMap<String, String>,
    query_parameters: aws_lambda_events::query_map::QueryMap,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.

    // TODO:
    // Extract "next_token" and "page_size" and utilize them in the query.
    let next_token: Option<Vec<&str>> = query_parameters.all("nextToken");
    let page_size: Option<Vec<&str>> = query_parameters.all("maxResults");
    let &status_str = query_parameters.all("status")
        .ok_or(EmilyApiError::BadRequest("Missing \"status\" query parameter.".to_string()))?
        .first()
        .ok_or(EmilyApiError::BadRequest("Failed getting \"status\" from parameters.".to_string()))?;

    // TODO:
    // Find a method to use the serde deserialization without manually converting the status to
    // json string format.
    let status = serde_json::from_str::<models::OpStatus>(format!("\"{}\"", status_str.replace("\"", "\\\"")).as_str())
        .map_err(|e| EmilyApiError::BadRequest(
            format!("Bad status name {} {:?}", status_str, e)
        ))?;

    // TODO:
    // Move to DynamoDB table accessor utility.
    let response: aws_sdk_dynamodb::operation::query::QueryOutput = context
        .dynamodb_client
        .query()
        .table_name(&context.settings.deposit_table_name)
        .index_name("DepositStatus".to_string())
        .key_condition_expression("#pk = :v")
        .expression_attribute_names("#pk", "OpStatus")
        .expression_attribute_values(":v", AttributeValue::N(status_to_id(status).to_string()))
        .send()
        .await
        .map_err(|e| EmilyApiError::InternalService(
            format!("failed at dynamodb call with parameters {:?}: {:?}", path_parameters, e)))?;

    let debug_string = format!(
        "next_token {:?} page_size {:?} status {:?} response {:?}",
        next_token,
        page_size,
        status,
        response,
    ).to_string();

    let deposit_basic_info_list: Vec<models::DepositBasicInfo> = response.items()
        .iter()
        .filter_map(|item| {
            // TODO: instead of filtering out errors, propagate the error to the end.
            let deposit_basic_info_resource: Result<DepositBasicInfoResource, EmilyApiError> = item.try_into();
            deposit_basic_info_resource
                .and_then(|resource| {
                    let deposit_packaged_for_response: models::DepositBasicInfo = resource.into();
                    Ok(deposit_packaged_for_response)
                })
                .ok()
        })
        .collect();

    common::package_response(models::GetDepositsResponseContent {
        next_token: Some(debug_string),
        deposits: Some(deposit_basic_info_list)
    }, 200)

}

/// Handles the update of deposit transactions
// TODO: Handle Update Deposit
pub async fn handle_update_deposits(
    body: Option<String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Decipher request.
    let request: models::UpdateDepositsRequestContent = common::deserialize_request(body)?;

    // Retrieve existing versions of the deposits.
    let futures: Vec<_> = request.deposits.iter()
        .map(|to_update| DepositTableEntryKey {
            bitcoin_txid: to_update.bitcoin_txid.clone(),
            bitcoin_tx_output_index: to_update.bitcoin_tx_output_index as u16,
        })
        .map(|key| get_deposit_table_entry(key, context))
        .collect();

    // Note that this will fail if any of the deposits that this call is trying
    // to update are not already present in the table. `try_join_all` maintains
    // order.
    let deposits_to_update: Vec<DepositTableEntry> = try_join_all(futures)
        .await?;

    // TODO:
    // Complete.

    // // Get a single entry to update.
    // let single_update = request.deposits.first()
    //     .ok_or(EmilyApiError::BadRequest("Request must contain at least one item to update.".to_string()))?;

    // let bitcoin_txid = single_update.bitcoin_txid.clone();
    // let bitcoin_tx_output_index = single_update.bitcoin_tx_output_index as u16;
    // let key: DepositTableEntryKey = DepositTableEntryKey {
    //     bitcoin_txid,
    //     bitcoin_tx_output_index,
    // };

    // // Construct the updates.
    // let mut updates: HashMap<String, AttributeValueUpdate> = HashMap::new();
    // updates.insert(
    //     "Version".to_string(),
    //     AttributeValueUpdate::builder()
    //         .value(AttributeValue::N("1".to_string()))
    //         .action(AttributeAction::Add)
    //         .build(),
    // );
    // let new_list_element = AttributeValue::S("NewListItem".to_string());
    // updates.insert(
    //     "Version".to_string(),
    //     AttributeValueUpdate::builder()
    //         .value(AttributeValue::L(vec![new_list_element]))
    //         .action(AttributeAction::Add)
    //         .build(),
    // );

    // // Construct the condition expression.
    // let expected_version = 0;
    // let mut expected: HashMap<String, ExpectedAttributeValue> = HashMap::new();
    // expected.insert(
    //     "Version".to_string(),
    //     ExpectedAttributeValue::builder()
    //         .value(AttributeValue::N(expected_version.to_string()))
    //         .exists(true)
    //         .build()
    // );

    Err(EmilyApiError::NotImplemented("query not implemented".to_string()))
}

// Tested in `bin/entrypoint.rs`. Tests will be added here when these outputs no longer mock.

/// Get deposit table entry for a given bitcoin txid and tx output index
/// from the DynamoDB table.
async fn get_deposit_table_entry(
    key: DepositTableEntryKey,
    context: &LambdaContext,
) -> Result<DepositTableEntry, EmilyApiError> {

    // TODO:
    // Move to DynamoDB table accessor utility.
    let response = context
        .dynamodb_client
        .get_item()
        .table_name(&context.settings.deposit_table_name)
        .set_key(Some((&key).into()))
        .send()
        .await
        .map_err(|e| EmilyApiError::InternalService(
            format!("Failed retrieving deposit {:?}: {:?}", key, e))
        )?;

    let deposit_entry = response.item()
        .ok_or(EmilyApiError::NotFound(
            format!("Deposit {:?} not found.", key)
        ))?;

    let deposit_table_entry: DepositTableEntry = deposit_entry.try_into()?;
    Ok(deposit_table_entry)
}

// TODO:
// Complete this function.
//
// /// Get deposit table entry for a given bitcoin txid and tx output index
// /// from the DynamoDB table.
// async fn get_deposit_table_entries(
//     keys: Vec<DepositTableEntryKey>,
//     context: &LambdaContext,
// ) -> Result<DepositTableEntry, EmilyApiError> {

//     let keys_as_dynamodb_lib_structure = keys.iter()
//         .map(|k| k.into())
//         .collect();

//     // TODO:
//     // Move to DynamoDB table accessor utility.
//     let response = context
//         .dynamodb_client
//         .batch_get_item()
//         // .table_name(&context.settings.deposit_table_name)
//         .request_items(
//             &context.settings.deposit_table_name,
//             KeysAndAttributes::builder()
//             .set_keys(Some(keys_as_dynamodb_lib_structure))
//             .build()
//             .map_err(|e| EmilyApiError::InternalService(
//                 "Error making batch table request".to_string(),
//             ))?
//         )
//         .send()
//         .await
//         .map_err(|e| EmilyApiError::InternalService(
//             format!("Failed retrieving multiple deposits. {:?}", e))
//         )?;

//     let a = response.responses
//         .ok_or(EmilyApiError::InternalService(
//             "Failed unpacking batch get deposits request.".to_string()
//         ))?
//         .iter()
//         .map(f);

//     let deposit_table_entry: DepositTableEntry = deposit_entry.try_into()?;
//     Ok(deposit_table_entry)
// }

/// Extracts a string representation of a token to continue the paged query from
/// the laste evaluated key field returned from the DynamoDB call
fn token_from_last_evaluated_key(
    last_evaluated_key: HashMap<String, AttributeValue>,
) -> String {
    // TODO:
    // Extract "next_token" from "response.last_evaluated_key"
    return "DUMMY_TOKEN".to_string();
}

/// Represents the fields that can be extracted from the deposit script in a bundle.
///
/// TODO:
/// Use transaction library function instead of this debug setup.
struct FieldsExtractedFromDepositScript {
    recipient: String,
    amount: u64,
    lock_time: u64,
    max_fee: u64,
}

/// Extracts fields from the reclaim script.
fn extract_fields_from_reclaim_script(
    reclaim_script: String,
) -> Result<FieldsExtractedFromDepositScript, EmilyApiError> {
    Ok(FieldsExtractedFromDepositScript {
        recipient: "DUMMY_RECIPIENT".to_string(),
        amount: 11111,
        lock_time: 22222,
        max_fee: 33333,
    })
}

// TODO:
// Add tests
