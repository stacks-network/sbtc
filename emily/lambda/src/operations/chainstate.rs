//! Handlers for chainstate-related API operations

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use emily::models::{self, CreateChainstateResponseContent, UpdateChainstateRequestContent, UpdateChainstateResponseContent};
use serde::{Deserialize, Serialize};
use serde_dynamo::Item;
use crate::common;
use crate::config::LambdaContext;
use crate::errors::{self, EmilyApiError};
use crate::resources::chainstate::ChainstateBlock;

/// Handles the creation of a new chainstate
pub async fn handle_create_chainstate(
    body: Option<String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    let request: models::CreateChainstateRequestContent = common::deserialize_request(body)?;

    // Create table entry.
    let new_block: ChainstateBlock = ChainstateBlock {
        block_height: request.block_height as u64,
        block_hash: request.block_hash,
    };

    // Make the item representation.
    let dynamodb_item: Item = serde_dynamo::to_item(&new_block)
        .map_err(errors::to_emily_api_error)?;

    // Put entry into table.
    //
    // TODO: [ticket link here once PR is approved]
    // Emplace collision logic.
    context.dynamodb_client
        .put_item()
        .table_name(&context.settings.chainstate_table_name)
        .set_item(Some(dynamodb_item.into()))
        .send()
        .await
        .map_err(errors::to_emily_api_error)?;

    // Return API response.
    common::package_response(CreateChainstateResponseContent {
        block_hash: new_block.block_hash,
        block_height: new_block.block_height as f64,
    }, 201)
}

/// Private "get chainstate" parameter representation to simplify deserialization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetChainstateParameters {
    /// Bitcoin txid.
    #[serde(deserialize_with = "crate::utils::deserialize_string_to_number")]
    height: u64,
}

/// Handles retrieval of the current chainstate
pub async fn handle_get_chainstate(
    path_parameters: HashMap<String, String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    // Extract request parameters.
    //
    // TODO: [ticket link here once PR is approved]
    // Refine extraction procedure for both query and path parameters.
    let parameters = serde_json::to_string(&path_parameters)
        .and_then(|param_string| serde_json::from_str::<GetChainstateParameters>(&param_string))
        .map_err(errors::to_emily_api_error)?;

    let response = context.dynamodb_client
        .query()
        .table_name(context.settings.chainstate_table_name.clone())
        .key_condition_expression("#h = :height")
        .expression_attribute_names("#h", "BlockHeight")
        .expression_attribute_values(":height", AttributeValue::N(parameters.height.to_string()))
        .send()
        .await
        .map_err(errors::to_emily_api_error)?;

    let items: Vec<ChainstateBlock> = serde_dynamo::from_items(response.items().to_vec())
        .map_err(errors::to_emily_api_error)?;

    // Change behavior depending on how many entries were found.
    match &items[..] {
        // No blocks found.
        [] => Err(EmilyApiError::NotFound(
            format!("No bock hash found for height {}", parameters.height)
        )),
        // A single block found; happy path.
        [item] => {
            common::package_response(models::GetChainstateResponseContent {
                block_hash: item.block_hash.clone(),
                block_height: item.block_height as f64,
            }, 200)
        },
        // Multiple conflicting blocks found.
        [_item, ..] => {
            Err(EmilyApiError::InternalService(format!(
                    "Found multiple block hashes for height {}",
                    parameters.height,
                ))
            )
        }
    }
}

/// Handles the update of an existing chainstate
pub async fn handle_update_chainstate(
    body: Option<String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    let request: UpdateChainstateRequestContent = common::deserialize_request(body)?;

    // Create table entry.
    let chainstate_block: ChainstateBlock = ChainstateBlock {
        block_height: request.block_height as u64,
        block_hash: request.block_hash,
    };

    // Make the item representation.
    let dynamodb_item: Item = serde_dynamo::to_item(&chainstate_block)
        .map_err(errors::to_emily_api_error)?;

    // Put entry into table.
    //
    // TODO: [ticket link here once PR is approved]
    // Emplace update logic.
    context.dynamodb_client
        .put_item()
        .table_name(&context.settings.chainstate_table_name)
        .set_item(Some(dynamodb_item.into()))
        .send()
        .await
        .map_err(errors::to_emily_api_error)?;

    common::package_response(UpdateChainstateResponseContent {
        block_height: chainstate_block.block_height as f64,
        block_hash: chainstate_block.block_hash,
    }, 202)
}

// Tested in `bin/entrypoint.rs`. Tests will be added here when these outputs no longer mock.
