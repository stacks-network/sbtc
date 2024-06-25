//! Handlers for chainstate-related API operations

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use emily::models;
use crate::common;
use crate::config::LambdaContext;
use crate::errors::{self, EmilyApiError};

/// Handles the creation of a new chainstate
pub async fn handle_create_chainstate(
    body: Option<String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    let request: models::CreateChainstateRequestContent =
        common::deserialize_request::<models::CreateChainstateRequestContent>(body)?;

    let chainstate_entry = models::CreateChainstateResponseContent {
        block_hash: request.block_hash.clone(),
        block_height: request.block_height,
    };

    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    item.insert("BlockHeight".to_string(), AttributeValue::N(request.block_height.to_string()));
    item.insert("BlockHash".to_string(), AttributeValue::S(request.block_hash));

    let response = context.dynamodb_client
        .put_item()
        .table_name(context.settings.chainstate_table_name.clone())
        .set_item(Some(item))
        .send()
        .await;

    match response {
        Err(e) => return Err(EmilyApiError::InternalService(
            format!("Error occurred for table {:?} {:?}", context.settings.chainstate_table_name.clone(), e).to_string()
        )),
        _ => {}
    }

    common::package_response(chainstate_entry, 201)
}

/// Handles retrieval of the current chainstate
pub async fn handle_get_chainstate(
    _path_parameters: HashMap<String, String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    // // path_parameters.keys()
    let height: &String = _path_parameters.get("height").unwrap();
    let response = context.dynamodb_client
        .query()
        .table_name(context.settings.chainstate_table_name.clone())
        .key_condition_expression("#h = :height")
        .expression_attribute_names("#h", "BlockHeight")
        .expression_attribute_values(":height", AttributeValue::N(height.clone()))
        .send()
        .await;

    match response {
        Err(e) => Err(EmilyApiError::InternalService(
            format!("Error occurred on height {:?} {:?}", height.clone(), e).to_string()
        )),
        Ok(output) => {
            return match output.items().len() {
                0 => Err(EmilyApiError::NotFound(
                    format!("No bock hash found for height {}", height).to_string()
                )),
                1 => {
                    // Extract.
                    let item = output.items().first().unwrap();
                    let block_hash = item.get("BlockHash").unwrap().as_s().unwrap();
                    let block_height = item.get("BlockHeight").unwrap().as_n().unwrap();

                    // Package.
                    common::package_response(models::GetChainstateResponseContent {
                        block_hash: block_hash.clone(),
                        block_height: block_height.parse::<f64>().unwrap(),
                    }, 200)
                },
                _ => {
                    let block_hashes = output.items()
                        .iter()
                        .map(|item| {
                            item.get("BlockHash").unwrap().as_s().unwrap().clone()
                        })
                        .collect::<Vec<String>>();

                    Err(EmilyApiError::InternalService(
                        format!(
                            "Multiple block hashes for height {}: [{}]",
                            height,
                            block_hashes.join(", "),
                        ).to_string()
                    ))
                }
            }
        }
    }
}

/// Handles the update of an existing chainstate
pub async fn handle_update_chainstate(
    body: Option<String>,
    context: &LambdaContext,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {

    let request: models::UpdateChainstateRequestContent =
        common::deserialize_request::<models::UpdateChainstateRequestContent>(body)?;

    let chainstate_entry: models::UpdateChainstateResponseContent = models::UpdateChainstateResponseContent {
        block_hash: request.block_hash.clone(),
        block_height: request.block_height,
    };

    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    item.insert("BlockHeight".to_string(), AttributeValue::N(request.block_height.to_string()));
    item.insert("BlockHash".to_string(), AttributeValue::S(request.block_hash));

    let response = context.dynamodb_client
        .put_item()
        .table_name(context.settings.chainstate_table_name.clone())
        .set_item(Some(item))
        .send()
        .await;

    match response {
        Err(e) => return Err(EmilyApiError::InternalService(
            format!("Error occurred for table {:?} {:?}", context.settings.chainstate_table_name.clone(), e).to_string()
        )),
        _ => {}
    }

    common::package_response(chainstate_entry, 202)
}

// Tested in `bin/entrypoint.rs`. Tests will be added here when these outputs no longer mock.
