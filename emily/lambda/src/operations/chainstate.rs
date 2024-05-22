//! Handlers for chainstate-related API operations

use std::collections::HashMap;

use emily::models;
use crate::common;
use crate::errors;

/// Handles the creation of a new chainstate
pub fn handle_create_chainstate(
    body:  Option<String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    common::deserialize_request::<models::CreateChainstateRequestContent>(body).map(|request| models::CreateChainstateResponseContent {
                block_hash: request.block_hash,
                block_height: request.block_height,
            })
        .and_then(|response| {
            common::package_response(response, 201)
        })
}

/// Handles retrieval of the current chainstate
pub fn handle_get_chainstate(
    _path_parameters:  HashMap<String, String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    // path_parameters.keys()
    Ok(models::GetChainstateResponseContent {
        block_hash: "Tortoise".to_string(),
        block_height: 42.0,
    })
    .and_then(|response| {
        common::package_response(response, 200)
    })
}

/// Handles the update of an existing chainstate
pub fn handle_update_chainstate(
    body:  Option<String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    common::deserialize_request::<models::UpdateChainstateRequestContent>(body).map(|request| models::UpdateChainstateResponseContent {
            block_hash: request.block_hash,
            block_height: request.block_height,
        })
    .and_then(|response| {
        // Return 202 because this PUT operation won't be reflected in GET calls
        // until the change is consistent in DynamoDB (<1 second).
        common::package_response(response, 202)
    })
}

// Tested in `bin/entrypoint.rs`. Tests will be added here when these outputs no longer mock.
