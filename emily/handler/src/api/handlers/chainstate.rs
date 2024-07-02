//! Handlers for chainstate endpoints.

use crate::common::error::Error;
use warp::filters::path::FullPath;

/// Get chainstate handler.
#[utoipa::path(
    get,
    operation_id = "getChainstate",
    path = "/chainstate/{height}",
    params(
        ("height" = u64, Path, description = "Height of the blockchain data to receive."),
    ),
    tag = "chainstate",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Chainstate retrieved successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_chainstate(
    _height: u64,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Set chainstate handler.
#[utoipa::path(
    post,
    operation_id = "setChainstate",
    path = "/chainstate",
    tag = "chainstate",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Chainstate updated successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn set_chainstate(
    _request: serde_json::Value,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Update chainstate handler.
#[utoipa::path(
    put,
    operation_id = "updateChainstate",
    path = "/chainstate",
    tag = "chainstate",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Chainstate updated successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn update_chainstate(
    _request: serde_json::Value,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}
