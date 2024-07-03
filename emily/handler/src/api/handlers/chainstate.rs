//! Handlers for chainstate endpoints.
use warp::reply::{json, with_status};
use crate::api::models::{
    chainstate::{requests::{SetChainstateRequestBody, UpdateChainstateRequestBody},
    responses::{GetChainstateResponse, SetChainstateResponse, UpdateChainstateResponse}},
    common::BlockHeight
};
use warp::http::StatusCode;

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
        (status = 200, description = "Chainstate retrieved successfully", body = GetChainstateResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_chainstate(
    _height: BlockHeight,
) -> impl warp::reply::Reply {
    let response = GetChainstateResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::OK)
}

/// Set chainstate handler.
#[utoipa::path(
    post,
    operation_id = "setChainstate",
    path = "/chainstate",
    tag = "chainstate",
    request_body = SetChainstateRequestBody,
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Chainstate updated successfully", body = SetChainstateResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn set_chainstate(
    _request: SetChainstateRequestBody,
) -> impl warp::reply::Reply {
    let response = SetChainstateResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::CREATED)
}

/// Update chainstate handler.
#[utoipa::path(
    put,
    operation_id = "updateChainstate",
    path = "/chainstate",
    tag = "chainstate",
    request_body = UpdateChainstateRequestBody,
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Chainstate updated successfully", body = UpdateChainstateResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn update_chainstate(
    _request: UpdateChainstateRequestBody,
) -> impl warp::reply::Reply {
    let response = UpdateChainstateResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::CREATED)
}
