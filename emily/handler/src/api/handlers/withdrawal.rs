//! Handlers for withdrawal endpoints.
use warp::reply::{json, with_status};

use warp::http::StatusCode;
use crate::api::models::withdrawal::{
    WithdrawalId,
    requests::{CreateWithdrawalRequestBody, GetWithdrawalsQuery, UpdateWithdrawalsRequestBody},
    responses::{CreateWithdrawalResponse, GetWithdrawalResponse, GetWithdrawalsResponse, UpdateWithdrawalsResponse},
};

/// Get withdrawal handler.
#[utoipa::path(
    get,
    operation_id = "getWithdrawal",
    path = "/withdrawal/{id}",
    params(
        ("id" = WithdrawalId, Path, description = "id associated with the Withdrawal"),
    ),
    tag = "withdrawal",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Withdrawal retrieved successfully", body = GetWithdrawalResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_withdrawal(
    _id: WithdrawalId,
) -> impl warp::reply::Reply {
    let response = GetWithdrawalResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::OK)
}

/// Get withdrawals handler.
#[utoipa::path(
    get,
    operation_id = "getWithdrawals",
    path = "/withdrawal",
    params(
        ("nextToken" = String, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = String, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "withdrawal",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Withdrawals retrieved successfully", body = GetWithdrawalsResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_withdrawals(
    _query: GetWithdrawalsQuery,
) -> impl warp::reply::Reply {
    let response = GetWithdrawalsResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::OK)
}

/// Create withdrawal handler.
#[utoipa::path(
    post,
    operation_id = "createWithdrawal",
    path = "/withdrawal",
    tag = "withdrawal",
    request_body = CreateWithdrawalRequestBody,
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Withdrawal created successfully", body = CreateWithdrawalResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn create_withdrawal(
    _body: CreateWithdrawalRequestBody,
) -> impl warp::reply::Reply {
    let response = CreateWithdrawalResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::CREATED)
}

/// Update withdrawals handler.
#[utoipa::path(
    put,
    operation_id = "updateWithdrawals",
    path = "/withdrawal",
    tag = "withdrawal",
    request_body = UpdateWithdrawalsRequestBody,
    responses(
        (status = 201, description = "Withdrawals updated successfully", body = UpdateWithdrawalsResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn update_withdrawals(
    _body: UpdateWithdrawalsRequestBody,
) -> impl warp::reply::Reply {
    let response = UpdateWithdrawalsResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::CREATED)
}
