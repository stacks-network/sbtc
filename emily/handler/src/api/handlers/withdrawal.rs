//! Handlers for withdrawal endpoints.

use crate::common::error::Error;
use warp::filters::path::FullPath;
use super::models;

/// Get withdrawal handler.
#[utoipa::path(
    get,
    operation_id = "getWithdrawal",
    path = "/withdrawal/{id}",
    params(
        ("id" = String, Path, description = "id associated with the Withdrawal"),
    ),
    tag = "withdrawal",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Withdrawal retrieved successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_withdrawal(
    _id: u64,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Get withdrawals handler.
#[utoipa::path(
    get,
    operation_id = "getWithdrawals",
    path = "/withdrawal",
    tag = "withdrawal",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Withdrawals retrieved successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_withdrawals(
    _query: models::requests::PaginatedQuery<String>,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Create withdrawal handler.
#[utoipa::path(
    post,
    operation_id = "createWithdrawal",
    path = "/withdrawal",
    tag = "withdrawal",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Withdrawals updated successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn create_withdrawal(
    _body: serde_json::Value,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Update withdrawals handler.
#[utoipa::path(
    put,
    operation_id = "updateWithdrawals",
    path = "/withdrawal",
    tag = "withdrawal",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Withdrawals updated successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn update_withdrawals(
    _body: serde_json::Value,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}
