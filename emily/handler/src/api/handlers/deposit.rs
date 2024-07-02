//! Handlers for Deposit endpoints.

use crate::common::error::Error;
use warp::filters::path::FullPath;
use super::models;

/// Get deposit handler.
#[utoipa::path(
    get,
    operation_id = "getDeposit",
    path = "/deposit/{txid}/{index}",
    params(
        ("txid" = String, Path, description = "txid associated with the Deposit."),
        ("index" = String, Path, description = "output index associated with the Deposit."),
    ),
    tag = "deposit",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Deposit retrieved successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_deposit(
    _txid: String,
    _index: u16,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Get deposits for transaction handler.
#[utoipa::path(
    get,
    operation_id = "getDepositsForTransaction",
    path = "/deposit/{txid}",
    params(
        ("txid" = String, Path, description = "txid associated with the Deposit."),
    ),
    tag = "deposit",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Deposits retrieved successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_deposits_for_transaction(
    _txid: String,
    _query: models::requests::PaginatedQuery<String>,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Get deposits handler.
#[utoipa::path(
    get,
    operation_id = "getDeposits",
    path = "/deposit",
    tag = "deposit",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Deposits retrieved successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_deposits(
    _query: models::requests::PaginatedQuery<String>,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Create deposit handler.
#[utoipa::path(
    post,
    operation_id = "createDeposit",
    path = "/deposit",
    tag = "deposit",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Deposit created successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn create_deposit(
    _body: serde_json::Value,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}

/// Update deposits handler.
#[utoipa::path(
    put,
    operation_id = "updateDeposits",
    path = "/deposit",
    tag = "deposit",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Deposits updated successfully", body = serde_json::Value),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn update_deposits(
    _body: serde_json::Value,
    path: FullPath,
) -> impl warp::reply::Reply {
    Error::NotImplemented(path)
}
