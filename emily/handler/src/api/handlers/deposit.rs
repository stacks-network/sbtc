//! Handlers for Deposit endpoints.
use warp::reply::{json, with_status};

use warp::http::StatusCode;

use crate::api::models::{
    common::{BitcoinTransactionId, BitcoinTransactionOutputIndex},
    deposit::requests::{CreateDepositRequestBody, GetDepositsForTransactionQuery, GetDepositsQuery, UpdateDepositsRequestBody},
    deposit::responses::{CreateDepositResponse, GetDepositResponse, GetDepositsForTransactionResponse, GetDepositsResponse, UpdateDepositsResponse},
};

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
        (status = 200, description = "Deposit retrieved successfully", body = GetDepositResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_deposit(
    _txid: BitcoinTransactionId,
    _index: BitcoinTransactionOutputIndex,
) -> impl warp::reply::Reply {
    let response = GetDepositResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::OK)
}

/// Get deposits for transaction handler.
#[utoipa::path(
    get,
    operation_id = "getDepositsForTransaction",
    path = "/deposit/{txid}",
    params(
        ("txid" = String, Path, description = "txid associated with the Deposit."),
        ("nextToken" = String, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = String, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "deposit",
    responses(
        (status = 200, description = "Deposits retrieved successfully", body = GetDepositsForTransactionResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_deposits_for_transaction(
    _txid: BitcoinTransactionId,
    _query: GetDepositsForTransactionQuery,
) -> impl warp::reply::Reply {
    let response = GetDepositsForTransactionResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::OK)
}

/// Get deposits handler.
#[utoipa::path(
    get,
    operation_id = "getDeposits",
    path = "/deposit",
    params(
        ("nextToken" = String, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = String, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "deposit",
    responses(
        (status = 200, description = "Deposits retrieved successfully", body = GetDepositsResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn get_deposits(
    _query: GetDepositsQuery,
) -> impl warp::reply::Reply {
    let response = GetDepositsResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::OK)
}

/// Create deposit handler.
#[utoipa::path(
    post,
    operation_id = "createDeposit",
    path = "/deposit",
    tag = "deposit",
    request_body = CreateDepositRequestBody,
    responses(
        (status = 201, description = "Deposit created successfully", body = CreateDepositResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn create_deposit(
    _body: CreateDepositRequestBody,
) -> impl warp::reply::Reply {
    let response = CreateDepositResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::CREATED)
}

/// Update deposits handler.
#[utoipa::path(
    put,
    operation_id = "updateDeposits",
    path = "/deposit",
    tag = "deposit",
    request_body = UpdateDepositsRequestBody,
    responses(
        (status = 201, description = "Deposits updated successfully", body = UpdateDepositsResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub fn update_deposits(
    _body: UpdateDepositsRequestBody,
) -> impl warp::reply::Reply {
    let response = UpdateDepositsResponse {
        ..Default::default()
    };
    with_status(json(&response), StatusCode::CREATED)
}
