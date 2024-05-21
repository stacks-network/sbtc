use crate::client::risk_client;
use crate::common::error::{Error, ErrorResponse};
use crate::config::RiskAnalysisConfig;
use reqwest::Client;
use std::convert::Infallible;
use tracing::error;
use warp::{http::StatusCode, Rejection, Reply};

/// Handles requests to check the blocklist status of a given address.
/// Converts successful blocklist status results to JSON and returns them,
/// or converts errors into Warp rejections.
#[utoipa::path(
    get,
    operation_id = "checkAddress",
    path = "/screen/{address}",
    tag = "address",
    params(
    ("address" = String, Path, description = "Address to get risk assessment for")
    ),
    responses(
    (status = 200, description = "Risk assessment retrieved successfully", body = BlocklistStatus),
    (status = 400, description = "Invalid request body"),
    (status = 404, description = "Address not found"),
    (status = 405, description = "Method not allowed"),
    (status = 500, description = "Internal server error")
    )
)]
pub async fn check_address_handler(
    address: String,
    client: Client,
    config: RiskAnalysisConfig,
) -> Result<impl Reply, Rejection> {
    risk_client::check_address(&client, &config, &address)
        .await
        .map(|blocklist_status| warp::reply::json(&blocklist_status))
        .map_err(warp::reject::custom)
}

/// Central error handler for Warp rejections, converting them to appropriate HTTP responses.
pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    if err.is_not_found() {
        let json = warp::reply::json(&ErrorResponse {
            message: "Not Found".to_string(),
        });
        return Ok(warp::reply::with_status(json, StatusCode::NOT_FOUND));
    }

    if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        let json = warp::reply::json(&ErrorResponse {
            message: format!("Invalid Body: {}", e),
        });
        return Ok(warp::reply::with_status(json, StatusCode::BAD_REQUEST));
    }

    if let Some(e) = err.find::<Error>() {
        // Custom application errors
        let (code, message) = e.as_http_response();
        let json = warp::reply::json(&ErrorResponse { message });
        return Ok(warp::reply::with_status(json, code));
    }

    if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        let json = warp::reply::json(&ErrorResponse {
            message: "Method Not Allowed".to_string(),
        });
        return Ok(warp::reply::with_status(
            json,
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }

    error!("Unhandled error: {:?}", err);
    let json = warp::reply::json(&ErrorResponse {
        message: "Internal Server Error".to_string(),
    });
    Ok(warp::reply::with_status(
        json,
        StatusCode::INTERNAL_SERVER_ERROR,
    ))
}
