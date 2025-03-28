//! Handlers for the blocklist client API

use crate::client::{risk_client, sanctions};
use crate::common::error::ErrorResponse;
use crate::config::{AssessmentMethod, Settings};
use reqwest::Client;
use std::convert::Infallible;
use tracing::error;
use warp::{Rejection, Reply, http::StatusCode};

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
    config: Settings,
) -> impl Reply {
    let result = (async {
        match config.assessment.assessment_method {
            AssessmentMethod::Sanctions => {
                sanctions::check_address(&client, &config.risk_analysis, &address).await
            }
            AssessmentMethod::RiskAnalysis => {
                risk_client::check_address(&client, &config.risk_analysis, &address).await
            }
        }
    })
    .await
    .map(|blocklist_status| warp::reply::json(&blocklist_status));

    match result {
        Ok(blocklist_status) => blocklist_status.into_response(),
        Err(error) => error.into_response(),
    }
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
