//! Handlers for the emily API

use crate::common::error::ErrorResponse;

use std::convert::Infallible;
use tracing::error;
use warp::{http::StatusCode, Rejection, Reply};

/// Chainstate handlers.
pub mod chainstate;
/// Deposit handlers.
pub mod deposit;
/// Health handlers.
pub mod health;
/// Withdrawal handlers.
pub mod withdrawal;

/// Turns a results for which both the error and success cases can be converted
/// into a reponse and flattens them into a single response.
fn to_response(
    handler_result: Result<impl warp::reply::Reply, impl warp::reply::Reply>
) -> warp::reply::Response {
    match handler_result {
        Ok(reply) => reply.into_response(),
        Err(reply) => reply.into_response(),
    }
}

/// Central error handler for Warp rejections, converting them to appropriate HTTP responses.
/// TODO(131): Alter handler for Emily API.
pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    if err.is_not_found() {
        let json = warp::reply::json(&ErrorResponse {
            message: format!("Not Found {err:?}")
        });
        return Ok(warp::reply::with_status(json, StatusCode::NOT_FOUND));
    }

    if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        let json = warp::reply::json(&ErrorResponse {
            message: format!("Invalid Body: {}", e),
        });
        return Ok(warp::reply::with_status(json, StatusCode::BAD_REQUEST));
    }

    if let Some(e) = err.find::<warp::reject::MethodNotAllowed>() {
        let json = warp::reply::json(&ErrorResponse {
            message: format!("Method Not Allowed: {e:?}"),
        });
        return Ok(warp::reply::with_status(
            json,
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }

    error!("Unhandled error: {:?}", err);
    let json = warp::reply::json(&ErrorResponse {
        message: format!("Internal Server Error: {err:?}"),
    });
    Ok(warp::reply::with_status(
        json,
        StatusCode::INTERNAL_SERVER_ERROR,
    ))
}
