use crate::client;
use crate::common::{Error, ErrorResponse};
use crate::config::RiskAnalysisConfig;
use reqwest::Client;
use std::convert::Infallible;
use tracing::error;

use warp::{http::StatusCode, Rejection, Reply};

pub async fn check_address_handler(
    address: String,
    client: Client,
    config: RiskAnalysisConfig,
) -> Result<impl Reply, Rejection> {
    match client::check_address(client, &config, &address).await {
        Ok(value) => Ok(warp::reply::json(&value)),
        Err(_) => Err(warp::reject::custom(Error::AddressNotFound)),
    }
}

pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found")
    } else if err
        .find::<warp::filters::body::BodyDeserializeError>()
        .is_some()
    {
        (StatusCode::BAD_REQUEST, "Invalid Body")
    } else if let Some(e) = err.find::<Error>() {
        error!("Unhandled application error: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
    } else {
        error!("Unhandled error: {:?}", err);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    };

    let json = warp::reply::json(&ErrorResponse { message: message.to_string() });

    Ok(warp::reply::with_status(json, code))
}
