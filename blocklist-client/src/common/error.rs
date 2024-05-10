use reqwest::StatusCode;
use serde::Serialize;
use warp::reject::Reject;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HTTP request failed with status code {0}: {1}")]
    HttpRequestErr(StatusCode, String),

    #[error("Network error: {0}")]
    NetworkErr(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    SerializationErr(#[from] serde_json::Error),

    #[error("Invalid API response structure")]
    InvalidApiResponse,

    #[error("Invalid risk value provided: {0}")]
    InvalidRiskValue(String),

    #[error("Unauthorized access - check your API key")]
    Unauthorized,

    #[error("Resource not found")]
    NotFound,

    #[error("Not acceptable format requested")]
    NotAcceptable,

    #[error("Request conflict")]
    Conflict,

    #[error("Internal server error")]
    InternalServerErr,

    #[error("Service unavailable")]
    ServiceUnavailable,

    #[error("Request timeout")]
    RequestTimeout,
}

impl Error {
    pub fn as_http_response(&self) -> (StatusCode, String) {
        match self {
            Error::HttpRequestErr(code, msg) => (*code, msg.clone()),
            Error::NetworkErr(_) => (StatusCode::BAD_GATEWAY, "Network error".to_string()),
            Error::SerializationErr(_) => (
                StatusCode::BAD_REQUEST,
                "Error in processing the data".to_string(),
            ),
            Error::InvalidApiResponse => (
                StatusCode::BAD_REQUEST,
                "Invalid API response structure".to_string(),
            ),
            Error::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "Unauthorized access - check your API key".to_string(),
            ),
            Error::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
            Error::NotAcceptable => (
                StatusCode::NOT_ACCEPTABLE,
                "Not acceptable format requested".to_string(),
            ),
            Error::Conflict => (StatusCode::CONFLICT, "Request conflict".to_string()),
            Error::InternalServerErr => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            Error::ServiceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service unavailable".to_string(),
            ),
            Error::RequestTimeout => (StatusCode::REQUEST_TIMEOUT, "Request timeout".to_string()),
            Error::InvalidRiskValue(_) => (
                StatusCode::BAD_REQUEST,
                "Invalid API response risk value".to_string(),
            ),
        }
    }
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub(crate) message: String,
}

impl Reject for Error {}
