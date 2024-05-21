use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use warp::reject::Reject;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HTTP request failed with status code {0}: {1}")]
    HttpRequest(StatusCode, String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid API response structure")]
    InvalidApiResponse,

    #[error("Unauthorized access - check your API key")]
    Unauthorized,

    #[error("Resource not found")]
    NotFound,

    #[error("Not acceptable format requested")]
    NotAcceptable,

    #[error("Request conflict")]
    Conflict,

    #[error("Internal server error")]
    InternalServer,

    #[error("Service unavailable")]
    ServiceUnavailable,

    #[error("Request timeout")]
    RequestTimeout,
}

impl Error {
    pub fn as_http_response(&self) -> (StatusCode, String) {
        match self {
            Error::HttpRequest(code, msg) => (*code, msg.clone()),
            Error::Network(_) => (StatusCode::BAD_GATEWAY, "Network error".to_string()),
            Error::Serialization(_) => (
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
            Error::InternalServer => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            Error::ServiceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service unavailable".to_string(),
            ),
            Error::RequestTimeout => (StatusCode::REQUEST_TIMEOUT, "Request timeout".to_string()),
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub(crate) message: String,
}

impl Reject for Error {}
