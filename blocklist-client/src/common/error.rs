//! Top-level error type for the Blocklist client

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use warp::reject::Reject;

/// Errors occurring from Blocklist client's API calls to risk client and request handling
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The request was unacceptable. This may refer to a missing or improperly formatted parameter
    /// or request body property, or non-valid JSON
    #[error("HTTP request failed with status code {0}: {1}")]
    HttpRequest(StatusCode, String),

    /// Network error
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Response serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Mismatch between defined response data model and what is returned by the risk API
    #[error("Invalid API response structure")]
    InvalidApiResponse,

    /// Your API key is invalid. This may be because your API Key is expired
    /// or not sent correctly as the value of the Token HTTP header
    #[error("Unauthorized access - check your API key")]
    Unauthorized,

    /// This may be because you either requested a nonexistent endpoint
    /// or referenced a user that does not exist
    #[error("Resource not found")]
    NotFound,

    /// You requested a response format that the API cannot produce
    /// We currently only support JSON output
    #[error("Not acceptable format requested")]
    NotAcceptable,

    /// The request has a conflict
    #[error("Request conflict")]
    Conflict,

    /// Internal error
    #[error("Internal server error")]
    InternalServer,

    /// Server may be unavailable or not ready to handle the request
    #[error("Service unavailable")]
    ServiceUnavailable,

    /// Request timeout error
    #[error("Request timeout")]
    RequestTimeout,
}

impl Error {
    /// Converts the error into an HTTP response representation.
    ///
    /// # Returns
    ///
    /// A tuple containing the corresponding HTTP status code and error message.
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

/// Structure representing an error response
/// This is used to serialize error messages in HTTP responses
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub(crate) message: String,
}

impl Reject for Error {}
