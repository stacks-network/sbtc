//! Top-level error type for the Blocklist client

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use warp::{filters::path::FullPath, reject::Reject, reply::Reply};

/// Errors from the internal API logic.
#[allow(dead_code)]
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

    /// The request targeted an endpoint that is not yet implemented.
    #[error("Not implemented")]
    NotImplemented(FullPath),

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

/// Error implementation.
impl Error {
    /// Provides the status code that corresponds to the error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::HttpRequest(code, _) => *code,
            Error::Network(_) => StatusCode::BAD_GATEWAY,
            Error::Serialization(_) => StatusCode::BAD_REQUEST,
            Error::InvalidApiResponse => StatusCode::BAD_REQUEST,
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            Error::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Error::Conflict => StatusCode::CONFLICT,
            Error::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            Error::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Error::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
        }
    }

    /// Provides the error message that corresponds to the error.
    pub fn error_message(&self) -> String {
        match self {
            Error::HttpRequest(_, msg) => msg.clone(),
            Error::Network(_) => "Network error".to_string(),
            Error::Serialization(_) => "Error in processing the data".to_string(),
            Error::InvalidApiResponse => "Invalid API response structure".to_string(),
            Error::Unauthorized => "Unauthorized access - check your API key".to_string(),
            Error::NotFound => "Resource not found".to_string(),
            Error::NotAcceptable => "Not acceptable format requested".to_string(),
            Error::NotImplemented(path) => format!("Handling {path:?} is not implemented."),
            Error::Conflict => "Request conflict".to_string(),
            Error::InternalServer => "Internal server error".to_string(),
            Error::ServiceUnavailable => "Service unavailable".to_string(),
            Error::RequestTimeout => "Request timeout".to_string(),
        }
    }
}

/// Structure representing an error response
/// This is used to serialize error messages in HTTP responses
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub(crate) message: String,
}

/// Implement reject for error.
impl Reject for Error {}

/// Implement reply for internal error representation so that the error can be
/// provided directly from Warp as a reply.
impl Reply for Error {

    /// Convert self into a warp response.
    fn into_response(self) -> warp::reply::Response {
       warp::reply::with_status(
            warp::reply::json(&ErrorResponse {
                message: self.error_message(),
            }),
            self.status_code(),
        )
        .into_response()
    }
}

