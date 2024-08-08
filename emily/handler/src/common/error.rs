//! Top-level error type for the Blocklist client

use std::env;

use aws_sdk_dynamodb::{
    error::SdkError,
    operation::{
        batch_write_item::BatchWriteItemError, delete_item::DeleteItemError,
        get_item::GetItemError, put_item::PutItemError, query::QueryError, scan::ScanError,
    },
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use warp::{reject::Reject, reply::Reply};

use crate::database::entries::chainstate::ChainstateEntry;

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

    /// Mismatch between defined response data model and what is returned by the API
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
    NotImplemented,

    /// The request has a conflict
    #[error("Request conflict")]
    Conflict,

    /// Internal error
    #[error("Internal server error")]
    InternalServer,

    /// Debug error.
    #[error("Debug error: {0}")]
    Debug(String),

    /// Server may be unavailable or not ready to handle the request
    #[error("Service unavailable")]
    ServiceUnavailable,

    /// Request timeout error
    #[error("Request timeout")]
    RequestTimeout,

    /// Inconsistent API state detected during request
    #[error("Inconsistent internal state: {0:?}")]
    InconsistentState(Vec<ChainstateEntry>),
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
            Error::NotImplemented => StatusCode::NOT_IMPLEMENTED,
            Error::Conflict => StatusCode::CONFLICT,
            Error::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Debug(_) => StatusCode::IM_A_TEAPOT,
            Error::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Error::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Error::InconsistentState(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    /// Converts the error into a warp response.
    pub fn into_response(self) -> warp::reply::Response {
        warp::reply::with_status(
            warp::reply::json(&ErrorResponse { message: format!("{self:?}") }),
            self.status_code(),
        )
        .into_response()
    }
    /// Convert error into a presentable version of the error that can be
    /// provided to a client in production.
    ///
    /// TODO(131): Scrutinize the outputs of the error messages to ensure they're
    /// production ready.
    pub fn into_production_error(self) -> Error {
        match self {
            Error::Serialization(_) | Error::InvalidApiResponse => Error::NotAcceptable,
            Error::NotImplemented
            | Error::Debug(_)
            | Error::Network(_)
            | Error::ServiceUnavailable => Error::InternalServer,
            err => err,
        }
    }
}

/// TODO(391): Route errors to the appropriate Emily API error.
///
/// Implement from for API Errors.
impl From<SdkError<GetItemError>> for Error {
    fn from(err: SdkError<GetItemError>) -> Self {
        Error::Debug(format!("SdkError<GetItemError> - {err:?}"))
    }
}
impl From<SdkError<PutItemError>> for Error {
    fn from(err: SdkError<PutItemError>) -> Self {
        Error::Debug(format!("SdkError<PutItemError> - {err:?}"))
    }
}
impl From<SdkError<QueryError>> for Error {
    fn from(err: SdkError<QueryError>) -> Self {
        Error::Debug(format!("SdkError<QueryError> - {err:?}"))
    }
}
impl From<SdkError<DeleteItemError>> for Error {
    fn from(err: SdkError<DeleteItemError>) -> Self {
        Error::Debug(format!("SdkError<DeleteItemError> - {err:?}"))
    }
}
impl From<SdkError<ScanError>> for Error {
    fn from(err: SdkError<ScanError>) -> Self {
        Error::Debug(format!("SdkError<ScanError> - {err:?}"))
    }
}
impl From<SdkError<BatchWriteItemError>> for Error {
    fn from(err: SdkError<BatchWriteItemError>) -> Self {
        Error::Debug(format!("SdkError<BatchWriteItemError> - {err:?}"))
    }
}
impl From<aws_sdk_dynamodb::error::BuildError> for Error {
    fn from(err: aws_sdk_dynamodb::error::BuildError) -> Self {
        Error::Debug(format!("aws_sdk_dynamodb::error::BuildError - {err:?}"))
    }
}
impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Debug(format!("base64::DecodeError - {err:?}"))
    }
}
impl From<env::VarError> for Error {
    fn from(err: env::VarError) -> Self {
        Error::Debug(format!("env::VarError - {err:?}"))
    }
}
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Debug(format!("serde_json::Error - {err:?}"))
    }
}
impl From<serde_dynamo::Error> for Error {
    fn from(err: serde_dynamo::Error) -> Self {
        Error::Debug(format!("serde_dynamo::Error - {err:?}"))
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
    #[cfg(not(feature = "testing"))]
    fn into_response(self: Error) -> warp::reply::Response {
        self.into_production_error().into_response()
    }
    /// Convert self into a warp response.
    #[cfg(feature = "testing")]
    fn into_response(self) -> warp::reply::Response {
        self.into_response()
    }
}
