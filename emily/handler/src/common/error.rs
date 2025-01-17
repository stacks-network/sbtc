//! Top-level error type for the Blocklist client

use std::env;

use aws_sdk_dynamodb::{
    error::SdkError,
    operation::{
        batch_write_item::BatchWriteItemError, delete_item::DeleteItemError,
        get_item::GetItemError, put_item::PutItemError, query::QueryError, scan::ScanError,
        update_item::UpdateItemError,
    },
};
use bitcoin::hex::HexToBytesError;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use warp::{reject::Reject, reply::Reply};

use crate::{api::models::chainstate::Chainstate, database::entries::chainstate::ChainstateEntry};

/// State inconsistency representations.
#[derive(Debug)]
pub enum Inconsistency {
    /// There is a chainstate inconsistency, and all the chainstates
    /// in the vector are the chainstates that are present in the API
    /// but are not known to be correct. All chainstates in the vector
    /// are considered equally canonical.
    Chainstates(Vec<Chainstate>),
    /// There is an inconsistency in the way an item is being updated.
    ItemUpdate(String),
}

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

    /// Internal too many retries error.
    #[error("Too many internal retries")]
    TooManyInternalRetries,

    /// Inconsistent API state detected during request
    #[error("Inconsistent internal state: {0:?}")]
    InconsistentState(Inconsistency),

    /// API is reorganizing.
    #[error("Api is reorganizing around new chain tip {0:?}")]
    Reorganzing(Chainstate),

    /// An entry update version conflict in a resource update resulted
    /// in an update not being performed.
    #[error("Version conflict")]
    VersionConflict,

    /// Bad request
    #[error("Bad request {0}")]
    BadRequest(String),
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
            Error::TooManyInternalRetries => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InconsistentState(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Reorganzing(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            Error::VersionConflict => StatusCode::INTERNAL_SERVER_ERROR,
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
            Error::Serialization(_) | Error::InvalidApiResponse | Error::NotAcceptable => {
                Error::NotAcceptable
            }
            Error::NotImplemented
            | Error::Debug(_)
            | Error::Network(_)
            | Error::ServiceUnavailable
            | Error::VersionConflict
            | Error::Reorganzing(_)
            | Error::InternalServer => Error::InternalServer,
            err => err,
        }
    }
    /// Makes an inconsistency error from a vector of chainstate entries.
    pub fn from_inconsistent_chainstate_entries(entries: Vec<ChainstateEntry>) -> Self {
        Error::InconsistentState(Inconsistency::Chainstates(
            entries.into_iter().map(|entry| entry.into()).collect(),
        ))
    }
    /// Makes an inconsistency error from a single chainstate entry.
    pub fn from_inconsistent_chainstate_entry(entry: ChainstateEntry) -> Self {
        Error::InconsistentState(Inconsistency::Chainstates(vec![entry.into()]))
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
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            PutItemError::ConditionalCheckFailedException(_) => Error::VersionConflict,
            service_err => Error::Debug(format!("SdkError<PutItemError> - {service_err:?}")),
        }
    }
}
impl From<SdkError<QueryError>> for Error {
    fn from(err: SdkError<QueryError>) -> Self {
        Error::Debug(format!("SdkError<QueryError> - {err:?}"))
    }
}
impl From<SdkError<DeleteItemError>> for Error {
    fn from(err: SdkError<DeleteItemError>) -> Self {
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            DeleteItemError::ConditionalCheckFailedException(_) => Error::VersionConflict,
            service_err => Error::Debug(format!("SdkError<DeleteItemError> - {service_err:?}")),
        }
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
impl From<SdkError<UpdateItemError>> for Error {
    fn from(err: SdkError<UpdateItemError>) -> Self {
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            UpdateItemError::ConditionalCheckFailedException(_) => Error::VersionConflict,
            service_err => Error::Debug(format!("SdkError<UpdateItemError> - {service_err:?}")),
        }
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
impl From<HexToBytesError> for Error {
    fn from(err: HexToBytesError) -> Self {
        Error::Debug(format!("HexToBytesError - {err:?}"))
    }
}
impl From<sbtc::error::Error> for Error {
    fn from(err: sbtc::error::Error) -> Self {
        Error::Debug(format!("sbtc::error::Error - {err:?}"))
    }
}
impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::Debug(format!("std::num::ParseIntError - {err:?}"))
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
