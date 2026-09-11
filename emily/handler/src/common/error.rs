//! Top-level error type for the Blocklist client

use std::env;

#[cfg(feature = "testing")]
use aws_sdk_dynamodb::operation::batch_write_item::BatchWriteItemError;

use aws_sdk_dynamodb::types::error::ConditionalCheckFailedException;
use aws_sdk_dynamodb::{
    error::SdkError,
    operation::{
        delete_item::DeleteItemError, get_item::GetItemError, put_item::PutItemError,
        query::QueryError, scan::ScanError, update_item::UpdateItemError,
    },
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use warp::http::StatusCode;
use warp::{reject::Reject, reply::Reply};

use crate::{
    api::models::{
        chainstate::Chainstate,
        common::{DepositStatus, WithdrawalStatus},
    },
    database::entries::{
        chainstate::ChainstateEntry, deposit::DepositEntryKey, withdrawal::WithdrawalEntryKey,
    },
};

/// State inconsistency representations.
#[derive(Debug)]
pub enum Inconsistency {
    /// There is a chainstate inconsistency, and all the chainstates
    /// in the vector are the chainstates that are present in the API
    /// but are not known to be correct. All chainstates in the vector
    /// are considered equally canonical.
    Chainstates(Vec<Chainstate>),
    /// There is an inconsistency in the way an item is being updated.
    ItemUpdate(&'static str),
}

/// Errors from the internal API logic.
/// Note that this error may be returned to the client, so it must not contain
/// any sensitive information.
#[derive(thiserror::Error, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ValidationError {
    /// The withdrawal is confirmed but missing the fulfillment data.
    #[error("missing fulfillment for confirmed withdrawal request with id: {0}")]
    WithdrawalMissingFulfillment(u64),

    /// The deposit is confirmed but missing the fulfillment data.
    #[error("missing fulfillment for confirmed deposit request with txid: {0}, vout: {1}")]
    DepositMissingFulfillment(String, u32),

    /// One of rolling_withdrawal_blocks or rolling_withdrawal_cap is missing while the other is set.
    /// Fields must be provided together to configure withdrawal limits.
    #[error(
        "incomplete withdrawal limit configuration: rolling_withdrawal_blocks and rolling_withdrawal_cap must be provided together"
    )]
    IncompleteWithdrawalLimitConfig,

    /// The deposit includes a replaced_by_tx field, but its status is not RBF.
    /// Only deposits with status RBF may include a replaced_by_tx.
    #[error(
        "deposit with replaced_by_tx is only valid if status is RBF, but got status {0:?} for txid: {1}, vout: {2}"
    )]
    InvalidReplacedByTxStatus(DepositStatus, String, u32),

    /// The deposit has status RBF but is missing the replaced_by_tx field.
    #[error("missing replaced_by_tx for RBF deposit with txid: {0}, vout: {1}")]
    DepositMissingReplacementTx(String, u32),

    /// A withdrawal update had fulfillment data where the status was not `Confirmed`.
    /// Only confirmed withdrawals can have fulfillment data.
    #[error(
        "withdrawal with fulfillment data must be confirmed, but got status {0:?} for request id: {1}"
    )]
    WithdrawalFulfillmentNotConfirmed(WithdrawalStatus, u64),

    /// A deposit update had fulfillment data where the status was not `Confirmed`.
    /// Only Confirmed deposits can have fulfillment data.
    #[error(
        "deposit with fulfillment data must be confirmed, but got status {0:?} for txid: {1}, vout: {2}"
    )]
    DepositFulfillmentNotConfirmed(DepositStatus, String, u32),
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

    /// You do not have permission to access or perform the requested action
    #[error("Forbidden")]
    Forbidden,

    /// Unathorized
    #[error("Unauthorized")]
    Unauthorized,

    /// Conflict.
    #[error("Conflict")]
    Conflict,

    /// This may be because you either requested a nonexistent endpoint
    /// or referenced a user that does not exist
    #[error("Resource not found")]
    NotFound,

    /// Internal error
    #[error("Internal server error")]
    InternalServer,

    /// Internal too many retries error.
    #[error("Too many internal retries")]
    TooManyInternalRetries,

    /// Inconsistent API state detected during request
    #[error("Inconsistent internal state: {0:?}")]
    InconsistentState(Inconsistency),

    /// API is reorganizing.
    #[error("The API is reorganizing around new chain tip {0:?}")]
    Reorganizing(Chainstate),

    /// An entry update version conflict in a resource update resulted
    /// in an update not being performed.
    #[error("There was a conflict when attempting to update the database; {0}")]
    VersionConflict(#[source] Box<ConditionalCheckFailedException>),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// This happens if the deposit entry that was stored in the database
    /// was invalid, or if the deposit entry that we are creating to store
    /// in the database is invalid.
    #[error("Deposit entry failed validation; {0}; ID: {1}")]
    InvalidDepositEntry(&'static str, DepositEntryKey),

    /// This happens when there is a mismatch in the outpoint of the new
    /// deposit event and the fetched deposit entry. Seeing this is
    /// probably due to a programming error.
    #[error("Mismatch when updating deposit request; existing: {0}; update: {1}")]
    DepositOutputMismatch(DepositEntryKey, DepositEntryKey),

    /// This happens if the withdrawal entry that was stored in the database
    /// was invalid, or if the withdrawal entry that we are creating to store
    /// in the database is invalid.
    #[error("Withdrawal entry failed validation; {0}; ID: {1}")]
    InvalidWithdrawalEntry(&'static str, WithdrawalEntryKey),

    /// This happens when there is a mismatch in the request ID of the new
    /// withdrawal event and the fetched withdrawal entry. Seeing this is
    /// probably due to a programming error.
    #[error("Mismatch when updating withdrawal request; existing: {0}; update: {1}")]
    WithdrawalRequestIdMismatch(WithdrawalEntryKey, u64),

    /// This means that the stacks address in the environment for the
    /// signers multisig address is invalid.
    #[error("Could not parse a stacks address from a string")]
    InvalidStacksAddress(#[source] Box<clarity::vm::errors::Error>),

    /// This happens when the request to DynamoDB succeeds but does not
    /// return any values. This happens when the request instructs the
    /// database to refrain from returning values, so this is likely a
    /// programming error.
    #[error("Entry in database for deposit request not returned from DynamoDB; {0}")]
    MissingAttributesDeposit(DepositEntryKey),

    /// This happens when the request to DynamoDB succeeds but does not
    /// return any values. This happens when the request instructs the
    /// database to refrain from returning values, so this is likely a
    /// programming error.
    #[error("Entry in database for withdrawal request not returned from DynamoDB; {0}")]
    MissingAttributesWithdrawal(WithdrawalEntryKey),

    /// DynamoDB should only contain one entry per withdrawal request ID.
    ///
    /// TODO: In case of a re-org, triple check that we can identify the
    /// correct withdrawal request if the transaction is replayed.
    #[error("DynamoDB contained many entries for the given request ID: {0}")]
    TooManyWithdrawalEntries(u64),

    /// DynamoDB should only contain one entry per key name.
    #[error("DynamoDB contained many entries for the given key name: {0}")]
    TooManyThrottleEntries(String),

    /// This happens when we fail to decode a base64 encoded string into a
    /// vector of bytes.
    #[error("Failed to base64 decode the string into bytes; {0}")]
    Base64Decode(base64::DecodeError),

    /// This is used when trying to get a required value from the
    /// environment and that operation fails.
    #[error("Could not read the environment variable; {0}")]
    EnvVariable(#[from] env::VarError),

    /// This occurs when serializing or deserializing an object into or
    /// from JSON.
    #[error("{0}")]
    SerdeJson(#[from] serde_json::Error),

    /// This occurs when converting structs to and from DynamoDB objects.
    #[error("{0}")]
    SerdeDynamo(#[from] serde_dynamo::Error),

    /// This happens when attempting to parse an integer from a string that
    /// has been read from an environment variable.
    #[error("Failed to parse the environment variable's value as an integer; {0}")]
    EnvParseInt(#[from] std::num::ParseIntError),

    /// This happens when attempting to read an item from DynamoDB.
    #[error("Could not retrieve an item from DynamoDB; {0}")]
    AwsSdkDynamoDbGetItem(#[from] Box<SdkError<GetItemError>>),

    /// This error occurs when storing an item in DynamoDB. Note that
    /// precondition errors on a PutItem operation are returned in the
    /// `VersionConflict` variant.
    #[error("Could not put the item into DynamoDB; {0}")]
    AwsSdkDynamoDbPutItem(#[source] Box<PutItemError>),

    /// This happens when attempting the "Query" operation in DynamoDB.
    #[error("Could not complete Query operation on DynamoDB; {0}")]
    AwsSdkDynamoDbQuery(#[from] Box<SdkError<QueryError>>),

    /// This happens when attempting the "Scan" operation in DynamoDB.
    #[error("Could not complete Scan operation on DynamoDB; {0}")]
    AwsSdkDynamoDbScan(#[from] Box<SdkError<ScanError>>),

    /// This happens when attempting to update a stored item in DynamoDB.
    /// Note that precondition errors on an UpdateItem operation are
    /// returned in the `VersionConflict` variant.
    #[error("Could not update the item in DynamoDB; {0}")]
    AwsSdkDynamoDbUpdateItem(#[source] Box<UpdateItemError>),

    /// This happens when attempting to delete an item in the database.
    /// Note that precondition errors on a DeleteItem operation are
    /// returned in the `VersionConflict` variant.
    #[error("Could not deleting an item in DynamoDB; {0}")]
    AwsSdkDynamoDbDeleteItem(#[source] Box<DeleteItemError>),

    /// This happens when we fail to build a request object when trying to
    /// interact with DynamoDB. For example, when deleting entries in the
    /// database in our tests, we build a request object and that operation
    /// may fail with this error.
    #[cfg(feature = "testing")]
    #[error("{0}")]
    DynamoDbBuild(#[from] aws_sdk_dynamodb::error::BuildError),

    /// This happens during the BatchWrite operation on DynamoDB.
    #[cfg(feature = "testing")]
    #[error("{0}")]
    AwsSdkDynamoDbBatchWriteItem(#[from] Box<SdkError<BatchWriteItemError>>),
}

/// Error implementation.
impl Error {
    /// Provides the status code that corresponds to the error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::HttpRequest(code, _) => *code,
            Error::Network(_) => StatusCode::BAD_GATEWAY,
            Error::Forbidden => StatusCode::FORBIDDEN,
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::Conflict => StatusCode::CONFLICT,
            Error::InternalServer => StatusCode::INTERNAL_SERVER_ERROR,
            Error::TooManyInternalRetries => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InconsistentState(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Reorganizing(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::VersionConflict(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Deserialization(_) => StatusCode::BAD_REQUEST,
            Error::InvalidStacksAddress(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InvalidDepositEntry(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::DepositOutputMismatch(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InvalidWithdrawalEntry(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::WithdrawalRequestIdMismatch(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::MissingAttributesDeposit(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::MissingAttributesWithdrawal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::TooManyWithdrawalEntries(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Base64Decode(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::EnvVariable(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::SerdeJson(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::SerdeDynamo(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::EnvParseInt(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbDeleteItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbGetItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbPutItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbQuery(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbScan(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::AwsSdkDynamoDbUpdateItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::TooManyThrottleEntries(_) => StatusCode::INTERNAL_SERVER_ERROR,
            #[cfg(feature = "testing")]
            Error::DynamoDbBuild(_) => StatusCode::INTERNAL_SERVER_ERROR,
            #[cfg(feature = "testing")]
            Error::AwsSdkDynamoDbBatchWriteItem(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    /// Converts the error into a warp response.
    pub fn into_response(self) -> warp::reply::Response {
        warp::reply::with_status(
            warp::reply::json(&ErrorResponse { message: format!("{self}") }),
            self.status_code(),
        )
        .into_response()
    }
    /// Convert error into a presentable version of the error that can be
    /// provided to a client in production.
    pub fn into_production_error(self) -> Error {
        match self {
            Error::DepositOutputMismatch(_, _)
            | Error::Forbidden
            | Error::NotFound
            | Error::Unauthorized
            | Error::Conflict
            | Error::TooManyInternalRetries
            | Error::InconsistentState(_)
            | Error::WithdrawalRequestIdMismatch(_, _)
            | Error::MissingAttributesDeposit(_)
            | Error::MissingAttributesWithdrawal(_)
            | Error::TooManyWithdrawalEntries(_)
            | Error::HttpRequest(_, _) => self,

            _ => Error::InternalServer,
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
impl From<ValidationError> for Error {
    fn from(err: ValidationError) -> Self {
        Error::HttpRequest(StatusCode::BAD_REQUEST, err.to_string())
    }
}

impl From<SdkError<PutItemError>> for Error {
    fn from(err: SdkError<PutItemError>) -> Self {
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            PutItemError::ConditionalCheckFailedException(err) => Error::from(err),
            service_err => Error::AwsSdkDynamoDbPutItem(Box::new(service_err)),
        }
    }
}

impl From<SdkError<DeleteItemError>> for Error {
    fn from(err: SdkError<DeleteItemError>) -> Self {
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            DeleteItemError::ConditionalCheckFailedException(err) => Error::from(err),
            service_err => Error::AwsSdkDynamoDbDeleteItem(Box::new(service_err)),
        }
    }
}

impl From<SdkError<UpdateItemError>> for Error {
    fn from(err: SdkError<UpdateItemError>) -> Self {
        match err.into_service_error() {
            // Note, this assumes that any conditional check that fails fails because
            // there's a version conflict. This isn't necessarily true but is a good
            // simplifying assumption.
            UpdateItemError::ConditionalCheckFailedException(err) => Error::from(err),
            service_err => Error::AwsSdkDynamoDbUpdateItem(Box::new(service_err)),
        }
    }
}

impl From<ConditionalCheckFailedException> for Error {
    fn from(value: ConditionalCheckFailedException) -> Self {
        Error::VersionConflict(Box::new(value))
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
        // Log before production sanitization discards the underlying error.
        // Debug includes nested SDK error details that Display can omit.
        tracing::error!(error = ?self, "Emily request failed");
        #[cfg(not(feature = "testing"))]
        let error = self.into_production_error();
        #[cfg(feature = "testing")]
        let error = self;
        Error::into_response(error)
    }
}
