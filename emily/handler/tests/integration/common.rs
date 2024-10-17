//! Common module for useful test functions.

use emily_client::{
    apis::{self, configuration::Configuration},
    models::ErrorResponse,
};
use serde::{Deserialize, Serialize};

use crate::config::SETTINGS;

/// Standard error type.
pub type StandardError = TestError<ErrorResponse>;

/// Setup test.
pub async fn clean_setup() -> Configuration {
    let mut configuration = Configuration::default();
    configuration.base_path = format!("http://{}:{}", SETTINGS.server.host, SETTINGS.server.port);
    apis::testing_api::wipe_databases(&configuration)
        .await
        .expect("Failed to wipe databases during test clean setup.");
    configuration
}

/// Error type that represents an error
#[derive(Debug, Serialize, Deserialize)]
pub struct TestError<T> {
    /// Http status code.
    pub status_code: u16,
    /// Deserialized response body.
    pub body: T,
}

/// Implement from function for the TestError struct so that the
/// output of the openapi failure can be easily extracted.
impl<E, T> From<apis::Error<E>> for TestError<T>
where
    T: for<'de> Deserialize<'de>,
{
    fn from(openapi_error: apis::Error<E>) -> Self {
        match openapi_error {
            apis::Error::ResponseError(inner) => TestError::<T> {
                status_code: inner.status.as_u16(),
                body: serde_json::from_str(&inner.content)
                    .expect("Failed to deserialize error body during test."),
            },
            e => panic!("Unexpected openapi error type found while extracting error data: {e}."),
        }
    }
}
