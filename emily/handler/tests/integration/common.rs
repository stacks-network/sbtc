//! Common module for useful test functions.

use crate::config::SETTINGS;
use serde::{Deserialize, Serialize};
use testing_emily_client::models::Chainstate;
use testing_emily_client::{
    apis::{
        self,
        configuration::{ApiKey, Configuration},
    },
    models::ErrorResponse,
};

/// Standard error type.
pub type StandardError = TestError<ErrorResponse>;

/// Setup test.
pub async fn clean_setup() -> Configuration {
    let configuration = testing_emily_client::apis::configuration::Configuration {
        base_path: format!("http://{}:{}", SETTINGS.server.host, SETTINGS.server.port),
        api_key: Some(ApiKey {
            prefix: None,
            key: SETTINGS.server.api_key.clone(),
        }),
        ..Default::default()
    };
    apis::testing_api::wipe_databases(&configuration)
        .await
        .expect("Failed to wipe databases during test clean setup.");
    configuration
}

/// Make a test chainstate.
pub fn new_test_chainstate(bitcoin_height: u64, height: u64, fork_id: i32) -> Chainstate {
    Chainstate {
        stacks_block_hash: format!("test-hash-{height}-fork-{fork_id}"),
        stacks_block_height: height,
        bitcoin_block_height: Some(Some(bitcoin_height)),
    }
}

/// Makes a bunch of chainstates.
pub async fn batch_set_chainstates(
    configuration: &Configuration,
    create_requests: Vec<Chainstate>,
) -> Vec<Chainstate> {
    let mut created: Vec<Chainstate> = Vec::with_capacity(create_requests.len());
    for request in create_requests {
        created.push(
            apis::chainstate_api::set_chainstate(configuration, request)
                .await
                .expect("Received an error after making a valid create deposit request api call."),
        );
    }
    created
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
