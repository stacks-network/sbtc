//! Test errors module.

/// Integration test specific errors so that printing and logging are easier.
#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum TestError {
    /// Unexpected response format.
    #[error("Unexpected response format: {0}")]
    ResponseFormat(String),
    /// Invalid test conditions.
    #[error("Invalid test conditions: {0}")]
    TestConditions(String),
    /// Unknown error
    #[error("An unknown error occurred: {0}")]
    Unknown(String),
    /// Endpoint request error.
    #[error("Request error for endpoint [{endpoint}]: {source}")]
    Request {
        endpoint: String,
        source: reqwest::Error,
    },
    /// Test deserialization error.
    #[error(
        "Deserialization error for endpoint [{endpoint}]: {source}\nResponse text: {response_text}"
    )]
    Deserialization {
        endpoint: String,
        source: serde_json::Error,
        response_text: String,
    },
}

/// reqwest error conversion.
impl From<reqwest::Error> for TestError {
    fn from(err: reqwest::Error) -> Self {
        TestError::Unknown(format!("reqwest::Error - {err:?}"))
    }
}
