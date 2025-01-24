//! # Blocklist Client Module
//!
//! This module provides the `BlocklistChecker` trait and its `BlocklistClient` implementation,
//! which are used to check addresses against a blocklist service. The module's responsibilities
//! include querying the blocklist API and interpreting the responses to determine if a given
//! address is blocklisted, along with its associated risk severity.

use blocklist_api::apis::address_api::{check_address, CheckAddressError};
use blocklist_api::apis::configuration::Configuration;
use blocklist_api::apis::Error as ClientError;
use std::future::Future;

use crate::context::Context;
use crate::error::Error;

/// Blocklist client error variants.
#[derive(Debug, thiserror::Error)]
pub enum BlocklistClientError {
    /// An error occurred while checking an address
    #[error("error checking an address: {0}")]
    CheckAddress(ClientError<CheckAddressError>),
}

/// A trait for checking if an address is blocklisted.
pub trait BlocklistChecker {
    /// Checks if the given address is blocklisted.
    /// Returns `true` if the address is blocklisted, otherwise `false`.
    fn can_accept(&self, address: &str) -> impl Future<Output = Result<bool, Error>> + Send;
}

/// A client for interacting with the blocklist service.
#[derive(Clone, Debug)]
pub struct BlocklistClient {
    config: Configuration,
}

impl BlocklistChecker for BlocklistClient {
    async fn can_accept(&self, address: &str) -> Result<bool, Error> {
        let config = self.config.clone();

        // Call the generated function from blocklist-api
        check_address(&config, address)
            .await
            .map_err(BlocklistClientError::CheckAddress)
            .map_err(Error::BlocklistClient)
            .map(|resp| resp.accept)
    }
}

impl BlocklistClient {
    /// Construct a new [`BlocklistClient`]
    pub fn new(ctx: &impl Context) -> Option<Self> {
        let config = ctx.config().blocklist_client.as_ref()?;

        let mut config = Configuration {
            base_path: config.endpoint.to_string(),
            ..Default::default()
        };

        // Url::parse defaults `path` to `/` even if the parsed url was without the trailing `/`
        // causing the api calls to have two leading slashes in the path (getting a 404)
        config.base_path = config
            .base_path
            .to_string()
            .trim_end_matches("/")
            .to_string();

        Some(BlocklistClient { config })
    }

    /// Construct a new [`BlocklistClient`] from a base url
    #[cfg(any(test, feature = "testing"))]
    pub fn with_base_url(base_url: String) -> Self {
        let config = Configuration {
            base_path: base_url.clone(),
            ..Default::default()
        };

        BlocklistClient { config }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        config::BlocklistClientConfig,
        testing::context::{
            self, BuildContext as _, ConfigureMockedClients, ConfigureSettings,
            ConfigureStorage as _,
        },
    };

    use super::*;
    use mockito::{Server, ServerGuard};
    use serde_json::json;
    use tokio::sync::Mutex;
    use url::Url;

    const ADDRESS: &str = "0x2337bBCD5766Bf2A9462D493E9A459b60b41B7f2";
    const SCREEN_PATH: &str = "/screen";

    struct TestContext {
        server_guard: Mutex<ServerGuard>,
        client: BlocklistClient,
    }

    async fn setup() -> TestContext {
        let server_guard = Server::new_async().await;
        let client = BlocklistClient::with_base_url(server_guard.url());
        TestContext {
            server_guard: Mutex::new(server_guard),
            client,
        }
    }

    #[tokio::test]
    async fn test_is_blocklisted_true() {
        let ctx = setup().await;
        let mut guard = ctx.server_guard.lock().await;
        let mock_json = json!({
            "is_blocklisted": true,
            "severity": "Severe",
            "accept": false,
            "reason": "Fraud"
        })
        .to_string();

        let mock = guard
            .mock("GET", format!("{}/{}", SCREEN_PATH, ADDRESS).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&mock_json)
            .create_async()
            .await;

        let can_accept = ctx.client.can_accept(ADDRESS).await;
        assert!(can_accept.is_ok());
        assert_eq!(can_accept.unwrap(), false);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_is_blocklisted_false() {
        let ctx = setup().await;
        let mut guard = ctx.server_guard.lock().await;
        let mock_json = json!({
            "is_blocklisted": false,
            "severity": "Low",
            "accept": true,
            "reason": null
        })
        .to_string();

        let mock = guard
            .mock("GET", format!("{}/{}", SCREEN_PATH, ADDRESS).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&mock_json)
            .create_async()
            .await;

        let can_accept = ctx.client.can_accept(ADDRESS).await;
        assert!(can_accept.is_ok());
        assert_eq!(can_accept.unwrap(), true);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_check_address_http_error() {
        let ctx = setup().await;
        let mut guard = ctx.server_guard.lock().await;

        guard
            .mock("GET", format!("{}/{}", SCREEN_PATH, ADDRESS).as_str())
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body("Not found")
            .create_async()
            .await;

        let result = ctx.client.can_accept(ADDRESS).await;
        assert!(result.is_err());
    }

    #[test]
    fn try_from_url_with_slash() {
        let endpoint = Url::parse("http://localhost:8080/").unwrap();

        let ctx = context::TestContext::builder()
            .modify_settings(|config| {
                config.blocklist_client = Some(BlocklistClientConfig { endpoint })
            })
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let client = BlocklistClient::new(&ctx).unwrap();

        assert_eq!(client.config.base_path, "http://localhost:8080");
    }

    #[test]
    fn try_from_url_without_slash() {
        let endpoint = Url::parse("http://localhost:8080").unwrap();

        let ctx = context::TestContext::builder()
            .modify_settings(|config| {
                config.blocklist_client = Some(BlocklistClientConfig { endpoint })
            })
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let client = BlocklistClient::new(&ctx).unwrap();

        assert_eq!(client.config.base_path, "http://localhost:8080");
    }
}
