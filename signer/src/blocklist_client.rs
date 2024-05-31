//! # Blocklist Client Module
//!
//! This module provides the `BlocklistChecker` trait and its `BlocklistClient` implementation,
//! which are used to check addresses against a blocklist service. The module's responsibilities
//! include querying the blocklist API and interpreting the responses to determine if a given
//! address is blocklisted, along with its associated risk severity.

use crate::config::SETTINGS;
use blocklist_api::apis::address_api::{check_address, CheckAddressError};
use blocklist_api::apis::configuration::Configuration;
use blocklist_api::apis::Error as ClientError;
use blocklist_api::models::BlocklistStatus;
use std::future::Future;

/// A trait for checking if an address is blocklisted.
pub trait BlocklistChecker {
    /// Checks if the given address is blocklisted.
    /// Returns `true` if the address is blocklisted, otherwise `false`.
    fn can_accept(
        &self,
        address: &str,
    ) -> impl Future<Output = Result<bool, ClientError<CheckAddressError>>> + Send;
}

/// A client for interacting with the blocklist service.
#[derive(Clone, Debug)]
pub struct BlocklistClient {
    config: Configuration,
}

impl BlocklistChecker for BlocklistClient {
    async fn can_accept(&self, address: &str) -> Result<bool, ClientError<CheckAddressError>> {
        let config = self.config.clone();

        // Call the generated function from blocklist-api
        let resp: BlocklistStatus = check_address(&config, address).await?;
        Ok(resp.accept)
    }
}

impl BlocklistClient {
    /// Construct a new [`BlocklistClient`]
    pub fn new() -> Self {
        let base_url = format!(
            "http://{}:{}",
            SETTINGS.blocklist_client.host, SETTINGS.blocklist_client.port
        );

        let config = Configuration {
            base_path: base_url.clone(),
            ..Default::default()
        };

        BlocklistClient { config }
    }

    #[cfg(test)]
    fn with_base_url(base_url: String) -> Self {
        let config = Configuration {
            base_path: base_url.clone(),
            ..Default::default()
        };

        BlocklistClient { config }
    }
}

impl Default for BlocklistClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Server, ServerGuard};
    use serde_json::json;
    use tokio::sync::Mutex;

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
}
