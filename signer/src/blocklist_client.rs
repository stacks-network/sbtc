//! # Blocklist Client Module
//!
//! This module provides the `BlocklistChecker` trait and its `BlocklistClient` implementation,
//! which are used to check addresses against a blocklist service. The module's responsibilities
//! include querying the blocklist API and interpreting the responses to determine if a given
//! address is blocklisted, along with its associated risk severity.

use crate::config::SETTINGS;
use async_trait::async_trait;
use blocklist_client::common::error::Error;
use blocklist_client::common::BlocklistStatus;
use reqwest::Client;

const SCREEN_PATH: &str = "/screen";

#[async_trait]
pub trait BlocklistChecker {
    /// Checks if the given address is blocklisted.
    /// Returns `true` if the address is blocklisted, otherwise `false`.
    async fn is_blocklisted(&self, address: &str) -> Result<bool, Error>;
}

#[derive(Clone, Debug)]
pub struct BlocklistClient {
    base_url: String,
    client: Client,
}

#[async_trait]
impl BlocklistChecker for BlocklistClient {
    async fn is_blocklisted(&self, address: &str) -> Result<bool, Error> {
        let url = Self::address_screening_path(&self.base_url, address);
        let resp = self
            .client
            .get(url)
            .send()
            .await?
            .json::<BlocklistStatus>()
            .await?;

        // Check if the request can be accepted or not based on the response
        Ok(resp.accept)
    }
}

impl BlocklistClient {
    pub fn new() -> Self {
        let base_url = format!(
            "http://{}:{}",
            SETTINGS.blocklist_client.host, SETTINGS.blocklist_client.port
        );
        BlocklistClient {
            base_url,
            client: Client::new(),
        }
    }
    #[cfg(test)]
    fn with_base_url(base_url: String) -> Self {
        BlocklistClient {
            base_url,
            client: Client::new(),
        }
    }

    fn address_screening_path(base_url: &str, address: &str) -> String {
        format!("{}{}/{}", base_url, SCREEN_PATH, address)
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

        let is_blocklisted = ctx.client.is_blocklisted(ADDRESS).await;
        assert!(is_blocklisted.is_ok());
        assert_eq!(is_blocklisted.unwrap(), false);

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

        let is_blocklisted = ctx.client.is_blocklisted(ADDRESS).await;
        assert!(is_blocklisted.is_ok());
        assert_eq!(is_blocklisted.unwrap(), true);

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

        let result = ctx.client.is_blocklisted(ADDRESS).await;
        assert!(result.is_err());
    }
}
