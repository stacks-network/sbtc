//! A module with structs that interact with the Stacks API.

use std::time::Duration;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksBlockId;
use config::Config;
use config::Environment;
use config::File;
use futures::StreamExt;
use serde::Deserialize;
use serde::Deserializer;

use crate::block_observer::StacksInteract;
use crate::error::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A deserializer for the url::Url type.
fn url_deserializer<'de, D>(deserializer: D) -> Result<url::Url, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
}

/// A struct for the entries in the signers Config.toml (which is currently
/// located in src/config/default.toml)
#[derive(Debug, serde::Deserialize)]
pub struct StacksSettings {
    api: StacksApiSettings,
    node: StacksNodeSettings,
}

/// Whatever
#[derive(Debug, serde::Deserialize)]
pub struct StacksApiSettings {
    /// TODO: We'll want to support specifying multiple Stacks Nodes
    /// endpoints.
    #[serde(deserialize_with = "url_deserializer")]
    endpoint: url::Url,
}

/// Settings associated with the stacks node that this signer uses for information
#[derive(Debug, serde::Deserialize)]
pub struct StacksNodeSettings {
    /// TODO: We'll want to support specifying multiple Stacks Nodes
    /// endpoints.
    #[serde(deserialize_with = "url_deserializer")]
    endpoint: url::Url,
}

impl StacksSettings {
    /// Create a new StacksSettings object by reading the relevant entries
    /// in the signer's config.toml. The values there can be overridden by
    /// environment variables.
    ///
    /// # Notes
    ///
    /// The relevant environment variables and the config entries that are
    /// overridden are:
    ///
    /// * SIGNER_STACKS_API_ENDPOINT <-> stacks.api.endpoint
    /// * SIGNER_STACKS_NODE_ENDPOINT <-> stacks.node.endpoint
    ///
    /// Each of these overrides an entry in the signer's `config.toml`
    pub fn new_from_config() -> Result<Self, Error> {
        let source = File::with_name("./src/config/default");
        let env = Environment::with_prefix("SIGNER")
            .prefix_separator("_")
            .separator("_");

        let conf = Config::builder()
            .add_source(source)
            .add_source(env)
            .build()
            .map_err(Error::SignerConfig)?;

        conf.get::<StacksSettings>("stacks")
            .map_err(Error::StacksApiConfig)
    }
}

/// A client for interacting with Stacks nodes and the Stacks API
pub struct StacksClient {
    /// The base URL (with the port) that will be used when making requests
    /// for to the Stacks API.
    pub api_endpoint: url::Url,
    /// The base URL (with the port) that will be used when making requests
    /// for to a Stacks node.
    pub node_endpoint: url::Url,
    /// The client used to make the request.
    pub client: reqwest::Client,
}

impl StacksClient {
    /// Create a new instance of the Stacks client using the entries in the
    /// signer's `config.toml` and environment variables.
    ///
    /// See [`StacksSettings::new_from_config`] for more on overridding
    /// the entries in `config.toml` using environment variables.
    pub fn new_from_config() -> Result<Self, Error> {
        let settings = StacksSettings::new_from_config()?;

        Ok(Self {
            api_endpoint: settings.api.endpoint,
            node_endpoint: settings.node.endpoint,
            client: reqwest::Client::new(),
        })
    }

    /// Get Stacks block IDs given the bitcoin block hash. Uses the Stacks API
    /// via the GET /extended/v2/burn-blocks/:height_or_hash endpoint.
    ///
    /// See https://docs.hiro.so/api/get-burn-block
    async fn get_block_ids(&self, hash: &bitcoin::BlockHash) -> Result<Vec<StacksBlockId>, Error> {
        // The Stacks API expects the hash to be hex encoded with the
        // leading 0x in the string, which is not produced by the Display
        // implementation of bitcoin::hashes::sha256d::Hash (but is for
        // the Debug implementation).
        let hash: &bitcoin::hashes::sha256d::Hash = hash.as_raw_hash();
        let path = format!("/extended/v2/burn-blocks/0x{}", hash);
        let url = self.api_endpoint.join(&path).map_err(Error::PathParse)?;

        let response = self.client.get(url).timeout(REQUEST_TIMEOUT).send().await?;
        let resp: GetBurnBlockResponse = response.json().await?;

        // The Stacks API often returns hex prefixed with 0x. If this is
        // the case, we split it off before constructing the block ids.
        resp.stacks_blocks
            .into_iter()
            .map(|hex_string| {
                let hex_str: &str = if hex_string.starts_with("0x") {
                    hex_string.split_at(2).1
                } else {
                    &hex_string
                };

                StacksBlockId::from_hex(hex_str)
                    .map_err(|err| Error::ParseStacksBlockId(err, hex_string))
            })
            .collect()
    }

    /// Fetch the raw stacks nakamoto block from a Stacks node given the
    /// Stacks block ID.
    async fn get_block(&self, block_id: &StacksBlockId) -> Result<NakamotoBlock, Error> {
        let path = format!("/v3/blocks/{}", block_id.to_hex());
        let url = self.node_endpoint.join(&path).map_err(Error::PathParse)?;

        // TODO: Add more context to these errors
        let response = self.client.get(url).timeout(REQUEST_TIMEOUT).send().await?;
        let resp = response.bytes().await?;

        NakamotoBlock::consensus_deserialize(&mut &*resp)
            .map_err(|err| Error::DecodeNakamotoBlock(err, *block_id))
    }
}

impl StacksInteract for StacksClient {
    async fn get_blocks_by_bitcoin_block(
        &mut self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<Vec<NakamotoBlock>, Error> {
        let block_ids = self.get_block_ids(block_hash).await?;

        let stream = block_ids
            .iter()
            .map(|block_hash| self.get_block(block_hash));
        let ans: Vec<Result<NakamotoBlock, Error>> = futures::stream::iter(stream)
            .buffer_unordered(3)
            .collect()
            .await;

        ans.into_iter().collect()
    }
}

/// Response from the Stacks API for GET /extended/v2/burn-blocks/:height_or_hash
/// requests.
///
/// See https://docs.hiro.so/api/get-burn-block
#[derive(Clone, Debug, Deserialize)]
pub struct GetBurnBlockResponse {
    /// The hash of the bitcoin block.
    pub burn_block_hash: String,
    /// The hash of the bitcoin block.
    pub burn_block_height: u32,
    /// Hashes of the Stacks blocks included in the bitcoin block
    pub stacks_blocks: Vec<String>,
    /// The total number of Stacks transactions included in the stacks
    /// blocks.
    pub total_tx_count: u64,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn default_config_toml_loads_with_environment() {
        // The default toml used here specifies http://localhost:3999
        // as the stacks API endpoint.
        let settings = StacksSettings::new_from_config().unwrap();
        let host = settings.api.endpoint.host();
        assert_eq!(host, Some(url::Host::Domain("localhost")));
        assert_eq!(settings.api.endpoint.port(), Some(3999));

        std::env::set_var("SIGNER_STACKS_API_ENDPOINT", "http://whatever:1234");

        let settings = StacksSettings::new_from_config().unwrap();
        let host = settings.api.endpoint.host();
        assert_eq!(host, Some(url::Host::Domain("whatever")));
        assert_eq!(settings.api.endpoint.port(), Some(1234));

        std::env::set_var("SIGNER_STACKS_API_ENDPOINT", "http://127.0.0.1:5678");

        let settings = StacksSettings::new_from_config().unwrap();
        let ip: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert_eq!(settings.api.endpoint.host(), Some(url::Host::Ipv4(ip)));
        assert_eq!(settings.api.endpoint.port(), Some(5678));

        std::env::set_var("SIGNER_STACKS_API_ENDPOINT", "http://[::1]:9101");

        let settings = StacksSettings::new_from_config().unwrap();
        let ip: std::net::Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(settings.api.endpoint.host(), Some(url::Host::Ipv6(ip)));
        assert_eq!(settings.api.endpoint.port(), Some(9101));
    }

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn get_blocks_by_bitcoin_block_works() {
        let block = bitcoin::BlockHash::from_str(
            "00e34f99fc2d8e4857680cec4e8a74b64bebe53fe9d5752a8912dd777677043c",
        )
        .unwrap();

        let client = StacksClient::new_from_config().unwrap();
        let resp = client.get_block_ids(&block).await.unwrap();
        dbg!(resp);
    }

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn get_blocks_works() {
        let block = bitcoin::BlockHash::from_str(
            "00e34f99fc2d8e4857680cec4e8a74b64bebe53fe9d5752a8912dd777677043c",
        )
        .unwrap();

        let client = StacksClient::new_from_config().unwrap();
        let block_ids = client.get_block_ids(&block).await.unwrap();
        let block_id = block_ids[0];

        dbg!(&block_id);
        let resp = client.get_block(&block_id).await.unwrap();
        dbg!(resp);
    }
}
