//! A module with structs that interact with the Stacks API.

use std::future::Future;
use std::time::Duration;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksBlockId;
use futures::StreamExt;
use serde::Deserialize;

use crate::config::StacksSettings;
use crate::error::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A trait detailing the interface with the Stacks API and Stacks Nodes.
pub trait StacksInteract {
    /// Get stacks blocks confirmed by the given bitcoin block
    fn get_blocks_by_bitcoin_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> impl Future<Output = Result<Vec<NakamotoBlock>, Error>> + Send;
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
    /// Create a new instance of the Stacks client using the given
    /// StacksSettings.
    pub fn new(settings: StacksSettings) -> Self {
        Self {
            api_endpoint: settings.api.endpoint,
            node_endpoint: settings.node.endpoint,
            client: reqwest::Client::new(),
        }
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

        tracing::debug!(%hash, "Fetching block IDs confirmed by bitcoin block from stacks API");

        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|err| Error::StacksNodeRequest(err, url.clone()))?;
        let resp: GetBurnBlockResponse = response
            .json()
            .await
            .map_err(|err| Error::UnexpectedStacksResponse(err, url))?;

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
    async fn get_block(&self, block_id: StacksBlockId) -> Result<NakamotoBlock, Error> {
        let path = format!("/v3/blocks/{}", block_id.to_hex());
        let url = self.node_endpoint.join(&path).map_err(Error::PathParse)?;

        tracing::debug!(%block_id, "Making request to the stacks node for the raw nakamoto block");

        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|err| Error::StacksNodeRequest(err, url.clone()))?;
        let resp = response
            .bytes()
            .await
            .map_err(|err| Error::UnexpectedStacksResponse(err, url))?;

        NakamotoBlock::consensus_deserialize(&mut &*resp)
            .map_err(|err| Error::DecodeNakamotoBlock(err, block_id))
    }
}

impl StacksInteract for StacksClient {
    async fn get_blocks_by_bitcoin_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<Vec<NakamotoBlock>, Error> {
        let block_ids = self.get_block_ids(block_hash).await?;

        let stream = block_ids
            .into_iter()
            .map(|block_id| self.get_block(block_id));
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

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn get_blocks_by_bitcoin_block_works() {
        let block = bitcoin::BlockHash::from_str(
            "00e34f99fc2d8e4857680cec4e8a74b64bebe53fe9d5752a8912dd777677043c",
        )
        .unwrap();

        let settings = StacksSettings::new_from_config().unwrap();
        let client = StacksClient::new(settings);

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

        let settings = StacksSettings::new_from_config().unwrap();
        let client = StacksClient::new(settings);

        let block_ids = client.get_block_ids(&block).await.unwrap();
        let block_id = block_ids[0];

        dbg!(&block_id);
        let resp = client.get_block(block_id).await.unwrap();
        dbg!(resp);
    }
}
