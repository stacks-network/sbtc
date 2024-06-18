//! A module with structs that interact with the Stacks API.

use std::borrow::Cow;
use std::future::Future;
use std::time::Duration;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo;
use blockstack_lib::types::chainstate::StacksBlockId;

use crate::config::StacksSettings;
use crate::error::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A trait detailing the interface with the Stacks API and Stacks Nodes.
pub trait StacksInteract {
    /// Get all Nakamoto stacks blocks for the last confirmed tenure.
    fn get_last_tenure_blocks(
        &self,
    ) -> impl Future<Output = Result<Vec<NakamotoBlock>, Error>> + Send;
}

/// A client for interacting with Stacks nodes and the Stacks API
pub struct StacksClient {
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
            node_endpoint: settings.node.endpoint,
            client: reqwest::Client::new(),
        }
    }

    /// Fetch the raw stacks nakamoto block from a Stacks node given the
    /// Stacks block ID.
    #[tracing::instrument(skip(self))]
    async fn get_block(&self, block_id: StacksBlockId) -> Result<NakamotoBlock, Error> {
        let path = format!("/v3/blocks/{}", block_id.to_hex());
        let base = self.node_endpoint.clone();
        let url = base
            .join(&path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Owned(path)))?;

        tracing::debug!("Making request to the stacks node for the raw nakamoto block");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;
        let resp = response
            .bytes()
            .await
            .map_err(Error::UnexpectedStacksResponse)?;

        NakamotoBlock::consensus_deserialize(&mut &*resp)
            .map_err(|err| Error::DecodeNakamotoBlock(err, block_id))
    }

    /// Fetch all Nakamoto ancestor blocks within the same tenure as the
    /// given block ID from a Stacks node.
    ///
    /// The response includes the Nakamoto block for the given block id.
    #[tracing::instrument(skip(self))]
    async fn get_blocks(&self, block_id: StacksBlockId) -> Result<Vec<NakamotoBlock>, Error> {
        let mut blocks = Vec::new();

        tracing::debug!("Making initial request for Nakamoto blocks within the tenure");
        blocks.extend(self.get_tenure(block_id).await?);

        let mut prev_last_block_id = block_id;

        // Given the response size limit of GET /v3/tenures/<block-id>
        // requests, there could be more blocks that we need to fetch.
        while let Some(last_block_id) = blocks.last().map(NakamotoBlock::block_id) {
            // To determine whether all blocks within a tenure have been
            // retrieved, we check if we've seen the last block in the
            // previous GET /v3/tenures/<block-id> response. Note that the
            // response always starts with the block corresponding to
            // <block-id> and is followed by its ancestors from the same
            // tenure.
            if last_block_id == prev_last_block_id {
                break;
            }
            prev_last_block_id = last_block_id;

            tracing::debug!(%last_block_id, "Fetching more Nakamoto blocks within the tenure");
            let blks = self.get_tenure(last_block_id).await?;
            // The first block in the GET /v3/tenures/<block-id> response
            // is always the block related to the given <block-id>. But we
            // already have that block so we can skip adding it again.
            debug_assert_eq!(blks.first().map(|b| b.block_id()), Some(last_block_id));
            blocks.extend(blks.into_iter().skip(1))
        }

        Ok(blocks)
    }

    /// Make a GET /v3/tenures/<block-id> request for Nakamoto ancestor
    /// blocks with the same tenure as the given block ID from a Stacks
    /// node.
    ///
    /// # Notes
    ///
    /// * The GET /v3/tenures/<block-id> response is capped at ~16 MB, so a
    ///   single request may not return all Nakamoto blocks.
    /// * The response includes the Nakamoto block for the given block id.
    #[tracing::instrument(skip(self))]
    async fn get_tenure(&self, block_id: StacksBlockId) -> Result<Vec<NakamotoBlock>, Error> {
        let base = self.node_endpoint.clone();
        let path = format!("/v3/tenures/{}", block_id.to_hex());
        let url = base
            .join(&path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Owned(path)))?;

        tracing::debug!("Making request to the stacks node for the raw nakamoto block");

        let response = self
            .client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        // The response here does not detail the number of blocks in the
        // response. So we essentially take the same implementation given
        // in [`StacksHttpResponse::decode_nakamoto_tenure`], which just
        // keeps decoding until there are no more bytes.
        let resp = response
            .bytes()
            .await
            .map_err(Error::UnexpectedStacksResponse)?;

        let bytes: &mut &[u8] = &mut resp.as_ref();
        let mut blocks = Vec::new();

        while !bytes.is_empty() {
            let block = NakamotoBlock::consensus_deserialize(bytes)
                .map_err(|err| Error::DecodeNakamotoTenure(err, block_id))?;

            blocks.push(block);
        }

        Ok(blocks)
    }

    /// Get information about the current tenure.
    ///
    /// Uses the GET /v3/tenures/info stacks node endpoint for retrieving
    /// tenure information.
    #[tracing::instrument(skip(self))]
    pub async fn get_tenure_info(&self) -> Result<RPCGetTenureInfo, Error> {
        let base = self.node_endpoint.clone();
        let path = "/v3/tenures/info";
        let url = base
            .join(path)
            .map_err(|err| Error::PathJoin(err, base, Cow::Borrowed(path)))?;

        tracing::debug!("Making request to the stacks node for the current tenure info");
        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(Error::StacksNodeRequest)?;

        response
            .json()
            .await
            .map_err(Error::UnexpectedStacksResponse)
    }
}

impl StacksInteract for StacksClient {
    async fn get_last_tenure_blocks(&self) -> Result<Vec<NakamotoBlock>, Error> {
        // We want to get the last block in the previous tenure. That block
        // is the parent block to the first block of the current tenure. So
        // yeah, let's get it.
        let info = self.get_tenure_info().await?;
        let block = self.get_block(info.tenure_start_block_id).await?;

        // This is the block ID of the previous tenure's last block.
        let prev_tenure_last_block_id = block.header.parent_block_id;
        self.get_blocks(prev_tenure_last_block_id).await
    }
}

#[cfg(test)]
mod tests {
    use crate::config::StacksNodeSettings;

    use super::*;
    use std::io::Read;

    /// Test that get_blocks works as expected.
    ///
    /// The author took the following steps to set up this test:
    /// 1. Get Nakamoto running locally. This was done using
    ///    https://github.com/hirosystems/stacks-regtest-env/blob/feat/signer/docker-compose.yml
    ///    where the STACKS_BLOCKCHAIN_COMMIT was changed to
    ///    "3d96d53b35409859ca2baa2f0b6ddaa1fbd80265" and the
    ///    MINE_INTERVAL_EPOCH3 was set to "60s".
    /// 2. After Nakamoto is running, use a dummy test like
    ///    `fetching_last_tenure_blocks_works` to get the blocks for an
    ///    actual tenure. Note the block IDs for the first and last
    ///    `NakamotoBlock`s in the result.
    /// 3. Use the block IDs from step (2) to make two curl requests:
    ///     * The tenure starting with the end block:
    ///     ```
    ///     curl http://localhost:20443/v3/tenures/<tenure-end-block-id> \
    ///         --output tests/fixtures/tenure-blocks-0-<tenure-end-block-id>.bin \
    ///         -vvv
    ///     ```
    ///     * The tenure starting at the tenure start block:
    ///     ```
    ///     curl http://localhost:20443/v3/tenures/<tenure-start-block-id> \
    ///         --output tests/fixtures/tenure-blocks-1-<tenure-start-block-id>.bin \
    ///         -vvv
    ///     ```
    /// 4. Done
    #[tokio::test]
    async fn get_blocks_test() {
        // Here we test that out code will handle the response from a
        // stacks node in the expected way.
        const TENURE_START_BLOCK_ID: &str =
            "8ff4eb1ed4a2f83faada29f6012b7f86f476eafed9921dff8d2c14cdfa30da94";
        const TENURE_END_BLOCK_ID: &str =
            "1ed91e0720129bda5072540ee7283dd5345d0f6de0cf5b982c6de3943b6e3291";

        // Okay we need to setup the server to returned what a stacks node
        // would return. We load up a file that contains a response from an
        // actual stacks node in regtest mode.
        let path = format!("tests/fixtures/tenure-blocks-0-{TENURE_END_BLOCK_ID}.bin");
        let mut file = std::fs::File::open(path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let mut stacks_node_server = mockito::Server::new_async().await;
        let endpoint_path = format!("/v3/tenures/{TENURE_END_BLOCK_ID}");
        let first_mock = stacks_node_server
            .mock("GET", endpoint_path.as_str())
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("transfer-encoding", "chunked")
            .with_chunked_body(move |w| w.write_all(&buf))
            .expect(1)
            .create();

        // The StacksClient::get_blocks call should make at least two
        // requests to the stacks node if there are two or more Nakamoto
        // blocks within the same tenure. Our test setup has 23 blocks
        // within the tenure so we need to tell the mock server what to
        // return in the second request.
        //
        // Also worth noting is that the total size of the blocks within a
        // GET /v3/tenures/<block-id> is ~16 MB (via the MAX_MESSAGE_LEN
        // constant in stacks-core). The size of the blocks for this test
        // is well under 1 MB so we get all the data during the first
        // request, which just don't know that until the second request.
        let path = format!("tests/fixtures/tenure-blocks-1-{TENURE_START_BLOCK_ID}.bin");
        let mut file = std::fs::File::open(path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let endpoint_path = format!("/v3/tenures/{TENURE_START_BLOCK_ID}");
        let second_mock = stacks_node_server
            .mock("GET", endpoint_path.as_str())
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("transfer-encoding", "chunked")
            .with_chunked_body(move |w| w.write_all(&buf))
            .expect(1)
            .create();

        let settings = StacksSettings {
            node: StacksNodeSettings {
                endpoint: url::Url::parse(stacks_node_server.url().as_str()).unwrap(),
            },
        };

        let client = StacksClient::new(settings);
        let block_id = StacksBlockId::from_hex(TENURE_END_BLOCK_ID).unwrap();
        // The moment of truth, do the requests succeed?
        let blocks = client.get_blocks(block_id).await.unwrap();
        assert!(blocks.len() > 1);
        dbg!(blocks.len());

        // We know that the blocks are ordered as a chain and we know the
        // first and last block IDs, let's check that.
        let last_block_id = StacksBlockId::from_hex(TENURE_START_BLOCK_ID).unwrap();
        let n = blocks.len() - 1;
        assert_eq!(blocks[0].block_id(), block_id);
        assert_eq!(blocks[n].block_id(), last_block_id);

        // Let's check that the returned blocks are distinct.
        let mut ans: Vec<StacksBlockId> = blocks.iter().map(|block| block.block_id()).collect();
        ans.sort();
        ans.dedup();
        assert_eq!(blocks.len(), ans.len());

        first_mock.assert();
        second_mock.assert();
    }

    #[tokio::test]
    async fn get_tenure_info_works() {
        let raw_json_response = r#"{
            "consensus_hash": "e42b3a9ffce62376e1f36cf76c33cc23d9305de1",
            "tenure_start_block_id": "e08c740242092eb0b5f74756ce203db048a5156e444df531a7c29e2d952cf628",
            "parent_consensus_hash": "d9693fbdf0a9bab9ee5ffd3c4f52fef6e1da1899",
            "parent_tenure_start_block_id": "8ff4eb1ed4a2f83faada29f6012b7f86f476eafed9921dff8d2c14cdfa30da94",
            "tip_block_id": "8f61dc41560560e8122609e82966740075929ed663543d9ad6733f8fc32876c5",
            "tip_height": 2037,
            "reward_cycle": 11
        }"#;

        let mut stacks_node_server = mockito::Server::new_async().await;
        let first_mock = stacks_node_server
            .mock("GET", "/v3/tenures/info")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(raw_json_response)
            .expect(1)
            .create();

        let settings = StacksSettings {
            node: StacksNodeSettings {
                endpoint: url::Url::parse(stacks_node_server.url().as_str()).unwrap(),
            },
        };

        let client = StacksClient::new(settings);
        let resp = client.get_tenure_info().await.unwrap();
        let expected: RPCGetTenureInfo = serde_json::from_str(raw_json_response).unwrap();

        assert_eq!(resp, expected);
        first_mock.assert();
    }

    #[tokio::test]
    #[ignore = "This is an integration test that hasn't been setup for CI yet"]
    async fn fetching_last_tenure_blocks_works() {
        let settings = StacksSettings::new_from_config().unwrap();
        let client = StacksClient::new(settings);

        let blocks = client.get_last_tenure_blocks().await.unwrap();
        assert!(!blocks.is_empty());
    }
}
