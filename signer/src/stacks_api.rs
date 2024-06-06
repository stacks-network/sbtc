//! A module with structs that interact with the Stacks API.

use std::future::Future;
use std::time::Duration;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo;
use blockstack_lib::types::chainstate::StacksBlockId;
use serde::Deserialize;

use crate::config::StacksSettings;
use crate::error::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A trait detailing the interface with the Stacks API and Stacks Nodes.
pub trait StacksInteract {
    /// Get stacks blocks confirmed by the given bitcoin block
    fn get_last_tenure_blocks(
        &self,
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

    /// Fetch all Nakamoto ancestor blocks with the same tenure as the
    /// given block ID from from a Stacks node.
    ///
    /// The response includes the Nakamoto block for the given block id.
    async fn get_tenure(&self, block_id: StacksBlockId) -> Result<Vec<NakamotoBlock>, Error> {
        let mut blocks = Vec::new();

        tracing::debug!(%block_id, "Making initial request for Nakamoto blocks within the tenure");
        blocks.extend(self._get_tenure(block_id).await?);

        let mut last_block_id = block_id;

        while let Some(last_block) = blocks.last() {
            // The first block returned from a GET /v3/tenures/<block-id>
            // RPC will be the block associated with the <block-id> path
            // parameter, with other blocks being ancestors within the
            // blockchain. Our last GET /v3/tenures/<block-id> request
            // could have returned only one Nakamoto block. If this is the
            // case then the block ID will match the block ID we used in
            // our last request and we know that there are no more Nakamoto
            // blocks within this tenure.
            let block_id = last_block.block_id();
            if block_id == last_block_id {
                break;
            }
            last_block_id = block_id;

            tracing::debug!(%block_id, "Fetching more Nakamoto blocks within the tenure");
            let new_blocks = self._get_tenure(block_id).await?;
            // The first block in the GET /v3/tenures/<block-id> response
            // is always the block related to the given <block-id>. But we
            // already have that block so we can skip adding it again.
            blocks.extend(new_blocks.into_iter().skip(1))
        }

        Ok(blocks)
    }

    /// Make a GET /v3/tenures/<block-id> request for Nakamoto ancestor
    /// blocks with the same tenure as the given block ID from from a
    /// Stacks node.
    ///
    /// # Notes
    ///
    /// * The GET /v3/tenures/<block-id> response is capped at ~16 MB, so a
    ///   single request may not return all Nakamoto blocks.
    /// * The response includes the Nakamoto block for the given block id.
    async fn _get_tenure(&self, block_id: StacksBlockId) -> Result<Vec<NakamotoBlock>, Error> {
        let path = format!("/v3/tenures/{}", block_id.to_hex());
        let url = self.node_endpoint.join(&path).map_err(Error::PathParse)?;

        tracing::debug!(%block_id, "Making request to the stacks node for the raw nakamoto block");

        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|err| Error::StacksNodeRequest(err, url.clone()))?;

        // The response here does not detail the number of blocks in the
        // response. So we essentially take the same implementation given
        // in [`StacksHttpResponse::decode_nakamoto_tenure`].
        let resp = response
            .bytes()
            .await
            .map_err(|err| Error::UnexpectedStacksResponse(err, url))?;

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
    pub async fn get_tenure_info(&self) -> Result<RPCGetTenureInfo, Error> {
        let url = self
            .node_endpoint
            .join("/v3/tenures/info")
            .map_err(Error::PathParse)?;

        tracing::debug!("Making request to the stacks node for the current tenure info");
        let response = self
            .client
            .get(url.clone())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|err| Error::StacksNodeRequest(err, url.clone()))?;

        response.json().await.map_err(|err| Error::Reqwest(err))
    }
}

impl StacksInteract for StacksClient {
    async fn get_last_tenure_blocks(&self) -> Result<Vec<NakamotoBlock>, Error> {
        // We want to get the last block in the previous tenure. That block
        // is the parent block to the first block of the current tenure. So
        // yeah, let's get it.
        let info = self.get_tenure_info().await?;
        let block = self.get_block(info.tenure_start_block_id).await?;

        let tenure_last_block = block.header.parent_block_id;
        self.get_tenure(tenure_last_block).await
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
        // let block = bitcoin::BlockHash::from_str(
        //     "7e462fb3a22d840026f017a9968e4a44ba11a51127cff5b41ed4c4e32fd48a0c",
        // )
        // .unwrap();

        let settings = StacksSettings::new_from_config().unwrap();
        let client = StacksClient::new(settings);

        // let block_ids = client.get_block_ids(&block).await.unwrap();
        // let block_id = block_ids[0];

        // dbg!(&block_ids);
        // let block_hex_str = "8f61dc41560560e8122609e82966740075929ed663543d9ad6733f8fc32876c5";
        let block_hex_str = "e08c740242092eb0b5f74756ce203db048a5156e444df531a7c29e2d952cf628";
        let block_id = StacksBlockId::from_hex(block_hex_str).unwrap();
        let resp = client.get_tenure(block_id).await.unwrap();
        let block = resp[0].clone();
        dbg!(&resp);
        assert_eq!(block_id, block.block_id());

        // use ripemd::Digest;
        // let burn_block_hash = "4bb86d7a8520b66bdede31f9f975216fb1a6359cd055b2ef7f5e8eb3b8fa6857";
        // let mut r160 = ripemd::Ripemd160::new();

        // r160.update(burn_block_hash);
        // let mut ch_bytes = [0u8; 20];
        // ch_bytes.copy_from_slice(r160.finalize().as_slice());
        // let ans = blockstack_lib::chainstate::burn::ConsensusHash(ch_bytes);

        // dbg!(ans);
        // dbg!(resp[0].header.consensus_hash);

        // let resp = client.get_block(block_id).await.unwrap();
        // dbg!(resp);
    }
}
