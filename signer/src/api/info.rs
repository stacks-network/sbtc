//! Handler for the `/info` endpoint.

use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;

use crate::{
    bitcoin::BitcoinInteract,
    config::Settings,
    context::Context,
    stacks::api::StacksInteract,
    storage::{
        model::{BitcoinBlockHash, StacksBlockHash},
        DbRead,
    },
};

use super::ApiState;

#[derive(Debug, Serialize)]
pub struct InfoResponse {
    pub bitcoin: BitcoinInfo,
    pub stacks: StacksInfo,
    pub dkg: DkgInfo,
    pub build_info: BuildInfo,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct BuildInfo {
    pub rust_version: String,
    pub git_revision: String,
    pub target_arch: String,
    pub target_env_abi: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BitcoinInfo {
    pub signer_tip: Option<ChainTipInfo<BitcoinBlockHash>>,
    pub node_tip: Option<ChainTipInfo<BitcoinBlockHash>>,
    pub node_chain: Option<String>,
    pub node_version: Option<usize>,
    pub node_subversion: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StacksInfo {
    pub signer_tip: Option<ChainTipInfo<StacksBlockHash>>,
    pub node_tip: Option<ChainTipInfo<StacksBlockHash>>,
    pub node_bitcoin_block_height: Option<u64>,
    pub node_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChainTipInfo<T> {
    pub block_hash: T,
    pub block_height: u64,
}

#[derive(Debug, Serialize)]
pub struct DkgInfo {
    pub rounds: u32,
    pub target_rounds: u32,
    pub current_aggregate_key: Option<String>,
    pub min_bitcoin_block_height: Option<u64>,
}

impl Default for InfoResponse {
    fn default() -> Self {
        // This is a build-time constant and varies per build environment,
        // so this lint is not applicable.
        #[allow(clippy::const_is_empty)]
        let target_env_abi = if crate::TARGET_ENV_ABI.is_empty() {
            None
        } else {
            Some(crate::TARGET_ENV_ABI.to_string())
        };

        Self {
            bitcoin: BitcoinInfo {
                signer_tip: None,
                node_tip: None,
                node_chain: None,
                node_version: None,
                node_subversion: None,
            },
            stacks: StacksInfo {
                signer_tip: None,
                node_tip: None,
                node_bitcoin_block_height: None,
                node_version: None,
            },
            dkg: DkgInfo {
                rounds: 0,
                current_aggregate_key: None,
                target_rounds: 1,
                min_bitcoin_block_height: None,
            },
            build_info: BuildInfo {
                rust_version: crate::RUSTC_VERSION.to_string(),
                git_revision: crate::GIT_COMMIT.to_string(),
                target_arch: crate::TARGET_ARCH.to_string(),
                target_env_abi,
            },
            timestamp: time::OffsetDateTime::now_utc().to_string(),
        }
    }
}

impl IntoResponse for InfoResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

/// Handler for the `/info` endpoint. This method is infallible and returns
/// `null` for any missing information.
pub async fn info_handler<C: Context>(state: State<ApiState<C>>) -> InfoResponse {
    let bitcoin_client = state.ctx.get_bitcoin_client();
    let stacks_client = state.ctx.get_stacks_client();
    let storage = state.ctx.get_storage();
    let config = state.ctx.config();

    let mut response = InfoResponse::default();

    response.populate_local_chain_info(&storage).await;
    response.populate_bitcoin_node_info(&bitcoin_client).await;
    response.populate_stacks_node_info(&stacks_client).await;
    response.populate_dkg_info(&storage, config).await;

    response
}

impl InfoResponse {
    /// Populates the local Bitcoin and Stacks chain tip information.
    async fn populate_local_chain_info(&mut self, storage: &impl DbRead) {
        match storage.get_bitcoin_canonical_chain_tip().await {
            Ok(Some(local_bitcoin_chain_tip)) => {
                let bitcoin_block = storage
                    .get_bitcoin_block(&local_bitcoin_chain_tip)
                    .await
                    .inspect_err(|e| {
                        tracing::error!("error reading bitcoin block from the database: {}", e)
                    });

                let Ok(Some(bitcoin_block)) = bitcoin_block else {
                    tracing::error!(
                        "canonical tip found but could not retrieve block from the database"
                    );
                    return;
                };

                self.bitcoin.signer_tip = Some(ChainTipInfo {
                    block_hash: bitcoin_block.block_hash,
                    block_height: bitcoin_block.block_height,
                });

                match storage
                    .get_stacks_chain_tip(&bitcoin_block.block_hash)
                    .await
                {
                    Ok(Some(local_stacks_chain_tip)) => {
                        self.stacks.signer_tip = Some(ChainTipInfo {
                            block_hash: local_stacks_chain_tip.block_hash,
                            block_height: local_stacks_chain_tip.block_height,
                        });
                    }
                    Ok(None) => {
                        tracing::debug!("no local stacks tip found in the database.");
                    }
                    Err(e) => {
                        tracing::error!("error reading local Stacks tip from the database: {}", e);
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("no local bitcoin tip found in the database.");
            }
            Err(e) => {
                tracing::error!("error reading bitcoin tip from the database: {}", e);
            }
        }
    }

    /// Populates the Bitcoin node tip information from the provided Bitcoin
    /// client. This uses a combination of `getblockchaininfo` and
    /// `getnetworkinfo` RPC calls to populate the information.
    async fn populate_bitcoin_node_info(&mut self, bitcoin_client: &impl BitcoinInteract) {
        match bitcoin_client.get_blockchain_info().await {
            Ok(info) => {
                self.bitcoin.node_chain = Some(info.chain.to_string());
                self.bitcoin.node_tip = Some(ChainTipInfo {
                    block_hash: info.best_block_hash.into(),
                    block_height: info.blocks,
                });
            }
            Err(e) => {
                tracing::error!("error getting bitcoin node blockchain info: {}", e);
            }
        }

        match bitcoin_client.get_network_info().await {
            Ok(info) => {
                self.bitcoin.node_version = Some(info.version);
                self.bitcoin.node_subversion = Some(info.subversion);
            }
            Err(e) => {
                tracing::error!("error getting bitcoin node network info: {}", e);
            }
        }
    }

    /// Populates the Stacks node tip information from the provided Stacks client.
    /// This uses the `/v2/info` RPC endpoint to populate the information.
    async fn populate_stacks_node_info(&mut self, stacks_client: &impl StacksInteract) {
        match stacks_client.get_node_info().await {
            Ok(node_info) => {
                self.stacks.node_tip = Some(ChainTipInfo {
                    block_hash: node_info.stacks_tip.0.into(),
                    block_height: node_info.stacks_tip_height,
                });
                self.stacks.node_bitcoin_block_height = Some(node_info.burn_block_height);
                self.stacks.node_version = Some(node_info.server_version);
            }
            Err(e) => {
                tracing::error!("error getting stacks node tip: {}", e);
            }
        }
    }

    /// Populates the DKG information from the provided storage.
    async fn populate_dkg_info(&mut self, storage: &impl DbRead, config: &Settings) {
        self.dkg.target_rounds = config.signer.dkg_target_rounds.get();
        self.dkg.min_bitcoin_block_height =
            config.signer.dkg_min_bitcoin_block_height.map(|h| h.get());

        match storage.get_latest_encrypted_dkg_shares().await {
            Ok(Some(keys)) => {
                self.dkg.current_aggregate_key = Some(keys.aggregate_key.to_string());
                match storage.get_encrypted_dkg_shares_count().await {
                    Ok(count) => {
                        self.dkg.rounds = count;
                    }
                    Err(e) => {
                        tracing::error!(
                            "error reading encrypted DKG shares count from the database: {}",
                            e
                        );
                    }
                }
            }
            Ok(None) => {
                self.dkg.rounds = 0;
            }
            Err(e) => {
                tracing::error!("error reading aggregate keys from the database: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use blockstack_lib::net::api::getinfo::RPCPeerInfoData;
    use fake::{Fake, Faker};

    use crate::{
        api::ApiState,
        error::Error,
        storage::{
            model::{BitcoinBlock, StacksBlock},
            DbWrite,
        },
        testing::context::*,
    };

    use super::*;

    #[tokio::test]
    async fn test_all_null() {
        let mut context = TestContext::default_mocked();

        context
            .with_bitcoin_client(|client| {
                client
                    .expect_get_blockchain_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));

                client
                    .expect_get_network_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));
            })
            .await;

        context
            .with_stacks_client(|client| {
                client
                    .expect_get_node_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));
            })
            .await;

        let state = State(ApiState { ctx: context });
        let result = info_handler(state).await;

        // Assert bitcoin info
        assert!(result.bitcoin.signer_tip.is_none());
        assert!(result.bitcoin.node_tip.is_none());

        // Assert stacks info
        assert!(result.stacks.signer_tip.is_none());
        assert!(result.stacks.node_tip.is_none());
        assert!(result.stacks.node_bitcoin_block_height.is_none());
        assert!(result.stacks.node_version.is_none());

        // Assert build info
        let target_env_abi = if crate::TARGET_ENV_ABI.is_empty() {
            None
        } else {
            Some(crate::TARGET_ENV_ABI.to_string())
        };
        assert_eq!(result.build_info.rust_version, crate::RUSTC_VERSION);
        assert_eq!(result.build_info.git_revision, crate::GIT_COMMIT);
        assert_eq!(result.build_info.target_arch, crate::TARGET_ARCH);
        assert_eq!(result.build_info.target_env_abi, target_env_abi);
    }

    #[tokio::test]
    async fn test_local_chain_info() {
        let mut context = TestContext::default_mocked();

        context
            .with_bitcoin_client(|client| {
                client
                    .expect_get_blockchain_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));

                client
                    .expect_get_network_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));
            })
            .await;

        context
            .with_stacks_client(|client| {
                client
                    .expect_get_node_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));
            })
            .await;

        let storage = context.get_storage_mut();

        let bitcoin_block: BitcoinBlock = Faker.fake();
        storage.write_bitcoin_block(&bitcoin_block).await.unwrap();

        let stacks_block = StacksBlock {
            bitcoin_anchor: bitcoin_block.block_hash,
            ..Faker.fake()
        };
        storage.write_stacks_block(&stacks_block).await.unwrap();

        let state = State(ApiState { ctx: context.clone() });
        let result = info_handler(state).await;

        // Assert local bitcoin tip
        let Some(bitcoin_local_tip) = result.bitcoin.signer_tip else {
            panic!("expected local bitcoin tip to be present");
        };
        assert_eq!(bitcoin_local_tip.block_hash, bitcoin_block.block_hash);
        assert_eq!(bitcoin_local_tip.block_height, bitcoin_block.block_height);

        // Assert local stacks tip
        let Some(stacks_local_tip) = result.stacks.signer_tip else {
            panic!("expected local stacks tip to be present");
        };
        assert_eq!(stacks_local_tip.block_hash, stacks_block.block_hash);
        assert_eq!(stacks_local_tip.block_height, stacks_block.block_height);
    }

    #[tokio::test]
    async fn test_bitcoin_node_info() {
        let mut context = TestContext::default_mocked();

        let get_network_info_response_json =
            include_str!("../../tests/fixtures/bitcoind-getnetworkinfo-data.json");
        let get_blockchain_info_response_json =
            include_str!("../../tests/fixtures/bitcoind-getblockchaininfo-data.json");

        let get_network_info_response: bitcoincore_rpc_json::GetNetworkInfoResult =
            serde_json::from_str(&get_network_info_response_json).unwrap();
        let get_blockchain_info_response: bitcoincore_rpc_json::GetBlockchainInfoResult =
            serde_json::from_str(&get_blockchain_info_response_json).unwrap();

        context
            .with_bitcoin_client(|client| {
                let get_network_info_response = get_network_info_response.clone();
                let get_blockchain_info_response = get_blockchain_info_response.clone();

                client.expect_get_network_info().once().returning(move || {
                    let get_network_info_response = get_network_info_response.clone();
                    Box::pin(async move { Ok(get_network_info_response) })
                });

                client
                    .expect_get_blockchain_info()
                    .once()
                    .returning(move || {
                        let get_blockchain_info_response = get_blockchain_info_response.clone();
                        Box::pin(async move { Ok(get_blockchain_info_response) })
                    });
            })
            .await;

        context
            .with_stacks_client(|client| {
                client
                    .expect_get_node_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));
            })
            .await;

        let state = State(ApiState { ctx: context.clone() });
        let result = info_handler(state).await;

        let Some(bitcoin_node_tip) = result.bitcoin.node_tip else {
            panic!("expected node bitcoin tip to be present");
        };
        assert_eq!(
            bitcoin_node_tip.block_hash,
            get_blockchain_info_response.best_block_hash.into()
        );
        assert_eq!(
            bitcoin_node_tip.block_height,
            get_blockchain_info_response.blocks
        );
        assert_eq!(
            result.bitcoin.node_chain,
            Some(get_blockchain_info_response.chain.to_string())
        );
        assert_eq!(
            result.bitcoin.node_version,
            Some(get_network_info_response.version)
        );
        assert_eq!(
            result.bitcoin.node_subversion,
            Some(get_network_info_response.subversion)
        );
    }

    #[tokio::test]
    async fn test_stacks_node_info() {
        let mut context = TestContext::default_mocked();

        context
            .with_bitcoin_client(|client| {
                client
                    .expect_get_blockchain_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));

                client
                    .expect_get_network_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));
            })
            .await;

        let stacks_info_response_json =
            include_str!("../../tests/fixtures/stacksapi-get-node-info-test-data.json");
        let stacks_info_response: RPCPeerInfoData =
            serde_json::from_str(&stacks_info_response_json).unwrap();

        context
            .with_stacks_client(|client| {
                let response = stacks_info_response.clone();
                client.expect_get_node_info().once().returning(move || {
                    let response = response.clone();
                    Box::pin(async move { Ok(response) })
                });
            })
            .await;

        let state = State(ApiState { ctx: context.clone() });
        let result = info_handler(state).await;

        let Some(stacks_node_tip) = result.stacks.node_tip else {
            panic!("expected node stacks tip to be present");
        };
        assert_eq!(
            stacks_node_tip.block_hash,
            stacks_info_response.stacks_tip.0.into()
        );
        assert_eq!(
            stacks_node_tip.block_height,
            stacks_info_response.stacks_tip_height
        );
    }
}
