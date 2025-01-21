//! Handler for the `/info` endpoint.

use axum::{extract::State, response::IntoResponse, Json};
use serde::Serialize;

use crate::{
    bitcoin::BitcoinInteract,
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
    pub has_local_tip: bool,
    pub local_tip: Option<ChainTipInfo<BitcoinBlockHash>>,
    pub has_node_tip: bool,
    pub node_tip: Option<ChainTipInfo<BitcoinBlockHash>>,
}

#[derive(Debug, Serialize)]
pub struct StacksInfo {
    pub has_local_tip: bool,
    pub local_tip: Option<ChainTipInfo<StacksBlockHash>>,
    pub has_node_tip: bool,
    pub node_tip: Option<ChainTipInfo<StacksBlockHash>>,
    pub node_bitcoin_block_height: Option<u64>,
    pub node_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChainTipInfo<T> {
    pub block_hash: T,
    pub block_height: u64,
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
                has_local_tip: false,
                local_tip: None,
                has_node_tip: false,
                node_tip: None,
            },
            stacks: StacksInfo {
                has_local_tip: false,
                local_tip: None,
                has_node_tip: false,
                node_tip: None,
                node_bitcoin_block_height: None,
                node_version: None,
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

    let mut response = InfoResponse::default();

    response.populate_local_chain_info(&storage).await;
    response.populate_bitcoin_node_info(&bitcoin_client).await;
    response.populate_stacks_node_info(&stacks_client).await;

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

                self.bitcoin.has_local_tip = true;
                self.bitcoin.local_tip = Some(ChainTipInfo {
                    block_hash: bitcoin_block.block_hash,
                    block_height: bitcoin_block.block_height,
                });

                match storage
                    .get_stacks_chain_tip(&bitcoin_block.block_hash)
                    .await
                {
                    Ok(Some(local_stacks_chain_tip)) => {
                        self.stacks.has_local_tip = true;
                        self.stacks.local_tip = Some(ChainTipInfo {
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

    /// Populates the Bitcoin node tip information from the provided Bitcoin client.
    async fn populate_bitcoin_node_info(&mut self, bitcoin_client: &impl BitcoinInteract) {
        match bitcoin_client.get_best_chain_tip().await {
            Ok((block_hash, block_height)) => {
                self.bitcoin.has_node_tip = true;
                self.bitcoin.node_tip = Some(ChainTipInfo {
                    block_hash: block_hash.into(),
                    block_height,
                });
            }
            Err(e) => {
                tracing::error!("error getting bitcoin node tip: {}", e);
            }
        }
    }

    /// Populates the Stacks node tip information from the provided Stacks client.
    async fn populate_stacks_node_info(&mut self, stacks_client: &impl StacksInteract) {
        match stacks_client.get_node_info().await {
            Ok(node_info) => {
                self.stacks.has_node_tip = true;
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
                    .expect_get_best_chain_tip()
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
        assert!(!result.bitcoin.has_local_tip);
        assert!(!result.bitcoin.has_node_tip);
        assert!(result.bitcoin.local_tip.is_none());
        assert!(result.bitcoin.node_tip.is_none());

        // Assert stacks info
        assert!(!result.stacks.has_local_tip);
        assert!(!result.stacks.has_node_tip);
        assert!(result.stacks.local_tip.is_none());
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
                    .expect_get_best_chain_tip()
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
        assert!(result.bitcoin.has_local_tip);
        assert!(!result.bitcoin.has_node_tip);
        let Some(bitcoin_local_tip) = result.bitcoin.local_tip else {
            panic!("expected local bitcoin tip to be present");
        };
        assert_eq!(bitcoin_local_tip.block_hash, bitcoin_block.block_hash);
        assert_eq!(bitcoin_local_tip.block_height, bitcoin_block.block_height);

        // Assert local stacks tip
        assert!(result.stacks.has_local_tip);
        assert!(!result.stacks.has_node_tip);
        let Some(stacks_local_tip) = result.stacks.local_tip else {
            panic!("expected local stacks tip to be present");
        };
        assert_eq!(stacks_local_tip.block_hash, stacks_block.block_hash);
        assert_eq!(stacks_local_tip.block_height, stacks_block.block_height);
    }

    #[tokio::test]
    async fn test_bitcoin_node_info() {
        let mut context = TestContext::default_mocked();

        let block_hash: BitcoinBlockHash = Faker.fake();
        let block_height = 42;

        context
            .with_bitcoin_client(|client| {
                client
                    .expect_get_best_chain_tip()
                    .once()
                    .returning(move || {
                        let block_hash = block_hash.clone();
                        Box::pin(async move { Ok((block_hash.into(), block_height)) })
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

        assert!(result.bitcoin.has_node_tip);
        assert!(!result.bitcoin.has_local_tip);
        let Some(bitcoin_node_tip) = result.bitcoin.node_tip else {
            panic!("expected node bitcoin tip to be present");
        };
        assert_eq!(bitcoin_node_tip.block_hash, block_hash);
        assert_eq!(bitcoin_node_tip.block_height, block_height);
    }

    #[tokio::test]
    async fn test_stacks_node_info() {
        let mut context = TestContext::default_mocked();

        context
            .with_bitcoin_client(|client| {
                client
                    .expect_get_best_chain_tip()
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

        assert!(result.stacks.has_node_tip);
        assert!(!result.stacks.has_local_tip);
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
