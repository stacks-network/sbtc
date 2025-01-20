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
    pub target_env_abi: String,
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
}

#[derive(Debug, Serialize)]
pub struct ChainTipInfo<T> {
    pub block_hash: T,
    pub block_height: u64,
}

impl Default for InfoResponse {
    fn default() -> Self {
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
            },
            build_info: BuildInfo {
                rust_version: crate::RUSTC_VERSION.to_string(),
                git_revision: crate::GIT_COMMIT.to_string(),
                target_arch: crate::TARGET_ARCH.to_string(),
                target_env_abi: crate::TARGET_ENV_ABI.to_string(),
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

    async fn populate_stacks_node_info(&mut self, stacks_client: &impl StacksInteract) {
        match stacks_client.get_node_info().await {
            Ok(node_info) => {
                self.stacks.has_node_tip = true;
                self.stacks.node_tip = Some(ChainTipInfo {
                    block_hash: node_info.stacks_tip.0.into(),
                    block_height: node_info.stacks_tip_height,
                });
            }
            Err(e) => {
                tracing::error!("error getting stacks node tip: {}", e);
            }
        }
    }
}
