//! Handler for the `/info` endpoint.

use axum::{extract::State, response::IntoResponse, Json};
use clarity::types::chainstate::StacksBlockId;
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
    pub config: Option<ConfigInfo>,
    pub build_info: BuildInfo,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct BuildInfo {
    pub rust_version: &'static str,
    pub git_revision: &'static str,
    pub target_arch: &'static str,
    pub target_env_abi: Option<&'static str>,
}

#[derive(Debug, Default, Serialize)]
pub struct BitcoinInfo {
    pub signer_tip: Option<ChainTipInfo<BitcoinBlockHash>>,
    pub node_tip: Option<ChainTipInfo<BitcoinBlockHash>>,
    pub node_chain: Option<String>,
    pub node_version: Option<usize>,
    pub node_subversion: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct StacksInfo {
    pub signer_tip: Option<ChainTipInfo<StacksBlockHash>>,
    pub node_tip: Option<ChainTipInfo<StacksBlockId>>,
    pub node_bitcoin_block_height: Option<u64>,
    pub node_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChainTipInfo<T> {
    pub block_hash: T,
    pub block_height: u64,
}

#[derive(Debug, Serialize)]
pub struct ConfigInfo {
    pub network: String,
    pub deployer: String,
    pub bootstrap_signatures_required: u16,
    pub bitcoin_processing_delay: u64,
    pub context_window: u16,
    pub signer_round_max_duration: u64,
    pub bitcoin_presign_request_max_duration: u64,
    pub dkg_max_duration: u64,
    pub sbtc_bitcoin_start_height: Option<u64>,
    pub dkg_begin_pause: u64,
    pub max_deposits_per_bitcoin_block: u16,
    pub dkg_min_bitcoin_block_height: Option<u64>,
    pub dkg_target_rounds: u32,
}

#[derive(Debug, Serialize)]
pub struct DkgInfo {
    pub rounds: u32,
    pub current_aggregate_key: Option<String>,
    pub contract_aggregate_key: Option<String>,
}

impl Default for InfoResponse {
    fn default() -> Self {
        // This is a build-time constant and varies per build environment,
        // so this lint is not applicable.
        #[allow(clippy::const_is_empty)]
        let target_env_abi = if crate::TARGET_ENV_ABI.is_empty() {
            None
        } else {
            Some(crate::TARGET_ENV_ABI)
        };

        Self {
            bitcoin: Default::default(),
            stacks: Default::default(),
            dkg: DkgInfo {
                rounds: 0,
                current_aggregate_key: None,
                contract_aggregate_key: None,
            },
            config: None,
            build_info: BuildInfo {
                rust_version: crate::RUSTC_VERSION,
                git_revision: crate::GIT_COMMIT,
                target_arch: crate::TARGET_ARCH,
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

    response.populate_config_info(config);
    response.populate_local_chain_info(&storage).await;
    response.populate_bitcoin_node_info(&bitcoin_client).await;
    response.populate_stacks_node_info(&stacks_client).await;
    response
        .populate_dkg_info(&storage, config, &stacks_client)
        .await;

    response
}

impl InfoResponse {
    fn populate_config_info(&mut self, config: &Settings) {
        self.config = Some(ConfigInfo {
            network: config.signer.network.to_string(),
            deployer: config.signer.deployer.to_string(),
            bootstrap_signatures_required: config.signer.bootstrap_signatures_required,
            bitcoin_processing_delay: config.signer.bitcoin_processing_delay.as_secs(),
            context_window: config.signer.context_window,
            signer_round_max_duration: config.signer.signer_round_max_duration.as_secs(),
            bitcoin_presign_request_max_duration: config
                .signer
                .bitcoin_presign_request_max_duration
                .as_secs(),
            dkg_max_duration: config.signer.dkg_max_duration.as_secs(),
            sbtc_bitcoin_start_height: config.signer.sbtc_bitcoin_start_height,
            dkg_begin_pause: config.signer.dkg_begin_pause.unwrap_or(0),
            max_deposits_per_bitcoin_block: config.signer.max_deposits_per_bitcoin_tx.get(),
            dkg_min_bitcoin_block_height: config
                .signer
                .dkg_min_bitcoin_block_height
                .map(|h| h.get()),
            dkg_target_rounds: config.signer.dkg_target_rounds.get(),
        });
    }

    /// Populates the local Bitcoin and Stacks chain tip information.
    async fn populate_local_chain_info(&mut self, storage: &impl DbRead) {
        let bitcoin_tip = storage.get_bitcoin_canonical_chain_tip().await;

        match bitcoin_tip {
            Ok(Some(local_bitcoin_chain_tip)) => {
                let bitcoin_block = storage
                    .get_bitcoin_block(&local_bitcoin_chain_tip)
                    .await
                    .inspect_err(|error| {
                        tracing::error!(%error, "error reading bitcoin block from the database")
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

                let stacks_tip = storage
                    .get_stacks_chain_tip(&bitcoin_block.block_hash)
                    .await;

                match stacks_tip {
                    Ok(Some(local_stacks_chain_tip)) => {
                        self.stacks.signer_tip = Some(ChainTipInfo {
                            block_hash: local_stacks_chain_tip.block_hash,
                            block_height: local_stacks_chain_tip.block_height,
                        });
                    }
                    Ok(None) => {
                        tracing::debug!("no local stacks tip found in the database.");
                    }
                    Err(error) => {
                        tracing::error!(%error, "error reading local Stacks tip from the database");
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("no local bitcoin tip found in the database.");
            }
            Err(error) => {
                tracing::error!(%error, "error reading bitcoin tip from the database");
            }
        }
    }

    /// Populates the Bitcoin node tip information from the provided Bitcoin
    /// client. This uses a combination of `getblockchaininfo` and
    /// `getnetworkinfo` RPC calls to populate the information.
    async fn populate_bitcoin_node_info(&mut self, bitcoin_client: &impl BitcoinInteract) {
        let blockchain_info = bitcoin_client.get_blockchain_info().await;
        let network_info = bitcoin_client.get_network_info().await;

        match blockchain_info {
            Ok(info) => {
                self.bitcoin.node_chain = Some(info.chain.to_string());
                self.bitcoin.node_tip = Some(ChainTipInfo {
                    block_hash: info.best_block_hash.into(),
                    block_height: info.blocks,
                });
            }
            Err(error) => {
                tracing::error!(%error, "error getting bitcoin node blockchain info");
            }
        }

        match network_info {
            Ok(info) => {
                self.bitcoin.node_version = Some(info.version);
                self.bitcoin.node_subversion = Some(info.subversion);
            }
            Err(error) => {
                tracing::error!(%error, "error getting bitcoin node network info");
            }
        }
    }

    /// Populates the Stacks node tip information from the provided Stacks client.
    /// This uses the `/v2/info` RPC endpoint to populate the information.
    async fn populate_stacks_node_info(&mut self, stacks_client: &impl StacksInteract) {
        let tenure_info = stacks_client.get_tenure_info().await;
        let node_info = stacks_client.get_node_info().await;

        match tenure_info {
            Ok(tenure_info) => {
                self.stacks.node_tip = Some(ChainTipInfo {
                    block_hash: tenure_info.tip_block_id,
                    block_height: tenure_info.tip_height,
                });
            }
            Err(error) => {
                tracing::error!(%error, "error getting stacks tenure info");
            }
        }

        match node_info {
            Ok(node_info) => {
                self.stacks.node_bitcoin_block_height = Some(node_info.burn_block_height);
                self.stacks.node_version = Some(node_info.server_version);
            }
            Err(error) => {
                tracing::error!(%error, "error getting stacks node info");
            }
        }
    }

    /// Populates the DKG information from the provided storage.
    async fn populate_dkg_info(
        &mut self,
        storage: &impl DbRead,
        settings: &Settings,
        stacks_client: &impl StacksInteract,
    ) {
        let latest_dkg_shares = storage.get_latest_encrypted_dkg_shares().await;

        match latest_dkg_shares {
            Ok(Some(keys)) => {
                self.dkg.current_aggregate_key = Some(keys.aggregate_key.to_string());
                let dkg_shares_count = storage.get_encrypted_dkg_shares_count().await;
                match dkg_shares_count {
                    Ok(count) => {
                        self.dkg.rounds = count;
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "error reading encrypted DKG shares count from the database"
                        );
                    }
                }
            }
            Ok(None) => {
                self.dkg.rounds = 0;
            }
            Err(error) => {
                tracing::error!(%error, "error reading aggregate keys from the database");
            }
        }

        let current_signers_aggregate_key = stacks_client
            .get_current_signers_aggregate_key(&settings.signer.deployer)
            .await;

        match current_signers_aggregate_key {
            Ok(Some(key)) => {
                self.dkg.contract_aggregate_key = Some(key.to_string());
            }
            Ok(None) => {
                tracing::debug!(deployer = %settings.signer.deployer, "no aggregate key found for the configured deployer address on the stacks node");
            }
            Err(error) => {
                tracing::error!(%error, "error getting current signers aggregate key from the stacks node");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::LazyCell,
        num::{NonZeroU16, NonZeroU32, NonZeroU64},
        time::Duration,
    };

    use blockstack_lib::net::api::{getinfo::RPCPeerInfoData, gettenureinfo::RPCGetTenureInfo};
    use clarity::types::chainstate::StacksAddress;
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

                client
                    .expect_get_tenure_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));

                client
                    .expect_get_current_signers_aggregate_key()
                    .once()
                    .returning(|_| Box::pin(async { Err(Error::Dummy) }));
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

        // Assert config info
        assert!(result.config.is_some());

        // Assert DKG info
        assert!(result.dkg.contract_aggregate_key.is_none());
        assert!(result.dkg.current_aggregate_key.is_none());
        assert_eq!(result.dkg.rounds, 0);

        // Assert build info
        let target_env_abi = if crate::TARGET_ENV_ABI.is_empty() {
            None
        } else {
            Some(crate::TARGET_ENV_ABI)
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

                client
                    .expect_get_tenure_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));

                client
                    .expect_get_current_signers_aggregate_key()
                    .once()
                    .returning(|_| Box::pin(async { Err(Error::Dummy) }));
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

                client
                    .expect_get_tenure_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));

                client
                    .expect_get_current_signers_aggregate_key()
                    .once()
                    .returning(|_| Box::pin(async { Err(Error::Dummy) }));
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

        const NODE_INFO_RESPONSE: LazyCell<RPCPeerInfoData> = LazyCell::new(|| {
            let json = include_str!("../../tests/fixtures/stacksapi-get-node-info-test-data.json");
            serde_json::from_str(json).unwrap()
        });

        const TENURE_INFO_RESPONSE: LazyCell<RPCGetTenureInfo> = LazyCell::new(|| {
            let json = include_str!("../../tests/fixtures/stacksapi-v3-tenures-info-data.json");
            serde_json::from_str(json).unwrap()
        });

        context
            .with_stacks_client(|client| {
                client
                    .expect_get_node_info()
                    .once()
                    .returning(|| Box::pin(async { Ok(NODE_INFO_RESPONSE.clone()) }));

                client
                    .expect_get_tenure_info()
                    .once()
                    .returning(|| Box::pin(async move { Ok(TENURE_INFO_RESPONSE.clone()) }));

                client
                    .expect_get_current_signers_aggregate_key()
                    .once()
                    .returning(|_| Box::pin(async { Err(Error::Dummy) }));
            })
            .await;

        let state = State(ApiState { ctx: context.clone() });
        let result = info_handler(state).await;

        let Some(stacks_node_tip) = result.stacks.node_tip else {
            panic!("expected node stacks tip to be present");
        };
        assert_eq!(
            stacks_node_tip.block_hash,
            TENURE_INFO_RESPONSE.tip_block_id
        );
        assert_eq!(
            stacks_node_tip.block_height,
            TENURE_INFO_RESPONSE.tip_height
        );
        assert_eq!(
            result.stacks.node_bitcoin_block_height,
            Some(NODE_INFO_RESPONSE.burn_block_height)
        );
        assert_eq!(
            result.stacks.node_version.expect("no node version"),
            NODE_INFO_RESPONSE.server_version
        );
    }

    #[tokio::test]
    async fn test_config_info() {
        let mut context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.network = crate::config::NetworkKind::Regtest;
                settings.signer.deployer = StacksAddress::burn_address(false);
                settings.signer.bootstrap_signatures_required = 3;
                settings.signer.bitcoin_processing_delay = Duration::from_secs(1);
                settings.signer.context_window = 10;
                settings.signer.signer_round_max_duration = Duration::from_secs(2);
                settings.signer.bitcoin_presign_request_max_duration = Duration::from_secs(3);
                settings.signer.dkg_max_duration = Duration::from_secs(4);
                settings.signer.sbtc_bitcoin_start_height = Some(101);
                settings.signer.dkg_begin_pause = Some(5);
                settings.signer.max_deposits_per_bitcoin_tx = NonZeroU16::new(6).unwrap();
                settings.signer.dkg_min_bitcoin_block_height = Some(NonZeroU64::new(102).unwrap());
                settings.signer.dkg_target_rounds = NonZeroU32::new(7).unwrap();
            })
            .build();

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

                client
                    .expect_get_tenure_info()
                    .once()
                    .returning(|| Box::pin(async { Err(Error::Dummy) }));

                client
                    .expect_get_current_signers_aggregate_key()
                    .once()
                    .returning(|_| Box::pin(async { Err(Error::Dummy) }));
            })
            .await;

        let state = State(ApiState { ctx: context.clone() });
        let result = info_handler(state).await;

        let Some(config) = result.config else {
            panic!("config info not populated");
        };

        let settings = context.config().clone().signer;

        assert_eq!(config.network, settings.network.to_string());
        assert_eq!(
            config.bootstrap_signatures_required,
            settings.bootstrap_signatures_required
        );
        assert_eq!(config.deployer, settings.deployer.to_string());
        assert_eq!(
            config.bitcoin_processing_delay,
            settings.bitcoin_processing_delay.as_secs()
        );
        assert_eq!(config.context_window, settings.context_window);
        assert_eq!(
            config.signer_round_max_duration,
            settings.signer_round_max_duration.as_secs()
        );
        assert_eq!(
            config.bitcoin_presign_request_max_duration,
            settings.bitcoin_presign_request_max_duration.as_secs()
        );
        assert_eq!(config.dkg_max_duration, settings.dkg_max_duration.as_secs());
        assert_eq!(
            config.sbtc_bitcoin_start_height,
            settings.sbtc_bitcoin_start_height
        );
        assert_eq!(config.dkg_begin_pause, settings.dkg_begin_pause.unwrap());
        assert_eq!(
            config.max_deposits_per_bitcoin_block,
            settings.max_deposits_per_bitcoin_tx.get()
        );
        assert_eq!(
            config.dkg_min_bitcoin_block_height,
            settings.dkg_min_bitcoin_block_height.map(|h| h.get())
        );
        assert_eq!(config.dkg_target_rounds, settings.dkg_target_rounds.get());
    }
}
