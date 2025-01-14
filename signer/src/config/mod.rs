//! Configuration management for the signer
use config::Config;
use config::ConfigError;
use config::Environment;
use config::File;
use libp2p::Multiaddr;
use serde::Deserialize;
use stacks_common::types::chainstate::StacksAddress;
use std::collections::BTreeSet;
use std::num::NonZeroU16;
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::path::Path;
use url::Url;

use crate::config::error::SignerConfigError;
use crate::config::serialization::duration_seconds_deserializer;
use crate::config::serialization::p2p_multiaddr_deserializer_vec;
use crate::config::serialization::parse_stacks_address;
use crate::config::serialization::private_key_deserializer;
use crate::config::serialization::url_deserializer_single;
use crate::config::serialization::url_deserializer_vec;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::stacks::wallet::SignerWallet;
use crate::DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX;

mod error;
mod serialization;

/// Maximum configurable delay (in seconds) before processing new Bitcoin blocks.
pub const MAX_BITCOIN_PROCESSING_DELAY_SECONDS: u64 = 300;

/// Trait for validating configuration values.
trait Validatable {
    /// Validate the configuration values.
    fn validate(&self, cfg: &Settings) -> Result<(), ConfigError>;
}

#[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "testing"), derive(serde::Serialize))]
#[serde(rename_all = "lowercase")]
/// The Stacks and Bitcoin networks to use.
pub enum NetworkKind {
    /// The mainnet network
    Mainnet,
    /// The testnet network
    Testnet,
    /// The regtest network. This is equivalent to Testnet when
    /// constructing Stacks addresses and transactions.
    Regtest,
}

impl From<NetworkKind> for bitcoin::NetworkKind {
    fn from(value: NetworkKind) -> Self {
        match value {
            NetworkKind::Mainnet => bitcoin::NetworkKind::Main,
            _ => bitcoin::NetworkKind::Test,
        }
    }
}

impl From<NetworkKind> for bitcoin::KnownHrp {
    fn from(value: NetworkKind) -> Self {
        match value {
            NetworkKind::Mainnet => bitcoin::KnownHrp::Mainnet,
            NetworkKind::Testnet => bitcoin::KnownHrp::Testnets,
            NetworkKind::Regtest => bitcoin::KnownHrp::Regtest,
        }
    }
}

impl From<NetworkKind> for bitcoin::Network {
    fn from(network: NetworkKind) -> Self {
        match network {
            NetworkKind::Mainnet => bitcoin::Network::Bitcoin,
            NetworkKind::Testnet => bitcoin::Network::Testnet,
            NetworkKind::Regtest => bitcoin::Network::Regtest,
        }
    }
}

impl NetworkKind {
    /// Returns whether the network variant is Mainnet.
    pub fn is_mainnet(&self) -> bool {
        self == &NetworkKind::Mainnet
    }
}

/// Top-level configuration for the signer
#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    /// Blocklist client specific config
    pub blocklist_client: Option<BlocklistClientConfig>,
    /// Signer-specific configuration
    pub signer: SignerConfig,
    /// Bitcoin core configuration
    pub bitcoin: BitcoinConfig,
    /// Stacks configuration
    pub stacks: StacksConfig,
    /// Emily client configuration
    pub emily: EmilyClientConfig,
}

/// Configuration used for the [`BitcoinCoreClient`](sbtc::rpc::BitcoinCoreClient).
#[derive(Deserialize, Clone, Debug)]
pub struct BitcoinConfig {
    /// Bitcoin RPC endpoints.
    #[serde(deserialize_with = "url_deserializer_vec")]
    pub rpc_endpoints: Vec<Url>,

    /// Bitcoin ZeroMQ block-hash stream endpoint.
    #[serde(deserialize_with = "url_deserializer_vec")]
    pub block_hash_stream_endpoints: Vec<Url>,
}

/// Signer network configuration
#[derive(Deserialize, Clone, Debug)]
pub struct P2PNetworkConfig {
    /// List of seeds for the P2P network. If empty then the signer will
    /// only use peers discovered via StackerDB.
    #[serde(deserialize_with = "p2p_multiaddr_deserializer_vec")]
    pub seeds: Vec<Multiaddr>,
    /// The local network interface(s) to listen on. If empty, then
    /// the signer will use [`DEFAULT_NETWORK_HOST`]:[`DEFAULT_NETWORK_PORT] as
    /// the default and listen on both TCP and QUIC protocols.
    #[serde(deserialize_with = "p2p_multiaddr_deserializer_vec")]
    pub listen_on: Vec<Multiaddr>,
    /// Optionally specifies the public endpoints of the signer. If empty, the
    /// signer will attempt to use peers in the network to discover its own
    /// public endpoint(s).
    #[serde(deserialize_with = "p2p_multiaddr_deserializer_vec")]
    pub public_endpoints: Vec<Multiaddr>,
    /// Enable mDNS discovery for the P2P network. This is useful for local
    /// testing and development.
    #[serde(default)]
    pub enable_mdns: bool,
}

impl Validatable for P2PNetworkConfig {
    fn validate(&self, cfg: &Settings) -> Result<(), ConfigError> {
        if [NetworkKind::Mainnet, NetworkKind::Testnet].contains(&cfg.signer.network)
            && self.seeds.is_empty()
        {
            return Err(ConfigError::Message(
                SignerConfigError::P2PSeedPeerRequired.to_string(),
            ));
        }

        Ok(())
    }
}

/// Blocklist client specific config
#[derive(Deserialize, Clone, Debug)]
pub struct BlocklistClientConfig {
    /// the url for the blocklist client
    #[serde(deserialize_with = "url_deserializer_single")]
    pub endpoint: Url,
}

/// Emily API configuration.
#[derive(Deserialize, Clone, Debug)]
pub struct EmilyClientConfig {
    /// Emily API endpoints.
    #[serde(deserialize_with = "url_deserializer_vec")]
    pub endpoints: Vec<Url>,
}

impl Validatable for EmilyClientConfig {
    fn validate(&self, _: &Settings) -> Result<(), ConfigError> {
        // At least one endpoint must be provided.
        if self.endpoints.is_empty() {
            return Err(ConfigError::Message(
                "[emily_client] At least one Emily API endpoint must be provided".to_string(),
            ));
        }
        // Validate each endpoint configuration.
        for endpoint in &self.endpoints {
            if !["http", "https"].contains(&endpoint.scheme()) {
                return Err(ConfigError::Message(
                    "[emily_client.endpoints] Invalid URL scheme: must be HTTP or HTTPS"
                        .to_string(),
                ));
            }

            if endpoint.host_str().is_none() {
                return Err(ConfigError::Message(
                    "[emily_client.endpoints] Invalid URL: host is required".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Signer-specific configuration
#[derive(Deserialize, Clone, Debug)]
pub struct SignerConfig {
    /// The private key of the signer
    #[serde(deserialize_with = "private_key_deserializer")]
    pub private_key: PrivateKey,
    /// P2P network configuration
    pub p2p: P2PNetworkConfig,
    /// P2P network configuration
    pub network: NetworkKind,
    /// Event observer server configuration
    pub event_observer: EventObserverConfig,
    /// The address of the deployer of the sBTC smart contracts.
    #[serde(deserialize_with = "parse_stacks_address")]
    pub deployer: StacksAddress,
    /// The postgres database endpoint
    #[serde(deserialize_with = "url_deserializer_single")]
    pub db_endpoint: Url,
    /// The scrape endpoint for exporting metrics for Prometheus.
    pub prometheus_exporter_endpoint: Option<std::net::SocketAddr>,
    /// The public keys of the signer sit during the bootstrapping phase of
    /// the signers.
    pub bootstrap_signing_set: Vec<PublicKey>,
    /// The number of signatures required for the signers' bootstrapped
    /// multi-sig wallet on Stacks.
    pub bootstrap_signatures_required: u16,
    /// The number of seconds the coordinator will wait
    /// before processing a new Bitcoin block
    /// (allowing it to propagate to the others signers)
    #[serde(deserialize_with = "duration_seconds_deserializer")]
    pub bitcoin_processing_delay: std::time::Duration,
    /// How many bitcoin blocks back from the chain tip the signer will
    /// look for requests.
    pub context_window: u16,
    /// The maximum duration of a signing round before the coordinator will
    /// time out and return an error.
    #[serde(deserialize_with = "duration_seconds_deserializer")]
    pub signer_round_max_duration: std::time::Duration,
    /// The maximum duration of a pre-sign request before the coordinator will
    /// time out and start sending the requests to the signers.
    #[serde(deserialize_with = "duration_seconds_deserializer")]
    pub bitcoin_presign_request_max_duration: std::time::Duration,
    /// The maximum duration of distributed key generation before the
    /// coordinator will time out and return an error.
    #[serde(deserialize_with = "duration_seconds_deserializer")]
    pub dkg_max_duration: std::time::Duration,
    /// The amount of time, in seconds, the signer should pause for after
    /// receiving a DKG begin message before relaying to give the other
    /// signers time to catch up.
    pub dkg_begin_pause: Option<u64>,
    /// The minimum bitcoin block height for which the sbtc signers will
    /// backfill bitcoin blocks to.
    pub sbtc_bitcoin_start_height: Option<u64>,
    /// The maximum number of deposit inputs that will be included in a
    /// single bitcoin transaction. Transactions must be constructed within
    /// a tenure of a bitcoin block, and higher values here imply lower
    /// likelihood of signing all inputs before the next bitcoin block
    /// arrives. The default here is controlled by the
    /// [`MAX_DEPOSITS_PER_BITCOIN_TX`] constant
    pub max_deposits_per_bitcoin_tx: NonZeroU16,
    /// Configures a DKG re-run Bitcoin block height. If this is set and DKG has
    /// already been run, the coordinator will attempt to re-run DKG after this
    /// block height is met if `dkg_target_rounds` has not been reached. If DKG
    /// has never been run, this configuration has no effect.
    pub dkg_min_bitcoin_block_height: Option<NonZeroU64>,
    /// Configures a target number of DKG rounds to run/accept. If this is set
    /// and the number of DKG shares is less than this number, the coordinator
    /// will continue to run DKG rounds until this number of rounds is reached,
    /// assuming the conditions for `dkg_min_bitcoin_block_height` are also met.
    /// If DKG has never been run, this configuration has no effect.
    pub dkg_target_rounds: NonZeroU32,
}

impl Validatable for SignerConfig {
    fn validate(&self, cfg: &Settings) -> Result<(), ConfigError> {
        self.p2p.validate(cfg)?;
        if self.deployer.is_mainnet() != self.network.is_mainnet() {
            let err = SignerConfigError::NetworkDeployerMismatch;
            return Err(ConfigError::Message(err.to_string()));
        }
        // At least perform a simple check to see if the database endpoint is
        // valid for the supported database drivers. We only support PostgreSQL
        // for now. The rest of the URI we delegate to the database driver for
        // validation (which will fail fast on startup).
        if !["postgres", "postgresql"].contains(&self.db_endpoint.scheme()) {
            let err =
                SignerConfigError::UnsupportedDatabaseDriver(self.db_endpoint.scheme().to_string());
            return Err(ConfigError::Message(err.to_string()));
        }

        // The requirement here is that the bootstrap wallet in the config
        // is a valid wallet, and all of those checks are done by the
        // `SignerWallet::load_boostrap_wallet` function.
        if let Err(err) = SignerWallet::load_boostrap_wallet(self) {
            return Err(ConfigError::Message(err.to_string()));
        }

        let delay_secs = cfg.signer.bitcoin_processing_delay.as_secs();
        if delay_secs > MAX_BITCOIN_PROCESSING_DELAY_SECONDS {
            return Err(ConfigError::Message(
                SignerConfigError::InvalidBitcoinProcessingDelay(
                    MAX_BITCOIN_PROCESSING_DELAY_SECONDS,
                    delay_secs,
                )
                .to_string(),
            ));
        }

        // All durations should be non-zero
        let zero = std::time::Duration::ZERO;
        if cfg.signer.dkg_max_duration == zero {
            return Err(ConfigError::Message(
                SignerConfigError::ZeroDurationForbidden("dkg_max_duration").to_string(),
            ));
        }
        if cfg.signer.bitcoin_presign_request_max_duration == zero {
            return Err(ConfigError::Message(
                SignerConfigError::ZeroDurationForbidden("bitcoin_presign_request_max_duration")
                    .to_string(),
            ));
        }
        if cfg.signer.signer_round_max_duration == zero {
            return Err(ConfigError::Message(
                SignerConfigError::ZeroDurationForbidden("signer_round_max_duration").to_string(),
            ));
        }
        // db_endpoint note: we don't validate the host because we will never
        // get here; the URL deserializer will fail if the host is empty.
        Ok(())
    }
}

impl SignerConfig {
    /// Return the bootstrapped signing set from the config. This function
    /// makes sure that the signing set includes the current signer.
    pub fn bootstrap_signing_set(&self) -> BTreeSet<PublicKey> {
        // We add in the current signer into the signing set from the
        // config just in case it hasn't been included already.
        let self_public_key = PublicKey::from_private_key(&self.private_key);
        self.bootstrap_signing_set
            .iter()
            .copied()
            .chain([self_public_key])
            .collect()
    }
}

/// Configuration for the Stacks event observer server (hosted within the signer).
#[derive(Debug, Clone, Deserialize)]
pub struct EventObserverConfig {
    /// The address and port to bind the server to.
    pub bind: std::net::SocketAddr,
}

impl Settings {
    /// Initializing the global config first with default values and then with
    /// provided/overwritten environment variables. The explicit separator with
    /// double underscores is needed to correctly parse the nested config structure.
    ///
    /// The environment variables are prefixed with `SIGNER_` and the nested
    /// fields are separated with double underscores. For example, the path
    /// `signer.p2p.listen_on` is parsed as following:
    ///
    /// ```text
    /// SIGNER_SIGNER__P2P__LISTEN_ON
    /// ^^^^^^ ^^^^^^  ^^^  ^^^^^^^^^
    ///    │  ^  │   ^^ │ ^^   │  ^
    ///    │  │  │   │  │ │    │  └ The underscore in the `listen_on` field
    ///    │  │  │   │  │ │    └ The `listen_on` field of the `p2p` object
    ///    │  │  │   │  │ └ separator("__")
    ///    │  │  │   │  └ The `p2p` field of the `signer` object
    ///    │  │  │   └ separator("__")
    ///    │  │  └ The `signer` field of the root object (`Settings`)
    ///    │  └ prefix_separator("_")
    ///    └ with_prefix("SIGNER")
    /// ```
    pub fn new(config_path: Option<impl AsRef<Path>>) -> Result<Self, ConfigError> {
        // To properly parse lists from both environment and config files while
        // using a custom deserializer, we need to specify the list separator,
        // enable try_parsing and specify the keys which should be parsed as lists.
        // If the keys aren't specified, the deserializer will try to parse all
        // Strings as lists which will result in an error.
        let env = Environment::with_prefix("SIGNER")
            .separator("__")
            .list_separator(",")
            .try_parsing(true)
            .with_list_parse_key("signer.bootstrap_signing_set")
            .with_list_parse_key("signer.p2p.seeds")
            .with_list_parse_key("signer.p2p.listen_on")
            .with_list_parse_key("signer.p2p.public_endpoints")
            .with_list_parse_key("bitcoin.rpc_endpoints")
            .with_list_parse_key("bitcoin.block_hash_stream_endpoints")
            .with_list_parse_key("stacks.endpoints")
            .with_list_parse_key("emily.endpoints")
            .prefix_separator("_");

        let mut cfg_builder = Config::builder();

        // TODO: We can reduce this to a more reasonable number, like 500,
        // after https://github.com/stacks-network/sbtc/issues/1004 gets
        // done.
        cfg_builder = cfg_builder.set_default("signer.context_window", 1000)?;
        cfg_builder = cfg_builder.set_default("signer.dkg_max_duration", 120)?;
        cfg_builder = cfg_builder.set_default("signer.bitcoin_presign_request_max_duration", 30)?;
        cfg_builder = cfg_builder.set_default("signer.signer_round_max_duration", 30)?;
        cfg_builder = cfg_builder.set_default(
            "signer.max_deposits_per_bitcoin_tx",
            DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        )?;
        cfg_builder = cfg_builder.set_default("signer.dkg_target_rounds", 1)?;

        if let Some(path) = config_path {
            cfg_builder = cfg_builder.add_source(File::from(path.as_ref()));
        }
        cfg_builder = cfg_builder.add_source(env);

        let cfg = cfg_builder.build()?;

        let settings: Settings = cfg.try_deserialize()?;

        settings.validate()?;

        Ok(settings)
    }

    /// Perform validation on the configuration.
    fn validate(&self) -> Result<(), ConfigError> {
        self.signer.validate(self)?;

        Ok(())
    }
}

/// Settings associated with the stacks node that this signer uses for information
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StacksConfig {
    /// The endpoint to use when making requests to a stacks node.
    #[serde(deserialize_with = "url_deserializer_vec")]
    pub endpoints: Vec<url::Url>,
}

impl Validatable for StacksConfig {
    fn validate(&self, _: &Settings) -> Result<(), ConfigError> {
        if self.endpoints.is_empty() {
            return Err(ConfigError::Message(
                "[stacks] Endpoints cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use tempfile;
    use toml_edit::DocumentMut;

    use crate::config::serialization::try_parse_p2p_multiaddr;

    use crate::error::Error;
    use crate::testing::clear_env;

    use std::time::Duration;

    use super::*;

    /// Helper function to quickly create a URL from a string in tests.
    fn url(s: &str) -> url::Url {
        s.parse().unwrap()
    }

    fn multiaddr(s: &str) -> Multiaddr {
        try_parse_p2p_multiaddr(s).unwrap()
    }

    /// This test checks that the default configuration values are loaded
    /// correctly from the default.toml file. The Stacks settings are excluded
    /// as they are covered by the [`default_config_toml_loads_with_environment`]
    /// test.
    // !! NOTE: This test needs to be updated if the default values in the
    // !! default.toml file are changed.
    #[test]
    fn default_config_toml_loads() {
        clear_env();

        let settings = Settings::new_from_default_config()
            .expect("Failed create settings from default config");
        assert!(settings.blocklist_client.is_none());

        assert_eq!(
            settings.signer.private_key,
            PrivateKey::from_str(
                "41634762d89dfa09133a4a8e9c1378d0161d29cd0a9433b51f1e3d32947a73dc"
            )
            .unwrap()
        );
        assert_eq!(settings.signer.network, NetworkKind::Regtest);

        assert_eq!(settings.signer.p2p.seeds, vec![]);
        assert_eq!(
            settings.signer.p2p.listen_on,
            vec![
                multiaddr("tcp://0.0.0.0:4122"),
                multiaddr("quic-v1://0.0.0.0:4122")
            ]
        );

        assert_eq!(
            settings.bitcoin.rpc_endpoints,
            vec![url("http://devnet:devnet@localhost:18443")]
        );
        assert_eq!(settings.bitcoin.rpc_endpoints[0].username(), "devnet");
        assert_eq!(settings.bitcoin.rpc_endpoints[0].password(), Some("devnet"));
        assert_eq!(
            settings.signer.event_observer.bind,
            "0.0.0.0:8801".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            settings.signer.max_deposits_per_bitcoin_tx,
            NonZeroU16::new(DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX).unwrap()
        );
        assert!(!settings.signer.bootstrap_signing_set.is_empty());
        assert!(settings.signer.dkg_begin_pause.is_none());
        assert_eq!(settings.signer.sbtc_bitcoin_start_height, Some(101));
        assert_eq!(settings.signer.bootstrap_signatures_required, 2);
        assert_eq!(settings.signer.context_window, 1000);
        assert!(settings.signer.prometheus_exporter_endpoint.is_none());
        assert_eq!(
            settings.signer.bitcoin_presign_request_max_duration,
            Duration::from_secs(30)
        );
        assert_eq!(
            settings.signer.signer_round_max_duration,
            Duration::from_secs(30)
        );
        assert_eq!(settings.signer.dkg_max_duration, Duration::from_secs(120));
        assert_eq!(
            settings.signer.dkg_target_rounds,
            NonZeroU32::new(1).unwrap()
        );
        assert_eq!(settings.signer.dkg_min_bitcoin_block_height, None);
    }

    #[test]
    fn default_config_toml_loads_with_signer_environment() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__CONTEXT_WINDOW", "600");
        std::env::set_var("SIGNER_SIGNER__BITCOIN_PRESIGN_REQUEST_MAX_DURATION", "60");
        std::env::set_var("SIGNER_SIGNER__SIGNER_ROUND_MAX_DURATION", "70");
        std::env::set_var("SIGNER_SIGNER__DKG_MAX_DURATION", "80");

        let settings = Settings::new_from_default_config().unwrap();

        assert_eq!(settings.signer.context_window, 600);
        assert_eq!(
            settings.signer.bitcoin_presign_request_max_duration,
            Duration::from_secs(60)
        );
        assert_eq!(
            settings.signer.signer_round_max_duration,
            Duration::from_secs(70)
        );
        assert_eq!(settings.signer.dkg_max_duration, Duration::from_secs(80));
    }

    #[test]
    fn default_config_toml_loads_signer_p2p_config_with_environment() {
        clear_env();

        std::env::set_var(
            "SIGNER_SIGNER__P2P__SEEDS",
            "tcp://seed-1:4122,tcp://seed-2:4122",
        );
        std::env::set_var("SIGNER_SIGNER__P2P__LISTEN_ON", "tcp://1.2.3.4:1234");

        let settings = Settings::new_from_default_config().unwrap();

        assert_eq!(
            settings.signer.p2p.seeds,
            vec![
                multiaddr("tcp://seed-1:4122"),
                multiaddr("tcp://seed-2:4122")
            ]
        );
        assert_eq!(
            settings.signer.p2p.listen_on,
            vec![multiaddr("tcp://1.2.3.4:1234")]
        );
    }

    #[test]
    fn default_config_toml_loads_bitcoin_config_with_environment() {
        clear_env();

        std::env::set_var(
            "SIGNER_BITCOIN__RPC_ENDPOINTS",
            "http://user:pass@localhost:1234,http://foo:bar@localhost:5678",
        );

        std::env::set_var(
            "SIGNER_BITCOIN__BLOCK_HASH_STREAM_ENDPOINTS",
            "tcp://localhost:1234,tcp://localhost:5678",
        );

        let settings = Settings::new_from_default_config().unwrap();

        assert_eq!(settings.bitcoin.rpc_endpoints.len(), 2);
        assert!(settings
            .bitcoin
            .rpc_endpoints
            .contains(&url("http://user:pass@localhost:1234")));
        assert!(settings
            .bitcoin
            .rpc_endpoints
            .contains(&url("http://foo:bar@localhost:5678")));
        assert!(settings
            .bitcoin
            .block_hash_stream_endpoints
            .contains(&url("tcp://localhost:1234")));
        assert!(settings
            .bitcoin
            .block_hash_stream_endpoints
            .contains(&url("tcp://localhost:5678")));
    }

    #[test]
    fn default_config_toml_loads_signer_private_key_config_with_environment() {
        clear_env();

        let new = "a1a6fcf2de80dcde3e0e4251eae8c69adf57b88613b2dcb79332cc325fa439bd";
        std::env::set_var("SIGNER_SIGNER__PRIVATE_KEY", new);

        let settings = Settings::new_from_default_config().unwrap();

        assert_eq!(
            settings.signer.private_key,
            PrivateKey::from_str(new).unwrap()
        );
    }

    #[test]
    fn default_config_toml_loads_max_deposits_per_bitcoin_tx() {
        clear_env();

        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(
            settings.signer.max_deposits_per_bitcoin_tx.get(),
            DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX
        );

        let value = "42";
        let expected_value: NonZeroU16 = value.parse().unwrap();
        // Let's make sure that this test is meaningful but checking that
        // the `value` and the default are different.
        assert_ne!(DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX, expected_value.get());

        std::env::set_var("SIGNER_SIGNER__MAX_DEPOSITS_PER_BITCOIN_TX", value);

        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(settings.signer.max_deposits_per_bitcoin_tx, expected_value);

        std::env::set_var("SIGNER_SIGNER__MAX_DEPOSITS_PER_BITCOIN_TX", "0");
        assert!(Settings::new_from_default_config().is_err());
    }

    #[test]
    fn default_config_toml_loads_dkg_min_bitcoin_block_height() {
        clear_env();

        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(settings.signer.dkg_min_bitcoin_block_height, None);

        std::env::set_var("SIGNER_SIGNER__DKG_MIN_BITCOIN_BLOCK_HEIGHT", "42");
        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(
            settings.signer.dkg_min_bitcoin_block_height,
            Some(NonZeroU64::new(42).unwrap())
        );
    }

    #[test]
    fn default_config_toml_loads_dkg_target_rounds() {
        clear_env();

        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(
            settings.signer.dkg_target_rounds,
            NonZeroU32::new(1).unwrap()
        );

        std::env::set_var("SIGNER_SIGNER__DKG_TARGET_ROUNDS", "42");
        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(
            settings.signer.dkg_target_rounds,
            NonZeroU32::new(42).unwrap()
        );
    }

    #[test]
    fn default_config_toml_loads_signer_network_with_environment() {
        clear_env();

        let new = "testnet";
        // We set the p2p seeds here as we'll otherwise fail p2p seed validation
        // when the network is mainnet or testnet.
        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://seed-1:4122");
        std::env::set_var("SIGNER_SIGNER__NETWORK", new);

        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(settings.signer.network, NetworkKind::Testnet);

        // We unset the p2p seeds here as they're not required for regtest.
        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "");
        let new = "regtest";
        std::env::set_var("SIGNER_SIGNER__NETWORK", new);

        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(settings.signer.network, NetworkKind::Regtest);
    }

    #[test]
    fn sbtc_bitcoin_start_height() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__SBTC_BITCOIN_START_HEIGHT", "12345");

        let settings = Settings::new_from_default_config().unwrap();
        let height = settings.signer.sbtc_bitcoin_start_height.unwrap();

        assert_eq!(height, 12345);
    }

    #[test]
    fn prometheus_exporter_endpoint_with_environment() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__PROMETHEUS_EXPORTER_ENDPOINT", "[::]:9851");

        let settings = Settings::new_from_default_config().unwrap();
        let endpoint = settings.signer.prometheus_exporter_endpoint.unwrap();

        assert!(endpoint.ip().is_unspecified());
        assert!(endpoint.is_ipv6());
        assert_eq!(endpoint.port(), 9851);

        std::env::set_var(
            "SIGNER_SIGNER__PROMETHEUS_EXPORTER_ENDPOINT",
            "0.0.0.0:9852",
        );

        let settings = Settings::new_from_default_config().unwrap();
        let endpoint = settings.signer.prometheus_exporter_endpoint.unwrap();

        assert!(endpoint.ip().is_unspecified());
        assert!(endpoint.is_ipv4());
        assert_eq!(endpoint.port(), 9852);
    }

    #[test]
    fn default_config_toml_loads_with_environment() {
        clear_env();

        // The default toml used here specifies http://localhost:20443
        // as the stacks node endpoint.
        let settings = Settings::new_from_default_config().unwrap();
        let host = settings.stacks.endpoints[0].host();
        assert_eq!(host, Some(url::Host::Domain("localhost")));
        assert_eq!(settings.stacks.endpoints[0].port(), Some(20443));

        std::env::set_var(
            "SIGNER_STACKS__ENDPOINTS",
            "http://whatever:1234,http://whateva:4321",
        );

        let settings = Settings::new_from_default_config().unwrap();
        let host = settings.stacks.endpoints[0].host();
        assert_eq!(host, Some(url::Host::Domain("whatever")));
        assert_eq!(settings.stacks.endpoints[0].port(), Some(1234));
        let host = settings.stacks.endpoints[1].host();
        assert_eq!(host, Some(url::Host::Domain("whateva")));
        assert_eq!(settings.stacks.endpoints[1].port(), Some(4321));

        std::env::set_var("SIGNER_STACKS__ENDPOINTS", "http://127.0.0.1:5678");

        let settings = Settings::new_from_default_config().unwrap();
        let ip: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            settings.stacks.endpoints[0].host(),
            Some(url::Host::Ipv4(ip))
        );
        assert_eq!(settings.stacks.endpoints[0].port(), Some(5678));

        std::env::set_var("SIGNER_STACKS__ENDPOINTS", "http://[::1]:9101");

        let settings = Settings::new_from_default_config().unwrap();
        let ip: std::net::Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(
            settings.stacks.endpoints[0].host(),
            Some(url::Host::Ipv6(ip))
        );
        assert_eq!(settings.stacks.endpoints[0].port(), Some(9101));

        let delay = 42;
        std::env::set_var("SIGNER_SIGNER__BITCOIN_PROCESSING_DELAY", delay.to_string());

        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(
            settings.signer.bitcoin_processing_delay,
            std::time::Duration::from_secs(delay),
        );
    }

    #[test]
    fn unprovided_optional_parameters_in_signer_config_set_to_default() {
        // In case there are some envs which provide values for this optional parameters,
        // this test will actually test nothing, so we need to reset them.
        clear_env();

        let config_file = format!("{}.toml", crate::testing::DEFAULT_CONFIG_PATH.unwrap());
        let config_str = std::fs::read_to_string(config_file).unwrap();
        let mut config_toml = config_str.parse::<DocumentMut>().unwrap();

        let mut remove_parameter = |parameter: &str| {
            config_toml
                .get_mut("signer")
                .unwrap()
                .as_table_mut()
                .unwrap()
                .remove(parameter);
        };
        remove_parameter("context_window");
        remove_parameter("signer_round_max_duration");
        remove_parameter("bitcoin_presign_request_max_duration");
        remove_parameter("dkg_max_duration");
        remove_parameter("max_deposits_per_bitcoin_tx");

        let new_config = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();

        std::fs::write(&new_config.path(), config_toml.to_string()).unwrap();

        let settings = Settings::new(Some(&new_config.path())).unwrap();

        assert_eq!(settings.signer.context_window, 1000);
        assert_eq!(
            settings.signer.bitcoin_presign_request_max_duration,
            Duration::from_secs(30)
        );
        assert_eq!(
            settings.signer.signer_round_max_duration,
            Duration::from_secs(30)
        );
        assert_eq!(settings.signer.dkg_max_duration, Duration::from_secs(120));
    }

    #[test]
    fn zero_durations_fails_in_signer_config() {
        fn test_one(field: &str) {
            clear_env();
            std::env::set_var(format!("SIGNER_SIGNER__{}", field.to_uppercase()), "0");
            let _ = Settings::new_from_default_config()
                .expect_err(&format!("Duration for {field} must be non zero"));
        }
        test_one("dkg_max_duration");
        test_one("bitcoin_presign_request_max_duration");
        test_one("signer_round_max_duration");
    }

    #[test]
    fn blocklist_client_endpoint() {
        clear_env();

        let endpoint = "http://127.0.0.1:12345";
        std::env::set_var("SIGNER_BLOCKLIST_CLIENT__ENDPOINT", endpoint);
        let settings = Settings::new_from_default_config().unwrap();

        let actual_endpoint = settings.blocklist_client.unwrap().endpoint;
        assert_eq!(actual_endpoint, url::Url::parse(endpoint).unwrap());
    }

    #[test]
    fn invalid_private_key_length_returns_correct_error() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__PRIVATE_KEY", "1234");

        let settings = Settings::new_from_default_config();
        assert!(settings.is_err());
        assert!(matches!(
            settings.unwrap_err(),
            ConfigError::Message(msg) if msg == SignerConfigError::InvalidStacksPrivateKeyLength(4).to_string()
        ));
    }

    #[test]
    fn invalid_bitcoin_processing_delay_returns_correct_error() {
        clear_env();

        let delay = MAX_BITCOIN_PROCESSING_DELAY_SECONDS + 1;
        std::env::set_var("SIGNER_SIGNER__BITCOIN_PROCESSING_DELAY", delay.to_string());

        let settings = Settings::new_from_default_config();
        assert!(settings.is_err());
        assert!(matches!(
            settings.unwrap_err(),
            ConfigError::Message(msg) if msg == SignerConfigError::InvalidBitcoinProcessingDelay(MAX_BITCOIN_PROCESSING_DELAY_SECONDS, delay).to_string()
        ));
    }

    #[test]
    fn invalid_private_key_compression_byte_marker_returns_correct_error() {
        clear_env();

        std::env::set_var(
            "SIGNER_SIGNER__PRIVATE_KEY",
            "a1a6fcf2de80dcde3e0e4251eae8c69adf57b88613b2dcb79332cc325fa439bd02",
        );
        let settings = Settings::new_from_default_config();
        assert!(settings.is_err());
        assert!(matches!(
            settings.unwrap_err(),
            ConfigError::Message(msg) if msg == SignerConfigError::InvalidStacksPrivateKeyCompressionByte("02".to_string()).to_string()
        ));
    }

    #[test]
    fn valid_33_byte_private_key_works() {
        clear_env();

        std::env::set_var(
            "SIGNER_SIGNER__PRIVATE_KEY",
            "a1a6fcf2de80dcde3e0e4251eae8c69adf57b88613b2dcb79332cc325fa439bd01",
        );
        let settings = Settings::new_from_default_config();
        assert!(settings.is_ok());
    }

    #[test]
    fn invalid_private_key_hex_returns_correct_error() {
        clear_env();

        std::env::set_var(
            "SIGNER_SIGNER__PRIVATE_KEY",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        );
        let hex_err = hex::decode("zz").unwrap_err();

        let settings = Settings::new_from_default_config();
        assert!(matches!(
            settings.unwrap_err(),
            ConfigError::Message(msg) if msg == Error::DecodeHexBytes(hex_err).to_string()
        ));
    }

    #[test]
    fn dkg_pause_env_variables_work() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__DKG_BEGIN_PAUSE", "1234");
        let config = Settings::new_from_default_config().unwrap();
        assert_eq!(config.signer.dkg_begin_pause, Some(1234));
    }

    #[test]
    fn invalid_p2p_uri_scheme_returns_correct_error() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "http://seed-1:4122");
        assert!(matches!(
            Settings::new_from_default_config(),
            Err(ConfigError::Message(msg)) if msg == SignerConfigError::InvalidP2PScheme("http".to_string()).to_string()
        ))
    }

    #[test]
    fn missing_p2p_uri_port_returns_correct_error() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://seed-1");
        assert!(matches!(
            Settings::new_from_default_config(),
            Err(ConfigError::Message(msg)) if msg == SignerConfigError::P2PPortRequired.to_string()
        ))
    }

    #[test]
    fn missing_p2p_uri_host_returns_correct_error() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://:4122");
        assert!(matches!(
            Settings::new_from_default_config(),
            Err(ConfigError::Message(msg)) if msg == SignerConfigError::InvalidP2PUri(url::ParseError::EmptyHost).to_string()
        ))
    }

    #[test]
    fn p2p_uri_with_username_returns_correct_error() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://user:@localhost:4122");
        assert!(matches!(
            Settings::new_from_default_config(),
            Err(ConfigError::Message(msg)) if msg == SignerConfigError::P2PUsernameNotSupported("user".to_string()).to_string()
        ))
    }

    #[test]
    fn p2p_uri_with_password_returns_correct_error() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://:pass@localhost:4122");
        assert!(matches!(
            Settings::new_from_default_config(),
            Err(ConfigError::Message(msg)) if msg == SignerConfigError::P2PPasswordNotSupported("pass".to_string()).to_string()
        ))
    }

    #[test]
    fn p2p_uri_with_query_string_returns_correct_error() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://localhost:4122?foo=bar");
        assert!(matches!(
            Settings::new_from_default_config(),
            Err(ConfigError::Message(msg)) if msg == SignerConfigError::P2PQueryStringsNotSupported("foo=bar".to_string()).to_string()
        ))
    }

    #[test]
    fn p2p_uri_with_path_returns_correct_error() {
        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://localhost:4122/hello");
        assert!(matches!(
            Settings::new_from_default_config(),
            Err(ConfigError::Message(msg)) if msg == SignerConfigError::P2PPathsNotSupported("/hello".to_string()).to_string()
        ))
    }

    #[test]
    fn p2p_ip4_uri_works() {
        use libp2p::multiaddr::Protocol;

        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__LISTEN_ON", "tcp://0.0.0.0:4122");
        let settings = Settings::new_from_default_config().expect("failed to load default config");

        let actual = settings
            .signer
            .p2p
            .listen_on
            .first()
            .expect("listen_on is empty");
        let expected = Multiaddr::empty()
            .with(Protocol::Ip4(
                "0.0.0.0".parse().expect("failed to parse ipaddr"),
            ))
            .with(Protocol::Tcp(4122));

        assert_eq!(*actual, expected);
    }

    #[test]
    fn p2p_ip6_uri_works() {
        use libp2p::multiaddr::Protocol;

        clear_env();

        std::env::set_var("SIGNER_SIGNER__P2P__LISTEN_ON", "tcp://[ff06::c3]:4122");
        let settings = Settings::new_from_default_config().expect("failed to load default config");

        let actual = settings
            .signer
            .p2p
            .listen_on
            .first()
            .expect("listen_on is empty");
        let expected = Multiaddr::empty()
            .with(Protocol::Ip6(
                "ff06::c3".parse().expect("failed to parse ipaddr"),
            ))
            .with(Protocol::Tcp(4122));

        assert_eq!(*actual, expected);
    }

    #[test_case::test_case(NetworkKind::Mainnet; "mainnet network, testnet deployer")]
    #[test_case::test_case(NetworkKind::Testnet; "testnet network, mainnet deployer")]
    fn network_mismatch_network_of_deployer(network: NetworkKind) {
        clear_env();

        let is_mainnet = network == NetworkKind::Mainnet;
        // The deployer address always has the opposite network kind.
        let address = StacksAddress::burn_address(!is_mainnet);
        std::env::set_var("SIGNER_SIGNER__DEPLOYER", address.to_string());
        // Let's set the network. maybe use strum for this in the future
        let network = match network {
            NetworkKind::Mainnet => "mainnet",
            NetworkKind::Testnet => "testnet",
            NetworkKind::Regtest => "regtest",
        };
        std::env::set_var("SIGNER_SIGNER__NETWORK", network);
        // We need to set at least one seed when deploying to mainnet.
        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://localhost:4122");

        assert!(matches!(
            Settings::new_from_default_config(),
            Err(ConfigError::Message(msg)) if msg == SignerConfigError::NetworkDeployerMismatch.to_string()
        ));
    }

    #[test_case::test_case(NetworkKind::Mainnet; "mainnet")]
    #[test_case::test_case(NetworkKind::Testnet; "testnet")]
    #[test_case::test_case(NetworkKind::Regtest; "regtest")]
    fn network_matches_network_of_deployer(network: NetworkKind) {
        clear_env();

        let is_mainnet = network == NetworkKind::Mainnet;
        // The deployer address always has the opposite network kind.
        let address = StacksAddress::burn_address(is_mainnet);
        std::env::set_var("SIGNER_SIGNER__DEPLOYER", address.to_string());
        // Let's set the network. maybe use strum for this in the future
        let network = match network {
            NetworkKind::Mainnet => "mainnet",
            NetworkKind::Testnet => "testnet",
            NetworkKind::Regtest => "regtest",
        };
        std::env::set_var("SIGNER_SIGNER__NETWORK", network);
        // We need to set at least one seed when deploying to mainnet.
        std::env::set_var("SIGNER_SIGNER__P2P__SEEDS", "tcp://localhost:4122");

        assert!(Settings::new_from_default_config().is_ok());
    }

    #[test]
    fn bootstrap_wallet_signatures_required() {
        clear_env();

        let signatures_required = 3;
        std::env::set_var(
            "SIGNER_SIGNER__BOOTSTRAP_SIGNATURES_REQUIRED",
            signatures_required.to_string(),
        );
        let settings = Settings::new_from_default_config().unwrap();

        assert_eq!(
            settings.signer.bootstrap_signatures_required,
            signatures_required
        );
    }

    #[test]
    fn bootstrap_wallet_signer_set() {
        clear_env();

        let keys = "035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46,031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380";
        std::env::set_var("SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET", keys);
        let settings = Settings::new_from_default_config().unwrap();
        let public_keys: Vec<PublicKey> = keys
            .split(",")
            .flat_map(secp256k1::PublicKey::from_str)
            .map(PublicKey::from)
            .collect();

        assert_eq!(settings.signer.bootstrap_signing_set, public_keys);
    }

    #[test]
    fn bad_bootstrap_wallet_signer_set() {
        clear_env();

        let keys = "031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380";
        let signatures_required = 3;
        std::env::set_var("SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET", keys);
        std::env::set_var(
            "SIGNER_SIGNER__BOOTSTRAP_SIGNATURES_REQUIRED",
            signatures_required.to_string(),
        );
        assert!(Settings::new_from_default_config().is_err());
    }

    #[test]
    fn db_endpoint_postgresql_works() {
        clear_env();

        let driver = "postgresql";
        let endpoint = format!("{driver}://user:pass@localhost:1234/abc123");

        std::env::set_var("SIGNER_SIGNER__DB_ENDPOINT", &endpoint);
        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(url(&endpoint), settings.signer.db_endpoint);
    }

    #[test]
    fn db_endpoint_invalid_driver_returns_correct_error() {
        clear_env();

        let driver = "somedb";
        let endpoint = format!("{driver}://user:pass@localhost:1234/abc123");

        std::env::set_var("SIGNER_SIGNER__DB_ENDPOINT", &endpoint);
        let settings = Settings::new_from_default_config();
        assert!(settings.is_err());
        assert!(matches!(
            settings.unwrap_err(),
            ConfigError::Message(msg) if msg == SignerConfigError::UnsupportedDatabaseDriver(driver.to_string()).to_string()
        ));
    }
}
