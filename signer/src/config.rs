//! Configuration management for the signer

use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use serde::Deserializer;
use std::str::FromStr;
use std::sync::LazyLock;

use crate::error::Error;
use crate::keys::PrivateKey;

/// The default signer network listen-on address.
pub const DEFAULT_P2P_HOST: &str = "0.0.0.0";
/// The default signer network listen-on port.
pub const DEFAULT_P2P_PORT: u16 = 4122;

/// Trait for validating configuration values.
trait Validatable {
    /// Validate the configuration values.
    fn validate(&self) -> Result<(), ConfigError>;
}

#[derive(serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// The Stacks network to use.
pub enum NetworkKind {
    /// The mainnet network
    Mainnet,
    /// The testnet network
    Testnet,
}

/// Top-level configuration for the signer
#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    /// Blocklist client specific config
    pub blocklist_client: BlocklistClientConfig,
    /// Electrum notifier specific config
    pub block_notifier: BlockNotifierConfig,
    /// Signer-specific configuration
    pub signer: SignerConfig,
}

/// Signer network configuration
#[derive(Deserialize, Clone, Debug)]
pub struct P2PNetworkConfig {
    /// List of seeds for the P2P network. If empty then the signer will
    /// only use peers discovered via StackerDB.
    #[serde(deserialize_with = "url_deserializer")]
    pub seeds: Vec<url::Url>,
    /// The local network interface(s) to listen on. If empty, then
    /// the signer will use [`DEFAULT_NETWORK_HOST`]:[`DEFAULT_NETWORK_PORT] as
    /// the default and listen on both TCP and QUIC protocols.
    #[serde(deserialize_with = "url_deserializer")]
    pub listen_on: Vec<url::Url>,
    /// Optionally specifies the public endpoints of the signer. If empty, the
    /// signer will attempt to use peers in the network to discover its own
    /// public endpoint(s).
    #[serde(deserialize_with = "url_deserializer")]
    pub public_endpoints: Vec<url::Url>,
}

impl Validatable for P2PNetworkConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        for addr in &self.seeds {
            self.validate_network_peering_addr("network.seeds", addr)?;
        }

        for addr in &self.listen_on {
            self.validate_network_peering_addr("network.listen_on", addr)?;
        }

        for addr in &self.public_endpoints {
            self.validate_network_peering_addr("network.public_endpoints", addr)?;
        }

        Ok(())
    }
}

impl P2PNetworkConfig {
    /// Validate a network address used by the peering protocol.
    fn validate_network_peering_addr(
        &self,
        section: &str,
        url: &url::Url,
    ) -> Result<(), ConfigError> {
        // Host must be present
        if url.host().is_none() {
            return Err(ConfigError::Message(format!(
                "[{section}] Host cannot be empty: '{url}'"
            )));
        }

        // We only support TCP and QUIC schemes
        if !["tcp", "quic-v1"].contains(&url.scheme()) {
            return Err(ConfigError::Message(format!(
                "[{section}] Only `tcp` and `quic-v1` schemes are supported"
            )));
        }

        // We don't support URL paths
        if !["/", ""].contains(&url.path()) {
            return Err(ConfigError::Message(format!(
                "[{section}] Paths are not supported: '{}'",
                url.path()
            )));
        }

        Ok(())
    }
}

/// Blocklist client specific config
#[derive(Deserialize, Clone, Debug)]
pub struct BlocklistClientConfig {
    /// Host of the blocklist client
    pub host: String,
    /// Port of the blocklist client
    pub port: u16,
}

impl Validatable for BlocklistClientConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.host.is_empty() {
            return Err(ConfigError::Message(
                "[blocklist_client] Host cannot be empty".to_string(),
            ));
        }
        if !(1..=65535).contains(&self.port) {
            return Err(ConfigError::Message(
                "[blocklist_client] Port must be between 1 and 65535".to_string(),
            ));
        }

        Ok(())
    }
}

/// Electrum notifier specific config
#[derive(Deserialize, Clone, Debug)]
pub struct BlockNotifierConfig {
    /// Electrum server address
    pub server: String,
    /// Retry interval in seconds
    pub retry_interval: u64,
    /// Maximum retry attempts
    pub max_retry_attempts: u32,
    /// Interval for pinging the server in seconds
    pub ping_interval: u64,
    /// Interval for subscribing to block headers in seconds
    pub subscribe_interval: u64,
}

impl Validatable for BlockNotifierConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.is_empty() {
            return Err(ConfigError::Message(
                "[block_notifier] Electrum server cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

/// Signer-specific configuration
#[derive(Deserialize, Clone, Debug)]
pub struct SignerConfig {
    /// Stacks account configuration. This is the account that the signer will
    /// use to identify itself on the network and sign transactions.
    pub stacks_account: StacksAccountConfig,
    /// P2P network configuration
    pub p2p: P2PNetworkConfig,
}

impl Validatable for SignerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        self.p2p.validate()?;
        Ok(())
    }
}

/// Keypair configuration
#[derive(Deserialize, Clone, Debug)]
pub struct StacksAccountConfig {
    /// The private key of the signer
    #[serde(deserialize_with = "private_key_deserializer")]
    pub private_key: PrivateKey,
}

/// Statically configured settings for the signer
pub static SETTINGS: LazyLock<Settings> =
    LazyLock::new(|| Settings::new().expect("Failed to load configuration"));

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
    pub fn new() -> Result<Self, ConfigError> {
        let env = Environment::with_prefix("SIGNER")
            .separator("__")
            .list_separator(",")
            .try_parsing(true)
            .with_list_parse_key("signer.p2p.seeds")
            .with_list_parse_key("signer.p2p.listen_on")
            .with_list_parse_key("signer.p2p.public_endpoints")
            .prefix_separator("_");
        let cfg = Config::builder()
            .add_source(File::with_name("./src/config/default"))
            .add_source(env)
            .build()?;

        let settings: Settings = cfg.try_deserialize()?;

        settings.validate()?;

        Ok(settings)
    }

    /// Perform validation on the configuration.
    fn validate(&self) -> Result<(), ConfigError> {
        self.blocklist_client.validate()?;
        self.block_notifier.validate()?;
        self.signer.validate()?;

        Ok(())
    }
}

/// A struct for the entries in the signers Config.toml (which is currently
/// located in src/config/default.toml)
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StacksSettings {
    /// The configuration entries related to the Stacks node
    pub node: StacksNodeSettings,
}

/// Settings associated with the stacks node that this signer uses for information
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StacksNodeSettings {
    /// TODO(225): We'll want to support specifying multiple Stacks Nodes
    /// endpoints.
    ///
    /// The endpoint to use when making requests to a stacks node.
    #[serde(deserialize_with = "url_deserializer")]
    pub endpoints: Vec<url::Url>,
    /// This is the start height of the first EPOCH 3.0 block on the stacks
    /// blockchain.
    pub nakamoto_start_height: u64,
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
    /// * SIGNER_STACKS_NODE_ENDPOINTS <-> stacks.node.endpoints
    ///
    /// Each of these overrides an entry in the signer's `config.toml`
    pub fn new_from_config() -> Result<Self, Error> {
        let source = File::with_name("./src/config/default");
        let env = Environment::with_prefix("SIGNER")
            .prefix_separator("_")
            .list_separator(",")
            .try_parsing(true)
            .with_list_parse_key("stacks.node.endpoints")
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

/// A deserializer for the url::Url type. This will return an empty [`Vec`] if
/// there are no URLs to deserialize.
fn url_deserializer<'de, D>(deserializer: D) -> Result<Vec<url::Url>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut v = Vec::new();
    for s in Vec::<String>::deserialize(deserializer)? {
        v.push(s.parse().map_err(serde::de::Error::custom)?);
    }
    Ok(v)
}

/// A deserializer for the PrivateKey type.
fn private_key_deserializer<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
where
    D: Deserializer<'de>,
{
    PrivateKey::from_str(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::keys::PrivateKey;

    use super::*;

    /// Helper function to quickly create a URL from a string in tests.
    fn url(s: &str) -> url::Url {
        s.parse().unwrap()
    }

    /// This test checks that the default configuration values are loaded
    /// correctly from the default.toml file. The Stacks settings are excluded
    /// as they are covered by the [`default_config_toml_loads_with_environment`]
    /// test.
    // !! NOTE: This test needs to be updated if the default values in the
    // !! default.toml file are changed.
    #[test]
    fn default_config_toml_loads() {
        let settings = Settings::new().unwrap();
        assert_eq!(settings.blocklist_client.host, "127.0.0.1");
        assert_eq!(settings.blocklist_client.port, 8080);
        assert_eq!(settings.block_notifier.server, "tcp://localhost:60401");
        assert_eq!(settings.block_notifier.retry_interval, 10);
        assert_eq!(settings.block_notifier.max_retry_attempts, 5);
        assert_eq!(settings.block_notifier.ping_interval, 60);
        assert_eq!(settings.block_notifier.subscribe_interval, 10);
        assert_eq!(
            settings.signer.stacks_account.private_key,
            PrivateKey::from_str(
                "8183dc385a7a1fc8353b9e781ee0859a71e57abea478a5bca679334094f7adb501"
            )
            .unwrap()
        );
        assert_eq!(settings.signer.p2p.seeds, vec![]);
        assert_eq!(
            settings.signer.p2p.listen_on,
            vec![url("tcp://0.0.0.0:4122"), url("quic-v1://0.0.0.0:4122")]
        );
    }

    #[test]
    fn default_config_toml_loads_signer_p2p_config_with_environment() {
        std::env::set_var(
            "SIGNER_SIGNER__P2P__SEEDS",
            "tcp://seed-1:4122,tcp://seed-2:4122",
        );
        std::env::set_var("SIGNER_SIGNER__P2P__LISTEN_ON", "tcp://1.2.3.4:1234");

        let settings = Settings::new().unwrap();

        assert_eq!(
            settings.signer.p2p.seeds,
            vec![url("tcp://seed-1:4122"), url("tcp://seed-2:4122")]
        );
        assert_eq!(
            settings.signer.p2p.listen_on,
            vec![url("tcp://1.2.3.4:1234")]
        );
    }

    #[test]
    fn default_config_toml_loads_signer_stacks_account_config_with_environment() {
        let new = "a1a6fcf2de80dcde3e0e4251eae8c69adf57b88613b2dcb79332cc325fa439bd01";
        std::env::set_var("SIGNER_SIGNER__STACKS_ACCOUNT__PRIVATE_KEY", new);
        eprintln!(
            "new: {}",
            std::env::var("SIGNER_SIGNER__STACKS_ACCOUNT__PRIVATE_KEY").unwrap()
        );

        let settings = Settings::new().unwrap();

        assert_eq!(
            settings.signer.stacks_account.private_key,
            PrivateKey::from_str(new).unwrap()
        );
    }

    #[test]
    fn default_config_toml_loads_with_environment() {
        // The default toml used here specifies http://localhost:20443
        // as the stacks node endpoint.
        let settings = StacksSettings::new_from_config().unwrap();
        let host = settings.node.endpoints[0].host();
        assert_eq!(host, Some(url::Host::Domain("localhost")));
        assert_eq!(settings.node.endpoints[0].port(), Some(20443));

        std::env::set_var(
            "SIGNER_STACKS_NODE_ENDPOINTS",
            "http://whatever:1234,http://whateva:4321",
        );

        let settings = StacksSettings::new_from_config().unwrap();
        let host = settings.node.endpoints[0].host();
        assert_eq!(host, Some(url::Host::Domain("whatever")));
        assert_eq!(settings.node.endpoints[0].port(), Some(1234));
        let host = settings.node.endpoints[1].host();
        assert_eq!(host, Some(url::Host::Domain("whateva")));
        assert_eq!(settings.node.endpoints[1].port(), Some(4321));

        std::env::set_var("SIGNER_STACKS_NODE_ENDPOINTS", "http://127.0.0.1:5678");

        let settings = StacksSettings::new_from_config().unwrap();
        let ip: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert_eq!(settings.node.endpoints[0].host(), Some(url::Host::Ipv4(ip)));
        assert_eq!(settings.node.endpoints[0].port(), Some(5678));

        std::env::set_var("SIGNER_STACKS_NODE_ENDPOINTS", "http://[::1]:9101");

        let settings = StacksSettings::new_from_config().unwrap();
        let ip: std::net::Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(settings.node.endpoints[0].host(), Some(url::Host::Ipv6(ip)));
        assert_eq!(settings.node.endpoints[0].port(), Some(9101));
    }
}
