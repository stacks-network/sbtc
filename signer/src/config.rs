//! Configuration management for the signer
use std::str::FromStr as _;

use clarity::vm::types::PrincipalData;
use config::{Config, ConfigError, Environment, File};
use libp2p::Multiaddr;
use serde::Deserialize;
use serde::Deserializer;
use stacks_common::types::chainstate::StacksAddress;
use std::path::Path;
use url::Url;

use crate::error::Error;
use crate::keys::PrivateKey;

/// The default signer network listen-on address.
pub const DEFAULT_P2P_HOST: &str = "0.0.0.0";
/// The default signer network listen-on port.
pub const DEFAULT_P2P_PORT: u16 = 4122;

/// Configuration error variants.
#[derive(Debug, thiserror::Error)]
pub enum SignerConfigError {
    /// Invalid Stacks private key length
    #[error("The Stacks private key provided is invalid, it must be either 64 or 66 hex characters long, got {0}")]
    InvalidStacksPrivateKeyLength(usize),

    /// Invalid Stacks private key compression byte marker
    #[error("The Stacks private key provided contains an invalid compression byte marker: {0}")]
    InvalidStacksPrivateKeyCompressionByte(String),

    /// Invalid P2P URI
    #[error("Invalid P2P URI: Failed to parse: {0}")]
    InvalidP2PUri(#[from] url::ParseError),

    /// The NetworkKind set in the config must match the network kind of
    /// the deployer address.
    #[error("The network set in the config must match the network kind of the deployer address")]
    NetworkDeployerMismatch,

    /// Invalid P2P URI
    #[error("Invalid P2P URI: Only schemes 'tcp' and 'quic-v1' are supported; got '{0}'")]
    InvalidP2PScheme(String),

    /// P2P port is required
    #[error("Invalid P2P URI: Port is required")]
    P2PPortRequired,

    /// P2P paths not supported
    #[error("Invalid P2P URI: Paths are not supported: '{0}'")]
    P2PPathsNotSupported(String),

    /// Usernames are not supported in P2P URIs
    #[error("Invalid P2P URI: Usernames are not supported: '{0}'")]
    P2PUsernameNotSupported(String),

    /// Passwords are not supported in P2P URIs
    #[error("Invalid P2P URI: Passwords are not supported: '{0}'")]
    P2PPasswordNotSupported(String),

    /// Query strings are not supported in P2P URIs
    #[error("Invalid P2P URI: Query strings are not supported: '{0}'")]
    P2PQueryStringsNotSupported(String),

    /// When the network kind is 'mainnet' or 'testnet', at least one P2P seed peer is required.
    /// Otherwise, we'll allow mDNS to discover any local peers (for testing).
    #[error(
        "At least one P2P seed peer is required when the network kind is 'mainnet' or 'testnet'."
    )]
    P2PSeedPeerRequired,
}

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
    pub blocklist_client: BlocklistClientConfig,
    /// Electrum notifier specific config
    pub block_notifier: BlockNotifierConfig,
    /// Signer-specific configuration
    pub signer: SignerConfig,
    /// Bitcoin core configuration
    pub bitcoin: BitcoinConfig,
}

/// Configuration used for the [`BitcoinCoreClient`](sbtc::rpc::BitcoinCoreClient).
#[derive(Deserialize, Clone, Debug)]
pub struct BitcoinConfig {
    /// Bitcoin RPC endpoints.
    #[serde(deserialize_with = "url_deserializer_vec")]
    pub endpoints: Vec<url::Url>,
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
    /// Host of the blocklist client
    pub host: String,
    /// Port of the blocklist client
    pub port: u16,
}

impl Validatable for BlocklistClientConfig {
    fn validate(&self, _: &Settings) -> Result<(), ConfigError> {
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
    fn validate(&self, _: &Settings) -> Result<(), ConfigError> {
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
}

impl Validatable for SignerConfig {
    fn validate(&self, cfg: &Settings) -> Result<(), ConfigError> {
        self.p2p.validate(cfg)?;
        if self.deployer.is_mainnet() != self.network.is_mainnet() {
            let err = SignerConfigError::NetworkDeployerMismatch;
            return Err(ConfigError::Message(err.to_string()));
        }
        Ok(())
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
            .with_list_parse_key("signer.p2p.seeds")
            .with_list_parse_key("signer.p2p.listen_on")
            .with_list_parse_key("signer.p2p.public_endpoints")
            .with_list_parse_key("bitcoin.endpoints")
            .prefix_separator("_");

        let mut cfg_builder = Config::builder();
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
        self.blocklist_client.validate(self)?;
        self.block_notifier.validate(self)?;
        self.signer.validate(self)?;

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
    #[serde(deserialize_with = "url_deserializer_vec")]
    pub endpoints: Vec<url::Url>,
    /// This is the start height of the first EPOCH 3.0 block on the Stacks
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
fn url_deserializer_vec<'de, D>(deserializer: D) -> Result<Vec<url::Url>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut v = Vec::new();
    for s in Vec::<String>::deserialize(deserializer)? {
        v.push(s.parse().map_err(serde::de::Error::custom)?);
    }
    Ok(v)
}

fn p2p_multiaddr_deserializer_vec<'de, D>(deserializer: D) -> Result<Vec<Multiaddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut addrs = Vec::new();

    let items = Vec::<String>::deserialize(deserializer)?;

    for s in items.iter().filter(|s| !s.is_empty()) {
        let addr = try_parse_p2p_multiaddr(s).map_err(serde::de::Error::custom)?;
        addrs.push(addr);
    }

    Ok(addrs)
}

/// A deserializer for the [`PrivateKey`] type. Returns an error if the private
/// key is not valid hex or is not the correct length.
fn private_key_deserializer<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let len = s.len();

    if ![64, 66].contains(&len) {
        Err(serde::de::Error::custom(
            SignerConfigError::InvalidStacksPrivateKeyLength(len),
        ))
    } else if len == 66 && &s[64..] != "01" {
        Err(serde::de::Error::custom(
            SignerConfigError::InvalidStacksPrivateKeyCompressionByte(s[64..].to_string()),
        ))
    } else {
        PrivateKey::from_str(&s[..64]).map_err(serde::de::Error::custom)
    }
}

fn try_parse_p2p_multiaddr(s: &str) -> Result<Multiaddr, SignerConfigError> {
    // Keeping these local here as this is the only place these should need to be used.
    use libp2p::multiaddr::Protocol;
    use SignerConfigError::{
        InvalidP2PScheme, InvalidP2PUri, P2PPasswordNotSupported, P2PPathsNotSupported,
        P2PPortRequired, P2PQueryStringsNotSupported, P2PUsernameNotSupported,
    };

    // We parse to a Url first to take advantage of its initial validation
    // and so that we can more easily work with the URI components below.
    // Note that this will catch missing host errors.
    let url: Url = s.parse().map_err(InvalidP2PUri)?;

    if !["/", ""].contains(&url.path()) {
        return Err(P2PPathsNotSupported(url.path().into()));
    }

    let port = url.port().ok_or(P2PPortRequired)?;

    // We only support tcp and quic-v1 schemes as these are the only relevant
    // protocols (quic is a UDP-based protocol).
    if !["tcp", "quic-v1"].contains(&url.scheme()) {
        return Err(InvalidP2PScheme(url.scheme().into()));
    }

    // We don't currently support usernames. The signer pub key is used as the
    // peer identifier.
    if !url.username().is_empty() {
        return Err(P2PUsernameNotSupported(url.username().into()));
    }

    // We don't currently support passwords.
    if let Some(pass) = url.password() {
        return Err(P2PPasswordNotSupported(pass.into()));
    }

    // We don't currently support query strings. This could be extended in the
    // future if we need to add additional P2P configuration options.
    if let Some(query) = url.query() {
        return Err(P2PQueryStringsNotSupported(query.into()));
    }

    // Initialize the Multiaddr using the host. We support IPv4, IPv6, and
    // DNS host types.
    let mut addr = match url.host() {
        Some(url::Host::Ipv4(ip)) => Multiaddr::empty().with(Protocol::from(ip)),
        Some(url::Host::Ipv6(ip)) => Multiaddr::empty().with(Protocol::from(ip)),
        Some(url::Host::Domain(host)) => Multiaddr::empty().with(Protocol::Dns(host.into())),
        None => unreachable!("this will have been caught by the Url parsing above"),
    };

    // Update the Multiaddr with the correct protocol.
    match url.scheme() {
        "tcp" => addr = addr.with(Protocol::Tcp(port)),
        "quic-v1" => addr = addr.with(Protocol::Udp(port)).with(Protocol::QuicV1),
        s => return Err(InvalidP2PScheme(s.to_string())),
    };

    Ok(addr)
}

/// Parse the string into a StacksAddress.
///
/// The [`StacksAddress`] struct does not implement any string parsing or
/// c32 decoding. However, the [`PrincipalData::parse_standard_principal`]
/// function does the expected c32 decoding and the validation, so we go
/// through that.
pub fn parse_stacks_address<'de, D>(des: D) -> Result<StacksAddress, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let literal = <String>::deserialize(des)?;

    PrincipalData::parse_standard_principal(&literal)
        .map(StacksAddress::from)
        .map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::testing::clear_env;

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

        let settings = Settings::new_from_default_config().unwrap();
        assert_eq!(settings.blocklist_client.host, "127.0.0.1");
        assert_eq!(settings.blocklist_client.port, 8080);

        assert_eq!(settings.block_notifier.server, "tcp://localhost:60401");
        assert_eq!(settings.block_notifier.retry_interval, 10);
        assert_eq!(settings.block_notifier.max_retry_attempts, 5);
        assert_eq!(settings.block_notifier.ping_interval, 60);
        assert_eq!(settings.block_notifier.subscribe_interval, 10);

        assert_eq!(
            settings.signer.private_key,
            PrivateKey::from_str(
                "8183dc385a7a1fc8353b9e781ee0859a71e57abea478a5bca679334094f7adb5"
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
            settings.bitcoin.endpoints,
            vec![url("http://user:pass@localhost:18443")]
        );
        assert_eq!(settings.bitcoin.endpoints[0].username(), "user");
        assert_eq!(settings.bitcoin.endpoints[0].password(), Some("pass"));
        assert_eq!(
            settings.signer.event_observer.bind,
            "0.0.0.0:8801".parse::<SocketAddr>().unwrap()
        );
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
            "SIGNER_BITCOIN__ENDPOINTS",
            "http://user:pass@localhost:1234,http://foo:bar@localhost:5678",
        );

        let settings = Settings::new_from_default_config().unwrap();

        assert_eq!(settings.bitcoin.endpoints.len(), 2);
        assert!(settings
            .bitcoin
            .endpoints
            .contains(&url("http://user:pass@localhost:1234")));
        assert!(settings
            .bitcoin
            .endpoints
            .contains(&url("http://foo:bar@localhost:5678")));
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
    fn default_config_toml_loads_with_environment() {
        clear_env();

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
        assert!(settings.is_err());
        assert!(matches!(
            settings.unwrap_err(),
            ConfigError::Message(msg) if msg == Error::DecodeHexBytes(hex_err).to_string()
        ));
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
}
