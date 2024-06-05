//! Configuration management for the signer

use config::{Config, ConfigError, Environment, File};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Deserializer;

use crate::error::Error;

/// Top-level configuration for the signer
#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    /// Blocklist client specific config
    pub blocklist_client: BlocklistClientConfig,
    /// Electrum notifier specific config
    pub block_notifier: BlockNotifierConfig,
}

/// Blocklist client specific config
#[derive(Deserialize, Clone, Debug)]
pub struct BlocklistClientConfig {
    /// Host of the blocklist client
    pub host: String,
    /// Port of the blocklist client
    pub port: u16,
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

/// Statically configured settings for the signer
pub static SETTINGS: Lazy<Settings> =
    Lazy::new(|| Settings::new().expect("Failed to load configuration"));

impl Settings {
    /// Initializing the global config first with default values and then with provided/overwritten environment variables.
    /// The explicit separator with double underscores is needed to correctly parse the nested config structure.
    pub fn new() -> Result<Self, ConfigError> {
        let env = Environment::with_prefix("SIGNER")
            .separator("__")
            .prefix_separator("_");
        let cfg = Config::builder()
            .add_source(File::with_name("./src/config/default"))
            .add_source(env)
            .build()?;

        let settings: Settings = cfg.try_deserialize()?;

        settings.validate()?;

        Ok(settings)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.blocklist_client.host.is_empty() {
            return Err(ConfigError::Message("Host cannot be empty".to_string()));
        }
        if !(1..=65535).contains(&self.blocklist_client.port) {
            return Err(ConfigError::Message(
                "Port must be between 1 and 65535".to_string(),
            ));
        }
        if self.block_notifier.server.is_empty() {
            return Err(ConfigError::Message(
                "Electrum server cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// A deserializer for the url::Url type.
fn url_deserializer<'de, D>(deserializer: D) -> Result<url::Url, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
}

/// A struct for the entries in the signers Config.toml (which is currently
/// located in src/config/default.toml)
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StacksSettings {
    /// The configuration entries related to the Stacks API
    pub api: StacksApiSettings,
    /// The configuration entries related to the Stacks node
    pub node: StacksNodeSettings,
}

/// Whatever
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StacksApiSettings {
    /// TODO(225): We'll want to support specifying multiple Stacks API
    /// endpoints.
    ///
    /// The endpoint to use when making requests to the stacks API.
    #[serde(deserialize_with = "url_deserializer")]
    pub endpoint: url::Url,
}

/// Settings associated with the stacks node that this signer uses for information
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StacksNodeSettings {
    /// TODO(225): We'll want to support specifying multiple Stacks Nodes
    /// endpoints.
    ///
    /// The endpoint to use when making requests to a stacks node.
    #[serde(deserialize_with = "url_deserializer")]
    pub endpoint: url::Url,
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
    /// * SIGNER_STACKS_NODE_ENDPOINT <-> stacks.node.endpoint
    ///
    /// Each of these overrides an entry in the signer's `config.toml`
    pub fn new_from_config() -> Result<Self, Error> {
        let source = File::with_name("./src/config/default");
        let env = Environment::with_prefix("SIGNER")
            .prefix_separator("_")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_toml_loads_with_environment() {
        // The default toml used here specifies http://localhost:3999
        // as the stacks API endpoint.
        let settings = StacksSettings::new_from_config().unwrap();
        let host = settings.api.endpoint.host();
        assert_eq!(host, Some(url::Host::Domain("localhost")));
        assert_eq!(settings.api.endpoint.port(), Some(3999));

        std::env::set_var("SIGNER_STACKS_API_ENDPOINT", "http://whatever:1234");

        let settings = StacksSettings::new_from_config().unwrap();
        let host = settings.api.endpoint.host();
        assert_eq!(host, Some(url::Host::Domain("whatever")));
        assert_eq!(settings.api.endpoint.port(), Some(1234));

        std::env::set_var("SIGNER_STACKS_API_ENDPOINT", "http://127.0.0.1:5678");

        let settings = StacksSettings::new_from_config().unwrap();
        let ip: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert_eq!(settings.api.endpoint.host(), Some(url::Host::Ipv4(ip)));
        assert_eq!(settings.api.endpoint.port(), Some(5678));

        std::env::set_var("SIGNER_STACKS_API_ENDPOINT", "http://[::1]:9101");

        let settings = StacksSettings::new_from_config().unwrap();
        let ip: std::net::Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(settings.api.endpoint.host(), Some(url::Host::Ipv6(ip)));
        assert_eq!(settings.api.endpoint.port(), Some(9101));
    }
}
