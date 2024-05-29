//! Configuration management for the signer

use config::{Config, ConfigError, Environment, File};
use once_cell::sync::Lazy;
use serde::Deserialize;

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
        let mut cfg = Config::new();
        cfg.merge(File::with_name("./src/config/default"))?;
        let env = Environment::with_prefix("SIGNER").separator("__");
        cfg.merge(env)?;
        let settings: Settings = cfg.try_into()?;

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
