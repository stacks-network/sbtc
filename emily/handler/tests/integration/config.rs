//! Configuration management for the Emily client tests.

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Top-level configuration.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    /// Server config.
    pub server: ServerConfig,
}

/// Server config.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerConfig {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Api key.
    pub api_key: String,
}

/// Statically configured settings.
pub static SETTINGS: LazyLock<Settings> =
    LazyLock::new(|| Settings::new().expect("Failed to load configuration"));

impl Settings {
    /// Initializing the global config first with default values and then with provided/overwritten environment variables.
    /// The explicit separator with double underscores is needed to correctly parse the nested config structure.
    pub fn new() -> Result<Self, ConfigError> {
        let mut cfg = Config::new();
        cfg.merge(File::with_name("./tests/integration/config/default"))?;
        let env = Environment::with_prefix("EMILY_TEST_CLIENT").separator("__");
        cfg.merge(env)?;
        let settings: Settings = cfg.try_into()?;

        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.host.is_empty() {
            return Err(ConfigError::Message("Host cannot be empty".to_string()));
        }
        if self.server.api_key.is_empty() {
            return Err(ConfigError::Message("Api key cannot be empty".to_string()));
        }
        if !(1..=65535).contains(&self.server.port) {
            return Err(ConfigError::Message(
                "Port must be between 1 and 65535".to_string(),
            ));
        }
        Ok(())
    }
}
