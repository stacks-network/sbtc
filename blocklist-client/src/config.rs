//! Configuration management for the Blocklist client

use config::{Config, ConfigError, Environment, File, FileFormat};
use serde::Deserialize;
use std::sync::LazyLock;

/// Top-level configuration for the Blocklist client
#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    /// Blocklist client's server related config
    pub server: ServerConfig,
    /// Blocklist client's risk service config
    pub risk_analysis: RiskAnalysisConfig,
    /// Blocklist client's assessment method config
    pub assessment: AssesmentConfig,
}

/// Blocklist client's assessment method config
#[derive(Deserialize, Clone, Debug)]
pub struct AssesmentConfig {
    /// Assessment method for the Blocklist client
    pub assessment_method: AssessmentMethod,
}

/// Blocklist client's server related config
#[derive(Deserialize, Clone, Debug)]
pub struct ServerConfig {
    /// Host of the Blocklist client
    pub host: String,
    /// Port of the Blocklist client
    pub port: u16,
}

/// Assessment method for the Blocklist client
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentMethod {
    /// Use sanctions list API
    Sanctions,
    /// Use risk analysis API
    RiskAnalysis,
}

/// Blocklist client's risk API config
#[derive(Deserialize, Clone, Debug)]
pub struct RiskAnalysisConfig {
    /// API URL of the Risk service
    pub api_url: String,
    /// API key for the Risk service
    pub api_key: String,
}

/// Statically configured settings for the Blocklist client
pub static SETTINGS: LazyLock<Settings> =
    LazyLock::new(|| Settings::new().expect("Failed to load configuration"));

impl Settings {
    /// Initializing the global config first with default values and then with provided/overwritten environment variables.
    /// The explicit separator with double underscores is needed to correctly parse the nested config structure.
    pub fn new() -> Result<Self, ConfigError> {
        let mut cfg = Config::new();
        cfg.merge(File::from_str(
            include_str!("config/default.toml"),
            FileFormat::Toml,
        ))?;
        let env = Environment::with_prefix("BLOCKLIST_CLIENT").separator("__");
        cfg.merge(env)?;
        let settings: Settings = cfg.try_into()?;

        settings.validate()?;

        Ok(settings)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.host.is_empty() {
            return Err(ConfigError::Message("Host cannot be empty".to_string()));
        }
        if !(1..=65535).contains(&self.server.port) {
            return Err(ConfigError::Message(
                "Port must be between 1 and 65535".to_string(),
            ));
        }
        Ok(())
    }
}
