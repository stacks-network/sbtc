use config::{Config, ConfigError, Environment, File};
use once_cell::sync::Lazy;
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    pub server: ServerConfig,
    pub risk_analysis: RiskAnalysisConfig,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RiskAnalysisConfig {
    pub api_url: String,
    pub api_key: String,
}

pub static SETTINGS: Lazy<Settings> =
    Lazy::new(|| Settings::new().expect("Failed to load configuration"));

impl Settings {
    // Initializing the global config first with default values and then with provided/overwritten environment variables.
    // The explicit separator with double underscores is needed to correctly parse the nested config structure.
    pub fn new() -> Result<Self, ConfigError> {
        let mut cfg = Config::new();
        cfg.merge(File::with_name("./src/config/default"))?;
        let env = Environment::with_prefix("BLOCKLIST_CLIENT").separator("__");
        cfg.merge(env)?;
        let settings: Settings = cfg.try_into()?;
        Ok(settings)
    }
}
