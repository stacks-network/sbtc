use config::{Config, ConfigError, Environment, File};
use once_cell::sync::Lazy;
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    pub blocklist_client: BlocklistClientConfig,
}
#[derive(Deserialize, Clone, Debug)]
pub struct BlocklistClientConfig {
    pub host: String,
    pub port: u16,
}

pub static SETTINGS: Lazy<Settings> =
    Lazy::new(|| Settings::new().expect("Failed to load configuration"));

impl Settings {
    // Initializing the global config first with default values and then with provided/overwritten environment variables.
    // The explicit separator with double underscores is needed to correctly parse the nested config structure.
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
        Ok(())
    }
}
