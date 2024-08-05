//! Context.
//! TODO(389): Improve the configuration setup.
//!
//! Create a `new` function similar to the settings in the blocklist client
//! and the Signer that grabs the configuration values from a local default
//! toml and potentially overwrites the fields with environment values.

use std::env;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client;
use serde::Serialize;

use crate::common::error::Error;

/// Emily lambda settings.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize)]
pub struct Settings {
    /// Whether the Emily lambda is running locally.
    pub is_local: bool,
    /// Deposit table name.
    pub deposit_table_name: String,
    /// Withdrawal table name.
    pub withdrawal_table_name: String,
    /// Chainstate table name.
    pub chainstate_table_name: String,
}

/// Lambda Context
#[derive(Clone, Debug, Serialize)]
pub struct EmilyContext {
    /// Lambda settings.
    pub settings: Settings,
    /// DynamoDB Client.
    #[serde(skip_serializing)]
    pub dynamodb_client: Client,
}

// Implementations -------------------------------------------------------------

/// Implement default settings.
impl Settings {
    /// Create settings from environment variables.
    pub fn from_env() -> Result<Self, Error> {
        Ok(Settings {
            is_local: env::var("IS_LOCAL")?.to_lowercase() == "true",
            deposit_table_name: env::var("DEPOSIT_TABLE_NAME")?,
            withdrawal_table_name: env::var("WITHDRAWAL_TABLE_NAME")?,
            chainstate_table_name: env::var("CHAINSTATE_TABLE_NAME")?,
        })
    }
}

/// Implementation of Context.
impl EmilyContext {
    /// Create struct instance from env.
    /// TODO(389): Make the implementation of this context more standard.
    pub async fn from_env() -> Result<Self, Error> {
        let settings: Settings = Settings::from_env()?;
        let mut config: aws_config::SdkConfig =
            aws_config::load_defaults(BehaviorVersion::latest()).await;
        // TODO(389): Instead of using `is_local` configuration parameter set the specific
        // field in the config.
        if settings.is_local {
            config = config
                .into_builder()
                .endpoint_url("http://dynamodb:8000")
                .build();
        }
        // Return.
        Ok(EmilyContext {
            settings,
            dynamodb_client: Client::new(&config),
        })
    }
}
