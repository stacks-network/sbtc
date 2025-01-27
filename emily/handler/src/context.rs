//! Context.
//! TODO(389): Improve the configuration setup.
//!
//! Create a `new` function similar to the settings in the blocklist client
//! and the Signer that grabs the configuration values from a local default
//! toml and potentially overwrites the fields with environment values.

use std::env;
use std::fmt;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client;
use serde::Deserialize;
use serde::Serialize;

use crate::api::models::limits::AccountLimits;
use crate::common::error::Error;

/// Emily lambda settings.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Whether the Emily lambda is running locally.
    pub is_local: bool,
    /// Deposit table name.
    pub deposit_table_name: String,
    /// Withdrawal table name.
    pub withdrawal_table_name: String,
    /// Chainstate table name.
    pub chainstate_table_name: String,
    /// Limit table name.
    pub limit_table_name: String,
    /// The default global limits for the system.
    pub default_limits: AccountLimits,
    /// The API key for the Bitcoin Layer 2 API.
    pub trusted_reorg_api_key: String,
    /// Whether the lambda is expecting transactions on mainnet.
    pub is_mainnet: bool,
}

/// Emily Context
#[derive(Clone, Serialize)]
pub struct EmilyContext {
    /// Lambda settings.
    pub settings: Settings,
    /// DynamoDB Client.
    #[serde(skip_serializing)]
    pub dynamodb_client: Client,
}

/// Implement debug print for the context struct.
impl fmt::Debug for EmilyContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string_pretty(self)
                .expect("Failed to serialize Emily Context in debug print.")
        )
    }
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
            limit_table_name: env::var("LIMIT_TABLE_NAME")?,
            default_limits: AccountLimits {
                peg_cap: env::var("DEFAULT_PEG_CAP")
                    .ok()
                    .map(|v| v.parse())
                    .transpose()?,
                per_deposit_minimum: env::var("DEFAULT_PER_DEPOSIT_MINIMUM")
                    .ok()
                    .map(|v| v.parse())
                    .transpose()?,
                per_deposit_cap: env::var("DEFAULT_PER_DEPOSIT_CAP")
                    .ok()
                    .map(|v| v.parse())
                    .transpose()?,
                per_withdrawal_cap: env::var("DEFAULT_PER_WITHDRAWAL_CAP")
                    .ok()
                    .map(|v| v.parse())
                    .transpose()?,
            },
            trusted_reorg_api_key: env::var("TRUSTED_REORG_API_KEY")?,
            is_mainnet: env::var("IS_MAINNET")?.to_lowercase() == "true",
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
    /// Create a local testing instance.
    #[cfg(feature = "testing")]
    pub async fn local_instance(dynamodb_endpoint: &str) -> Result<Self, Error> {
        use std::collections::HashMap;

        // Get config that always points to the dynamodb table directly
        // from outside of a docker compose setup.
        let sdk_config = aws_config::load_defaults(BehaviorVersion::latest())
            .await
            .into_builder()
            .endpoint_url(dynamodb_endpoint)
            .build();
        let dynamodb_client = Client::new(&sdk_config);

        // Get the names of the existing tables so we can populate from them.
        let table_names = dynamodb_client
            .list_tables()
            // Get at most 20 table names - there should be 3...
            .limit(20)
            .send()
            .await
            .expect("Failed setting up settings from table names")
            .table_names
            .unwrap_or_default();

        // Attempt to get all the tables by searching the output of the
        // list tables operation.
        let mut table_name_map: HashMap<&str, String> = HashMap::new();
        let tables_to_find: Vec<&str> = vec!["Deposit", "Chainstate", "Withdrawal", "Limit"];
        for name in table_names {
            for table_to_find in &tables_to_find {
                if name.contains(table_to_find) {
                    table_name_map.insert(table_to_find, name.clone());
                }
            }
        }

        // Make the context using the assumed table names.
        Ok(EmilyContext {
            settings: Settings {
                is_local: true,
                deposit_table_name: table_name_map
                    .get("Deposit")
                    .expect("Couldn't find valid deposit table in existing table list.")
                    .to_string(),
                withdrawal_table_name: table_name_map
                    .get("Withdrawal")
                    .expect("Couldn't find valid withdrawal table in existing table list.")
                    .to_string(),
                chainstate_table_name: table_name_map
                    .get("Chainstate")
                    .expect("Couldn't find valid chainstate table in existing table list.")
                    .to_string(),
                limit_table_name: table_name_map
                    .get("Limit")
                    .expect("Couldn't find valid limit table table in existing table list.")
                    .to_string(),
                default_limits: AccountLimits::default(),
                trusted_reorg_api_key: "testApiKey".to_string(),
                is_mainnet: false,
            },
            dynamodb_client,
        })
    }
}
