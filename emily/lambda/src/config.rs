use aws_sdk_dynamodb::Client;

/// Temporary chainstate Table name.
pub static CHAINSTATE_TABLE_NAME: &str = "ChainstateTable-xxxxxxxxxxxx-us-west-2-local";

/// Temporary withdrawal Table name.
pub static WITHDRAWAL_TABLE_NAME: &str = "WithdrawalTable-xxxxxxxxxxxx-us-west-2-local";

/// Temporary deposit Table name.
pub static DEPOSIT_TABLE_NAME: &str = "DepositTable-xxxxxxxxxxxx-us-west-2-local";

/// Emily lambda settings.
#[derive(Debug)]
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
pub struct LambdaContext {
    /// Lambda settings.
    pub settings: Settings,
    /// DynamoDB Client.
    pub dynamodb_client: Client,
}

// TODO:
// Create a `new` function similar to the settings in the blocklist client
// and the Signer that grabs the configuration values from a local default
// toml and potentially overwrites the fields with environment values.
