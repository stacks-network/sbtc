use std::env;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client;
use emily_lambda::{config::LambdaContext, eventhandler};
use emily_lambda::config::{Settings, CHAINSTATE_TABLE_NAME, DEPOSIT_TABLE_NAME, WITHDRAWAL_TABLE_NAME};
use aws_lambda_events::apigw::ApiGatewayProxyRequest;
use lambda_runtime::{service_fn, LambdaEvent};

/// Main entry point for the AWS Lambda function.
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {

    // TODO: [ticket link here once PR is approved]
    // clean up setup with constructor function.
    let settings = Settings {
        is_local: env::var("IS_LOCAL")?.to_lowercase() == "true",
        // TODO: [ticket link here once PR is approved]
        // Take the names from the environment variables. (Determine why the table names are no longer being
        // populated as expected in the local environment).
        deposit_table_name: DEPOSIT_TABLE_NAME.to_string(), // env::var("DEPOSIT_TABLE_NAME")?,
        withdrawal_table_name: WITHDRAWAL_TABLE_NAME.to_string(), // env::var("WITHDRAWAL_TABLE_NAME")?,
        chainstate_table_name: CHAINSTATE_TABLE_NAME.to_string(), // env::var("CHAINSTATE_TABLE_NAME")?,
    };

    // AWS SDK configuration
    //
    // TODO: [ticket link here once PR is approved]
    // Gatekeep endpoint url using individual environment parameters as opposed to
    // specific hardcoded behavior when run locally.
    let mut config: aws_config::SdkConfig = aws_config::load_defaults(BehaviorVersion::latest()).await;
    if settings.is_local {
        config = config.into_builder()
            .endpoint_url("http://dynamodb:8000")
            .build();
    }

    // TODO: [ticket link here once PR is approved]
    // Create the context in a constructor function.
    let context = LambdaContext {
        settings,
        dynamodb_client: Client::new(&config),
    };

    // Run the lambda service.
    lambda_runtime::run(
        service_fn(
            |event: LambdaEvent<ApiGatewayProxyRequest>| eventhandler::handle_event(event, &context)
        )
    ).await
}
