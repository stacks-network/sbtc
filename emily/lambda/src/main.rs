use emily_operation_lambda::eventhandler::handle_event;
use aws_lambda_events::apigw::ApiGatewayProxyRequest;
use lambda_runtime::{service_fn, LambdaEvent};

/// Main entry point for the AWS Lambda function.
#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    // Run the lambda service.
    lambda_runtime::run(
        service_fn(
            |event: LambdaEvent<ApiGatewayProxyRequest>| handle_event(event)
        )
    ).await
}
