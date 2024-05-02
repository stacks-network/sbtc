use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use aws_lambda_events::encodings::Body;
use emily::models::{CreateDepositRequestContent, DepositParameters};
use http::{header, HeaderValue};
use lambda_runtime::{service_fn, LambdaEvent};
use http::{HeaderMap, Method};

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

/// Asynchronously handles incoming API Gateway events and dispatches them
/// to the correct method based on the route and method.
///
/// # Arguments
/// * `event` - A LambdaEvent containing the ApiGatewayProxyRequest.
///
/// # Returns
/// A result containing the API Gateway Proxy Response or an lambda_runtime::Error.
async fn handle_event(
    event: LambdaEvent<ApiGatewayProxyRequest>
) -> Result<ApiGatewayProxyResponse, lambda_runtime::Error> {

    // Extract base data.
    let resource = event.payload.resource.unwrap_or_default();
    let http_method = event.payload.http_method;
    let body = event.payload.body.clone();

    // Dispatch based on API call.
    match (resource.as_str(), http_method) {
        ("/deposits", Method::POST) => {

            // Deserialize the create deposit request.
            let request: CreateDepositRequestContent = body
                .map(|serailzed_request| {
                    serde_json::from_str::<CreateDepositRequestContent>(serailzed_request.as_str())
                    .unwrap() // TODO: Handle lambda_runtime::Errors. https://github.com/stacks-network/sbtc/issues/111
                })
                .unwrap(); // TODO: Handle lambda_runtime::Errors. https://github.com/stacks-network/sbtc/issues/111

            // Generate dummy response with all the necesary fields, taking
            // the identifiers from the request.
            let response = emily::models::CreateDepositResponseContent {
                bitcoin_txid: request.bitcoin_txid.to_string(),
                bitcoin_tx_output_index: request.bitcoin_tx_output_index,
                recipient: "MOCK_RECIPIENT".to_string(),
                amount: 11111.0,
                status: emily::models::OpStatus::Pending,
                status_message: "MOCK_CREATE_DEPOSIT_RESPONSE".to_string(),
                parameters: Box::new(DepositParameters {
                    lock_time: Some(22222.0),
                    max_fee: Some(33333.0),
                    reclaim_script: Some("MOCK_RECLAIM_SCRIPT".to_string())
                }),
                last_update_block_hash: None, // Unknown on creation.
                last_update_height: None, // Unknown on creation.
                fulfillment: None, // Unknown on creation.
            };

            // Serialize response.
            let serialized_response: String = serde_json::to_string(&response)
                .map_err(lambda_runtime::Error::from)
                .unwrap();

            // Setup CORS headers.
            // TODO: Refactor ApiGatewayProxyResponse packaging into a helper function.
            // https://github.com/stacks-network/sbtc/issues/111
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type"));
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
            headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("OPTIONS,POST,GET"));
            Ok(ApiGatewayProxyResponse {
                status_code: 201,
                multi_value_headers: headers.clone(),
                is_base64_encoded: false,
                body: Some(Body::Text(serialized_response)),
                headers,
            })
        }
        _ => {
            // Generate Not implemented for all unmatched requests.
            let response: emily::models::NotImplementedErrorResponseContent = emily::models::NotImplementedErrorResponseContent {
                message: "API call not implemented.".to_string()
            };

            // Serialize response.
            let serialized_response: String = serde_json::to_string(&response)
                .map_err(lambda_runtime::Error::from)
                .unwrap();

            // Setup CORS headers.
            // TODO: Refactor ApiGatewayProxyResponse packaging into a helper function.
            // https://github.com/stacks-network/sbtc/issues/111
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type"));
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
            headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("OPTIONS,POST,GET"));
            Ok(ApiGatewayProxyResponse {
                status_code: 501,
                multi_value_headers: headers.clone(),
                is_base64_encoded: false,
                body: Some(Body::Text(serialized_response)),
                headers,
            })
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    fn create_event(method: Method, resource: &str, body: Option<String>) -> LambdaEvent<ApiGatewayProxyRequest> {
        LambdaEvent {
            payload: ApiGatewayProxyRequest {
                http_method: method,
                resource: Some(resource.to_string()),
                body,
                ..Default::default()
            },
            context: Default::default()
        }
    }

    #[tokio::test]
    async fn test_post_deposits_successful() {
        // Arrange.
        let json_body = serde_json::to_string(&CreateDepositRequestContent {
            bitcoin_txid: "BITCOIN_TXID_UNITTEST".to_string(),
            bitcoin_tx_output_index: 0.0,
            reclaim: "RECLAIM_UNITTEST".to_string(),
            deposit: "DEPOSIT_UNITTEST".to_string(),
        }).unwrap();
        let event = create_event(Method::POST, "/deposits", Some(json_body));

        // Act.
        let response = handle_event(event).await.expect("Failed to handle event");

        // Assert.
        assert_eq!(response.status_code, 201);
        assert_eq!(response.body.unwrap(), Body::Text("{\"bitcoinTxid\":\"BITCOIN_TXID_UNITTEST\",\"bitcoinTxOutputIndex\":0.0,\"recipient\":\"MOCK_RECIPIENT\",\"amount\":11111.0,\"status\":\"PENDING\",\"statusMessage\":\"MOCK_CREATE_DEPOSIT_RESPONSE\",\"parameters\":{\"maxFee\":33333.0,\"lockTime\":22222.0,\"reclaimScript\":\"MOCK_RECLAIM_SCRIPT\"}}".to_string()));
    }

    #[test_case(Method::GET, "/deposits/{txid}/{outputIndex}", None; "get-deposit")]
    #[test_case(Method::GET, "/deposits/{txid}", None; "get-txn-deposits")]
    #[test_case(Method::GET, "/deposits", None; "get-deposits")]
    #[test_case(Method::PUT, "/deposits", None; "update-deposits")]
    #[test_case(Method::POST, "/withdrawals", None; "create-withdrawal")]
    #[test_case(Method::GET, "/withdrawals/{id}", None; "get-withdrawal")]
    #[test_case(Method::GET, "/withdrawals", None; "get-withdrawals")]
    #[test_case(Method::PUT, "/withdrawals", None; "update-withdrawals")]
    #[test_case(Method::GET, "/chainstate/{height}", None; "get-chainstate")]
    #[test_case(Method::PUT, "/chainstate/{height}", None; "set-chainstate")]
    #[test_case(Method::POST, "/chainstate/{height}", None; "update-chainstate")]
    #[tokio::test]
    async fn test_method_not_implemented(method: Method, resource: &str, body: Option<String>) {
        // Arrange.
        let event: LambdaEvent<ApiGatewayProxyRequest> = create_event(method, resource, body);

        // Act.
        let response: ApiGatewayProxyResponse = handle_event(event).await.expect("Failed to handle event");

        // Assert.
        assert_eq!(response.status_code, 501);
        assert_eq!(response.body.unwrap(), Body::Text("{\"message\":\"API call not implemented.\"}".to_string()));
    }
}
