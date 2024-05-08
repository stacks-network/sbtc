
use crate::{
    errors,
    operations::deposits,
    operations::withdrawals,
    operations::chainstate,
};
use std::collections::HashMap;
use aws_lambda_events::apigw::{ApiGatewayProxyRequest, ApiGatewayProxyResponse};
use lambda_runtime::LambdaEvent;
use http::Method;

/// Asynchronously handles incoming API Gateway events and dispatches them
/// to the correct method based on the route and method.
///
/// # Arguments
/// * `event` - A LambdaEvent containing the ApiGatewayProxyRequest.
///
/// # Returns
/// A result containing the API Gateway Proxy Response or an lambda_runtime::Error.
pub async fn handle_event(
    event: LambdaEvent<ApiGatewayProxyRequest>
) -> Result<ApiGatewayProxyResponse, lambda_runtime::Error> {

    // Extract base data.
    let resource = event.payload.resource.unwrap_or_default();
    let http_method = event.payload.http_method;
    let body: Option<String> = event.payload.body;
    let path_parameters: HashMap<String, String> = event.payload.path_parameters;

    // Dispatch based on API call.
    let event_handler_result = match (resource.as_str(), http_method) {
        // Deposits
        ("/deposits", Method::POST) => deposits::handle_create_deposit(body),
        ("/deposits/{txid}", Method::GET) => deposits::handle_get_txn_deposits(path_parameters),
        ("/deposits/{txid}/{outputIndex}", Method::GET) => deposits::handle_get_deposit(path_parameters),
        ("/deposits", Method::GET) => deposits::handle_get_deposits(path_parameters),
        ("/deposits", Method::PUT) => deposits::handle_update_deposits(body),
        // Withdrawals
        ("/withdrawals", Method::POST) => withdrawals::handle_create_withdrawal(body),
        ("/withdrawals/{id}", Method::GET) => withdrawals::handle_get_withdrawal(path_parameters),
        ("/withdrawals", Method::GET) => withdrawals::handle_get_withdrawals(path_parameters),
        ("/withdrawals", Method::PUT) => withdrawals::handle_update_withdrawals(body),
        // Chainstate
        ("/chainstate", Method::POST) => chainstate::handle_create_chainstate(body),
        ("/chainstate/{height}", Method::GET) => chainstate::handle_get_chainstate(path_parameters),
        ("/chainstate", Method::PUT) => chainstate::handle_update_chainstate(body),
        _ => {
            Err(errors::EmilyApiError::BadRequest(format!("Invalid endpoint \"{}\".", resource).to_string()))
        },
    };

    // Specify the type to include the lambda runtime error to meet the `service_fn` function contract.
    let result: Result<ApiGatewayProxyResponse, lambda_runtime::Error> = match event_handler_result {
        Ok(response) => Ok(response.to_apigw_response()),
        Err(err) => Ok(err.to_apigw_response()),
    };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use lambda_runtime::Context;
    use aws_lambda_events::apigw::ApiGatewayProxyRequest;
    use http::Method;
    use test_case::test_case;
    use crate::utils::test;

    /// Tests that the API calls that require bodies execute in the expected way based on the format of the body.
    #[test_case(Method::POST, "/deposits", test::create_deposit_request_body, 201; "create-deposit")]
    #[test_case(Method::PUT, "/deposits", test::update_deposits_request_body, 202; "update-deposits")]
    #[test_case(Method::POST, "/withdrawals", test::create_withdrawal_request_body, 201; "create-withdrawal")]
    #[test_case(Method::PUT, "/withdrawals", test::update_withdrawals_request_body, 202; "update-withdrawals")]
    #[test_case(Method::POST, "/chainstate", test::create_chainstate_request_body, 201; "update-chainstate")]
    #[test_case(Method::PUT, "/chainstate", test::update_chainstate_request_body, 202; "set-chainstate")]
    #[tokio::test]
    async fn test_write_method_variations(
        method: Method,
        resource: &str,
        body_factory: fn(test::RequestType) -> Option<String>,
        success_status_code: i64
    ) {
        // Success: Good inputs.
        let response_on_full_request = test_execute_api(&method, resource, body_factory(test::RequestType::FULL)).await;
        assert_eq!(response_on_full_request.status_code, success_status_code, "Failed handling a well formed request with all the fields defined: {:?}.",
            response_on_full_request.body);
        let response_on_minimal_request = test_execute_api(&method, resource, body_factory(test::RequestType::MINIMAL)).await;
        assert_eq!(response_on_minimal_request.status_code, success_status_code, "Failed handling a well formed request with the least fields defined: {:?}.",
            response_on_minimal_request.body);

        // Failure: Bad inputs.
        let response_on_missing_request = test_execute_api(&method, resource, body_factory(test::RequestType::MISSING)).await;
        assert_eq!(response_on_missing_request.status_code, 400, "Improperly handled a request missing required fields.");
        let response_on_malformed_request = test_execute_api(&method, resource, body_factory(test::RequestType::MALFORMED)).await;
        assert_eq!(response_on_malformed_request.status_code, 400, "Improperly handled a malformed request.");
        let response_on_missing_request = test_execute_api(&method, resource, body_factory(test::RequestType::EMPTY)).await;
        assert_eq!(response_on_missing_request.status_code, 400, "Improperly handled a missing request.");
    }

    #[test_case(Method::GET, "/deposits/{txid}/{outputIndex}"; "get-deposit")]
    #[test_case(Method::GET, "/deposits/{txid}"; "get-txn-deposits")]
    #[test_case(Method::GET, "/deposits"; "get-deposits")]
    #[test_case(Method::GET, "/withdrawals/{id}"; "get-withdrawal")]
    #[test_case(Method::GET, "/withdrawals"; "get-withdrawals")]
    #[test_case(Method::GET, "/chainstate/{height}"; "get-chainstate")]
    #[tokio::test]
    async fn test_read_method(
        method: Method,
        resource: &str,
    ) {
        let response = test_execute_api(&method, resource, None).await;
        assert_eq!(response.status_code, 200, "Failed handling an unsinkable GET request: {:?}.",
            response.body);
    }

    /// Helper function to call the event handler in a more intuitive way.
    async fn test_execute_api(
        method: &Method,
        resource: &str,
        body: Option<String>,
    ) -> ApiGatewayProxyResponse {
        handle_event(mock_request(method, resource, body, HashMap::new())).await.unwrap()
    }

    /// Helper function to create a mock API Gateway request.
    fn mock_request(method: &Method, path: &str, body: Option<String>, path_parameters: HashMap<String, String>) -> LambdaEvent<ApiGatewayProxyRequest> {
        LambdaEvent {
            payload: ApiGatewayProxyRequest {
                http_method: method.clone(),
                resource: Some(path.to_string()),
                body,
                path_parameters,
                ..Default::default()
            },
            context: Context::default(),
        }
    }
}
