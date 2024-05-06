
use crate::errors;
use crate::common;

/// A struct that encapsulates the response details for API Gateway.
///
/// This struct is used to hold the HTTP status code and optional body for
/// a response that is intended to be returned from an AWS Lambda function
/// interacting with API Gateway.
#[derive(Debug)]
pub struct SimpleApiResponse {
    pub status_code: u16,
    pub body: Option<aws_lambda_events::encodings::Body>,
}

impl SimpleApiResponse {
    /// Converts this `SimpleApiResponse` into an `ApiGatewayProxyResponse` which
    /// is suitable for returning from a Lambda function to API Gateway.
    ///
    /// This method also sets necessary HTTP headers to support CORS and specifies
    /// the content type as `application/json`.
    ///
    /// # Returns
    /// - `ApiGatewayProxyResponse`: The API Gateway compatible response.
    #[allow(clippy::wrong_self_convention)] // Allow `to_apigw_response` to consume `self`.
    pub fn to_apigw_response(self) -> aws_lambda_events::apigw::ApiGatewayProxyResponse {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
        headers.insert(http::header::ACCESS_CONTROL_ALLOW_HEADERS, http::HeaderValue::from_static("Content-Type"));
        headers.insert(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, http::HeaderValue::from_static("*"));
        headers.insert(http::header::ACCESS_CONTROL_ALLOW_METHODS, http::HeaderValue::from_static("OPTIONS,POST,GET"));
        aws_lambda_events::apigw::ApiGatewayProxyResponse {
            status_code: i64::from(self.status_code),
            multi_value_headers: headers.clone(),
            is_base64_encoded: false,
            body: self.body,
            headers,
        }
    }
}

/// Deserializes a JSON string into a specified type `T`.
///
/// This function takes an optional JSON string and attempts to deserialize it into an instance of type `T`,
/// which must implement the `DeserializeOwned` trait. If the input is `None` or deserialization fails,
/// it returns an appropriate error.
///
/// # Parameters
/// - `body`: An `Option<String>` representing the JSON string to be deserialized.
///
/// # Returns
/// - `Ok(T)`: If the deserialization is successful.
/// - `Err(errors::EmilyApiError)`: If the input is `None` or deserialization fails.
///
/// # Errors
/// - `BadRequest`: If no body is present or if a deserialization error occurs.
#[allow(unused)] // Unsure why Cargo believes this is unused.
pub fn deserialize_request<T: serde::de::DeserializeOwned>(
    body:  Option<String>
) -> Result<T, errors::EmilyApiError> {
    body
        .ok_or_else(|| errors::EmilyApiError::BadRequest("No body present".to_string())) // should be client
        // Deserialize body.
        .and_then(|body_string|
            serde_json::from_str::<T>(&body_string)
                .map_err(|e| {
                    errors::EmilyApiError::BadRequest(format!("{} but instead got \"{}\"", e, body_string).to_string())
                }
            )
        )
}

/// Serializes a given response object of type `T` into a JSON string and packages it into a common API response format.
///
/// This function takes a response object which must implement the `Serialize` trait and a status code,
/// then attempts to serialize the response object into JSON. If successful, it packages this JSON into
/// a common response structure, otherwise returns an error.
///
/// # Parameters
/// - `response`: An instance of type `T` that should be serialized.
/// - `status_code`: A `u16` HTTP status code to be associated with the response.
///
/// # Returns
/// - `Ok(common::SimpleApiResponse)`: A successful API response including the JSON string and status code.
/// - `Err(errors::EmilyApiError)`: If serialization fails.
///
/// # Errors
/// - This function can return an `EmilyApiError` if serialization fails, encapsulating the underlying serialization error.
#[allow(unused)] // Unsure why Cargo believes this is unused.
pub fn package_response<T: serde::Serialize>(
    response:  T,
    status_code: u16,
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    serde_json::to_string(&response)
            .map_err(|e| {
                errors::EmilyApiError::UnhandledService(Box::new(e))
            }
        ).map(|response_str| common::SimpleApiResponse {
                status_code,
                body: Some(aws_lambda_events::encodings::Body::Text(response_str))
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lambda_events::encodings::Body;
    use crate::utils::test;

    #[test]
    fn test_to_apigw_response() {
        let response = SimpleApiResponse {
            status_code: 200,
            body: Some(Body::Text("success".to_string())),
        };
        let api_response = response.to_apigw_response();
        assert_eq!(api_response.status_code, 200);
        assert_eq!(api_response.body, Some(Body::Text("success".to_string())));
        assert_eq!(api_response.headers["Content-Type"], "application/json");
        assert_eq!(api_response.headers["Access-Control-Allow-Origin"], "*");
    }

    #[test]
    fn deserialize_request_none_body() {
        let result: Result<test::TestResponse, _> = deserialize_request(None);
        assert!(matches!(result, Err(errors::EmilyApiError::BadRequest(_))));
    }

    #[test]
    fn deserialize_request_invalid_json() {
        let result: Result<test::TestResponse, _> = deserialize_request(Some(test::BAD_JSON.to_string()));
        assert!(matches!(result, Err(errors::EmilyApiError::BadRequest(_))));
    }

    #[test]
    fn deserialize_request_valid_json() {
        let json = serde_json::to_string(&test::TestResponse { message: "Hello".to_string() }).unwrap();
        let result: Result<test::TestResponse, _> = deserialize_request(Some(json));
        assert_eq!(result.unwrap(), test::TestResponse { message: "Hello".to_string() });
    }

    #[test]
    fn package_response_serialization_failure() {
        let result: Result<SimpleApiResponse, _> = package_response(test::AlwaysFailSerialization, 200);
        assert!(matches!(result, Err(errors::EmilyApiError::UnhandledService(_))));
    }

    #[test]
    fn package_response_success() {
        let response = test::TestResponse { message: "Success".to_string() };
        let result: Result<SimpleApiResponse, _> = package_response(response, 200);
        assert!(result.is_ok(), "Expected Ok(_) but got the following: {:?}", result);
        let api_response = result.unwrap();
        assert_eq!(api_response.status_code, 200);
        assert!(matches!(api_response.body, Some(Body::Text(body)) if body == "{\"message\":\"Success\"}"));
    }
}
