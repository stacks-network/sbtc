//! Top-level error type for the Emily lambda

use aws_lambda_events::apigw::ApiGatewayProxyResponse;
use aws_lambda_events::encodings::Body;
use emily::models;
use crate::common;

/// Top-level Emily API error
#[derive(Debug, thiserror::Error)]
pub enum EmilyApiError {
    /// Bad request error
    #[error("Bad Request: {0}")]
    BadRequest(String),

    // Currently unused.
    // #[error("Forbidden Error:  {0}")]
    // Forbidden(String),

    // Currently unused.
    // #[error("Not Found Error: {0}")]
    // NotFound(String),

    // Currently unused.
    // #[error("Conflict Error: {0}")]
    // Conflict(String),

    // Currently unused.
    // #[error("Not Implemented Error: {0}")]
    // NotImplemented(String),

    // Currently unused.
    // #[error("Throttling Error: {0}")]
    // Throttling(String), // Handled by the gateway, here for completeness.

    // Currently unused.
    // #[error("Internal Server Error: {0}")]
    // InternalService(String),

    /// Unhandled server error
    #[error("Unhandled Server Exception: {0}")]
    UnhandledService(
        #[source]
        Box<dyn std::error::Error>,
    ),
}

impl EmilyApiError {
    fn status_code(&self) -> u16 {
        match *self {
            EmilyApiError::BadRequest(_) => http::StatusCode::BAD_REQUEST,
            // EmilyApiError::Forbidden(_) => http::StatusCode::FORBIDDEN,
            // EmilyApiError::NotFound(_) => http::StatusCode::NOT_FOUND,
            // EmilyApiError::Conflict(_) => http::StatusCode::CONFLICT,
            // EmilyApiError::NotImplemented(_) => http::StatusCode::NOT_IMPLEMENTED,
            // EmilyApiError::Throttling(_) => http::StatusCode::TOO_MANY_REQUESTS,
            // EmilyApiError::InternalService(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
            EmilyApiError::UnhandledService(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
        }.as_u16()
    }

    fn response_body(&self) -> Result<String, serde_json::Error> {
        match *self {
            EmilyApiError::BadRequest(_) =>
                serde_json::to_string(&models::BadRequestErrorResponseContent { message: self.to_string() }),
            // EmilyApiError::Forbidden(_) =>
            //     serde_json::to_string(&ForbiddenErrorResponseContent { message: self.to_string() }),
            // EmilyApiError::NotFound(_) =>
            //     serde_json::to_string(&NotFoundErrorResponseContent { message: self.to_string() }),
            // EmilyApiError::Conflict(_) =>
            //     serde_json::to_string(&ConflictErrorResponseContent { message: self.to_string() }),
            // EmilyApiError::NotImplemented(_) =>
            //     serde_json::to_string(&NotImplementedErrorResponseContent { message: self.to_string() }),
            // EmilyApiError::Throttling(_) =>
            //     serde_json::to_string(&ThrottlingErrorResponseContent { message: self.to_string() }),
            // EmilyApiError::InternalService(_) =>
            //     serde_json::to_string(&models::ServiceErrorResponseContent { message: self.to_string() }),
            EmilyApiError::UnhandledService(_) =>
                serde_json::to_string(&models::ServiceErrorResponseContent { message: self.to_string() }),
        }
    }

    #[allow(clippy::wrong_self_convention)]
    /// Converts the current object to an `ApiGatewayProxyResponse`.
    ///
    /// Serializes the response body and constructs a `SimpleApiResponse`
    /// with the status code. If serialization fails, returns a 500 Internal
    /// Server Error with a generic message. Converts `SimpleApiResponse`
    /// to `ApiGatewayProxyResponse` before returning.
    ///
    /// # Returns
    ///
    /// An `ApiGatewayProxyResponse` containing the status code and body.
    pub fn to_apigw_response(self) -> ApiGatewayProxyResponse {
        let status_code = self.status_code();
        let body_result = self.response_body();
        match body_result {
            Ok(body) => common::SimpleApiResponse {
                status_code,
                body: Some(Body::Text(body)),
            },
            // This occurs in the rare case that the API Error itself failed to serialize.
            Err(_) => common::SimpleApiResponse {
                status_code: http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                // This output won't be of the right format for the client, but this is an edge case where
                // the serialization will have needed to fail on a well defined structure, and this error
                // can be handled by someone receiving data from the client since they'll need to handle
                // potential errors anyway.
                body: Some(Body::Text(serde_json::json!({"message": format!("Server error: {self}")}).to_string()))
            }
        }.to_apigw_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_display_bad_request() {
        let error = EmilyApiError::BadRequest("invalid input".to_string());
        assert_eq!(format!("{}", error), "Bad Request: invalid input");
    }

    #[test]
    fn test_display_service_error_err() {
        let inner_error = std::io::Error::new(std::io::ErrorKind::Other, "oops");
        let error = EmilyApiError::UnhandledService(Box::new(inner_error));
        assert!(format!("{}", error).contains("Unhandled Server Exception:"));
    }

    #[test]
    fn test_error_source_none() {
        let error = EmilyApiError::BadRequest("error".to_string());
        assert!(error.source().is_none());
    }

    #[test]
    fn test_error_source_some() {
        let inner_error = std::io::Error::new(std::io::ErrorKind::Other, "oops");
        let error = EmilyApiError::UnhandledService(Box::new(inner_error));
        assert!(error.source().is_some());
    }

    #[test]
    fn test_status_code_bad_request() {
        let error = EmilyApiError::BadRequest("error".to_string());
        assert_eq!(error.status_code(), 400);
    }

    #[test]
    fn test_response_body_bad_request() {
        let error = EmilyApiError::BadRequest("invalid input".to_string());
        let result = error.response_body().unwrap();
        assert!(result.contains("\"message\":\"Bad Request: invalid input\""));
    }

    #[test]
    fn test_to_apigw_response() {
        let error = EmilyApiError::BadRequest("invalid input".to_string());
        let response = error.to_apigw_response();
        assert_eq!(response.status_code, 400);
        assert!(response.body.is_some());
    }
}
