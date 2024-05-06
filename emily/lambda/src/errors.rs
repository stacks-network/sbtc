use std::fmt;
use aws_lambda_events::apigw::ApiGatewayProxyResponse;
use aws_lambda_events::encodings::Body;
use emily::models;
use crate::common;

#[derive(Debug)]
pub enum EmilyApiError {
    BadRequest(String),
    // Forbidden(String), // Currently unused.
    // NotFound(String), // Currently unused.
    // Conflict(String), // Currently unused.
    // NotImplemented(String), // Currently unused.
    // Throttling(String), // Handled by the gateway, here for completeness.
    Service(Result<String, Box<dyn std::error::Error>>),
}

impl fmt::Display for EmilyApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EmilyApiError::BadRequest(ref err_msg) => write!(f, "Bad Request: {}", err_msg),
            // EmilyApiError::Forbidden(ref err_msg) => write!(f, "Forbidden Error: {}", err_msg),
            // EmilyApiError::NotFound(ref err_msg) => write!(f, "Not Found Error: {}", err_msg),
            // EmilyApiError::Conflict(ref err_msg) => write!(f, "Conflict Error: {}", err_msg),
            // EmilyApiError::NotImplemented(ref err_msg) => write!(f, "Not Implemented Error: {}", err_msg),
            // EmilyApiError::Throttling(ref err_msg) => write!(f, "Throttling Error: {}", err_msg),
            EmilyApiError::Service(ref err) => match err {
                Ok(ref err_msg) => write!(f, "Internal Server Error: {}", err_msg),
                Err(ref err) => write!(f, "Unhandled Server Exception: {}", err),
            },
        }
    }
}

impl std::error::Error for EmilyApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            EmilyApiError::Service(Err(ref err)) => Some(err.as_ref()),
            _ => None,
        }
    }
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
            EmilyApiError::Service(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
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
            EmilyApiError::Service(_) =>
                serde_json::to_string(&models::ServiceErrorResponseContent { message: self.to_string() }),
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_apigw_response(self) -> ApiGatewayProxyResponse {
        match self.response_body() {
            Ok(body) => common::SimpleApiResponse {
                status_code: self.status_code(),
                body: Some(Body::Text(body)),
            },
            // This occurs in the rare case that the API Error itself failed to serialize.
            Err(err) => common::SimpleApiResponse {
                status_code: http::StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                // This output won't be of the right format for the client, but this is an edge case where
                // the serialization will have needed to fail on a well defined structure, and this error
                // can be handled by someone receiving data from the client since they'll need to handle
                // potential errors anyway.
                body: Some(Body::Text(format!("Error Deserializing: {}, {}", self, err).to_string())),
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
    fn test_display_service_error_ok() {
        let error = EmilyApiError::Service(Ok("temporary error".to_string()));
        assert_eq!(format!("{}", error), "Internal Server Error: temporary error");
    }

    #[test]
    fn test_display_service_error_err() {
        let inner_error = std::io::Error::new(std::io::ErrorKind::Other, "oops");
        let error = EmilyApiError::Service(Err(Box::new(inner_error)));
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
        let error = EmilyApiError::Service(Err(Box::new(inner_error)));
        assert!(error.source().is_some());
    }

    #[test]
    fn test_status_code_bad_request() {
        let error = EmilyApiError::BadRequest("error".to_string());
        assert_eq!(error.status_code(), 400);
    }

    #[test]
    fn test_status_code_service_error() {
        let error = EmilyApiError::Service(Ok("error".to_string()));
        assert_eq!(error.status_code(), 500);
    }

    #[test]
    fn test_response_body_bad_request() {
        let error = EmilyApiError::BadRequest("invalid input".to_string());
        let result = error.response_body().unwrap();
        assert!(result.contains("\"message\":\"Bad Request: invalid input\""));
    }

    #[test]
    fn test_response_body_service_error() {
        let error = EmilyApiError::Service(Ok("problem occurred".to_string()));
        let result = error.response_body().unwrap();
        assert!(result.contains("\"message\":\"Internal Server Error: problem occurred\""));
    }

    #[test]
    fn test_to_apigw_response() {
        let error = EmilyApiError::BadRequest("invalid input".to_string());
        let response = error.to_apigw_response();
        assert_eq!(response.status_code, 400);
        assert!(response.body.is_some());
    }
}
