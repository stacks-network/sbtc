//! Handlers for Health endpoint endpoints.

use crate::common::error::Error;

/// Get health handler.
#[utoipa::path(
    get,
    operation_id = "checkHealth",
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Successfully retrieved health data.", body = HealthData),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
pub async fn get_health() -> impl warp::reply::Reply {
    Error::NotImplemented
}
