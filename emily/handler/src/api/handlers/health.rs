//! Handlers for Health endpoint endpoints.

use crate::common::error::Error;

/// Get health handler.
#[utoipa::path(
    get,
    operation_id = "checkHealth",
    path = "/health",
    tag = "health",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Successfully retrieved health data.", body = HealthData),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_health() -> impl warp::reply::Reply {
    Error::NotImplemented
}
