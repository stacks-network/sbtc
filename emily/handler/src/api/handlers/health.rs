//! Handlers for Health endpoint endpoints.

use warp::reply::Reply;

use crate::{api::models::health::responses::HealthData, context::EmilyContext};

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
)]
pub async fn get_health(context: EmilyContext) -> impl warp::reply::Reply {
    // Handle and respond.
    warp::reply::json(&HealthData {
        version: context.settings.version.clone(),
    })
    .into_response()
}
