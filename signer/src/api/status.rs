//! This module is for the `GET /` endpoint, which just returns the status.

use axum::http::StatusCode;

/// A basic handler that responds with 200 OK
pub async fn status_handler() -> StatusCode {
    StatusCode::OK
}
