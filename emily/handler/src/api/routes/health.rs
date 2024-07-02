//! Route definitions for the health endpoint.

use super::handlers;
use warp::Filter;

/// Health routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_health()
}

/// Get health endpoint.
fn get_health() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("health")
        .and(warp::get())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .then(handlers::health::get_health)
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::StatusCode;

    #[tokio::test]
    async fn test_get_health() {
        let filter = get_health();

        let response = warp::test::request()
            .method("GET")
            .path("/health")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
