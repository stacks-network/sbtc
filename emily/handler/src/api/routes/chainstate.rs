//! Route definitions for the chainstate endpoint.

use warp::Filter;

use super::handlers;

/// Chainstate routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_chainstate()
        .or(set_chainstate())
        .or(update_chainstate())
}

/// Get chainstate endpoint.
fn get_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate" / u64)
        .and(warp::get())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::chainstate::get_chainstate)
}

/// Set chainstate endpoint.
fn set_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate")
        .and(warp::post())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::chainstate::set_chainstate)
}

/// Update chainstate endpoint.
fn update_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate")
        .and(warp::put())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::chainstate::update_chainstate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::StatusCode;

    #[tokio::test]
    async fn test_get_chainstate() {
        let filter = get_chainstate();

        let response = warp::test::request()
            .method("GET")
            .path("/chainstate/123")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_set_chainstate() {
        let filter = set_chainstate();

        let response = warp::test::request()
            .method("POST")
            .path("/chainstate")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_update_chainstate() {
        let filter = update_chainstate();

        let response = warp::test::request()
            .method("PUT")
            .path("/chainstate")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_routes() {
        let filter = routes();

        // Test get_chainstate
        let response = warp::test::request()
            .method("GET")
            .path("/chainstate/123")
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test set_chainstate
        let response = warp::test::request()
            .method("POST")
            .path("/chainstate")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test update_chainstate
        let response = warp::test::request()
            .method("PUT")
            .path("/chainstate")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
