//! Route definitions for the withdrawal endpoint.
use warp::Filter;

use super::handlers;

/// Withdrawal routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_withdrawal()
        .or(get_withdrawals())
        .or(create_withdrawal())
        .or(update_withdrawals())
}

/// Get withdrawal endpoint.
fn get_withdrawal() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal" / u64)
        .and(warp::get())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::withdrawal::get_withdrawal)
}

/// Get withdrawals endpoint.
fn get_withdrawals() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::get())
        .and(warp::query())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::withdrawal::get_withdrawals)
}

/// Create withdrawal endpoint.
fn create_withdrawal() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::post())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::withdrawal::create_withdrawal)
}

/// Update withdrawals endpoint.
fn update_withdrawals() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::put())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::withdrawal::update_withdrawals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::StatusCode;

    #[tokio::test]
    async fn test_get_withdrawal() {
        let filter = get_withdrawal();

        let response = warp::test::request()
            .method("GET")
            .path("/withdrawal/123")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_get_withdrawals() {
        let filter = get_withdrawals();

        let response = warp::test::request()
            .method("GET")
            .path("/withdrawal?param=value")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_create_withdrawal() {
        let filter = create_withdrawal();

        let response = warp::test::request()
            .method("POST")
            .path("/withdrawal")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_update_withdrawals() {
        let filter = update_withdrawals();

        let response = warp::test::request()
            .method("PUT")
            .path("/withdrawal")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_routes() {
        let filter = routes();

        // Test get_withdrawal
        let response = warp::test::request()
            .method("GET")
            .path("/withdrawal/123")
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test get_withdrawals
        let response = warp::test::request()
            .method("GET")
            .path("/withdrawal?param=value")
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test create_withdrawal
        let response = warp::test::request()
            .method("POST")
            .path("/withdrawal")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test update_withdrawals
        let response = warp::test::request()
            .method("PUT")
            .path("/withdrawal")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
