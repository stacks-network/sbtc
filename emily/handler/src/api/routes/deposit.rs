//! Route definitions for the deposit endpoint.
use warp::Filter;

use super::handlers;

/// Deposit routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_deposit()
        .or(get_deposits_for_transaction())
        .or(get_deposits())
        .or(create_deposit())
        .or(update_deposits())
}

/// Get deposit endpoint.
pub fn get_deposit() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit" / String / u16)
        .and(warp::get())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::deposit::get_deposit)
}

/// Get deposits endpoint.
pub fn get_deposits_for_transaction() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit" / String)
        .and(warp::get())
        .and(warp::query())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::deposit::get_deposits_for_transaction)
}

/// Get deposits endpoint.
pub fn get_deposits() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit")
        .and(warp::get())
        .and(warp::query())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::deposit::get_deposits)
}

/// Create deposits endpoint.
pub fn create_deposit() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit")
        .and(warp::post())
        .and(warp::query())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::deposit::create_deposit)
}

/// Update deposits endpoint.
pub fn update_deposits() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("deposit")
        .and(warp::post())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::deposit::update_deposits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::StatusCode;

    #[tokio::test]
    async fn test_get_deposit() {
        let filter = get_deposit();

        let response = warp::test::request()
            .method("GET")
            .path("/deposit/abc/123")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_get_deposits_for_transaction() {
        let filter = get_deposits_for_transaction();

        let response = warp::test::request()
            .method("GET")
            .path("/deposit/abc?param=value")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_get_deposits() {
        let filter = get_deposits();

        let response = warp::test::request()
            .method("GET")
            .path("/deposit?param=value")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_create_deposit() {
        let filter = create_deposit();

        let response = warp::test::request()
            .method("POST")
            .path("/deposit?param=value")
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_update_deposits() {
        let filter = update_deposits();

        let response = warp::test::request()
            .method("POST")
            .path("/deposit")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_routes() {
        let filter = routes();

        // Test get_deposit
        let response = warp::test::request()
            .method("GET")
            .path("/deposit/abc/123")
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test get_deposits_for_transaction
        let response = warp::test::request()
            .method("GET")
            .path("/deposit/abc?param=value")
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test get_deposits
        let response = warp::test::request()
            .method("GET")
            .path("/deposit?param=value")
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test create_deposit
        let response = warp::test::request()
            .method("POST")
            .path("/deposit?param=value")
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        // Test update_deposits
        let response = warp::test::request()
            .method("POST")
            .path("/deposit")
            .json(&serde_json::json!({ "key": "value" }))
            .reply(&filter)
            .await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
