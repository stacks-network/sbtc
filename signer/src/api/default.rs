//! Default/fallback route for the API.

use axum::http::StatusCode;

/// Default/fallback route for the API.
pub async fn default_handler() -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
        Router,
    };
    use tower::ServiceExt;

    use crate::{api::ApiState, testing::context::TestContext};

    #[tokio::test]
    async fn test_unknown_routes_return_ok() {
        let context = TestContext::default_mocked();

        // Test that we get 404 when the fallback handler isn't set.
        let state = ApiState { ctx: context.clone() };
        let app: Router = Router::new()
            .route("/", axum::routing::get(crate::api::status_handler))
            .route(
                "/new_block",
                axum::routing::post(crate::api::new_block_handler),
            )
            .with_state(state);
        let request = Request::builder()
            .uri("/asdf")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Now test that we get 200 OK when the fallback handler is set.
        let state = ApiState { ctx: context.clone() };
        let app: Router = Router::new()
            .route("/", axum::routing::get(crate::api::status_handler))
            .route(
                "/new_block",
                axum::routing::post(crate::api::new_block_handler),
            )
            .fallback(crate::api::default_handler)
            .with_state(state);
        let request = Request::builder()
            .uri("/asdf")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
