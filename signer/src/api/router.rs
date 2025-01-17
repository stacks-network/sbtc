//! This module contains the default router for the signers api
//!

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};

use crate::context::Context;

use axum::http::StatusCode;

use super::{new_block, status, ApiState};

async fn new_attachment_handler() -> StatusCode {
    StatusCode::OK
}

/// Return the default router
pub fn get_router<C: Context + 'static>() -> Router<ApiState<C>> {
    Router::new()
        .route("/", get(status::status_handler))
        .route(
            "/new_block",
            post(new_block::new_block_handler)
                .layer(DefaultBodyLimit::max(new_block::EVENT_OBSERVER_BODY_LIMIT)),
        )
        // TODO: remove this once https://github.com/stacks-network/stacks-core/issues/5558
        // is addressed
        .route("/attachments/new", post(new_attachment_handler))
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
        Router,
    };
    use tower::ServiceExt;

    use crate::{
        api::{router::get_router, ApiState},
        testing::context::TestContext,
    };

    #[tokio::test]
    async fn test_new_attachment() {
        let context = TestContext::default_mocked();

        let state = ApiState { ctx: context.clone() };
        let app: Router = get_router().with_state(state);

        let request = Request::builder()
            .uri("/attachments/new")
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
