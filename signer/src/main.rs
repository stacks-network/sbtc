use axum::routing::get;
use axum::routing::post;
use axum::Router;

#[tokio::main]
async fn main() {
    // Build the signer API application
    let app = Router::new()
        .route("/", get(signer::api::status_handler))
        .route("/new_block", post(signer::api::new_block_handler));

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8800").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
