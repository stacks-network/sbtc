use axum::routing::get;
use axum::routing::post;
use axum::Router;
use signer::api;
use signer::storage::postgres::PgStore;

const DATABASE_URL: &str = "postgres://user:password@localhost:5432/signer";

fn get_connection_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(DATABASE_URL)
        .unwrap()
}

#[tokio::main]
async fn main() {
    sbtc::logging::setup_logging("info,signer=debug", false);

    let pool = get_connection_pool();
    let pool_store = PgStore::from(pool);
    // Build the signer API application
    let app = Router::new()
        .route("/", get(api::status_handler))
        .route("/new_block", post(api::new_block_handler::<PgStore>))
        .with_state(pool_store);

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8801").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
