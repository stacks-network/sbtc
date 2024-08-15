use crate::config::SETTINGS;
use reqwest::Client;
use tracing::info;
use warp::Filter;

mod api;
mod client;
mod common;
mod config;

#[tokio::main]
async fn main() {
    blocklist_client::logging::setup_logging(false);

    let client = Client::new();

    let routes = api::routes::routes(client)
        .recover(api::handlers::handle_rejection)
        .with(warp::log("api"));

    let addr_str = format!("{}:{}", SETTINGS.server.host, SETTINGS.server.port);
    info!("Server will run on {}", addr_str);

    let addr: std::net::SocketAddr = addr_str.parse().expect("Failed to parse address");

    warp::serve(routes).run(addr).await;
}
