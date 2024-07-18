use crate::config::SETTINGS;
use reqwest::Client;
use std::net::ToSocketAddrs;
use tracing::{error, info};
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

    let addr = match addr_str.to_socket_addrs() {
        Ok(mut addrs) => addrs.next().expect("No addresses found"),
        Err(e) => {
            error!("Failed to resolve address: {}", e);
            return;
        }
    };

    warp::serve(routes).run(addr).await;
}
