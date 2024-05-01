use crate::config::Settings;
use ::config::{Config, File};
use env_logger::{Builder, Env};
use log::info;
use warp::Filter;

mod api;
mod client;
mod common;
mod config;

#[tokio::main]
async fn main() {
    // Initializing logger with default logging
    Builder::from_env(Env::default().default_filter_or("info")).init();

    let mut settings = Config::default();
    settings
        .merge(File::with_name("settings").required(false))
        .expect("Configuration file 'config/settings.toml' not found.");

    let settings: Settings = settings.try_into().unwrap();

    info!(
        "Server will run on {}:{}",
        settings.server.host, settings.server.port
    );
    info!("Using API URL: {}", settings.risk_analysis.api_url);

    let api_routes = api::routes::routes(&settings);
    let routes = api_routes.with(warp::log("api"));

    warp::serve(routes)
        .run((
            settings.server.host.parse::<std::net::IpAddr>().unwrap(),
            settings.server.port,
        ))
        .await;
}
