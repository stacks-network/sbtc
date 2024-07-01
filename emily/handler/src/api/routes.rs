//! Route configuration for the Blocklist client

use super::handlers;
use crate::config::SETTINGS;
use reqwest::Client;
use std::convert::Infallible;
use warp::Filter;

/// This function sets up the Warp filters for handling incoming screening requests. It defines a
/// route for the `/screen/{address}` endpoint, which accepts GET requests
pub fn routes(
    client: Client,
) -> impl Filter<Extract = impl warp::Reply, Error = Infallible> + Clone {
    warp::path("screen")
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(warp::any().map(move || client.clone()))
        .and(warp::any().map(move || SETTINGS.risk_analysis.clone()))
        .and_then(handlers::check_address_handler)
        .recover(handlers::handle_rejection)
}
