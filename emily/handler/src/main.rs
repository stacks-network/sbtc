//! Emily API entrypoint.

use api::handlers;
use sbtc_common::logging::setup_logging;
use warp::Filter;

mod api;
mod common;

#[tokio::main]
async fn main() {
    setup_logging(false);

    let routes = api::routes::routes()
        .recover(handlers::handle_rejection)
        .with(warp::log("api"));

    let warp_service = warp::service(routes);

    // TODO(276): Remove warp_lambda in Emily API and use different library.
    warp_lambda::run(warp_service)
        .await
        .expect("An error occured");
}
