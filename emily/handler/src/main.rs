//! Emily API entrypoint.

use api::handlers;
use context::EmilyContext;
use tracing::info;
use warp::Filter;

mod api;
mod common;
mod context;
mod database;
mod logging;

#[tokio::main]
async fn main() {
    crate::logging::setup_logging("info,emily-handler=debug", false);

    // TODO(389 + 358): Handle config pickup in a way that will only fail for the relevant call.
    let emily_context: EmilyContext = EmilyContext::from_env()
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // Print configuration.
    info!("Emily Context Setup.");
    let emily_context_string =
        serde_json::to_string_pretty(&emily_context).expect("Context must be serializable.");
    info!(emily_context_string);

    let routes = api::routes::routes(emily_context)
        .recover(handlers::handle_rejection)
        .with(warp::log("api"));

    let warp_service = warp::service(routes);

    // TODO(276): Remove warp_lambda in Emily API and use different library.
    warp_lambda::run(warp_service)
        .await
        .expect("An error occured");
}
