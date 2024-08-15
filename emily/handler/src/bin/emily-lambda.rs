//! Emily API entrypoint.

use emily_handler::context::EmilyContext;
use tracing::info;
use warp::Filter;

use emily_handler::api;
use emily_handler::logging;

#[tokio::main]
async fn main() {
    logging::setup_logging("info,emily-handler=debug", false);

    // TODO(389 + 358): Handle config pickup in a way that will only fail for the relevant call.
    let emily_context: EmilyContext = EmilyContext::from_env()
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // Print configuration.
    info!("Emily context setup for Emily Lambda.");
    let emily_context_string =
        serde_json::to_string_pretty(&emily_context).expect("Context must be serializable.");
    info!(emily_context_string);

    // Make routes.
    let routes = api::routes::routes(emily_context)
        .recover(api::handlers::handle_rejection)
        .with(warp::log("api"));

    // Create warp service.
    let warp_service = warp::service(routes);

    // TODO(276): Remove warp_lambda in Emily API and use different library.
    warp_lambda::run(warp_service)
        .await
        .expect("An error occurred");
}
