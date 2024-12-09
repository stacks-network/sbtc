//! Emily API entrypoint.

use emily_handler::context::EmilyContext;
use tracing::info;

use emily_handler::api;
use emily_handler::logging;
use warp::Filter;

#[tokio::main]
async fn main() {
    // Setup logging.
    // TODO(TBD): Make the logging configurable.
    logging::setup_logging("info,emily_handler=debug", false);

    // Setup context.
    // TODO(389 + 358): Handle config pickup in a way that will only fail for the relevant call.
    let context: EmilyContext = EmilyContext::from_env()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    info!(lambdaContext = ?context);

    // Create CORS configuration
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST", "OPTIONS"])
        .allow_headers(vec!["content-type", "x-api-key"])
        .build();

    // Setup service filters.
    let service_filter = api::routes::routes_with_stage_prefix(context)
        .recover(api::handlers::handle_rejection)
        .with(warp::log("api"))
        .with(cors);

    // Create warp service.
    // TODO(276): Remove warp_lambda in Emily API and use different library.
    let warp_service = warp::service(service_filter);
    warp_lambda::run(warp_service)
        .await
        .expect("An error occurred");
}
