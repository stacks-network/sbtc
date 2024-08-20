//! Emily API entrypoint.

use emily_handler::context::EmilyContext;
use tracing::info;
use tracing::warn;
use warp::Filter;

use emily_handler::api;
use emily_handler::logging;

#[tokio::main]
async fn main() {
    // Setup logging.
    logging::setup_logging("info,emily-handler=debug", false);

    // Setup context.
    // TODO(389 + 358): Handle config pickup in a way that will only fail for the relevant call.
    let context: EmilyContext = EmilyContext::from_env()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    info!("Lambda Context:\n{context:?}");

    // Setup service filters.
    let service_filter = routes(context)
        .recover(api::handlers::handle_rejection)
        .with(warp::log("api"));

    // Create warp service.
    // TODO(276): Remove warp_lambda in Emily API and use different library.
    let warp_service = warp::service(service_filter);
    warp_lambda::run(warp_service)
        .await
        .expect("An error occurred");
}

/// Makes the routes.
#[cfg(not(feature = "testing"))]
fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    api::routes::routes(context)
}

/// Makes the routes.
#[cfg(feature = "testing")]
fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warn!(
        "Running lambda server with testing features - all paths will be prefixed with \"/local\""
    );
    warp::path("local").and(api::routes::routes(context))
}
