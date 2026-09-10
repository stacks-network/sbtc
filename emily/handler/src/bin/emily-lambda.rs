//! Emily API entrypoint.

use emily_handler::api;
use emily_handler::context::EmilyContext;
use emily_handler::logging;
use tracing::{info, info_span};
use warp::Filter as _;
use warp_lambda::lambda_http::Context;

#[tokio::main]
async fn main() {
    // Setup logging.
    logging::setup_logging("info,emily_handler=debug", false);

    // Setup context.
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

    let inject_lambda_id = warp::any()
        .and(warp::ext::optional::<Context>())
        .map(|ctx: Option<Context>| {
            if let Some(c) = ctx {
                tracing::Span::current().record("request_id", c.request_id.as_str());
            }
        })
        .untuple_one();

    let service_routes =
        api::routes::routes_with_stage_prefix(context).recover(api::handlers::handle_rejection);

    let service_filter = inject_lambda_id
        .and(service_routes)
        .with(warp::trace(|info| {
            let trace_id = info
                .request_headers()
                .get("x-amzn-trace-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("unknown");
            info_span!(
                "request",
                request_id = tracing::field::Empty,
                trace_id = %trace_id,
                method = %info.method(),
                path = info.path(),
            )
        }))
        .with(warp::log("api"))
        .with(cors);

    // Create warp service.
    let warp_service = warp::service(service_filter);

    warp_lambda::run(warp_service)
        .await
        .expect("An error occurred");
}
