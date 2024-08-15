//! Emily Warp Service Binary.

use emily_handler::context::EmilyContext;
use tracing::info;
use warp::Filter;

use emily_handler::api;
use emily_handler::logging;

#[tokio::main]
async fn main() {
    logging::setup_logging("info,emily-handler=debug", false);

    // TODO(389 + 358): Handle config pickup in a way that will only fail for the relevant call.
    let emily_context: EmilyContext = EmilyContext::local_test_instance()
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // Print configuration.
    info!("Emily context setup for Emily local server.");
    let emily_context_string =
        serde_json::to_string_pretty(&emily_context).expect("Context must be serializable.");
    info!(emily_context_string);

    let routes = api::routes::routes(emily_context)
        .recover(api::handlers::handle_rejection)
        .with(warp::log("api"));

    // Create warp service as a local service.
    // TODO(TBD): Make these fields configurable.
    let host: &str = "127.0.0.1";
    let port: i32 = 3031;
    let addr_str = format!("{}:{}", host, port);

    info!("Server will run locally on {}", addr_str);
    let addr: std::net::SocketAddr = addr_str.parse().expect("Failed to parse address");

    warp::serve(routes).run(addr).await;
}
