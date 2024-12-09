//! Emily Warp Service Binary.

use clap::Args;
use clap::Parser;
use emily_handler::context::EmilyContext;
use tracing::info;
use warp::Filter;

use emily_handler::api;
use emily_handler::logging;

/// The arguments for the Emily server.
#[derive(Parser, Debug)]
#[command(
    name = "EmilyServer",
    version = "1.0",
    author = "Ashton Stephens <ashton@trustmachines.co>",
    about = "Local emily server binary"
)]
pub struct Cli {
    /// Server arguments.
    #[command(flatten)]
    pub server: ServerArgs,
    /// General arguments.
    #[command(flatten)]
    pub general: GeneralArgs,
}

/// General arguments.
#[derive(Args, Debug)]
pub struct GeneralArgs {
    /// Whether to use pretty log printing.
    #[arg(long, default_value = "false")]
    pub pretty_logs: bool,
    /// Log directives.
    #[arg(long, default_value = "info,emily_handler=debug,api=debug")]
    pub log_directives: String,
    /// DynamoDB endpoint.
    #[arg(long, default_value = "http://localhost:8000")]
    pub dynamodb_endpoint: String,
}

/// Server related arguments.
#[derive(Args, Debug)]
pub struct ServerArgs {
    /// Host.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Port to run on.
    #[arg(long, default_value = "3031")]
    pub port: u64,
}

/// Main program.
#[tokio::main]
async fn main() {
    // Get command line arguments.
    let Cli {
        server: ServerArgs { host, port },
        general:
            GeneralArgs {
                pretty_logs,
                log_directives,
                dynamodb_endpoint,
            },
    } = Cli::parse();

    // Setup logging.
    logging::setup_logging(&log_directives, pretty_logs);

    // Setup context.
    // TODO(389 + 358): Handle config pickup in a way that will only fail for the relevant call.
    let context: EmilyContext = EmilyContext::local_instance(&dynamodb_endpoint)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    info!(lambdaContext = ?context);

    // Create CORS configuration
    let cors = warp::cors()
        .allow_any_origin()
        .allow_methods(vec!["GET", "POST", "OPTIONS"])
        .allow_headers(vec!["content-type", "x-api-key"])
        .build();

    let routes = api::routes::routes(context)
        .recover(api::handlers::handle_rejection)
        .with(warp::log("api"))
        .with(cors);

    // Create address.
    let addr_str = format!("{host}:{port}");
    info!("Server will run locally on {}", addr_str);
    let addr: std::net::SocketAddr = addr_str.parse().expect("Failed to parse address");

    // Create warp service as a local service and listen at the address.
    warp::serve(routes).run(addr).await;
}
