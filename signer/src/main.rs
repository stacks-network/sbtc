use std::path::PathBuf;

use axum::routing::get;
use axum::routing::post;
use axum::Router;
use clap::Parser;
use signer::api;
use signer::context::Context;
use signer::context::SignerContext;
use signer::context::SignerSignal;
use signer::error::Error;
use signer::storage::postgres::PgStore;

// TODO: This should be read from configuration
const DATABASE_URL: &str = "postgres://user:password@localhost:5432/signer";

fn get_connection_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(DATABASE_URL)
        .unwrap()
}

/// Command line arguments for the signer.
#[derive(Debug, Parser)]
#[clap(name = "sBTC Signer")]
struct SignerArgs {
    /// Optional path to the configuration file. If not provided, it is expected
    /// that all parameters are provided via environment variables.
    #[clap(short = 'c', long, required = false)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    sbtc::logging::setup_logging("info,signer=debug", false);

    // Parse the command line arguments.
    let args = SignerArgs::parse();

    // Initialize the signer context.
    let context = SignerContext::init(args.config)?;

    // Run the Stacks event observer and Ctrl-C watcher concurrently.
    let _ = tokio::join!(
        run_stacks_event_observer(&context),
        run_ctrl_c_watcher(&context),
        run_libp2p_swarm(&context),
    );

    Ok(())
}

/// Runs the Ctrl-C watcher.
async fn run_ctrl_c_watcher(ctx: &impl Context) -> Result<(), Error> {
    tokio::signal::ctrl_c().await?;
    ctx.signal_shutdown()?;
    Ok(())
}

/// Runs the libp2p swarm.
async fn run_libp2p_swarm(ctx: &impl Context) -> Result<(), Error> {
    // Subscribe to the signal channel so that we can catch shutdown events.
    let mut signal = ctx.signal_subscribe();

    // TODO(409): Add libp2p swarm initialization here.

    tokio::select! {
        Ok(SignerSignal::Shutdown) = signal.recv() => {
            tracing::info!("Received shutdown signal, stopping libp2p swarm");
            Ok(())
        }
    }
}

/// Runs the Stacks event observer server.
async fn run_stacks_event_observer(ctx: &impl Context) -> Result<(), Error> {
    let pool = get_connection_pool();
    let pool_store = PgStore::from(pool);
    // Build the signer API application
    let app = Router::new()
        .route("/", get(api::status_handler))
        .route("/new_block", post(api::new_block_handler::<PgStore>))
        .with_state(pool_store);

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8801").await.unwrap();

    // Subscribe to the signal channel so that we can catch shutdown events.
    let mut signal = ctx.signal_subscribe();

    // Start the server in its own task.
    let handle = tokio::spawn(async { axum::serve(listener, app).await });

    // Wait for either the server to stop or a shutdown signal. If the server
    // stops on its own, this is probably a premature termination of some sort,
    // so return an error.
    tokio::select! {
        _ = handle => {
            tracing::info!("Stacks event observer server aborted");
            ctx.signal_shutdown()?;
            Err(Error::StacksEventObserverAborted)
        }
        Ok(SignerSignal::Shutdown) = signal.recv() => {
            tracing::info!("Received shutdown signal, stopping Stacks event observer server");
            Ok(())
        }
    }
}
