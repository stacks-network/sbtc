use std::path::PathBuf;

use axum::routing::get;
use axum::routing::post;
use axum::Router;
use cfg_if::cfg_if;
use clap::Parser;
use signer::api;
use signer::api::ApiState;
use signer::context::Context;
use signer::context::SignerContext;
use signer::context::SignerSignal;
use signer::error::Error;
use signer::storage::postgres::PgStore;
use tokio::signal;

// TODO: This should be read from configuration
const DATABASE_URL: &str = "postgres://user:password@localhost:5432/signer";

// TODO: Should this be part of the SignerContext?
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

    // Run the application components concurrently. We're `join!`ing them
    // here so that every component can shut itself down gracefully when
    // the shutdown signal is received.
    let _ = tokio::join!(
        run_stacks_event_observer(&context),
        run_shutdown_signal_watcher(&context),
        run_libp2p_swarm(&context),
    );

    Ok(())
}

/// Runs the shutdown-signal watcher. On Unix systems, this listens for SIGHUP,
/// SIGTERM, and SIGINT. On other systems, it listens for Ctrl-C.
async fn run_shutdown_signal_watcher(ctx: &impl Context) -> Result<(), Error> {
    cfg_if! {
        // If we are on a Unix system, we can listen for more signals.
        if #[cfg(unix)] {
            let mut terminate = tokio::signal::unix::signal(signal::unix::SignalKind::terminate())?;
            let mut hangup = tokio::signal::unix::signal(signal::unix::SignalKind::hangup())?;
            let mut interrupt = tokio::signal::unix::signal(signal::unix::SignalKind::interrupt())?;

            tokio::select! {
                _ = terminate.recv() => {
                    tracing::info!(signal = "SIGTERM", "received termination signal");
                },
                _ = hangup.recv() => {
                    tracing::info!(signal = "SIGHUP", "received termination signal");
                },
                // Ctrl-C will be received as a SIGINT.
                _ = interrupt.recv() => {
                    tracing::info!(signal = "SIGINT", "received termination signal");
                },
            }
        // Otherwise, we'll just listen for Ctrl-C, which is the most portable.
        } else {
            tokio::signal::ctrl_c().await?;
            tracing::info!(signal = "Ctrl+C", "received termination signal");
        }
    }

    // Send the shutdown signal to the rest of the application.
    tracing::info!("sending shutdown signal to the application");
    ctx.signal(SignerSignal::Shutdown)?;

    Ok(())
}

/// Runs the libp2p swarm.
async fn run_libp2p_swarm(ctx: &impl Context) -> Result<(), Error> {
    // Subscribe to the signal channel so that we can catch shutdown events.
    let mut signal = ctx.get_signal_receiver();

    // TODO(409): Add libp2p swarm initialization here.

    tokio::select! {
        Ok(SignerSignal::Shutdown) = signal.recv() => {
            tracing::info!("stopping the libp2p swarm");
            Ok(())
        }
    }
}

/// Runs the Stacks event observer server.
async fn run_stacks_event_observer(ctx: &impl Context) -> Result<(), Error> {
    let pool = get_connection_pool();
    let state = ApiState {
        db: PgStore::from(pool),
        settings: ctx.config().clone(),
    };
    // Build the signer API application
    let app = Router::new()
        .route("/", get(api::status_handler))
        .route("/new_block", post(api::new_block_handler))
        .with_state(state);

    // run our app with hyper
    // TODO: This should be read from configuration
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8801").await.unwrap();

    // Subscribe to the signal channel so that we can catch shutdown events.
    let mut signal = ctx.get_signal_receiver();

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // Listen for an application shutdown signal. We need to loop here
            // because we may receive other signals (which we will ignore here).
            loop {
                if let Ok(SignerSignal::Shutdown) = signal.recv().await {
                    tracing::info!("stopping the Stacks event observer server");
                    break;
                }
            }
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "error running Stacks event observer server");
            let _ = ctx.signal(SignerSignal::Shutdown);
            error.into()
        })
}
