use std::path::PathBuf;

use axum::routing::get;
use axum::routing::post;
use axum::Router;
use cfg_if::cfg_if;
use clap::Parser;
use libp2p::Multiaddr;
use signer::api;
use signer::context::Context;
use signer::context::SignerCommand;
use signer::context::SignerContext;
use signer::context::SignerSignal;
use signer::error::Error;
use signer::network::libp2p::SignerSwarmBuilder;
use signer::network::libp2p::TryIntoMultiAddrs as _;
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
    sbtc::logging::setup_logging("info,signer=debug", true);

    // Parse the command line arguments.
    let args = SignerArgs::parse();

    // Initialize the signer context.
    let context = SignerContext::init(args.config)?;

    // Run the application components concurrently. We're `join!`ing them
    // here so that every component can shut itself down gracefully when
    // the shutdown signal is received.
    let _ = tokio::join!(
        run_checked(run_stacks_event_observer, &context),
        run_checked(run_shutdown_signal_watcher, &context),
        run_checked(run_libp2p_swarm, &context),
    );

    Ok(())
}

/// A helper method that captures errors from the provided future and sends a
/// shutdown signal to the application if an error is encountered. This is needed
/// as otherwise the application would continue running indefinitely (since no
/// shutdown signal is sent automatically on error).
async fn run_checked<'a, F, Fut, C>(f: F, ctx: &'a C) -> Result<(), Error>
where
    C: Context + 'a,
    F: FnOnce(&'a C) -> Fut,
    Fut: std::future::Future<Output = Result<(), Error>> + 'a,
{
    if let Err(error) = f(ctx).await {
        tracing::error!(%error, "a fatal error occurred; shutting down the application");
        let _ = ctx.signal(SignerSignal::Command(SignerCommand::Shutdown));
        return Err(error);
    }

    Ok(())
}

/// Runs the shutdown-signal watcher. On Unix systems, this listens for SIGHUP,
/// SIGTERM, and SIGINT. On other systems, it listens for Ctrl-C.
async fn run_shutdown_signal_watcher(ctx: &impl Context) -> Result<(), Error> {
    let mut signal = ctx.get_signal_receiver();

    cfg_if! {
        // If we are on a Unix system, we can listen for more signals.
        if #[cfg(unix)] {
            let mut terminate = tokio::signal::unix::signal(signal::unix::SignalKind::terminate())?;
            let mut hangup = tokio::signal::unix::signal(signal::unix::SignalKind::hangup())?;
            let mut interrupt = tokio::signal::unix::signal(signal::unix::SignalKind::interrupt())?;

            tokio::select! {
                Ok(SignerSignal::Command(SignerCommand::Shutdown)) = signal.recv() => {
                    tracing::debug!("shutdown signal received, signal watcher is shutting down");
                },
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
    ctx.signal(SignerSignal::Command(SignerCommand::Shutdown))?;

    Ok(())
}

/// Runs the libp2p swarm.
#[tracing::instrument(skip(ctx))]
async fn run_libp2p_swarm(ctx: &impl Context) -> Result<(), Error> {
    tracing::info!("initializing the p2p network");

    // Convert the listen `Url`s from the config into `Multiaddr`s.
    tracing::debug!("parsing listen addresses");
    let mut listen_addrs: Vec<Multiaddr> = Vec::new();
    for addr in ctx.config().signer.p2p.listen_on.iter() {
        listen_addrs.extend(addr.try_into_multiaddrs()?);
    }

    // Convert the seed `Url`s from the config into `Multiaddr`s.
    tracing::debug!("parsing seed addresses");
    let mut seed_addrs: Vec<Multiaddr> = Vec::new();
    for addr in ctx.config().signer.p2p.seeds.iter() {
        seed_addrs.extend(addr.try_into_multiaddrs()?);
    }

    // Build the swarm.
    tracing::debug!("building the libp2p swarm");
    let mut swarm = SignerSwarmBuilder::new(&ctx.config().signer.stacks_account.private_key)
        .add_listen_endpoints(&listen_addrs)
        .add_seed_addrs(&seed_addrs)
        .build()?;

    // Start the libp2p swarm. This will run until either the shutdown signal is
    // received, or an unrecoverable error has occurred.
    tracing::info!("starting the libp2p swarm");
    swarm.start(ctx).await.map_err(|error| {
        tracing::error!(%error, "error executing the libp2p swarm");
        let _ = ctx.signal(SignerSignal::Command(SignerCommand::Shutdown));
        error.into()
    })
}

/// Runs the Stacks event observer server.
async fn run_stacks_event_observer(ctx: &impl Context) -> Result<(), Error> {
    tracing::info!("initializing the Stacks event observer server");

    let pool = get_connection_pool();
    let pool_store = PgStore::from(pool);
    // Build the signer API application
    let app = Router::new()
        .route("/", get(api::status_handler))
        .route("/new_block", post(api::new_block_handler::<PgStore>))
        .with_state(pool_store);

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
                if let Ok(SignerSignal::Command(SignerCommand::Shutdown)) = signal.recv().await {
                    tracing::info!("stopping the Stacks event observer server");
                    break;
                }
            }
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "error running Stacks event observer server");
            let _ = ctx.signal(SignerSignal::Command(SignerCommand::Shutdown));
            error.into()
        })
}
