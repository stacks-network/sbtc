use std::path::PathBuf;

use axum::routing::get;
use axum::routing::post;
use axum::Router;
use cfg_if::cfg_if;
use clap::Parser;
use signer::api;
use signer::api::ApiState;
use signer::config::Settings;
use signer::context::Context;
use signer::context::SignerContext;
use signer::error::Error;
use signer::network::libp2p::SignerSwarmBuilder;
use signer::storage::postgres::PgStore;
use tokio::signal;

// TODO: Should this be part of the SignerContext?
fn get_connection_pool(uri: &url::Url) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(uri.as_str())
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
    // TODO(497): The whole logging thing should be revisited. We should support
    //   enabling different layers, i.e. for pretty console, for opentelem, etc.
    //sbtc::logging::setup_logging("info,signer=debug", false);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // Parse the command line arguments.
    let args = SignerArgs::parse();

    let settings = Settings::new(args.config)?;

    // Initialize the signer context.
    let context = SignerContext::init(settings)?;

    // Run the application components concurrently. We're `join!`ing them
    // here so that every component can shut itself down gracefully when
    // the shutdown signal is received.
    //
    // Note that we must use `join` here instead of `select` as `select` would
    // immediately abort the remaining tasks on the first completion, which
    // deprives the other tasks of the opportunity to shut down gracefully. This
    // is the reason we also use the `run_checked` helper method, which will
    // intercept errors and send a shutdown signal to the other components if an error
    // does occur, otherwise the `join` will continue running indefinitely.
    let _ = tokio::join!(
        // Our global termination signal watcher. This does not run using `run_checked`
        // as it sends its own shutdown signal.
        run_shutdown_signal_watcher(&context),
        // The rest of our services which run concurrently, and must all be
        // running for the signer to be operational.
        run_checked(run_stacks_event_observer, &context),
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
        ctx.get_termination_handle().signal_shutdown();
        return Err(error);
    }

    Ok(())
}

/// Runs the shutdown-signal watcher. On Unix systems, this listens for SIGHUP,
/// SIGTERM, and SIGINT. On other systems, it listens for Ctrl-C.
#[tracing::instrument(skip(ctx))]
async fn run_shutdown_signal_watcher(ctx: &impl Context) -> Result<(), Error> {
    let mut term = ctx.get_termination_handle();

    cfg_if! {
        // If we are on a Unix system, we can listen for more signals.
        if #[cfg(unix)] {
            let mut terminate = tokio::signal::unix::signal(signal::unix::SignalKind::terminate())?;
            let mut hangup = tokio::signal::unix::signal(signal::unix::SignalKind::hangup())?;
            let mut interrupt = tokio::signal::unix::signal(signal::unix::SignalKind::interrupt())?;

            tokio::select! {
                // If the shutdown signal is received, we'll shut down the signal watcher
                // by returning early; the rest of the components have already received
                // the shutdown signal.
                _ = term.wait_for_shutdown() => {
                    tracing::info!("termination signal received, signal watcher is shutting down");
                    return Ok(());
                },
                // SIGTERM (kill -15 "nice")
                _ = terminate.recv() => {
                    tracing::info!(signal = "SIGTERM", "received termination signal");
                },
                // SIGHUP (kill -1)
                _ = hangup.recv() => {
                    tracing::info!(signal = "SIGHUP", "received termination signal");
                },
                // Ctrl-C will be received as a SIGINT (kill -2)
                _ = interrupt.recv() => {
                    tracing::info!(signal = "SIGINT", "received termination signal");
                },
            }
        // Otherwise, we'll just listen for Ctrl-C, which is the most portable.
        } else {
            tokio::select! {
                // If the shutdown signal is received, we'll shut down the signal watcher
                // by returning early; the rest of the components have already received
                // the shutdown signal.
                Ok(_) = ctx.wait_for_shutdown() => {
                    tracing::info!("termination signal received, signal watcher is shutting down");
                    return Ok(());
                },
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!(signal = "Ctrl+C", "received termination signal");
                }
            }

        }
    }

    // Send the shutdown signal to the rest of the application.
    tracing::info!("sending shutdown signal to the application");
    term.signal_shutdown();

    Ok(())
}

/// Runs the libp2p swarm.
#[tracing::instrument(skip(ctx))]
async fn run_libp2p_swarm(ctx: &impl Context) -> Result<(), Error> {
    tracing::info!("initializing the p2p network");

    // Build the swarm.
    tracing::debug!("building the libp2p swarm");
    let mut swarm = SignerSwarmBuilder::new(&ctx.config().signer.private_key)
        .add_listen_endpoints(&ctx.config().signer.p2p.listen_on)
        .add_seed_addrs(&ctx.config().signer.p2p.seeds)
        .build()?;

    // Start the libp2p swarm. This will run until either the shutdown signal is
    // received, or an unrecoverable error has occurred.
    tracing::info!("starting the libp2p swarm");
    swarm.start(ctx).await.map_err(Error::SignerSwarm)
}

/// Runs the Stacks event observer server.
#[tracing::instrument(skip(ctx))]
async fn run_stacks_event_observer(ctx: &impl Context) -> Result<(), Error> {
    tracing::info!("initializing the Stacks event observer server");

    let pool = get_connection_pool(&ctx.config().signer.db_endpoint);

    let state = ApiState {
        db: PgStore::from(pool),
        settings: ctx.config().clone(),
    };
    // Build the signer API application
    let app = Router::new()
        .route("/", get(api::status_handler))
        .route("/new_block", post(api::new_block_handler))
        .with_state(state);

    let config = ctx.config().signer.event_observer.clone();

    // Bind to the configured address and port
    let listener = tokio::net::TcpListener::bind(config.bind).await.unwrap();

    // Get the termination signal handle.
    let mut term = ctx.get_termination_handle();

    // Run our app with hyper
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // Listen for an application shutdown signal. We need to loop here
            // because we may receive other signals (which we will ignore here).
            term.wait_for_shutdown().await;
            tracing::info!("stopping the Stacks event observer server");
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "error running Stacks event observer server");
            ctx.get_termination_handle().signal_shutdown();
            error.into()
        })
}
