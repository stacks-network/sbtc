use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::http::Request;
use axum::http::Response;
use cfg_if::cfg_if;
use clap::Parser;
use clap::ValueEnum;
use lru::LruCache;
use signer::api;
use signer::api::ApiState;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::bitcoin::zmq::BitcoinCoreMessageStream;
use signer::block_observer;
use signer::blocklist_client::BlocklistClient;
use signer::config::Settings;
use signer::context::Context;
use signer::context::SignerContext;
use signer::emily_client::EmilyClient;
use signer::error::Error;
use signer::network::libp2p::SignerSwarmBuilder;
use signer::network::P2PNetwork;
use signer::request_decider::RequestDeciderEventLoop;
use signer::stacks::api::StacksClient;
use signer::storage::postgres::PgStore;
use signer::transaction_coordinator;
use signer::transaction_signer;
use signer::util::ApiFallbackClient;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::Instrument;
use tracing::Span;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogOutputFormat {
    Json,
    Pretty,
}

/// Command line arguments for the signer.
#[derive(Debug, Parser)]
#[clap(name = "sBTC Signer")]
struct SignerArgs {
    /// Optional path to the configuration file. If not provided, it is expected
    /// that all parameters are provided via environment variables.
    #[clap(short = 'c', long, required = false)]
    config: Option<PathBuf>,

    /// If this flag is set, the signer will attempt to automatically apply any
    /// pending migrations to the database on startup.
    #[clap(long)]
    migrate_db: bool,

    #[clap(short = 'o', long = "output-format", default_value = "pretty")]
    output_format: Option<LogOutputFormat>,
}

#[tokio::main]
#[tracing::instrument(name = "signer")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse the command line arguments.
    let args = SignerArgs::parse();

    // Configure the binary's stdout/err output based on the provided output format.
    let pretty = matches!(args.output_format, Some(LogOutputFormat::Pretty));
    signer::logging::setup_logging("info,signer=debug", pretty);

    tracing::info!(
        rust_version = signer::RUSTC_VERSION,
        revision = signer::GIT_COMMIT,
        arch = signer::TARGET_ARCH,
        env_abi = signer::TARGET_ENV_ABI,
        "starting the sBTC signer",
    );

    // Load the configuration file and/or environment variables.
    let settings = Settings::new(args.config)?;
    signer::metrics::setup_metrics(settings.signer.prometheus_exporter_endpoint);

    // Open a connection to the signer db.
    let db = PgStore::connect(settings.signer.db_endpoint.as_str()).await?;

    // Apply any pending migrations if automatic migrations are enabled.
    if args.migrate_db {
        db.apply_migrations().await?;
    }

    // Initialize the signer context.
    let context = SignerContext::<
        _,
        ApiFallbackClient<BitcoinCoreClient>,
        ApiFallbackClient<StacksClient>,
        ApiFallbackClient<EmilyClient>,
    >::init(settings, db)?;

    // TODO: We should first check "another source of truth" for the current
    // signing set, and only assume we are bootstrapping if that source is
    // empty.
    let settings = context.config();
    for signer in settings.signer.bootstrap_signing_set() {
        context.state().current_signer_set().add_signer(signer);
    }

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
        run_shutdown_signal_watcher(context.clone()),
        // The rest of our services which run concurrently, and must all be
        // running for the signer to be operational.
        run_checked(run_api, &context),
        run_checked(run_libp2p_swarm, &context),
        run_checked(run_block_observer, &context),
        run_checked(run_request_decider, &context),
        run_checked(run_transaction_coordinator, &context),
        run_checked(run_transaction_signer, &context),
    );

    Ok(())
}

/// A helper method that captures errors from the provided future and sends a
/// shutdown signal to the application if an error is encountered. This is needed
/// as otherwise the application would continue running indefinitely (since no
/// shutdown signal is sent automatically on error).
async fn run_checked<F, Fut, C>(f: F, ctx: &C) -> Result<(), Error>
where
    C: Context,
    F: FnOnce(C) -> Fut,
    Fut: std::future::Future<Output = Result<(), Error>>,
{
    if let Err(error) = f(ctx.clone()).await {
        tracing::error!(%error, "a fatal error occurred; shutting down the application");
        ctx.get_termination_handle().signal_shutdown();
        return Err(error);
    }

    Ok(())
}

/// Runs the shutdown-signal watcher. On Unix systems, this listens for SIGHUP,
/// SIGTERM, and SIGINT. On other systems, it listens for Ctrl-C.
#[tracing::instrument(skip(ctx), name = "shutdown-watcher")]
async fn run_shutdown_signal_watcher(ctx: impl Context) -> Result<(), Error> {
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
#[tracing::instrument(skip_all, name = "p2p")]
async fn run_libp2p_swarm(ctx: impl Context) -> Result<(), Error> {
    tracing::info!("initializing the p2p network");

    // Build the swarm.
    tracing::debug!("building the libp2p swarm");
    let config = ctx.config();
    let mut swarm =
        SignerSwarmBuilder::new(&config.signer.private_key, config.signer.p2p.enable_mdns)
            .add_listen_endpoints(&ctx.config().signer.p2p.listen_on)
            .add_seed_addrs(&ctx.config().signer.p2p.seeds)
            .add_external_addresses(&ctx.config().signer.p2p.public_endpoints)
            .build()?;

    // Start the libp2p swarm. This will run until either the shutdown signal is
    // received, or an unrecoverable error has occurred.
    tracing::info!("starting the libp2p swarm");
    swarm
        .start(&ctx)
        .in_current_span()
        .await
        .map_err(Error::SignerSwarm)
}

/// Runs the signer's API server, which includes the Stacks event observer.
#[tracing::instrument(skip_all, name = "api")]
async fn run_api(ctx: impl Context + 'static) -> Result<(), Error> {
    let socket_addr = ctx.config().signer.event_observer.bind;
    tracing::info!(%socket_addr, "initializing the signer API server");

    let state = ApiState { ctx: ctx.clone() };

    let request_id = Arc::new(AtomicU64::new(0));

    // Build the signer API application
    let app = api::get_router()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    tracing::info_span!("api-request",
                        uri = %request.uri(),
                        method = %request.method(),
                        id = tracing::field::Empty,
                    )
                })
                .on_request(move |_: &Request<_>, span: &Span| {
                    span.record("id", request_id.fetch_add(1, Ordering::SeqCst));
                    tracing::trace!("processing request");
                })
                .on_response(|_: &Response<_>, duration: Duration, _: &Span| {
                    tracing::trace!(duration_ms = duration.as_millis(), "request completed");
                }),
        )
        .with_state(state);

    // Bind to the configured address and port
    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .expect("failed to bind the signer API to configured address");

    // Get the termination signal handle.
    let mut term = ctx.get_termination_handle();

    // Run our app with hyper
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // Listen for an application shutdown signal. We need to loop here
            // because we may receive other signals (which we will ignore here).
            term.wait_for_shutdown().await;
            tracing::info!("stopping the signer API server");
        })
        .await
        .map_err(|error| {
            tracing::error!(%error, "error running the signer API server");
            ctx.get_termination_handle().signal_shutdown();
            error.into()
        })
}

/// Run the block observer event-loop.
async fn run_block_observer(ctx: impl Context) -> Result<(), Error> {
    let config = ctx.config().clone();

    // TODO: Need to handle multiple endpoints, so some sort of
    // failover-stream-wrapper.
    let stream = BitcoinCoreMessageStream::new_from_endpoint(
        config.bitcoin.block_hash_stream_endpoints[0].as_str(),
        &["hashblock"],
    )
    .await
    .unwrap();

    // TODO: We should have a new() method that builds from the context
    let block_observer = block_observer::BlockObserver {
        context: ctx,
        bitcoin_blocks: stream.to_block_hash_stream(),
    };

    block_observer.run().await
}

/// Run the transaction signer event-loop.
async fn run_transaction_signer(ctx: impl Context) -> Result<(), Error> {
    let config = ctx.config().clone();
    let network = P2PNetwork::new(&ctx);

    // The _ as usize cast is fine, since we know that
    // MAX_SIGNER_STATE_MACHINES is less than u32::MAX, and we only support
    // running this binary on 32 or 64-bit CPUs.
    let max_state_machines = NonZeroUsize::new(signer::MAX_SIGNER_STATE_MACHINES as usize)
        .ok_or(Error::TypeConversion)?;

    let signer = transaction_signer::TxSignerEventLoop {
        network,
        context: ctx.clone(),
        context_window: config.signer.context_window,
        threshold: config.signer.bootstrap_signatures_required.into(),
        rng: rand::thread_rng(),
        signer_private_key: config.signer.private_key,
        wsts_state_machines: LruCache::new(max_state_machines),
        dkg_begin_pause: config.signer.dkg_begin_pause.map(Duration::from_secs),
    };

    signer.run().await
}

/// Run the transaction coordinator event-loop.
async fn run_transaction_coordinator(ctx: impl Context) -> Result<(), Error> {
    let config = ctx.config().clone();
    let private_key = config.signer.private_key;
    let network = P2PNetwork::new(&ctx);

    let coord = transaction_coordinator::TxCoordinatorEventLoop {
        network,
        context: ctx,
        context_window: config.signer.context_window,
        private_key,
        signing_round_max_duration: config.signer.signer_round_max_duration,
        bitcoin_presign_request_max_duration: config.signer.bitcoin_presign_request_max_duration,
        threshold: config.signer.bootstrap_signatures_required,
        dkg_max_duration: config.signer.dkg_max_duration,
        is_epoch3: false,
    };

    coord.run().await
}

/// Run the request decider event-loop.
async fn run_request_decider(ctx: impl Context) -> Result<(), Error> {
    let config = ctx.config().clone();
    let network = P2PNetwork::new(&ctx);

    let decider = RequestDeciderEventLoop {
        network,
        context: ctx.clone(),
        context_window: config.signer.context_window,
        blocklist_checker: BlocklistClient::new(&ctx),
        signer_private_key: config.signer.private_key,
    };

    decider.run().await
}
