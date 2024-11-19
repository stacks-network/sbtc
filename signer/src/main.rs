use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use axum::routing::get;
use axum::routing::post;
use axum::Router;
use cfg_if::cfg_if;
use clap::Parser;
use clarity::types::chainstate::StacksBlockId;
use signer::api;
use signer::api::ApiState;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::bitcoin::zmq::BitcoinCoreMessageStream;
use signer::bitcoin::BitcoinInteract;
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
use signer::stacks::api::GetNakamotoStartHeight;
use signer::stacks::api::StacksClient;
use signer::stacks::api::StacksInteract;
use signer::storage::model;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead;
use signer::storage::DbWrite;
use signer::transaction_coordinator;
use signer::transaction_signer;
use signer::util::ApiFallbackClient;
use tokio::signal;

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
}

#[tokio::main]
#[tracing::instrument(name = "signer")]
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

    // Load the configuration file and/or environment variables.
    let settings = Settings::new(args.config)?;

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

    // Pause until the Stacks node is fully-synced, otherwise we will not be
    // able to properly back-fill blocks and the sBTC signer will generally just
    // not work.
    tracing::info!("waiting for stacks node to report full-sync");
    wait_for_stacks_node_to_report_full_sync(&context).await?;
    tracing::info!("stacks node reports that is is up-to-date");

    // Back-fill the Bitcoin and Stacks blockchains to the Nakamoto activation
    // height.
    tracing::info!("preparing to sync both bitcoin & stacks blockchains back to the nakamoto activation height");
    sync_blockchains(&context).await?;

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
        run_checked(run_stacks_event_observer, &context),
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
#[tracing::instrument(skip(ctx))]
async fn run_libp2p_swarm(ctx: impl Context) -> Result<(), Error> {
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
    swarm.start(&ctx).await.map_err(Error::SignerSwarm)
}

/// Runs the Stacks event observer server.
#[tracing::instrument(skip_all, name = "stacks-event-observer")]
async fn run_stacks_event_observer(ctx: impl Context + 'static) -> Result<(), Error> {
    let socket_addr = ctx.config().signer.event_observer.bind;
    tracing::info!(%socket_addr, "initializing the Stacks event observer server");

    let state = ApiState { ctx: ctx.clone() };

    // Build the signer API application
    let app = Router::new()
        .route("/", get(api::status_handler))
        .route("/new_block", post(api::new_block_handler))
        .with_state(state);

    // Bind to the configured address and port
    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .expect("failed to retrieve event observer bind address from config");

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

    // TODO: Get clients from context when implemented
    let emily_client: ApiFallbackClient<EmilyClient> =
        TryFrom::try_from(&config.emily.endpoints[..])?;
    let stacks_client: ApiFallbackClient<StacksClient> = TryFrom::try_from(&config)?;

    // TODO: We should have a new() method that builds from the context
    let block_observer = block_observer::BlockObserver {
        context: ctx,
        bitcoin_blocks: stream.to_block_hash_stream(),
        stacks_client,
        emily_client,
        horizon: 20,
    };

    block_observer.run().await
}

/// Run the transaction signer event-loop.
async fn run_transaction_signer(ctx: impl Context) -> Result<(), Error> {
    let config = ctx.config().clone();
    let network = P2PNetwork::new(&ctx);

    let signer = transaction_signer::TxSignerEventLoop {
        network,
        context: ctx.clone(),
        context_window: 10000,
        threshold: 2,
        rng: rand::thread_rng(),
        signer_private_key: config.signer.private_key,
        wsts_state_machines: HashMap::new(),
    };

    signer.run().await
}

/// Run the transaction coordinator event-loop.
async fn run_transaction_coordinator(ctx: impl Context) -> Result<(), Error> {
    let private_key = ctx.config().signer.private_key;
    let network = P2PNetwork::new(&ctx);

    let coord = transaction_coordinator::TxCoordinatorEventLoop {
        network,
        context: ctx,
        context_window: 10000,
        private_key,
        signing_round_max_duration: Duration::from_secs(10),
        threshold: 2,
        dkg_max_duration: Duration::from_secs(10),
        sbtc_contracts_deployed: false,
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
        context_window: 10000,
        blocklist_checker: BlocklistClient::new(&ctx),
        signer_private_key: config.signer.private_key,
    };

    decider.run().await
}

async fn sync_blockchains(ctx: &impl Context) -> Result<(), Error> {
    let stacks_client = ctx.get_stacks_client();

    let pox_info = stacks_client.get_pox_info().await?;
    let node_info = stacks_client.get_node_info().await?;
    let Some(nakamoto_activation_height) = pox_info.nakamoto_start_height() else {
        tracing::error!("missing nakamoto activation height, failing sync");
        return Err(Error::MissingNakamotoStartHeight);
    };

    let sortition = stacks_client
        .get_sortition_info(&node_info.stacks_tip_consensus_hash).await?;
 
    sync_bitcoin_blocks(
        ctx, 
        &sortition.burn_block_hash.into(), 
        sortition.burn_block_height, 
        nakamoto_activation_height
    ).await?;

    let tenure = stacks_client.get_tenure_info().await?;

    sync_stacks_blocks(
        ctx, 
        &tenure.tip_block_id,
        nakamoto_activation_height,
    ).await?;
    
    todo!()
}

/// Performs a back-fill of the Bitcoin blockchain from the provided chain-tip,
/// filling the `bitcoin_blocks` table in the database.
async fn sync_bitcoin_blocks(
    ctx: &impl Context,
    chain_tip: &model::BitcoinBlockHash,
    chain_tip_height: u64,
    nakamoto_activation_height: u64,
) -> Result<(), Error> {
    let term = ctx.get_termination_handle();
    let storage = ctx.get_storage_mut();
    let bitcoin_client = ctx.get_bitcoin_client();
    let mut next_bitcoin_block = *chain_tip;

    loop {
        if term.shutdown_signalled() {
            return Ok(());
        }

        tracing::debug!(block_hash = %next_bitcoin_block, "syncing next bitcoin block");

        // Check if we already have the block. If we do, then we have already
        // been synced up to this point and can break out of the loop.
        let existing_block = storage.get_bitcoin_block(&next_bitcoin_block).await?;
        if existing_block.is_some() {
            tracing::info!("reached already-stored block, bitcoin block-sync completed");
            return Ok(())
        }
        
        // Retrieve the next Bitcoin block from the Bitcoin Core node. If the
        // block is missing, we will fail the sync.
        let block = bitcoin_client.get_block(&next_bitcoin_block).await?;
        let Some(block) = block else {
            tracing::error!("failed to get block from Bitcoin Core, failing sync");
            return Err(Error::MissingBitcoinBlock(next_bitcoin_block.into()));
        };

        // If we can't read the BIP34 block height from the retrieved block, we
        // will fail the sync because we need this information both in the db
        // and for the sync logic (to know when to stop).
        let Ok(block_height) = block.bip34_block_height() else {
            tracing::error!("missing bip34 block height, failing sync");
            return Err(Error::MissingBitcoinBlockHeight(next_bitcoin_block.into()));
        };

        // If the block height reported by Bitcoin core doesn't match the
        // burnchain block height reported by the Stacks node, we fail the sync
        // as well as this is likely indicative that something is "off".
        if block_height != chain_tip_height {
            tracing::error!("block height mismatch, failing sync");
            return Err(Error::BitcoinBlockHeightMismatch(next_bitcoin_block.into(), block_height, chain_tip_height));
        }

        // If the block height is less than the Nakamoto activation height, we
        // have reached the end of the sync and can break out of the loop.
        if block_height < nakamoto_activation_height {
            tracing::info!("nakamoto activation height reached, bitcoin block-sync completed");
            return Ok(());
        }

        // The next block that we will process will be this block's parent.
        next_bitcoin_block = block.header.prev_blockhash.into();

        // Write the block to storage. At present there are no FK's for parent
        // blocks, so it's okay that we're writing them in reverse order.
        storage.write_bitcoin_block(&block.into()).await?;
    }
}

/// Performs a back-fill of the Stacks blockchain from the provided chain-tip,
/// filling the `stacks_blocks` table in the database.
#[tracing::instrument(skip_all, fields(
    chain_tip = %chain_tip, 
    nakamoto_activation_height
))]
async fn sync_stacks_blocks(
    ctx: &impl Context, 
    chain_tip: &StacksBlockId,
    nakamoto_activation_height: u64,
) -> Result<(), Error> {
    let term = ctx.get_termination_handle();
    let stacks_client = ctx.get_stacks_client();
    let storage = ctx.get_storage_mut();

    let mut next_tenure_tip = *chain_tip;

    loop {
        if term.shutdown_signalled() {
            return Ok(());
        }

        tracing::debug!(block_id = %next_tenure_tip, "syncing next tenure");

        // Retrieve the tenure from the Stacks node representing the current
        // Stacks chain-tip.
        let tenure = stacks_client.get_tenure(next_tenure_tip).await?;

        // If there are no blocks in the tenure (which shouldn't happen), then
        // we fail the sync.
        if tenure.blocks().is_empty() {
            tracing::error!("received an empty tenure from the stacks node, failing sync");
            return Err(Error::EmptyTenure(next_tenure_tip.into()));
        }

        // Retrieve the anchor Bitcoin block from our local storage. We should
        // have already processed this block and thus it should exist.
        let bitcoin_block = storage
            .get_bitcoin_block(&tenure.anchor_block_hash)
            .await?;

        // If the Bitcoin block is missing, we fail the sync.
        let Some(bitcoin_block) = bitcoin_block else {
            tracing::error!("missing anchor block, failing sync");
            return Err(Error::MissingBitcoinBlock(tenure.anchor_block_hash.into()));
        };

        // We use `get_tenure` to fetch all of the Nakamoto blocks for each
        // tenure, walking backwards, which accepts a `StacksBlockId` as its
        // parameter. As we're walking backwards, we grab the first block in
        // the tenure and use its parent block ID for the next iteration, which
        // should give us the previous tenure and all of its blocks.
        #[allow(clippy::expect_used)]
        let first_block = tenure.blocks()
            .first()
            // We assert that this is not empty above.
            .expect("empty tenure");

        next_tenure_tip = first_block.header.parent_block_id;

        // Iterate through all of the blocks in the tenure and write them to
        // storage.
        for block in tenure.as_stacks_blocks() {
            storage.write_stacks_block(&block).await?;
        }

        // If the block height of the anchor block is equal to the nakamoto
        // activation height then we're done.
        if bitcoin_block.block_height == nakamoto_activation_height {
            tracing::info!("nakamoto activation height reached, stacks block-sync completed");
            return Ok(());
        }
    }
}

/// Waits for the Stacks node to report that it is fully-synced. It does this
/// by polling the node's `info` endpoint every 5 seconds until the response's
/// `is_fully_synced` field is `true`.
#[tracing::instrument(skip_all)]
async fn wait_for_stacks_node_to_report_full_sync(ctx: &impl Context) -> Result<(), Error> {
    let mut term = ctx.get_termination_handle();
    let stacks_client = ctx.get_stacks_client();

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        match stacks_client.get_node_info().await {
            Ok(node_info) if node_info.is_fully_synced => break,
            Ok(_) => tracing::info!("Stacks node reports that it is not yet fully-synced, waiting..."),
            Err(error) => tracing::warn!(%error, "Failed to get node info from Stacks node, will retry"),
        }

        tokio::select! {
            _ = term.wait_for_shutdown() => return Ok(()),
            _ = interval.tick() => {},
        }
    }
    Ok(())
}