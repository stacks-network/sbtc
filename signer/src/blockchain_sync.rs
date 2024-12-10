//! Contains blockchain synchronization logic.

use std::time::Duration;

use clarity::types::chainstate::StacksBlockId;

use crate::{
    bitcoin::BitcoinInteract,
    block_observer,
    context::Context,
    error::Error,
    stacks::api::{GetNakamotoStartHeight as _, StacksInteract as _},
    storage::{model, DbRead as _},
};

/// Helper function to determine the Nakamoto activation height (in Bitcoin
/// block height).
#[tracing::instrument(skip_all)]
pub async fn determine_nakamoto_activation_height(ctx: &impl Context) -> Result<u64, Error> {
    let mut term = ctx.get_termination_handle();
    let stacks_client = ctx.get_stacks_client();

    // If the nakamoto start height is provided in the config, use that value.
    // Otherwise, get the value from the Stacks node's PoX-info endpoint.
    let nakamoto_activation_height = {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            if let Ok(pox_info) = stacks_client.get_pox_info().await {
                let Some(nakamoto_activation_height) = pox_info.nakamoto_start_height() else {
                    tracing::error!("missing nakamoto activation height");
                    return Err(Error::MissingNakamotoStartHeight);
                };
                break nakamoto_activation_height;
            }

            tokio::select! {
                _ = term.wait_for_shutdown() => return Err(Error::SignerShutdown),
                _ = interval.tick() => {},
            }
        }
    };

    Ok(nakamoto_activation_height)
}

/// Back-fills Bitcoin and Stacks blockchains' blocks from the current Stacks
/// tip back to the Nakamoto activation height (in Bitcoin block height).
///
/// This method uses the Stacks node's RPC endpoints to retrieve the necessary
/// information regarding the current chain tip, and proceeds to back-fill
/// first the Bitcoin blockchain, and then the Stacks blockchain.
#[tracing::instrument(skip_all)]
pub async fn sync_blockchains(
    ctx: &impl Context,
    nakamoto_activation_height: u64,
) -> Result<(), Error> {
    let mut term = ctx.get_termination_handle();
    let stacks_client = ctx.get_stacks_client();

    // Get the current tenure tip and anchor (Bitcoin) block information.
    tracing::debug!("fetching current tenure tip and anchor block info");
    let current_tenure = stacks_client.get_tenure_info().await?;

    tracing::debug!(
        tenure_tip = %current_tenure.tip_block_id,
        "retrieving tenure tip based on reported stacks tenure tip"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let tenure = loop {
        if let Ok(tenure) = stacks_client.get_tenure(current_tenure.tip_block_id).await {
            tracing::debug!("got tenure");
            break tenure;
        }

        tracing::debug!("retry get tenure");
        tokio::select! {
            _ = term.wait_for_shutdown() => return Ok(()),
            _ = interval.tick() => {},
        }
    };

    // Back-fill the Bitcoin blockchain first.
    tracing::info!(
        anchor_block_hash = %tenure.anchor_block_hash,
        anchor_block_height = %tenure.anchor_block_height,
        "beginning bitcoin block sync"
    );
    sync_bitcoin_blocks(
        ctx,
        &tenure.anchor_block_hash,
        tenure.anchor_block_height,
        nakamoto_activation_height,
    )
    .await?;

    tracing::info!(
        tenure_tip = %current_tenure.tip_block_id,
        "beginning stacks block sync"
    );
    sync_stacks_blocks(
        ctx,
        &current_tenure.tip_block_id,
        nakamoto_activation_height,
    )
    .await?;

    Ok(())
}

/// Performs a back-fill of the Bitcoin blockchain from the provided chain-tip,
/// filling the `bitcoin_blocks` table in the database.
#[tracing::instrument(
    skip_all,
    fields(chain_tip, chain_tip_height, nakamoto_activation_height)
)]
pub async fn sync_bitcoin_blocks(
    ctx: &impl Context,
    chain_tip: &model::BitcoinBlockHash,
    _chain_tip_height: u64,
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
            return Ok(());
        }

        // Retrieve the next Bitcoin block from the Bitcoin Core node. If the
        // block is missing, we will fail the sync.
        let block = bitcoin_client.get_block(&next_bitcoin_block).await?;
        let Some(block) = block else {
            tracing::error!("failed to get block from Bitcoin Core, failing sync");
            return Err(Error::MissingBitcoinBlock(next_bitcoin_block));
        };

        // If we can't read the BIP34 block height from the retrieved block, we
        // will fail the sync because we need this information both in the db
        // and for the sync logic (to know when to stop).
        let Ok(block_height) = block.bip34_block_height() else {
            tracing::error!("missing bip34 block height, failing sync");
            return Err(Error::MissingBitcoinBlockHeight(next_bitcoin_block.into()));
        };

        // TODO: I thought this would be a good check, but I ran into issues
        // getting it to work properly so maybe my assumptions are wrong..?
        //
        // If the block height reported by Bitcoin core doesn't match the
        // burnchain block height reported by the Stacks node, we fail the sync
        // as well as this is likely indicative that something is "off".
        // if block_height != chain_tip_height {
        //     tracing::error!("block height mismatch, failing sync");
        //     return Err(Error::BitcoinBlockHeightMismatch(
        //         next_bitcoin_block.into(),
        //         block_height,
        //         chain_tip_height,
        //     ));
        // }

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
        // This method also extracts sBTC-related transactions.
        block_observer::write_bitcoin_block(&storage, &bitcoin_client, &block).await?;
    }
}

/// Performs a back-fill of the Stacks blockchain from the provided chain-tip,
/// filling the `stacks_blocks` table in the database.
#[tracing::instrument(skip_all, fields(
    chain_tip = %chain_tip,
    nakamoto_activation_height
))]
pub async fn sync_stacks_blocks(
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
        //
        // Note: This specifically does not use the `fetch_unknown_ancestors`
        // method as this is intended to be run on startup, which for an initial
        // sync can result in high memory usage if all blocks from all tenures
        // are fetched/buffered.
        let tenure = stacks_client.get_tenure(next_tenure_tip).await?;

        // If there are no blocks in the tenure (which shouldn't happen), then
        // we fail the sync.
        if tenure.blocks().is_empty() {
            tracing::error!("received an empty tenure from the stacks node, failing sync");
            return Err(Error::EmptyTenure(next_tenure_tip));
        }

        // Retrieve the anchor Bitcoin block from our local storage. We should
        // have already processed this block and thus it should exist.
        let bitcoin_block = storage.get_bitcoin_block(&tenure.anchor_block_hash).await?;

        // If the Bitcoin block is missing, we fail the sync because then our
        // stacks-block-linking is broken.
        let Some(bitcoin_block) = bitcoin_block else {
            tracing::error!("missing anchor block, failing sync");
            return Err(Error::MissingBitcoinBlock(tenure.anchor_block_hash));
        };

        // We use `get_tenure` to fetch all of the Nakamoto blocks for each
        // tenure, walking backwards, which accepts a `StacksBlockId` as its
        // parameter. As we're walking backwards, we grab the first block in
        // the tenure and use its parent block ID for the next iteration, which
        // should give us the previous tenure and all of its blocks.
        let first_block = tenure
            .blocks()
            .first()
            .ok_or(Error::EmptyTenure(next_tenure_tip))?;

        next_tenure_tip = first_block.header.parent_block_id;

        // We re-use the same code as the block observer to write the blocks to
        // the database.
        block_observer::write_stacks_blocks(
            &ctx.get_storage_mut(),
            &ctx.config().signer.deployer,
            &[tenure],
        )
        .await?;

        // If the block height of the anchor block is equal to the nakamoto
        // activation height then we're done.
        if bitcoin_block.block_height == nakamoto_activation_height {
            tracing::info!("nakamoto activation height reached, stacks block-sync completed");
            return Ok(());
        }
    }
}

/// Helper function to wait for the Stacks node to reach the Nakamoto activation
/// height.
#[tracing::instrument(skip_all, fields(%nakamoto_activation_height))]
pub async fn wait_for_nakamoto_activation_height(
    ctx: &impl Context,
    nakamoto_activation_height: u64,
) -> Result<(), Error> {
    let mut term = ctx.get_termination_handle();
    let stacks_client = ctx.get_stacks_client();

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        if let Ok(node_info) = stacks_client.get_node_info().await {
            if node_info.burn_block_height > nakamoto_activation_height {
                tracing::info!(
                    current_height = %node_info.burn_block_height,
                    "stacks node has reached the nakamoto activation height"
                );

                break;
            }

            tracing::info!(
                current = %node_info.burn_block_height,
                target = %nakamoto_activation_height,
                "waiting for stacks node to reach nakamoto activation height"
            );
        }

        tokio::select! {
            _ = term.wait_for_shutdown() => return Ok(()),
            _ = interval.tick() => {},
        }
    }

    Ok(())
}

/// Waits for the Stacks node to report that it is fully-synced. It does this
/// by polling the node's `info` endpoint every 5 seconds until the response's
/// `is_fully_synced` field is `true`.
#[tracing::instrument(skip_all)]
pub async fn wait_for_stacks_node_to_report_full_sync(ctx: &impl Context) -> Result<(), Error> {
    let mut term = ctx.get_termination_handle();
    let stacks_client = ctx.get_stacks_client();

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        match stacks_client.get_node_info().await {
            Ok(node_info) if node_info.is_fully_synced => break,
            Ok(_) => {
                tracing::info!("Stacks node reports that it is not yet fully-synced, waiting...")
            }
            Err(error) => {
                tracing::warn!(%error, "Failed to get node info from Stacks node, will retry")
            }
        }

        tokio::select! {
            _ = term.wait_for_shutdown() => return Ok(()),
            _ = interval.tick() => {},
        }
    }
    Ok(())
}
