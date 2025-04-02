//! Handlers for internal endpoints.

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::api::models::chainstate::Chainstate;
use crate::common::error::{Error, Inconsistency};
use crate::context::EmilyContext;
use crate::database::accessors;
use crate::database::entries::chainstate::{ApiStateEntry, ApiStatus};
use crate::database::entries::deposit::DepositEntry;
use crate::database::entries::withdrawal::WithdrawalEntry;

const MAX_SET_API_STATE_ATTEMPTS_DURING_REORG: u32 = 20;
const ENTRY_UPDATE_RETRIES: u32 = 4;

/// Request for executing a reorg.
#[derive(Debug, Deserialize, Serialize)]
pub struct ExecuteReorgRequest {
    /// New canonical chainstate tip.
    pub canonical_tip: Chainstate,
    /// Conflicting chainstates.
    pub conflicting_chainstates: Vec<Chainstate>,
}

/// Sets the api status to the provided status.
///
/// Return meanings:
/// - Err(e):
///     Something went wrong.
/// - Ok(None):
///     The API status is already what we wanted it to be, so there's
///     no action required.
/// - Ok(Some(ApiStateEntry)):
///     We have successfully converted the api to the state returned.
async fn set_api_state_status(
    context: &EmilyContext,
    new_status: &ApiStatus,
) -> Result<Option<ApiStateEntry>, Error> {
    let mut api_state: ApiStateEntry;
    for attempt_number in 0..MAX_SET_API_STATE_ATTEMPTS_DURING_REORG {
        let original_api_state = accessors::get_api_state(context).await?;
        api_state = original_api_state.clone();

        // Update the api status.
        api_state.api_status = match (new_status, &original_api_state.api_status) {
            (ApiStatus::Reorg(_), ApiStatus::Stable(_))
            | (ApiStatus::Stable(_), ApiStatus::Reorg(_)) => new_status.clone(),
            (ApiStatus::Stable(new_tip), ApiStatus::Stable(old_tip)) => {
                if new_tip == old_tip {
                    return Ok(None);
                } else {
                    new_status.clone()
                }
            }
            // Handle trying to set the api status to reorganizing.
            (ApiStatus::Reorg(new_reorg_tip), ApiStatus::Reorg(current_reorg_tip)) => {
                // Compare only `.key` (stacks height and hash) since old chainstate entries lack
                // `bitcoin_block_height`. A Stacks block always has the same Bitcoin height, so
                // ignoring it prevents false mismatches for old data.
                if new_reorg_tip.key == current_reorg_tip.key {
                    return Ok(None);
                } else {
                    let err_msg: String = format!(
                        "Trying to reorg with new chaintip {new_reorg_tip:?} while the api is reorganizing around the chaintip {current_reorg_tip:?}"
                    );
                    warn!(err_msg);
                    return Err(Error::InconsistentState(Inconsistency::ItemUpdate(err_msg)));
                }
            }
        };

        debug!(
            "Changing Api state from [{original_api_state:?}] to [{api_state:?}]. Attempt {attempt_number} of maximum {MAX_SET_API_STATE_ATTEMPTS_DURING_REORG}."
        );

        // Attempt to set the API state.
        match accessors::set_api_state(context, &api_state).await {
            // We successfully set the API state.
            Ok(()) => {
                info!("Successfully set api state: {:?}.", api_state);
                return Ok(Some(api_state));
            }
            // Retry if there was a version conflict.
            Err(Error::VersionConflict) => {
                debug!("Failed to update API state - retrying: {api_state:?}")
            }
            // If some other error occurred then return from here; this shouldn't
            // happen and something has actually gone wrong.
            e @ Err(_) => e?,
        }
    }
    // Return.
    Err(Error::InternalServer)
}

/// Handler that executes a reorg.
///
/// This function isn't intended to be exposed into any specific endpoint
/// outside of what could maybe be a testing endpoint one day. It handles
/// the internal requests to execute a reorg.
pub async fn execute_reorg_handler(
    context: &EmilyContext,
    request: ExecuteReorgRequest,
) -> Result<impl warp::reply::Reply, Error> {
    info!("Executing a reorg with request {request:?}.");
    let empty_reply = warp::reply::with_status(warp::reply(), StatusCode::NO_CONTENT);

    let new_status = ApiStatus::Reorg(request.canonical_tip.clone().into());
    match set_api_state_status(context, &new_status).await? {
        // Do nothing if we claimed the api correctly.
        Some(_) => {}
        None => {
            return Ok(empty_reply);
        }
    };

    // We have control of the API at this point. For each entry of the deposit
    // and withdrawal table we'll wipe out all the history that's no longer relevant.

    // Get all deposits that would be impacted by this reorg.
    let all_deposits = accessors::get_all_deposit_entries_modified_from_height(
        context,
        request.canonical_tip.stacks_block_height,
        None,
    )
    .await?;

    // Setup debug modified deposit list.
    let mut debug_modified_deposit_entries: Vec<DepositEntry> =
        Vec::with_capacity(all_deposits.len());

    // Kill the history from all the deposits.
    for deposit in all_deposits {
        for attempt in 0..ENTRY_UPDATE_RETRIES {
            let mut entry =
                accessors::get_deposit_entry(context, &deposit.primary_index_key).await?;
            entry.reorganize_around(&request.canonical_tip)?;
            match accessors::set_deposit_entry(context, &mut entry).await {
                Ok(_) => break,
                Err(Error::VersionConflict) => {
                    debug!(
                        "Encountered race condition in updating entry {:?}. Attempt {}/{}",
                        entry, attempt, ENTRY_UPDATE_RETRIES
                    );
                }
                e @ Err(_) => e?,
            }
            // Add modified deposit entries.
            debug_modified_deposit_entries.push(entry);
        }
    }

    // Show updated deposits when in debug mode.
    debug!(
        "Reorganized deposits: {}",
        serde_json::to_string_pretty(&debug_modified_deposit_entries)?
    );

    // Get all withdrawals that would be impacted by this reorg.
    let all_withdrawals = accessors::get_all_withdrawal_entries_modified_from_height(
        context,
        request.canonical_tip.stacks_block_height,
        None,
    )
    .await?;

    // Setup debug modified withdrawal list.
    let mut debug_modified_withdrawal_entries: Vec<WithdrawalEntry> =
        Vec::with_capacity(all_withdrawals.len());

    // Kill the history from all the withdrawals.
    for withdrawal in all_withdrawals {
        for attempt in 0..ENTRY_UPDATE_RETRIES {
            let request_id = withdrawal.primary_index_key.request_id;
            let mut entry = accessors::get_withdrawal_entry(context, &request_id).await?;
            entry.reorganize_around(&request.canonical_tip)?;
            match accessors::set_withdrawal_entry(context, &mut entry).await {
                Ok(_) => break,
                Err(Error::VersionConflict) => {
                    debug!(
                        "Encountered race condition in updating entry {:?}. Attempt {}/{}",
                        entry, attempt, ENTRY_UPDATE_RETRIES
                    );
                }
                e @ Err(_) => e?,
            }
            // Add modified withdrawal entries.
            debug_modified_withdrawal_entries.push(entry);
        }
    }

    // Show updated withdrawals when in debug mode.
    debug!(
        "Reorganized withdrawals: {}",
        serde_json::to_string_pretty(&debug_modified_withdrawal_entries)?
    );

    // Cleanup API state.
    set_api_state_status(context, &ApiStatus::Stable(request.canonical_tip.into())).await?;

    // All good.
    Ok(empty_reply)
}

// TODO: Unit tests.
