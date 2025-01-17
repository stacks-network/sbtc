//! Accessors.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
use serde_dynamo::Item;

use tracing::{debug, warn};

use crate::api::models::limits::{AccountLimits, Limits};
use crate::common::error::{Error, Inconsistency};

use crate::{api::models::common::Status, context::EmilyContext};

use super::entries::deposit::{
    DepositInfoByRecipientEntry, DepositTableByRecipientSecondaryIndex, ValidatedDepositUpdate,
};
use super::entries::limits::{
    LimitEntry, LimitEntryKey, LimitTablePrimaryIndex, GLOBAL_CAP_ACCOUNT,
};
use super::entries::withdrawal::ValidatedWithdrawalUpdate;
use super::entries::{
    chainstate::{
        ApiStateEntry, ApiStatus, ChainstateEntry, ChainstateTablePrimaryIndex,
        SpecialApiStateIndex,
    },
    deposit::{
        DepositEntry, DepositEntryKey, DepositInfoEntry, DepositTablePrimaryIndex,
        DepositTableSecondaryIndex, DepositUpdatePackage,
    },
    withdrawal::{
        WithdrawalEntry, WithdrawalInfoEntry, WithdrawalTablePrimaryIndex,
        WithdrawalTableSecondaryIndex, WithdrawalUpdatePackage,
    },
    EntryTrait, KeyTrait, TableIndexTrait, VersionedEntryTrait, VersionedTableIndexTrait,
};

// TODO: have different Table structs for each of the table types instead of
// these individual wrappers.

// Deposit ---------------------------------------------------------------------

/// Add deposit entry.
pub async fn add_deposit_entry(context: &EmilyContext, entry: &DepositEntry) -> Result<(), Error> {
    put_entry::<DepositTablePrimaryIndex>(context, entry).await
}

/// Sets / updates an existing deposit entry.
pub async fn set_deposit_entry(
    context: &EmilyContext,
    entry: &mut DepositEntry,
) -> Result<(), Error> {
    put_entry_with_version::<DepositTablePrimaryIndex>(context, entry).await
}

/// Get deposit entry.
pub async fn get_deposit_entry(
    context: &EmilyContext,
    key: &DepositEntryKey,
) -> Result<DepositEntry, Error> {
    let entry = get_entry::<DepositTablePrimaryIndex>(context, key).await?;
    #[cfg(feature = "testing")]
    Ok(entry)
}

/// Get deposit entries.
pub async fn get_deposit_entries(
    context: &EmilyContext,
    status: &Status,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<u16>,
) -> Result<(Vec<DepositInfoEntry>, Option<String>), Error> {
    query_with_partition_key::<DepositTableSecondaryIndex>(
        context,
        status,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

/// Get deposit entries by recipient.
#[allow(clippy::ptr_arg)]
pub async fn get_deposit_entries_by_recipient(
    context: &EmilyContext,
    recipient: &String,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<u16>,
) -> Result<(Vec<DepositInfoByRecipientEntry>, Option<String>), Error> {
    query_with_partition_key::<DepositTableByRecipientSecondaryIndex>(
        context,
        recipient,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

/// Hacky exhasutive list of all statuses that we will iterate over in order to
/// get every deposit present.
const ALL_STATUSES: &[Status] = &[
    Status::Accepted,
    Status::Confirmed,
    Status::Failed,
    Status::Pending,
    Status::Reprocessing,
];

/// Gets all deposit entries modified from (on or after) a given height.
pub async fn get_all_deposit_entries_modified_from_height(
    context: &EmilyContext,
    minimum_height: u64,
    maybe_page_size: Option<u16>,
) -> Result<Vec<DepositInfoEntry>, Error> {
    let mut all = Vec::new();
    for status in ALL_STATUSES {
        let mut received = get_all_deposit_entries_modified_from_height_with_status(
            context,
            status,
            minimum_height,
            maybe_page_size,
        )
        .await?;
        all.append(&mut received);
    }
    // Return.
    Ok(all)
}

/// Gets all deposit entries modified from (on or after) a given height.
pub async fn get_all_deposit_entries_modified_from_height_with_status(
    context: &EmilyContext,
    status: &Status,
    minimum_height: u64,
    maybe_page_size: Option<u16>,
) -> Result<Vec<DepositInfoEntry>, Error> {
    // Make the query.
    query_all_with_partition_and_sort_key::<DepositTableSecondaryIndex>(
        context,
        status,
        &minimum_height,
        ">=",
        maybe_page_size,
    )
    .await
}

/// Get deposit entries for a given transaction.
#[allow(clippy::ptr_arg)]
pub async fn get_deposit_entries_for_transaction(
    context: &EmilyContext,
    bitcoin_txid: &String,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<u16>,
) -> Result<(Vec<DepositEntry>, Option<String>), Error> {
    query_with_partition_key::<DepositTablePrimaryIndex>(
        context,
        bitcoin_txid,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

/// Pulls in a deposit entry and then updates it, retrying the specified number
/// of times when there's a version conflict.
///
/// TODO(792): Combine this with the withdrawal version.
pub async fn pull_and_update_deposit_with_retry(
    context: &EmilyContext,
    update: ValidatedDepositUpdate,
    retries: u16,
) -> Result<DepositEntry, Error> {
    for _ in 0..retries {
        // Get original deposit entry.
        let deposit_entry = get_deposit_entry(context, &update.key).await?;
        // Return the existing entry if no update is necessary.
        if update.is_unnecessary(&deposit_entry) {
            return Ok(deposit_entry);
        }
        // Make the update package.
        let update_package: DepositUpdatePackage =
            DepositUpdatePackage::try_from(&deposit_entry, update.clone())?;
        // Attempt to update the deposit.
        match update_deposit(context, &update_package).await {
            Err(Error::VersionConflict) => {
                // Retry.
                continue;
            }
            otherwise => {
                return otherwise;
            }
        }
    }
    // Failed to update due to a version conflict
    Err(Error::VersionConflict)
}

/// Updates a deposit.
pub async fn update_deposit(
    context: &EmilyContext,
    update: &DepositUpdatePackage,
) -> Result<DepositEntry, Error> {
    // Setup the update procedure.
    let update_expression: &str = " SET
        History = list_append(History, :new_event),
        Version = Version + :one,
        OpStatus = :new_op_status,
        LastUpdateHeight = :new_height,
        LastUpdateBlockHash = :new_hash
    ";
    // Ensure the version field is what we expect it to be.
    let condition_expression = "attribute_exists(Version) AND Version = :expected_version";
    // Make the key item.
    let key_item: Item = serde_dynamo::to_item(&update.key)?;
    // Get simplified status enum.
    let status: Status = (&update.event.status).into();
    // Build the update.
    context
        .dynamodb_client
        .update_item()
        .table_name(&context.settings.deposit_table_name)
        .set_key(Some(key_item.into()))
        .expression_attribute_values(":new_op_status", serde_dynamo::to_attribute_value(&status)?)
        .expression_attribute_values(
            ":new_height",
            serde_dynamo::to_attribute_value(update.event.stacks_block_height)?,
        )
        .expression_attribute_values(
            ":new_hash",
            serde_dynamo::to_attribute_value(&update.event.stacks_block_hash)?,
        )
        .expression_attribute_values(
            ":new_event",
            serde_dynamo::to_attribute_value(vec![update.event.clone()])?,
        )
        .expression_attribute_values(
            ":expected_version",
            serde_dynamo::to_attribute_value(update.version)?,
        )
        .expression_attribute_values(":one", AttributeValue::N(1.to_string()))
        .condition_expression(condition_expression)
        .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
        .update_expression(update_expression)
        .send()
        .await?
        .attributes
        .ok_or(Error::Debug("Failed updating withdrawal".into()))
        .and_then(|attributes| {
            serde_dynamo::from_item::<Item, DepositEntry>(attributes.into()).map_err(Error::from)
        })
}

// Withdrawal ------------------------------------------------------------------

/// Add withdrawal entry.
pub async fn add_withdrawal_entry(
    context: &EmilyContext,
    entry: &WithdrawalEntry,
) -> Result<(), Error> {
    put_entry::<WithdrawalTablePrimaryIndex>(context, entry).await
}

/// Sets / updates an existing withdrawal entry.
pub async fn set_withdrawal_entry(
    context: &EmilyContext,
    entry: &mut WithdrawalEntry,
) -> Result<(), Error> {
    put_entry_with_version::<WithdrawalTablePrimaryIndex>(context, entry).await
}

/// Get withdrawal entry.
pub async fn get_withdrawal_entry(
    context: &EmilyContext,
    key: &u64,
) -> Result<WithdrawalEntry, Error> {
    // Get the entries.
    let num_to_retrieve_if_multiple = 3;
    let (entries, _) = query_with_partition_key::<WithdrawalTablePrimaryIndex>(
        context,
        key,
        None,
        Some(num_to_retrieve_if_multiple),
    )
    .await?;
    // Return.
    match entries.as_slice() {
        [] => Err(Error::NotFound),
        [withdrawal] =>
        {
            #[cfg(feature = "testing")]
            Ok(withdrawal.clone())
        }
        _ => {
            warn!(
                "Found too many withdrawals for id {key}: {}",
                serde_json::to_string_pretty(&entries)?
            );
            Err(Error::Debug(format!(
                "Found too many withdrawals for id {key}: {entries:?}"
            )))
        }
    }
}

/// Get withdrawal entries.
pub async fn get_withdrawal_entries(
    context: &EmilyContext,
    status: &Status,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<u16>,
) -> Result<(Vec<WithdrawalInfoEntry>, Option<String>), Error> {
    query_with_partition_key::<WithdrawalTableSecondaryIndex>(
        context,
        status,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

/// Gets all withdrawal entries modified from (on or after) a given height.
pub async fn get_all_withdrawal_entries_modified_from_height(
    context: &EmilyContext,
    minimum_height: u64,
    maybe_page_size: Option<u16>,
) -> Result<Vec<WithdrawalInfoEntry>, Error> {
    let mut all = Vec::new();
    for status in ALL_STATUSES {
        let mut received = get_all_withdrawal_entries_modified_from_height_with_status(
            context,
            status,
            minimum_height,
            maybe_page_size,
        )
        .await?;
        all.append(&mut received);
    }
    // Return.
    Ok(all)
}

/// Gets all withdrawal entries modified from (on or after) a given height.
pub async fn get_all_withdrawal_entries_modified_from_height_with_status(
    context: &EmilyContext,
    status: &Status,
    minimum_height: u64,
    maybe_page_size: Option<u16>,
) -> Result<Vec<WithdrawalInfoEntry>, Error> {
    // Make the query.
    query_all_with_partition_and_sort_key::<WithdrawalTableSecondaryIndex>(
        context,
        status,
        &minimum_height,
        ">=",
        maybe_page_size,
    )
    .await
}

/// Pulls in a withdrawal entry and then updates it, retrying the specified number
/// of times when there's a version conflict.
///
/// TODO(792): Combine this with the deposit version.
pub async fn pull_and_update_withdrawal_with_retry(
    context: &EmilyContext,
    update: ValidatedWithdrawalUpdate,
    retries: u16,
) -> Result<WithdrawalEntry, Error> {
    for _ in 0..retries {
        // Get original withdrawal entry.
        let entry = get_withdrawal_entry(context, &update.request_id).await?;
        // Return the existing entry if no update is necessary.
        if update.is_unnecessary(&entry) {
            return Ok(entry);
        }
        // Make the update package.
        let update_package = WithdrawalUpdatePackage::try_from(&entry, update.clone())?;
        // Attempt to update the deposit.
        match update_withdrawal(context, &update_package).await {
            Err(Error::VersionConflict) => {
                // Retry.
                continue;
            }
            otherwise => {
                return otherwise;
            }
        }
    }
    // Failed to update due to a version conflict
    Err(Error::VersionConflict)
}

/// Updates a withdrawal based on the update package.
pub async fn update_withdrawal(
    context: &EmilyContext,
    update: &WithdrawalUpdatePackage,
) -> Result<WithdrawalEntry, Error> {
    // Setup the update procedure.
    let update_expression: &str = " SET
        History = list_append(History, :new_event),
        Version = Version + :one,
        OpStatus = :new_op_status,
        LastUpdateHeight = :new_height,
        LastUpdateBlockHash = :new_hash
    ";
    // Ensure the version field is what we expect it to be.
    let condition_expression = "attribute_exists(Version) AND Version = :expected_version";
    // Make the key item.
    let key_item: Item = serde_dynamo::to_item(&update.key)?;
    // Get simplified status enum.
    let status: Status = (&update.event.status).into();
    // Execute the update.
    context
        .dynamodb_client
        .update_item()
        .table_name(&context.settings.withdrawal_table_name)
        .set_key(Some(key_item.into()))
        .expression_attribute_values(":new_op_status", serde_dynamo::to_attribute_value(&status)?)
        .expression_attribute_values(
            ":new_height",
            serde_dynamo::to_attribute_value(update.event.stacks_block_height)?,
        )
        .expression_attribute_values(
            ":new_hash",
            serde_dynamo::to_attribute_value(&update.event.stacks_block_hash)?,
        )
        .expression_attribute_values(
            ":new_event",
            serde_dynamo::to_attribute_value(vec![update.event.clone()])?,
        )
        .expression_attribute_values(
            ":expected_version",
            serde_dynamo::to_attribute_value(update.version)?,
        )
        .expression_attribute_values(":one", AttributeValue::N(1.to_string()))
        .condition_expression(condition_expression)
        .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
        .update_expression(update_expression)
        .send()
        .await?
        .attributes
        .ok_or(Error::Debug("Failed updating withdrawal".into()))
        .and_then(|attributes| {
            serde_dynamo::from_item::<Item, WithdrawalEntry>(attributes.into()).map_err(Error::from)
        })
}

// Chainstate ------------------------------------------------------------------

/// Adds a chainstate entry to the database with the specified number of retries.
pub async fn add_chainstate_entry_with_retry(
    context: &EmilyContext,
    entry: &ChainstateEntry,
    retries: u16,
) -> Result<(), Error> {
    for _ in 0..retries {
        match add_chainstate_entry(context, entry).await {
            Err(Error::VersionConflict) => {
                // Retry.
                continue;
            }
            otherwise => {
                return otherwise;
            }
        }
    }
    Err(Error::TooManyInternalRetries)
}

/// Add a chainstate entry.
pub async fn add_chainstate_entry(
    context: &EmilyContext,
    entry: &ChainstateEntry,
) -> Result<(), Error> {
    // Get the current api state and give up if reorging.
    let mut api_state = get_api_state(context).await?;
    debug!("Adding chainstate entry, current api state: {api_state:?}");
    if let ApiStatus::Reorg(reorg_chaintip) = &api_state.api_status {
        if reorg_chaintip != entry {
            warn!("Attempting to update chainstate during a reorg [ new entry {entry:?} | reorg chaintip {reorg_chaintip:?} ]");
            return Err(Error::InconsistentState(Inconsistency::ItemUpdate(
                "Attempting to update chainstate during a reorg.".to_string(),
            )));
        }
    }

    // Get the existing chainstate entry for height. If there's a conflict
    // then propagate it back to the caller.
    let current_chainstate_entry_result =
        get_chainstate_entry_at_height(context, &entry.key.height)
            .await
            .and_then(|existing_entry: ChainstateEntry| {
                if &existing_entry != entry {
                    debug!("Inconsistent state because of a conflict with the current interpretation of a height.");
                    debug!("Existing entry: {existing_entry:?} | New entry: {entry:?}");
                    Err(Error::from_inconsistent_chainstate_entry(existing_entry))
                } else {
                    Ok(())
                }
            });

    match current_chainstate_entry_result {
        // Fall through if there is no existing entry..
        Err(Error::NotFound) => (),
        // If the chainstate entry is already in the table but the api believes the chaintip is behind
        // this entry, that means a reorg has occurred and the api got pulled back, but then it went
        // back to the chain it had been following before the reorg. This is a stable state, and we
        // will skip putting it into the table but will update the api state.
        Ok(_) if api_state.chaintip().key.height < entry.key.height => {
            api_state.api_status = ApiStatus::Stable(entry.clone());
            return set_api_state(context, &api_state).await;
        }
        // If there's an inconsistency BUT the chaintip is behind the inconsistency, this means we've gone
        // back in time a bit and are now overwriting the old chainstate entries that we had put in before.
        // While the chainstate table is inconsistent with the current chainstate, it's actually a stable
        // state because we can resolve that inconsistency by just overwriting the old entry/s at that height.
        // Note that it would be really odd for there to be multiple chainstates at the same height and for
        // the chain tip to be behind them, but luckily in this scenario we can be fine by just deleting all
        // the entries above.
        Err(Error::InconsistentState(Inconsistency::Chainstates(chainstates)))
            if api_state.chaintip().key.height < entry.key.height =>
        {
            for chainstate in chainstates {
                // Remove the entry from the table.
                let existing_entry: ChainstateEntry = chainstate.into();
                delete_entry::<ChainstateTablePrimaryIndex>(context, &existing_entry.key).await?;
            }
        }
        // ..otherwise exit here.
        irrecoverable_or_okay => {
            return irrecoverable_or_okay;
        }
    };

    let chaintip: ChainstateEntry = api_state.chaintip();
    let blocks_higher_than_current_tip = (entry.key.height as i128) - (chaintip.key.height as i128);
    if blocks_higher_than_current_tip == 1 || chaintip.key.height == 0 {
        api_state.api_status = ApiStatus::Stable(entry.clone());
        // Put the chainstate entry into the table. If two lambdas get exactly here at the same time
        // and have different views of the block hash at this height it would result in two hashes
        // for the same height. This will be explicitly handled when the api attempts to retrieve the
        // chainstate for this height and finds multiple, indicating a conflicting internal state.
        put_entry::<ChainstateTablePrimaryIndex>(context, entry).await?;
        // Version locked api state prevents inconsistencies here.
        set_api_state(context, &api_state).await
    } else if blocks_higher_than_current_tip > 1 {
        warn!(
            "Attempting to add a chaintip that is more than one block ({}) higher than the current tip. {:?} -> {:?}",
            blocks_higher_than_current_tip,
            chaintip,
            entry,
        );
        // TODO(TBD): Determine the ramifications of allowing a chaintip to be added much
        // higher than expected.
        api_state.api_status = ApiStatus::Stable(entry.clone());
        put_entry::<ChainstateTablePrimaryIndex>(context, entry).await?;
        set_api_state(context, &api_state).await
    } else {
        // Current tip is higher than the entry we attempted to emplace
        // but there is no record of the chainstate at the current height.
        // This means that we're trying to back populate the chainstate from a period
        // that has never had a history before.
        //
        // We'll consider this an internal state inconsistency because we choose to
        // interpret reverting to filling out an earlier point in time to mean that a
        // reorg has reset the knowledge of the API maintainer to an earlier time.
        //
        // Worst case this causes an unnecessary reorg.
        Err(Error::from_inconsistent_chainstate_entry(chaintip))
    }
}

/// Gets the chainstate at the given height, and provides a conflict error
/// if there's a conflict.
pub async fn get_chainstate_entry_at_height(
    context: &EmilyContext,
    height: &u64,
) -> Result<ChainstateEntry, Error> {
    let (entries, _) =
        query_with_partition_key::<ChainstateTablePrimaryIndex>(context, height, None, None)
            .await?;
    // If there are multiple entries at this height report an inconsistent state
    // error.
    match entries.as_slice() {
        [] => Err(Error::NotFound),
        [single_entry] => Ok(single_entry.clone()),
        [_, ..] => Err(Error::from_inconsistent_chainstate_entries(entries)),
    }
}

/// Get all chainstate entries for a given height.
/// Note that there should only really be one.
pub async fn get_chainstate_entries_for_height(
    context: &EmilyContext,
    height: &u64,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<u16>,
) -> Result<(Vec<ChainstateEntry>, Option<String>), Error> {
    query_with_partition_key::<ChainstateTablePrimaryIndex>(
        context,
        height,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

/// Gets the state of the API.
pub async fn get_api_state(context: &EmilyContext) -> Result<ApiStateEntry, Error> {
    let get_api_state_result =
        get_entry::<SpecialApiStateIndex>(context, &ApiStateEntry::key()).await;
    match get_api_state_result {
        // If the API state wasn't found then initialize it into the table.
        // TODO(390): Handle any race conditions with the version field in case
        // the entry was initialized and then updated after creation.
        Err(Error::NotFound) => {
            let initial_api_state_entry = ApiStateEntry::default();
            put_entry::<SpecialApiStateIndex>(context, &initial_api_state_entry).await?;
            Ok(initial_api_state_entry)
        }
        result => result,
    }
}

/// Sets the API state.
/// TODO(TBD): Include the relevant logic for updating the entry version.
pub async fn set_api_state(context: &EmilyContext, api_state: &ApiStateEntry) -> Result<(), Error> {
    put_entry_with_version::<SpecialApiStateIndex>(context, &mut api_state.clone()).await
}

// Limits ----------------------------------------------------------------------

/// Note, this function provides the direct output structure for the api call
/// to get the limits for the full sbtc system, and therefore is breaching the
/// typical contract for these accessor functions. We do this here because the
/// data for this sigular entry is spread across the entire table in a way that
/// needs to be first gathered, then filtered. It does not neatly fit into a
/// return type that is within the table as an entry.
pub async fn get_limits(context: &EmilyContext) -> Result<Limits, Error> {
    // Get all the entries of the limit table. This table shouldn't be too large.
    let all_entries =
        LimitTablePrimaryIndex::get_all_entries(&context.dynamodb_client, &context.settings)
            .await?;
    // Create the default global cap.
    let default_global_cap = context.settings.default_limits.clone();
    let mut global_cap = LimitEntry {
        key: LimitEntryKey {
            account: GLOBAL_CAP_ACCOUNT.to_string(),
            // Make the timestamp the smallest possible to any other timestamp
            // will be greater than this.
            timestamp: 0,
        },
        peg_cap: default_global_cap.peg_cap,
        per_deposit_minimum: default_global_cap.per_deposit_minimum,
        per_deposit_cap: default_global_cap.per_deposit_cap,
        per_withdrawal_cap: default_global_cap.per_withdrawal_cap,
    };
    // Aggregate all the latest entries by account.
    let mut limit_by_account: HashMap<String, LimitEntry> = HashMap::new();
    for entry in all_entries.iter() {
        let account = &entry.key.account;
        if account == GLOBAL_CAP_ACCOUNT {
            // If the account is the global cap account and either we haven't encountered
            // the cap before or the cap we have encountered is older than the current one
            // then set the global cap to the current entry.
            if global_cap.key.timestamp < entry.key.timestamp {
                global_cap = entry.clone();
            }
        } else if limit_by_account.contains_key(account) {
            // If the account is already in the map then update the entry if the current
            // entry is newer.
            if let Some(existing_entry) = limit_by_account.get_mut(account) {
                if existing_entry.key.timestamp < entry.key.timestamp {
                    *existing_entry = entry.clone();
                }
            }
        } else {
            // If the account isn't in the map then insert it.
            limit_by_account.insert(entry.key.account.clone(), entry.clone());
        }
    }
    // Turn the account limits into the correct structure.
    let account_caps = limit_by_account
        .into_iter()
        .filter(|(_, limit_entry)| !limit_entry.is_empty())
        .map(|(account, limit_entry)| (account, AccountLimits::from(limit_entry)))
        .collect();
    // Get the global limit for the whole thing.
    Ok(Limits {
        peg_cap: global_cap.peg_cap,
        per_deposit_minimum: global_cap.per_deposit_minimum,
        per_deposit_cap: global_cap.per_deposit_cap,
        per_withdrawal_cap: global_cap.per_withdrawal_cap,
        account_caps,
    })
}

/// Get the limit for a specific account.
#[allow(clippy::ptr_arg)]
pub async fn get_limit_for_account(
    context: &EmilyContext,
    account: &String,
) -> Result<LimitEntry, Error> {
    // Make the query.
    let (mut entries, _) = query_with_partition_key::<LimitTablePrimaryIndex>(
        context,
        account,
        None,
        // Only get the most recent entry. The internals of this query uses
        // scan_index_forward = false.
        Some(1),
    )
    .await?;
    // The limit is set to 1 so there should always only be one entry returned,
    // but for the sake of redundancy also get the most recent entry.
    entries.sort_by_key(|entry| entry.key.timestamp);
    entries.pop().ok_or(Error::NotFound)
}

/// Set the limit for a specific account.
pub async fn set_limit_for_account(
    context: &EmilyContext,
    limit: &LimitEntry,
) -> Result<(), Error> {
    put_entry::<LimitTablePrimaryIndex>(context, limit).await
}

// Testing ---------------------------------------------------------------------

/// Wipes all the tables.
/// TODO(395): Include check for whether the table is running locally.
#[cfg(feature = "testing")]
pub async fn wipe_all_tables(context: &EmilyContext) -> Result<(), Error> {
    wipe_deposit_table(context).await?;
    wipe_withdrawal_table(context).await?;
    wipe_chainstate_table(context).await?;
    wipe_limit_table(context).await?;
    Ok(())
}

/// Wipes the deposit table.
#[cfg(feature = "testing")]
async fn wipe_deposit_table(context: &EmilyContext) -> Result<(), Error> {
    wipe::<DepositTablePrimaryIndex>(context).await
}

/// Wipes the withdrawal table.
#[cfg(feature = "testing")]
async fn wipe_withdrawal_table(context: &EmilyContext) -> Result<(), Error> {
    wipe::<WithdrawalTablePrimaryIndex>(context).await
}

/// Wipes the chainstate table.
#[cfg(feature = "testing")]
async fn wipe_chainstate_table(context: &EmilyContext) -> Result<(), Error> {
    delete_entry::<SpecialApiStateIndex>(context, &ApiStateEntry::key()).await?;
    wipe::<ChainstateTablePrimaryIndex>(context).await
}

/// Wipes the limit table.
#[cfg(feature = "testing")]
async fn wipe_limit_table(context: &EmilyContext) -> Result<(), Error> {
    wipe::<LimitTablePrimaryIndex>(context).await
}

// Generics --------------------------------------------------------------------

async fn get_entry<T: TableIndexTrait>(
    context: &EmilyContext,
    key: &<<T as TableIndexTrait>::Entry as EntryTrait>::Key,
) -> Result<<T as TableIndexTrait>::Entry, Error> {
    <T as TableIndexTrait>::get_entry(&context.dynamodb_client, &context.settings, key).await
}

async fn put_entry<T: TableIndexTrait>(
    context: &EmilyContext,
    entry: &<T as TableIndexTrait>::Entry,
) -> Result<(), Error> {
    <T as TableIndexTrait>::put_entry(&context.dynamodb_client, &context.settings, entry).await
}

async fn put_entry_with_version<T: VersionedTableIndexTrait>(
    context: &EmilyContext,
    entry: &mut <T as TableIndexTrait>::Entry,
) -> Result<(), Error>
where
    <T as TableIndexTrait>::Entry: VersionedEntryTrait,
{
    <T as VersionedTableIndexTrait>::put_entry_with_version(
        &context.dynamodb_client,
        &context.settings,
        entry,
    )
    .await
}

async fn delete_entry<T: TableIndexTrait>(
    context: &EmilyContext,
    key: &<<T as TableIndexTrait>::Entry as EntryTrait>::Key,
) -> Result<(), Error> {
    <T as TableIndexTrait>::delete_entry(&context.dynamodb_client, &context.settings, key).await
}

async fn query_with_partition_key<T: TableIndexTrait>(
    context: &EmilyContext,
    parition_key: &<<<T as TableIndexTrait>::Entry as EntryTrait>::Key as KeyTrait>::PartitionKey,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<u16>,
) -> Result<(Vec<<T as TableIndexTrait>::Entry>, Option<String>), Error> {
    <T as TableIndexTrait>::query_with_partition_key(
        &context.dynamodb_client,
        &context.settings,
        parition_key,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

async fn query_all_with_partition_and_sort_key<T: TableIndexTrait>(
    context: &EmilyContext,
    parition_key: &<<<T as TableIndexTrait>::Entry as EntryTrait>::Key as KeyTrait>::PartitionKey,
    sort_key: &<<<T as TableIndexTrait>::Entry as EntryTrait>::Key as KeyTrait>::SortKey,
    sort_key_operator: &str,
    maybe_page_size: Option<u16>,
) -> Result<Vec<<T as TableIndexTrait>::Entry>, Error> {
    // item aggregator.
    let mut items: Vec<<T as TableIndexTrait>::Entry> = Vec::new();
    // Next token.
    let mut next_token: Option<String> = None;
    // Loop over all items.
    loop {
        let mut new_items: Vec<<T as TableIndexTrait>::Entry>;
        (new_items, next_token) = <T as TableIndexTrait>::query_with_partition_and_sort_key(
            &context.dynamodb_client,
            &context.settings,
            parition_key,
            sort_key,
            sort_key_operator,
            next_token,
            maybe_page_size,
        )
        .await?;
        // add new items.
        items.append(&mut new_items);
        if next_token.is_none() {
            // If there are no more entries then end the loop.
            break;
        }
    }
    // Return the items.
    Ok(items)
}

#[cfg(feature = "testing")]
async fn wipe<T: TableIndexTrait>(context: &EmilyContext) -> Result<(), Error> {
    <T as TableIndexTrait>::wipe(&context.dynamodb_client, &context.settings).await
}

// TODO(397): Add accessor function unit tests.
