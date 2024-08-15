//! Accessors.

use crate::{
    api::models::{common::BlockHeight, withdrawal::WithdrawalId},
    common::error::Error,
};

use crate::{
    api::models::common::{BitcoinTransactionId, Status},
    context::EmilyContext,
};

use super::entries::{
    chainstate::{
        ApiStateEntry, ChainstateEntry, ChainstateTablePrimaryIndex, SpecialApiStateIndex,
    },
    deposit::{
        DepositEntry, DepositEntryKey, DepositInfoEntry, DepositTablePrimaryIndex,
        DepositTableSecondaryIndex,
    },
    withdrawal::{
        WithdrawalEntry, WithdrawalEntryKey, WithdrawalInfoEntry, WithdrawalTablePrimaryIndex,
        WithdrawalTableSecondaryIndex,
    },
    EntryTrait, KeyTrait, TableIndexTrait,
};

// TODO: have different Table structs for each of the table types instead of
// these individual wrappers.

// Deposit ---------------------------------------------------------------------

/// Add deposit entry.
pub async fn add_deposit_entry(context: &EmilyContext, entry: &DepositEntry) -> Result<(), Error> {
    put_entry::<DepositTablePrimaryIndex>(context, entry).await
}

/// Get deposit entry.
pub async fn get_deposit_entry(
    context: &EmilyContext,
    key: &DepositEntryKey,
) -> Result<DepositEntry, Error> {
    get_entry::<DepositTablePrimaryIndex>(context, key).await
}

/// Get deposit entries.
pub async fn get_deposit_entries(
    context: &EmilyContext,
    status: &Status,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<DepositInfoEntry>, Option<String>), Error> {
    query_with_partition_key::<DepositTableSecondaryIndex>(
        context,
        status,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

/// Get deposit entries for a given transaction.
pub async fn get_deposit_entries_for_transaction(
    context: &EmilyContext,
    bitcoin_txid: &BitcoinTransactionId,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<DepositEntry>, Option<String>), Error> {
    query_with_partition_key::<DepositTablePrimaryIndex>(
        context,
        bitcoin_txid,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

// Withdrawal ------------------------------------------------------------------

/// Add withdrawal entry.
pub async fn add_withdrawal_entry(
    context: &EmilyContext,
    entry: &WithdrawalEntry,
) -> Result<(), Error> {
    put_entry::<WithdrawalTablePrimaryIndex>(context, entry).await
}

/// Get withdrawal entry.
pub async fn _get_withdrawal_entry(
    context: &EmilyContext,
    key: &WithdrawalEntryKey,
) -> Result<WithdrawalEntry, Error> {
    get_entry::<WithdrawalTablePrimaryIndex>(context, key).await
}

/// Get all withdrawal with a given id.
pub async fn get_withdrawal_entries_for_id(
    context: &EmilyContext,
    request_id: &WithdrawalId,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<WithdrawalEntry>, Option<String>), Error> {
    query_with_partition_key::<WithdrawalTablePrimaryIndex>(
        context,
        request_id,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

/// Get withdrawal entries.
pub async fn get_withdrawal_entries(
    context: &EmilyContext,
    status: &Status,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<WithdrawalInfoEntry>, Option<String>), Error> {
    query_with_partition_key::<WithdrawalTableSecondaryIndex>(
        context,
        status,
        maybe_next_token,
        maybe_page_size,
    )
    .await
}

// Chainstate ------------------------------------------------------------------

/// Add a chainstate entry.
pub async fn add_chainstate_entry(
    context: &EmilyContext,
    entry: &ChainstateEntry,
) -> Result<(), Error> {
    // Get the existing chainstate entry for height. If there's a conflict
    // then propagate it back to the caller.
    let current_chainstate_entry_result =
        get_chainstate_entry_at_height(context, &entry.key.height)
            .await
            .and_then(|existing_entry| {
                if &existing_entry != entry {
                    Err(Error::InconsistentState(vec![
                        entry.clone(),
                        existing_entry,
                    ]))
                } else {
                    Ok(())
                }
            });

    // Exit here unless this chain height hasn't been detected before.
    match current_chainstate_entry_result {
        // Fall through if there is no existing entry..
        Err(Error::NotFound) => (),
        // ..otherwise exit here.
        irrecoverable_or_okay => {
            return irrecoverable_or_okay;
        }
    };

    // TODO(390): Determine whether the order for these operations is correct
    // given the eventual consistency guarantees of dynamodb.
    //
    // TODO(TBD): Handle api status being "Reorg" during this period.
    let mut api_state = get_api_state(context).await?;
    let blocks_higher_than_current_tip =
        (entry.key.height as i128) - (api_state.chaintip.key.height as i128);

    if blocks_higher_than_current_tip == 1 || api_state.chaintip.key.height == 0 {
        api_state.chaintip = entry.clone();
        // Put the chainstate entry into the table. If two lambdas get exactly here at the same time
        // and have different views of the block hash at this height it would result in two hashes
        // for the same height. This will be explicitly handled when the api attempts to retrieve the
        // chainstate for this height and finds multiple, indicating a conflicting internal state.
        put_entry::<ChainstateTablePrimaryIndex>(context, entry).await?;
        // Version locked api state prevents inconsistencies here.
        set_api_state(context, &api_state).await
    } else if blocks_higher_than_current_tip > 1 {
        // Attempting to put an entry into the table that's significantly higher than the current
        // known chain tip.
        Err(Error::NotAcceptable)
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
        Err(Error::InconsistentState(vec![]))
    }
}

/// Gets the chainstate at the given height, and provides a conflict error
/// if there's a conflict.
pub async fn get_chainstate_entry_at_height(
    context: &EmilyContext,
    height: &BlockHeight,
) -> Result<ChainstateEntry, Error> {
    let (entries, _) =
        query_with_partition_key::<ChainstateTablePrimaryIndex>(context, height, None, None)
            .await?;
    // If there are multiple entries at this height report an inconsistent state
    // error.
    match entries.as_slice() {
        [] => Err(Error::NotFound),
        [single_entry] => Ok(single_entry.clone()),
        [_, ..] => Err(Error::InconsistentState(entries)),
    }
}

/// Get all chainstate entries for a given height.
/// Note that there should only really be one.
pub async fn get_chainstate_entries_for_height(
    context: &EmilyContext,
    height: &BlockHeight,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
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
    put_entry::<SpecialApiStateIndex>(context, api_state).await
}

// Testing ---------------------------------------------------------------------

/// Wipes all the tables.
/// TODO(395): Include check for whether the table is running locally.
#[cfg(feature = "testing")]
pub async fn wipe_all_tables(context: &EmilyContext) -> Result<(), Error> {
    wipe_deposit_table(context).await?;
    wipe_withdrawal_table(context).await?;
    wipe_chainstate_table(context).await?;
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
    maybe_page_size: Option<i32>,
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

#[cfg(feature = "testing")]
async fn wipe<T: TableIndexTrait>(context: &EmilyContext) -> Result<(), Error> {
    <T as TableIndexTrait>::wipe(&context.dynamodb_client, &context.settings).await
}

// TODO(397): Add accessor function unit tests.
