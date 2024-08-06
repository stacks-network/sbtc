//! Accessors.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::{AttributeValue, DeleteRequest, WriteRequest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use serde::{Deserialize, Serialize};

use crate::{
    api::models::{common::BlockHeight, withdrawal::WithdrawalId},
    common::error::Error,
};

use serde_dynamo::Item;

use crate::{
    api::models::common::{BitcoinTransactionId, Status},
    context::EmilyContext,
};

use super::entries::{
    chainstate::{ApiStateEntry, ChainstateEntry, ChainstateEntryKey},
    deposit::{DepositEntry, DepositEntryKey, DepositInfoEntry, DepositInfoEntrySearchToken},
    withdrawal::{
        WithdrawalEntry, WithdrawalEntryKey, WithdrawalInfoEntry, WithdrawalInfoEntrySearchToken,
    },
};

// Deposit ---------------------------------------------------------------------

/// Get deposit entry.
pub async fn get_deposit_entry(
    context: &EmilyContext,
    key: DepositEntryKey,
) -> Result<DepositEntry, Error> {
    get_entry(
        &(context.dynamodb_client),
        &context.settings.deposit_table_name,
        key,
    )
    .await
}

/// Add deposit entry.
pub async fn add_deposit_entry(context: &EmilyContext, entry: &DepositEntry) -> Result<(), Error> {
    put_entry(
        &(context.dynamodb_client),
        &context.settings.deposit_table_name,
        entry,
    )
    .await
}

/// Get deposit entries.
pub async fn get_deposit_entries(
    context: &EmilyContext,
    status: Status,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<DepositInfoEntry>, Option<String>), Error> {
    let partition_key_attribute_name = "OpStatus";
    let maybe_index_name = Some("DepositStatus".to_string());
    query_with_partition_key::<_, DepositInfoEntrySearchToken>(
        &(context.dynamodb_client),
        &context.settings.deposit_table_name,
        status,
        partition_key_attribute_name,
        maybe_page_size,
        maybe_next_token,
        maybe_index_name,
    )
    .await
}

/// Get deposit entries for a given transaction.
pub async fn get_deposit_entries_for_transaction(
    context: &EmilyContext,
    bitcoin_txid: BitcoinTransactionId,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<DepositEntry>, Option<String>), Error> {
    let partition_key_attribute_name = "BitcoinTxid";
    let maybe_index_name = None;
    query_with_partition_key::<_, DepositEntryKey>(
        &(context.dynamodb_client),
        &context.settings.deposit_table_name,
        bitcoin_txid,
        partition_key_attribute_name,
        maybe_page_size,
        maybe_next_token,
        maybe_index_name,
    )
    .await
}

// Withdrawal ------------------------------------------------------------------

/// Add withdrawal entry.
pub async fn add_withdrawal_entry(
    context: &EmilyContext,
    entry: &WithdrawalEntry,
) -> Result<(), Error> {
    put_entry(
        &(context.dynamodb_client),
        &context.settings.withdrawal_table_name,
        entry,
    )
    .await
}

/// Get withdrawal entry.
pub async fn _get_withdrawal_entry(
    context: &EmilyContext,
    key: WithdrawalEntryKey,
) -> Result<WithdrawalEntry, Error> {
    get_entry(
        &(context.dynamodb_client),
        &context.settings.withdrawal_table_name,
        key,
    )
    .await
}

/// Get all withdrawal with a given id.
pub async fn get_withdrawal_entries_for_id(
    context: &EmilyContext,
    request_id: WithdrawalId,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<WithdrawalEntry>, Option<String>), Error> {
    let partition_key_attribute_name = "RequestId";
    let maybe_index_name = None;
    query_with_partition_key::<_, WithdrawalEntryKey>(
        &(context.dynamodb_client),
        &context.settings.withdrawal_table_name,
        request_id,
        partition_key_attribute_name,
        maybe_page_size,
        maybe_next_token,
        maybe_index_name,
    )
    .await
}

/// Get withdrawal entries.
pub async fn get_withdrawal_entries(
    context: &EmilyContext,
    status: Status,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<WithdrawalInfoEntry>, Option<String>), Error> {
    let partition_key_attribute_name = "OpStatus";
    let maybe_index_name = Some("WithdrawalStatus".to_string());
    query_with_partition_key::<_, WithdrawalInfoEntrySearchToken>(
        &(context.dynamodb_client),
        &context.settings.withdrawal_table_name,
        status,
        partition_key_attribute_name,
        maybe_page_size,
        maybe_next_token,
        maybe_index_name,
    )
    .await
}

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
    wipe_table::<DepositEntry, DepositEntryKey>(
        &context.dynamodb_client,
        context.settings.deposit_table_name.as_str(),
        |entry: DepositEntry| entry.key,
    )
    .await
}

/// Wipes the withdrawal table.
#[cfg(feature = "testing")]
async fn wipe_withdrawal_table(context: &EmilyContext) -> Result<(), Error> {
    wipe_table::<WithdrawalEntry, WithdrawalEntryKey>(
        &context.dynamodb_client,
        context.settings.withdrawal_table_name.as_str(),
        |entry: WithdrawalEntry| entry.key,
    )
    .await
}

/// Wipes the chainstate table.
#[cfg(feature = "testing")]
async fn wipe_chainstate_table(context: &EmilyContext) -> Result<(), Error> {
    delete_entry(
        &context.dynamodb_client,
        context.settings.chainstate_table_name.as_str(),
        ApiStateEntry::key(),
    )
    .await?;
    wipe_table::<ChainstateEntry, ChainstateEntryKey>(
        &context.dynamodb_client,
        context.settings.chainstate_table_name.as_str(),
        |entry: ChainstateEntry| entry.key,
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
    let current_chainstate_entry_result = get_chainstate_entry_at_height(context, entry.key.height)
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
    let blocks_higher_than_current_tip = (entry.key.height as i128) - (api_state.chaintip.key.height as i128);

    if blocks_higher_than_current_tip == 1 || api_state.chaintip.key.height == 0 {
        api_state.chaintip = entry.clone();
        // Put the chainstate entry into the table. If two lambdas get exactly here at the same time
        // and have different views of the block hash at this height it would result in two hashes
        // for the same height. This will be explicitly handled when the api attempts to retrieve the
        // chainstate for this height and finds multiple, indicating a conflicting internal state.
        put_entry(
            &context.dynamodb_client,
            &context.settings.chainstate_table_name,
            entry,
        )
        .await?;
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
    height: BlockHeight,
) -> Result<ChainstateEntry, Error> {
    let partition_key_attribute_name = "Height";
    let entries: Vec<ChainstateEntry> =
        query_with_partition_key_without_pages::<_, ChainstateEntryKey>(
            &(context.dynamodb_client),
            &context.settings.chainstate_table_name,
            height,
            partition_key_attribute_name,
            None,
        )
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
    height: BlockHeight,
    maybe_next_token: Option<String>,
    maybe_page_size: Option<i32>,
) -> Result<(Vec<ChainstateEntry>, Option<String>), Error> {
    let partition_key_attribute_name = "Height";
    let maybe_index_name = None;
    query_with_partition_key::<_, ChainstateEntryKey>(
        &(context.dynamodb_client),
        &context.settings.chainstate_table_name,
        height,
        partition_key_attribute_name,
        maybe_page_size,
        maybe_next_token,
        maybe_index_name,
    )
    .await
}

/// Gets the state of the API.
pub async fn get_api_state(context: &EmilyContext) -> Result<ApiStateEntry, Error> {
    let get_api_state_result: Result<ApiStateEntry, Error> = get_entry(
        &(context.dynamodb_client),
        &context.settings.chainstate_table_name,
        ApiStateEntry::key(),
    )
    .await;

    match get_api_state_result {
        // If the API state wasn't found then initialize it into the table.
        // TODO(390): Handle any race conditions with the version field in case
        // the entry was initialized and then updated after creation.
        Err(Error::NotFound) => {
            let initial_api_state_entry = ApiStateEntry::default();
            put_entry(
                &(context.dynamodb_client),
                &context.settings.chainstate_table_name,
                &initial_api_state_entry,
            )
            .await?;
            Ok(initial_api_state_entry)
        }
        result => result,
    }
}

/// Sets the API state.
/// TODO(TBD): Include the relevant logic for updating the entry version.
pub async fn set_api_state(context: &EmilyContext, api_state: &ApiStateEntry) -> Result<(), Error> {
    put_entry(
        &(context.dynamodb_client),
        &context.settings.chainstate_table_name,
        api_state,
    )
    .await
}

/// Sets a new chain tip.
pub async fn _set_chain_tip(
    context: &EmilyContext,
    new_chaintip: &ChainstateEntry,
) -> Result<(), Error> {
    let mut api_state = get_api_state(context).await?;
    api_state.chaintip = new_chaintip.clone();
    set_api_state(context, &api_state).await
}

// Generics --------------------------------------------------------------------

/// Generic put table entry.
pub async fn put_entry(
    dynamodb_client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    entry: impl Serialize,
) -> Result<(), Error> {
    // Convert Entry into the type needed for querying.
    let entry_item: Item = serde_dynamo::to_item(&entry)?;
    // Add to the database.
    dynamodb_client
        .put_item()
        .table_name(table_name)
        .set_item(Some(entry_item.into()))
        .send()
        .await?;
    // Return.
    Ok(())
}

/// Generic delete table entry.
pub async fn delete_entry(
    dynamodb_client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    key: impl Serialize,
) -> Result<(), Error> {
    // Convert Entry into the type needed for querying.
    let key_item: Item = serde_dynamo::to_item(&key)?;
    // Add to the database.
    dynamodb_client
        .delete_item()
        .table_name(table_name)
        .set_key(Some(key_item.into()))
        .send()
        .await?;
    // Return.
    Ok(())
}

/// Wipes a specific table.
#[cfg(feature = "testing")]
async fn wipe_table<T, K>(
    dynamodb_client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    key_from_entry: fn(T) -> K,
) -> Result<(), Error>
where
    T: for<'de> Deserialize<'de>,
    K: Serialize,
{
    // Get keys to delete.
    let keys_to_delete: Vec<K> =
        serde_dynamo::from_items(get_all_entries(dynamodb_client, table_name).await?)?
            .into_iter()
            .map(key_from_entry)
            .collect();

    // Delete all entries.
    delete_entries(dynamodb_client, table_name, keys_to_delete).await
}

/// Get all entries from a dynamodb table.
async fn get_all_entries(
    dynamodb_client: &aws_sdk_dynamodb::Client,
    table_name: &str,
) -> Result<Vec<HashMap<String, AttributeValue>>, Error> {
    // Create vector to aggregate items in.
    let mut all_items: Vec<HashMap<String, AttributeValue>> = Vec::new();

    // Create the base scan builder with the table name.
    let scan_builder = dynamodb_client.scan().table_name(table_name);

    // Scan the table for as many entries as possible.
    let mut scan_output = scan_builder.clone().send().await?;

    // Put items into aggregate list.
    all_items.extend_from_slice(scan_output.items());

    // Continue to query until the scan is done.
    while let Some(exclusive_start_key) = scan_output.last_evaluated_key {
        scan_output = scan_builder
            .clone()
            .set_exclusive_start_key(Some(exclusive_start_key))
            .send()
            .await?;
        all_items.extend_from_slice(scan_output.items());
    }

    Ok(all_items)
}

/// Deletes every entry in a table with the specified keys.
async fn delete_entries<K>(
    dynamodb_client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    keys_to_delete: Vec<K>,
) -> Result<(), Error>
where
    K: Serialize,
{
    let mut write_delete_requests: Vec<WriteRequest> = Vec::new();
    for key in keys_to_delete {
        let key_item = serde_dynamo::to_item::<K, Item>(key)?;
        let write_request = WriteRequest::builder()
            .delete_request(
                DeleteRequest::builder()
                    .set_key(Some(key_item.into()))
                    .build()?,
            )
            .build();
        write_delete_requests.push(write_request);
    }

    // Execute the deletes in chunks.
    for chunk in write_delete_requests.chunks(25) {
        dynamodb_client
            .batch_write_item()
            .request_items(table_name, chunk.to_vec())
            .send()
            .await?;
    }

    Ok(())
}

/// Generic table get.
pub async fn get_entry<T>(
    dynamodb_client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    key: impl Serialize,
) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    // Convert key into the type needed for querying.
    let key_item: Item = serde_dynamo::to_item(key)?;
    // Query the database.
    let get_item_output = dynamodb_client
        .get_item()
        .table_name(table_name)
        .set_key(Some(key_item.into()))
        .send()
        .await?;
    // Get DynamoDB item.
    let item = get_item_output.item.ok_or(Error::NotFound)?;
    // Convert item into entry.
    let entry = serde_dynamo::from_item(item)?;
    // Return.
    Ok(entry)
}

/// Generic table query that queries for a partition key but doesn't use pages.
/// This function is best used for accessing entries that shouldn't have multiple
/// entries for a primary key but potentially can.
async fn query_with_partition_key_without_pages<T, K>(
    dynamodb_client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    partition_key: impl Serialize,
    partition_key_attribute_name: &str,
    maybe_index_name: Option<String>,
) -> Result<Vec<T>, Error>
where
    T: for<'de> Deserialize<'de>,
    K: Serialize + for<'de> Deserialize<'de>,
{
    query_with_partition_key::<T, K>(
        dynamodb_client,
        table_name,
        partition_key,
        partition_key_attribute_name,
        None,
        None,
        maybe_index_name,
    )
    .await
    .map(|(entries, _)| entries)
}

/// Generic table query for all attributes with a given primary key.
pub async fn query_with_partition_key<T, K>(
    dynamodb_client: &aws_sdk_dynamodb::Client,
    table_name: &str,
    partition_key: impl Serialize,
    partition_key_attribute_name: &str,
    maybe_page_size: Option<i32>,
    maybe_next_token: Option<String>,
    maybe_index_name: Option<String>,
) -> Result<(Vec<T>, Option<String>), Error>
where
    T: for<'de> Deserialize<'de>,
    K: Serialize + for<'de> Deserialize<'de>,
{
    // Convert inputs into the types needed for querying.
    let exclusive_start_key = maybe_exclusive_start_key_from_next_token::<K>(maybe_next_token)?;
    let partition_key_attribute_value = serde_dynamo::to_attribute_value(partition_key)?;
    // Query the database.
    let query_output = dynamodb_client
        .query()
        .table_name(table_name)
        .set_exclusive_start_key(exclusive_start_key)
        .set_limit(maybe_page_size)
        .set_index_name(maybe_index_name)
        .key_condition_expression("#pk = :v")
        .expression_attribute_names("#pk", partition_key_attribute_name)
        .expression_attribute_values(":v", partition_key_attribute_value)
        .send()
        .await?;
    // Convert data into output format.
    let entries: Vec<T> = serde_dynamo::from_items(query_output.items.unwrap_or_default())?;
    let next_token =
        maybe_next_token_from_last_evaluated_key::<K>(query_output.last_evaluated_key)?;
    // Return.
    Ok((entries, next_token))
}

// Utilities -------------------------------------------------------------------

/// Converts an optional `HashMap<String, AttributeValue>` representing the last evaluated key
/// into an optional token string. If the `Option` contains a value, it is deserialized into a type `T`
/// and then serialized into a token string.
pub fn maybe_next_token_from_last_evaluated_key<T>(
    maybe_last_evaluated_key: Option<HashMap<String, AttributeValue>>,
) -> Result<Option<String>, Error>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let maybe_next_token = maybe_last_evaluated_key
        .map(|key| serde_dynamo::from_item(key))
        .transpose()?
        .map(|token_data: T| tokenize(token_data))
        .transpose()?;
    Ok(maybe_next_token)
}

/// Turns an optional key into a token.
pub fn tokenize<T>(key: T) -> Result<String, Error>
where
    T: Serialize,
{
    let serialied = serde_json::to_string(&key)?;
    let encoded: String = URL_SAFE_NO_PAD.encode(serialied);
    Ok(encoded)
}

/// Converts an optional token string into an optional `HashMap<String, AttributeValue>` representing
/// the exclusive start key. If the `Option` contains a value, it is deserialized into a type `T`
/// and then serialized into a `HashMap<String, AttributeValue>`.
pub fn maybe_exclusive_start_key_from_next_token<T>(
    maybe_next_token: Option<String>,
) -> Result<Option<HashMap<String, AttributeValue>>, Error>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let maybe_exclusive_start_key = maybe_next_token
        .map(|next_token| detokenize(next_token))
        .transpose()?
        .map(|token_data: T| serde_dynamo::to_item(token_data))
        .transpose()?
        .map(|token_item: Item| token_item.into());
    Ok(maybe_exclusive_start_key)
}

/// Turns an optional token into a key.
pub fn detokenize<T>(token: String) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    let decoded = URL_SAFE_NO_PAD.decode(token)?;
    let deserialized = serde_json::from_slice::<T>(&decoded)?;
    Ok(deserialized)
}

// TODO(397): Add accessor function unit tests.
