//! Accessors.

use std::collections::HashMap;

use aws_sdk_dynamodb::types::AttributeValue;
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
    chainstate::{ChainstateEntry, ChainstateEntryKey},
    deposit::{DepositEntry, DepositEntryKey, DepositInfoEntry, DepositInfoEntrySearchToken},
    withdrawal::{
        WithdrawalEntry, WithdrawalEntryKey, WithdrawalInfoEntry, WithdrawalInfoEntrySearchToken,
    },
};

// Chainstate ------------------------------------------------------------------

/// Add a chainstate entry.
pub async fn add_chainstate_entry(
    context: &EmilyContext,
    entry: &ChainstateEntry,
) -> Result<(), Error> {
    put_entry(
        &(context.dynamodb_client),
        &context.settings.chainstate_table_name,
        entry,
    )
    .await
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

// TODO(TBD): Add table access functions for chain tip related queries.

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
pub async fn _delete_entry(
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

// TODO(TBD): Test the generic functions with unit tests and a mock.
