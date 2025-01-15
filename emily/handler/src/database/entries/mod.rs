//! This module defines the structures, traits, and implementations necessary for managing
//! entries within a DynamoDB database. It provides generic abstractions for handling different
//! types of database entries, including their indexing, retrieval, insertion, and deletion
//! operations.
//!
//! ## Module Overview
//!
//! The module is divided into several submodules and components:
//!
//! - **Submodules**:
//!   - `chainstate`: Handles entries related to the chain state table.
//!   - `deposit`: Manages entries for the deposit table.
//!   - `withdrawal`: Manages entries for the withdrawal table.
//!
//! - **Structures**:
//!   - `PrimaryIndex<T>`: Wrapper for primary index structures.
//!   - `SecondaryIndex<T>`: Wrapper for secondary index structures.
//!
//! - **Traits**:
//!   - `EntryTrait`: A trait common to all database entries, defining how entries are keyed.
//!   - `KeyTrait`: Defines the structure of a table key, including partition and sort keys.
//!   - `PrimaryIndexTrait`: Used for defining a primary index and its associated table operations.
//!   - `SecondaryIndexTrait`: Extends the `PrimaryIndexTrait` to support secondary indexes.
//!   - `TableIndexTrait`: A base trait that defines common table operations across indexes.
//!
//! - **Implementations**:
//!   - Generic implementations for handling database operations such as get, query, put, and delete
//!     across different types of indexes.
//!
//! ## Database Operations
//!
//! This module abstracts the complexity of interacting with DynamoDB by providing easy-to-use
//! methods for common operations such as:
//!
//! - **Retrieval**: Fetch entries by key or query based on a partition key.
//! - **Insertion**: Add new entries to the database.
//! - **Deletion**: Remove entries from the database either by key or in bulk.
//! - **Scanning**: Retrieve all entries from a table.
//! - **Table Management**: Wipe a table clean for testing or other purposes.
//!
//! ## Usage
//!
//! This module is intended for internal use within the application and is designed to be flexible
//! enough to support various data models while maintaining strong type safety and clear separation
//! of concerns.

use std::{collections::HashMap, fmt::Debug};

use aws_sdk_dynamodb::types::AttributeValue;
#[cfg(feature = "testing")]
use aws_sdk_dynamodb::types::{DeleteRequest, WriteRequest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_dynamo::Item;

use crate::{
    api::models::common::{Fulfillment, Status},
    common::error::Error,
    context::Settings,
};

/// Chainstate table entries.
pub mod chainstate;
/// Deposit table entries.
pub mod deposit;
/// Limits table entries.
pub mod limits;
/// Withdrawal table entries.
pub mod withdrawal;

// Event structure
// -----------------------------------------------------------------------------

/// Status entry.
#[derive(Clone, Default, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "PascalCase")]
pub enum StatusEntry {
    /// Transaction hasn't yet been addressed by the sBTC Signers.
    #[default]
    Pending,
    /// Transaction was dealt with by the signers at one point but is now being
    /// reprocessed. The Signers are aware of the operation request.
    Reprocessing,
    /// Transaction has been seen and accepted by the sBTC Signers, but is not
    /// yet included in any on chain artifact. The transaction can still fail
    /// at this point if the Signers fail to include the transaciton in an on
    /// chain artifact.
    ///
    /// For example, a deposit or withdrawal that has specified too low of a
    /// BTC fee may fail after being accepted.
    Accepted,
    /// The articacts that fulill the operation have been observed in a valid fork of
    /// both the Stacks blockchain and the Bitcoin blockchain by at least one signer.
    ///
    /// Note that if the signers detect a conflicting chainstate in which the operation
    /// is not confirmed this status will be reverted to either ACCEPTED or REEVALUATING
    /// depending on whether the conflicting chainstate calls the acceptance into question.
    Confirmed(Fulfillment),
    /// The operation was not fulfilled.
    Failed,
}

impl From<&StatusEntry> for Status {
    fn from(value: &StatusEntry) -> Self {
        match value {
            StatusEntry::Pending => Status::Pending,
            StatusEntry::Reprocessing => Status::Reprocessing,
            StatusEntry::Accepted => Status::Accepted,
            StatusEntry::Confirmed(_) => Status::Confirmed,
            StatusEntry::Failed => Status::Failed,
        }
    }
}

// Structures
// -----------------------------------------------------------------------------

/// Primary index wrapper struct.
pub struct PrimaryIndex<T>(pub T);

/// Secondary index wrapper struct.
pub struct SecondaryIndex<T>(pub T);

// Traits
// -----------------------------------------------------------------------------

/// Trait common to entries.
pub trait EntryTrait: serde::Serialize + for<'de> serde::Deserialize<'de> + Debug {
    /// Key type for the entry.
    type Key: KeyTrait;
    /// Retrieves the entry key.
    fn key(&self) -> Self::Key;
}

/// Table key.
pub trait KeyTrait: serde::Serialize + for<'de> serde::Deserialize<'de> {
    /// Partition key type.
    type PartitionKey: serde::Serialize + for<'de> serde::Deserialize<'de>;
    /// Sort key type.
    type SortKey: serde::Serialize + for<'de> serde::Deserialize<'de>;
    /// Parition key name.
    const PARTITION_KEY_NAME: &'static str;
    /// Sort key name.
    const SORT_KEY_NAME: &'static str;
}

/// Trait that defines a primary index.
pub(crate) trait PrimaryIndexTrait {
    /// Entry type.
    type Entry: EntryTrait;
    /// Gets table name.
    fn table_name(settings: &Settings) -> &str;
}

/// Trait for defining a secondary index.
pub(crate) trait SecondaryIndexTrait {
    /// Primary Index.
    type PrimaryIndex: TableIndexTrait;
    /// Entry type.
    type Entry: EntryTrait;
    /// Index name.
    const INDEX_NAME: &'static str;
}

// Implementations for underlying trait.
// -----------------------------------------------------------------------------

/// Implementation of the table index trait for Primary Index.
impl<T> TableIndexTrait for PrimaryIndex<T>
where
    T: PrimaryIndexTrait,
{
    type Entry = <T as PrimaryIndexTrait>::Entry;
    type PrimaryIndex = PrimaryIndex<T>;
    type SearchToken = <<T as PrimaryIndexTrait>::Entry as EntryTrait>::Key;
    const INDEX_NAME_IF_GSI: Option<&'static str> = None;
    fn table_name(settings: &Settings) -> &str {
        <T as PrimaryIndexTrait>::table_name(settings)
    }
}

/// Implementation of the table index trait for Primary Index.
impl<T> TableIndexTrait for SecondaryIndex<T>
where
    T: SecondaryIndexTrait,
{
    type Entry = <T as SecondaryIndexTrait>::Entry;
    type PrimaryIndex = <T as SecondaryIndexTrait>::PrimaryIndex;
    type SearchToken = SecondaryIndexSearchToken<
        <<<T as SecondaryIndexTrait>::PrimaryIndex as TableIndexTrait>::Entry as EntryTrait>::Key,
        <<T as SecondaryIndexTrait>::Entry as EntryTrait>::Key,
    >;
    const INDEX_NAME_IF_GSI: Option<&'static str> = Some(<T as SecondaryIndexTrait>::INDEX_NAME);
    fn table_name(settings: &Settings) -> &str {
        <<T as SecondaryIndexTrait>::PrimaryIndex as TableIndexTrait>::table_name(settings)
    }
}

// Base Trait
// -----------------------------------------------------------------------------

/// Table index trait.
pub(crate) trait TableIndexTrait {
    /// Entry type.
    type Entry: EntryTrait;
    /// Search token.
    type SearchToken: serde::Serialize + for<'de> serde::Deserialize<'de>;
    /// Primary index trait.
    type PrimaryIndex: TableIndexTrait;
    /// Index name if the index is a GSI.
    const INDEX_NAME_IF_GSI: Option<&'static str>;
    /// Gets table name.
    fn table_name(settings: &Settings) -> &str;

    /// Generic table get.
    async fn get_entry(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
        key: &<Self::Entry as EntryTrait>::Key,
    ) -> Result<Self::Entry, Error> {
        // Convert key into the type needed for querying.
        let key_item: serde_dynamo::Item = serde_dynamo::to_item(key)?;
        // Query the database.
        let get_item_output = dynamodb_client
            .get_item()
            .table_name(Self::table_name(settings))
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
    async fn query_with_partition_key(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
        partition_key: &<<Self::Entry as EntryTrait>::Key as KeyTrait>::PartitionKey,
        maybe_next_token: Option<String>,
        maybe_page_size: Option<u16>,
    ) -> Result<(Vec<Self::Entry>, Option<String>), Error> {
        // Convert inputs into the types needed for querying.
        let exclusive_start_key =
            maybe_exclusive_start_key_from_next_token::<Self::SearchToken>(maybe_next_token)?;
        // Query the database.
        let query_output = dynamodb_client
            .query()
            .table_name(Self::table_name(settings))
            .set_index_name(Self::INDEX_NAME_IF_GSI.map(|s| s.to_string()))
            .set_exclusive_start_key(exclusive_start_key)
            .set_limit(maybe_page_size.map(|u| u as i32))
            .key_condition_expression("#pk = :v")
            .expression_attribute_names(
                "#pk",
                <<Self::Entry as EntryTrait>::Key as KeyTrait>::PARTITION_KEY_NAME,
            )
            .expression_attribute_values(":v", serde_dynamo::to_attribute_value(partition_key)?)
            .scan_index_forward(false)
            .send()
            .await?;
        // Convert data into output format.
        let entries: Vec<Self::Entry> =
            serde_dynamo::from_items(query_output.items.unwrap_or_default())?;
        let next_token = maybe_next_token_from_last_evaluated_key::<Self::SearchToken>(
            query_output.last_evaluated_key,
        )?;
        // Return.
        Ok((entries, next_token))
    }

    /// Generic table query for all attributes with a given primary key.
    async fn query_with_partition_and_sort_key(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
        partition_key: &<<Self::Entry as EntryTrait>::Key as KeyTrait>::PartitionKey,
        sort_key: &<<Self::Entry as EntryTrait>::Key as KeyTrait>::SortKey,
        sort_key_operator: &str,
        maybe_next_token: Option<String>,
        maybe_page_size: Option<u16>,
    ) -> Result<(Vec<Self::Entry>, Option<String>), Error> {
        // Convert inputs into the types needed for querying.
        let exclusive_start_key =
            maybe_exclusive_start_key_from_next_token::<Self::SearchToken>(maybe_next_token)?;

        // Query the database.
        let query_output = dynamodb_client
            .query()
            .table_name(Self::table_name(settings))
            .set_index_name(Self::INDEX_NAME_IF_GSI.map(|s| s.to_string()))
            .set_exclusive_start_key(exclusive_start_key)
            .set_limit(maybe_page_size.map(|u| u as i32))
            .key_condition_expression(format!("#pk = :pk AND #sk {sort_key_operator} :sk"))
            .expression_attribute_names(
                "#pk",
                <<Self::Entry as EntryTrait>::Key as KeyTrait>::PARTITION_KEY_NAME,
            )
            .expression_attribute_names(
                "#sk",
                <<Self::Entry as EntryTrait>::Key as KeyTrait>::SORT_KEY_NAME,
            )
            .expression_attribute_values(":pk", serde_dynamo::to_attribute_value(partition_key)?)
            .expression_attribute_values(":sk", serde_dynamo::to_attribute_value(sort_key)?)
            .scan_index_forward(false)
            .send()
            .await?;
        // Convert data into output format.
        let entries: Vec<Self::Entry> =
            serde_dynamo::from_items(query_output.items.unwrap_or_default())?;
        let next_token = maybe_next_token_from_last_evaluated_key::<Self::SearchToken>(
            query_output.last_evaluated_key,
        )?;
        // Return.
        Ok((entries, next_token))
    }

    /// Generic put table entry.
    async fn put_entry(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
        entry: &Self::Entry,
    ) -> Result<(), Error> {
        // Get table name.
        let table_name = Self::table_name(settings);
        // Convert Entry into the type needed for querying.
        let entry_item: Item = serde_dynamo::to_item(entry)?;
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

    /// Get all entries from a dynamodb table.
    #[cfg(feature = "testing")]
    async fn get_all_entries(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
    ) -> Result<Vec<Self::Entry>, Error> {
        // Get table name.
        let table_name = Self::table_name(settings);
        // Create vector to aggregate items in.
        let mut all_entries: Vec<Self::Entry> = Vec::new();
        // Scan the table for as many entries as possible.
        let mut scan_output = dynamodb_client.scan().table_name(table_name).send().await?;
        // Put items into aggregate list.
        all_entries.extend(serde_dynamo::from_items(
            scan_output.items.unwrap_or_default(),
        )?);
        // Continue to query until the scan is done.
        while let Some(exclusive_start_key) = scan_output.last_evaluated_key {
            scan_output = dynamodb_client
                .scan()
                .table_name(table_name)
                .set_exclusive_start_key(Some(exclusive_start_key))
                .send()
                .await?;
            all_entries.extend(serde_dynamo::from_items(
                scan_output.items.unwrap_or_default(),
            )?);
        }
        // Return.
        Ok(all_entries)
    }

    /// Generic delete table entry.
    #[cfg(feature = "testing")]
    async fn delete_entry(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
        key: &<Self::Entry as EntryTrait>::Key,
    ) -> Result<(), Error> {
        // Get table name.
        let table_name = Self::table_name(settings);
        // Convert Entry into the type needed for querying.
        let key_item: Item = serde_dynamo::to_item(key)?;
        // Add to the database.'
        dynamodb_client
            .delete_item()
            .table_name(table_name)
            .set_key(Some(key_item.into()))
            .send()
            .await?;
        // Return.
        Ok(())
    }

    /// Deletes every entry in a table with the specified keys.
    #[cfg(feature = "testing")]
    async fn delete_entries(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
        keys_to_delete: Vec<<Self::Entry as EntryTrait>::Key>,
    ) -> Result<(), Error> {
        // Get table name.
        let table_name = Self::table_name(settings);
        // Make delete request aggregator.
        let mut write_delete_requests: Vec<WriteRequest> = Vec::new();
        for key in keys_to_delete {
            let key_item = serde_dynamo::to_item::<<Self::Entry as EntryTrait>::Key, Item>(key)?;
            let req = DeleteRequest::builder()
                .set_key(Some(key_item.into()))
                .build()?;
            let write_request = WriteRequest::builder().delete_request(req).build();
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
        // Return.
        Ok(())
    }

    /// Wipes the table.
    #[cfg(feature = "testing")]
    async fn wipe(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
    ) -> Result<(), Error> {
        // Get table name.
        match Self::INDEX_NAME_IF_GSI {
            // If this is secondary index, so go to primary:
            Some(_) => {
                let keys_to_delete = <Self::PrimaryIndex as TableIndexTrait>::get_all_entries(
                    dynamodb_client,
                    settings,
                )
                .await?
                .iter()
                .map(<<Self::PrimaryIndex as TableIndexTrait>::Entry as EntryTrait>::key)
                .collect();

                <Self::PrimaryIndex as TableIndexTrait>::delete_entries(
                    dynamodb_client,
                    settings,
                    keys_to_delete,
                )
                .await
            }
            // Otherwise this is a primary index so wipe the table.
            None => {
                Self::delete_entries(
                    dynamodb_client,
                    settings,
                    Self::get_all_entries(dynamodb_client, settings)
                        .await?
                        .iter()
                        .map(<Self::Entry as EntryTrait>::key)
                        .collect(),
                )
                .await
            }
        }
    }
}

/// Versioned entry trait.
pub trait VersionedEntryTrait: EntryTrait {
    /// Version field.
    const VERSION_FIELD: &'static str;
    /// Get version.
    fn get_version(&self) -> u64;
    /// Increment version.
    fn increment_version(&mut self);
}

/// Index trait for a versioned thing.
pub(crate) trait VersionedTableIndexTrait: TableIndexTrait
where
    Self::Entry: VersionedEntryTrait,
{
    /// Put generic table entry but add a version check.
    async fn put_entry_with_version(
        dynamodb_client: &aws_sdk_dynamodb::Client,
        settings: &Settings,
        entry: &mut Self::Entry,
    ) -> Result<(), Error> {
        // Get table name.
        let table_name = Self::table_name(settings);
        // Get the expected version.
        let expected_version: u64 = entry.get_version();
        // Increment version.
        entry.increment_version();
        // Convert Entry into the type needed for querying.
        let entry_item: Item = serde_dynamo::to_item(entry)?;
        // Add to the database.
        dynamodb_client
            .put_item()
            .table_name(table_name)
            .set_item(Some(entry_item.into()))
            .condition_expression("attribute_exists(#version) AND #version = :expected_version")
            .expression_attribute_names(
                "#version",
                <Self::Entry as VersionedEntryTrait>::VERSION_FIELD,
            )
            .expression_attribute_values(
                ":expected_version",
                serde_dynamo::to_attribute_value(expected_version)?,
            )
            .send()
            .await?;
        // Return.
        Ok(())
    }
}

// Implement VersionedTableIndexTrait for all structs that implement TableIndexTrait
// and where the associated Entry type implements VersionedEntry
impl<T> VersionedTableIndexTrait for T
where
    T: TableIndexTrait,
    T::Entry: VersionedEntryTrait,
{
}

/// Secondary index search token definition.
#[derive(Clone, Default, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SecondaryIndexSearchToken<P, S> {
    /// Primary index.
    #[serde(flatten)]
    primary: P,
    /// Secondary index.
    #[serde(flatten)]
    secondary: S,
}

// Private Helpers -------------------------------------------------------------

/// Converts an optional `HashMap<String, AttributeValue>` representing the last evaluated key
/// into an optional token string. If the `Option` contains a value, it is deserialized into a type `T`
/// and then serialized into a token string.
fn maybe_next_token_from_last_evaluated_key<T>(
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
fn tokenize<T>(key: T) -> Result<String, Error>
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
fn maybe_exclusive_start_key_from_next_token<T>(
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
fn detokenize<T>(token: String) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    let decoded = URL_SAFE_NO_PAD.decode(token)?;
    let deserialized = serde_json::from_slice::<T>(&decoded)?;
    Ok(deserialized)
}
