//! This module contains structs that represent the payload for new block
//! webhooks from a stacks node.
//!
//! The payload of a Stacks node webhooks is really defined in the source.
//! Here we attempt to follow the source and deserialize them using the
//! internal methods that are built for deserialization, which is typically
//! not their [`serde::Deserialize`] implementation.
//!
//! Fields in a stacks-node webhook, the types fall into three categories
//! 1. Types that are sent as hex encoded binary, where the binary is
//!    serialized using the type's `T::to_hex` implementation (implemented
//!    using the [`stacks_common::util::macros::impl_byte_array_newtype!`]
//!    macro).
//! 2. Types that are sent as hex encoded binary, where the binary is
//!    serialized using the type's
//!    [`StacksMessageCodec::consensus_serialize`] implementation.
//! 3. Types that are serialized using the type's serde::Serialized
//!    implementation.
//!
//! Unfortunately, sometimes the same type is serialized using two
//! different methods for two different parts of the same payload.

use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::types::Value as ClarityValue;
use serde::Deserialize;
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::HexError;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
/// The raw payload of a new block event from a stacks node.
/// This is the raw JSON string that is sent to the webhook.
/// Ideally, NewBlockEvent would be used directly, but because of the
/// the imported data types, we can't derive ToSchema for it to be used
/// in the OpenAPI spec.
pub struct NewBlockEventRaw(pub String);

impl NewBlockEventRaw {
    /// Deserialize the raw payload into a NewBlockEvent.
    pub fn deserialize(&self) -> Result<NewBlockEvent, serde_json::Error> {
        serde_json::from_str(&self.0)
    }
}

/// This struct represents the body of POST /new_block events from a stacks
/// node.
///
/// # Note
///
/// This struct leaves out some of the fields that are included. For the
/// full payload, see the source here:
/// <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L644-L687>
#[derive(Debug, Deserialize)]
pub struct NewBlockEvent {
    /// The hash of the stacks block
    #[serde(deserialize_with = "deserialize_hex")]
    pub block_hash: BlockHeaderHash,
    /// The height of the stacks block
    pub block_height: u64,
    /// The hash of the bitcoin block associated with the stacks block.
    #[serde(deserialize_with = "deserialize_hex")]
    pub burn_block_hash: BurnchainHeaderHash,
    /// The height of the bitcoin block associated with the stacks block.
    pub burn_block_height: u32,
    /// The timestamp in the header of the burn block. This corresponds to
    /// the `burn_header_timestamp` field in the
    /// [`blockstack_lib::chainstate::stacks::db::StacksHeaderInfo`]
    pub burn_block_time: u64,
    /// The block ID of the block for this event. This corresponds to the
    /// [`blockstack_lib::chainstate::stacks::db::StacksHeaderInfo::index_block_hash`]
    /// function.
    #[serde(deserialize_with = "deserialize_hex")]
    pub index_block_hash: StacksBlockId,
    /// The events associated with transactions within the block. These are
    /// only the events that we have configured our stacks node to send.
    pub events: Vec<TransactionEvent>,
    /// The transactions and their results that included within the block.
    pub transactions: Vec<TransactionReceipt>,
    /// The block hash of the parent Stacks block in the blockchain.
    #[serde(deserialize_with = "deserialize_hex")]
    pub parent_block_hash: BlockHeaderHash,
    /// The block id of the parent Stacks block in the blockchain.
    #[serde(deserialize_with = "deserialize_hex")]
    pub parent_index_block_hash: StacksBlockId,
    /// The block hash of the parent bitcoin block associated with this new
    /// Stacks block.
    #[serde(deserialize_with = "deserialize_hex")]
    pub parent_burn_block_hash: BurnchainHeaderHash,
    /// The height of the parent of the bitcoin burn block.
    pub parent_burn_block_height: u32,
    /// The timestamp in the header of the parent bitcoin burn block.
    pub parent_burn_block_timestamp: u64,
}

/// This matches the json value that is defined in stacks-core[^1]. It
/// contains the raw transaction and the result of the transaction.
///
/// <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L499-L511>
#[derive(Debug, Deserialize)]
pub struct TransactionReceipt {
    /// The id of this transaction .
    #[serde(deserialize_with = "deserialize_webhook_codec")]
    pub txid: String,
    /// Can drop, just a sequence
    pub tx_index: u32,
    /// Probably should be an enum
    pub status: String,
    /// These are probably bytes as hex
    #[serde(rename = "raw_result", deserialize_with = "deserialize_webhook_codec")]
    pub result: String,
    /// This is the raw transaction and is always sent. But, this field is
    /// overloaded. It is a burn chain "operation" whenever this field
    /// value is "0x00" and is a regular stacks transaction otherwise. We
    /// replace "0x00" with [`None`] here.
    // #[serde(rename = "raw_tx", deserialize_with = "deserialize_tx")]
    pub raw_tx: String,
}

/// The type of event that occurred within the transaction.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionEventType {
    /// A smart contract event
    ContractEvent,
    /// A STX transfer event
    StxTransferEvent,
    /// An STX mint event
    StxMintEvent,
    /// An STX burn event
    StxBurnEvent,
    /// An STX lock event
    StxLockEvent,
    /// A transfer event for a NFT
    NftTransferEvent,
    /// A non-fungible-token mint event
    NftMintEvent,
    /// A non-fungible-token burn event
    NftBurnEvent,
    /// A fungible-token transfer event
    FtTransferEvent,
    /// A fungible-token mint event
    FtMintEvent,
    /// A fungible-token burn event
    FtBurnEvent,
}

/// An event that was emitted during the execution of the transaction. It
/// is defined in [^1].
///
/// [^1]: <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/clarity/src/vm/events.rs#L45-L51>
#[derive(Debug, Deserialize)]
pub struct TransactionEvent {
    /// The id of the transaction that generated the event.
    #[serde(deserialize_with = "deserialize_webhook_codec")]
    pub txid: String,
    /// can drop, just a sequence
    pub event_index: u64,
    /// This corresponds to the negation of the value in the
    /// [`StacksTransactionReceipt.post_condition_aborted`] field.
    pub committed: bool,
    /// The type of event that this is. We only care about contract events,
    /// so we only have the corresponding fields for it.
    #[serde(rename = "type")]
    pub event_type: TransactionEventType,
    /// The actual event
    pub contract_event: Option<SmartContractEvent>,
}

/// Smart contracts emit events when they are executed. This represents
/// such an event. The expected type is taken from stacks-core[^1].
///
/// [^1]: <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/clarity/src/vm/events.rs#L358-L363>
#[derive(Debug, Deserialize)]
pub struct SmartContractEvent {
    /// Identifies the smart contract that generated the event.
    #[serde(deserialize_with = "parse_contract_name")]
    pub contract_identifier: QualifiedContractIdentifier,
    /// The specific topic of the event. This is placed in the stacks node
    /// config when specifying events.
    pub topic: String,
    /// The actual event
    pub value: ClarityValue,
}

/// This is for deserializing fields that were effectively serialized the
/// type's `to_hex` function, which they implemented through the
/// [`stacks_common::util::macros::impl_byte_array_newtype!`] macro.
///
/// # Notes
///
/// A good example of how this works is with the `block_hash` field in the
/// `POST /new_block` webhook[^1]. It's set using the [`std::fmt::Display`]
/// implementation of a [`BlockHeaderHash`] type. The [`std::fmt::Display`]
/// implementation uses the [`BlockHeaderHash::to_hex`] function. That type
/// also implements [`HexDeser`], where the [`HexDeser::try_from`]
/// implementation uses the types `from_hex` function. All the types that
/// we use here that implement [`HexDeser`] follow this same pattern.
///
/// [^1]: <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L645>
pub fn deserialize_hex<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: HexDeser,
{
    let hex_str = <String>::deserialize(deserializer)?;
    let hex_str = hex_str.trim_start_matches("0x");
    <T as HexDeser>::try_from(hex_str).map_err(serde::de::Error::custom)
}

/// This is for deserializing fields in webhooks that were effectively
/// serialized using [`StacksMessageCodec::consensus_serialize`].
///
/// # Notes
///
/// Fields deserialized with this function were serialized by "effectively"
/// calling [`StacksMessageCodec::consensus_serialize`] followed by
/// [`bytes_to_hex`] on the output and prepending "0x".
pub fn deserialize_webhook_codec<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Hex encoded binary from stacks-node Webhooks appear to always(?) be
    // prefixed with "0x". If they aren't then this works too.
    let hex_str = <String>::deserialize(deserializer)?;
    Ok(hex_str.trim_start_matches("0x").to_string())
}

/// The [`QualifiedContractIdentifier::parse`] function inverts the
/// [`<QualifiedContractIdentifier as std::fmt::Display>::fmt`] call that
/// was used to generate the fields that use this function for
/// deserialization.
pub fn parse_contract_name<'de, D>(des: D) -> Result<QualifiedContractIdentifier, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let literal = <String>::deserialize(des)?;
    QualifiedContractIdentifier::parse(&literal).map_err(serde::de::Error::custom)
}

/// This trait is defined in stackslib, but to avoid adding it as a
/// dependency, we define it here.
pub trait HexDeser: Sized {
    /// Attempt to create an instance of the type from a hex string.
    fn try_from(hex: &str) -> Result<Self, HexError>;
}

macro_rules! impl_hex_deser {
    ($thing:ident) => {
        impl HexDeser for $thing {
            fn try_from(hex: &str) -> Result<Self, HexError> {
                $thing::from_hex(hex)
            }
        }
    };
}

impl_hex_deser!(BurnchainHeaderHash);
impl_hex_deser!(StacksBlockId);
impl_hex_deser!(BlockHeaderHash);
