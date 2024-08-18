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

use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::net::api::HexDeser;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::types::Value as ClarityValue;
use serde::Deserialize;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::StacksBlockId;

/// This struct represents the body of POST /new_block events from a stacks
/// node.
///
/// # Note
///
/// This struct leaves out some of the fields that are included. For the
/// full payload, see the source here:
/// https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L644-L687
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
    /// The timestamp in the header of the burn block. This corresponds to
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

/// https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L499-L511
#[derive(Debug, Deserialize)]
pub struct TransactionReceipt {
    /// The id of this transaction .
    #[serde(deserialize_with = "deserialize_codec")]
    pub txid: Txid,
    /// Can drop, just a sequence
    pub tx_index: u32,
    /// Probably should be an enum
    pub status: String,
    /// These are probably bytes as hex
    #[serde(rename = "raw_result", deserialize_with = "deserialize_codec")]
    pub result: ClarityValue,
    /// These are bytes as hex
    #[serde(rename = "raw_tx", deserialize_with = "deserialize_codec")]
    pub tx: StacksTransaction,
}

/// The type of event that occurred within the transaction.
#[derive(Debug, Deserialize)]
#[serde(rename = "lower_camel_case")]
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

/// https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/clarity/src/vm/events.rs#L358-L363
/// https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/clarity/src/vm/events.rs#L45-L51
#[derive(Debug, Deserialize)]
pub struct TransactionEvent {
    /// The id of the transaction that generated the event.
    #[serde(deserialize_with = "deserialize_codec")]
    pub txid: Txid,
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
/// such an event.
#[derive(Debug, Deserialize)]
pub struct SmartContractEvent {
    /// Identifies the smart contract that generated event.
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
/// A good example of how why this works is with the `block_hash` field in
/// the `POST /new_block` webhook[^1]. It's set using the
/// [`std::fmt::Display`] implementation of a [`BlockHeaderHash`] type. The
/// [`std::fmt::Display`] implementation is done using the
/// [`stacks_common::util::macros::impl_byte_array_newtype!`] macro, which
/// is implemented using the [`BlockHeaderHash::to_hex`] function. That
/// type also implements [`HexDeser`], with the implementation of
/// [`HexDeser::try_from`] done using the types `from_hex` function. All
/// the types that we use here that implement [`HexDeser`] here follow that
/// same pattern.
///
/// [^1]: https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L645
pub fn deserialize_hex<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: HexDeser,
{
    let hex_str = <&str>::deserialize(deserializer)?;
    let hex_str = hex_str.trim_start_matches("0x");
    <T as HexDeser>::try_from(hex_str).map_err(serde::de::Error::custom)
}

/// This is for deserializing fields that were effectively serialized using
/// [`StacksMessageCodec::consensus_serialize`].
///
/// # Notes
///
/// Fields deserialized with this function were serialized by "effectively"
/// calling [`StacksMessageCodec::consensus_serialize`] followed by
/// [`bytes_to_hex`] on the output and prepending "0x".
pub fn deserialize_codec<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: StacksMessageCodec,
{
    let hex_str = <&str>::deserialize(deserializer)?;
    let hex_str = hex_str.trim_start_matches("0x");
    let bytes = stacks_common::util::hash::hex_bytes(hex_str).map_err(serde::de::Error::custom)?;
    let fd = &mut bytes.as_slice();
    <T as StacksMessageCodec>::consensus_deserialize(fd).map_err(serde::de::Error::custom)
}

/// The [`QualifiedContractIdentifier::parse`] function inverts the
/// [`<QualifiedContractIdentifier as std::fmt::Display>::fmt`] call that
/// was used to generate the fields that use this function for
/// deserialization.
pub fn parse_contract_name<'de, D>(des: D) -> Result<QualifiedContractIdentifier, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let literal = <&str>::deserialize(des)?;
    QualifiedContractIdentifier::parse(literal).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_me() {}
}
