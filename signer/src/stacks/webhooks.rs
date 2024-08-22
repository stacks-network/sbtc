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

use crate::error::Error;

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

/// This matches the json value that is defined in stacks-core[^1]. It
/// contains the raw tranaction and the result of the transaction.
///
/// <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L499-L511>
#[derive(Debug, Deserialize)]
pub struct TransactionReceipt {
    /// The id of this transaction .
    #[serde(deserialize_with = "deserialize_webhook_codec")]
    pub txid: Txid,
    /// Can drop, just a sequence
    pub tx_index: u32,
    /// Probably should be an enum
    pub status: String,
    /// These are probably bytes as hex
    #[serde(rename = "raw_result", deserialize_with = "deserialize_webhook_codec")]
    pub result: ClarityValue,
    /// This is the raw transaction and is always sent. But, this field is
    /// overloaded. It is a burn chain "operation" whenever this field
    /// value is "0x00" and is a regular stacks transaction otherwise. We
    /// replace "0x00" with [`None`] here.
    #[serde(rename = "raw_tx", deserialize_with = "deserialize_tx")]
    pub tx: Option<StacksTransaction>,
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
/// such an event. The expected type is taken from stackss-core[^1].
///
/// [^1]: <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/clarity/src/vm/events.rs#L358-L363>
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
pub fn deserialize_webhook_codec<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: StacksMessageCodec,
{
    // Hex encoded binary from stacks-node Webhooks appear to always(?) be
    // prefixed with "0x". If they aren't then this works too.
    let hex_str = <String>::deserialize(deserializer)?;
    let hex_str = hex_str.trim_start_matches("0x");
    deserialize_codec(hex_str).map_err(serde::de::Error::custom)
}

/// This is for deserializing stacks transactions in the raw_tx field.
///
/// # Notes
///
/// This returns [`Ok(None)`] whenever the "raw_tx" is "0x00", which
/// corresponds to a burnchain operation.
pub fn deserialize_tx<'de, D>(deserializer: D) -> Result<Option<StacksTransaction>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str = <String>::deserialize(deserializer)?;
    let hex_str = hex_str.trim_start_matches("0x");

    if hex_str == "00" {
        return Ok(None);
    }

    deserialize_codec(hex_str)
        .map_err(serde::de::Error::custom)
        .map(Some)
}

/// This if for deserializing hex encoded strings where the raw bytes were generated using
/// [`StacksMessageCodec::consensus_serialize`].
fn deserialize_codec<T>(hex_str: &str) -> Result<T, Error>
where
    T: StacksMessageCodec,
{
    let bytes = hex::decode(hex_str).map_err(Error::DecodeHexBytes)?;
    let fd: &mut &[u8] = &mut bytes.as_ref();
    <T as StacksMessageCodec>::consensus_deserialize(fd).map_err(Error::StacksCodec)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// This was captured using a slightly modified version of the above
    /// function against a stacks-node running Nakamoto on commit
    /// cbf0c52fb7a0b8ac55badadcf3773ca0848a25cf from 2024-08-20.
    const WEBHOOK_PAYLOAD: &str = r#"{
    "anchored_cost": {
        "read_count": 0,
        "read_length": 0,
        "runtime": 0,
        "write_count": 0,
        "write_length": 0
    },
    "block_hash": "0xe012ca1ad766b2abe03c1cb661930af72fd29f6d197a7d8e4280b54bf2883dec",
    "block_height": 449,
    "burn_block_hash": "0x7d4db9d88dd86c31c75a351e4974940db55f6db77c9d49881dd0028946c661ac",
    "burn_block_height": 159,
    "burn_block_time": 1724181975,
    "confirmed_microblocks_cost": {
        "read_count": 0,
        "read_length": 0,
        "runtime": 0,
        "write_count": 0,
        "write_length": 0
    },
    "cycle_number": null,
    "events": [],
    "index_block_hash": "0x646ebc3118346162ae38cd0973ce4fd6e890a1684c3775c2fe3b0a186c5ad0c8",
    "matured_miner_rewards": [],
    "miner_signature": "0x011e8135ba62a248ff78daf9e7ac9c2da2f6b8cf3b28cb1082d259db2f3a9c297816a667e09579065de2820866ca90b8eea4b43a3a2bfc350874cd11d28e251165",
    "miner_txid": "0x7d53908d95c98e5479582074e4d8eee4e417265610b128c0c603d168ff97cb56",
    "parent_block_hash": "0x1a02201a746c0ff9abd2c81c40ba31f8a4b22f893007f6931e1aef1d70edcf0b",
    "parent_burn_block_hash": "0x7d4db9d88dd86c31c75a351e4974940db55f6db77c9d49881dd0028946c661ac",
    "parent_burn_block_height": 159,
    "parent_burn_block_timestamp": 1724181975,
    "parent_index_block_hash": "0x1706c7b20fb661dfb31fd97363e92a05e9865e20dbee764fce5cd51572206b1c",
    "parent_microblock": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "parent_microblock_sequence": 0,
    "pox_v1_unlock_height": 104,
    "pox_v2_unlock_height": 106,
    "pox_v3_unlock_height": 109,
    "reward_set": null,
    "signer_bitvec": "000800000001ff",
    "signer_signature": [
        "01555a3544f68a067c7e08392c07c1259cc7176d692250966bf82f828a84a653f8371b51a0922fc50756cad3d50a7f0b26955394294b7deb8e686029dbbdbb5755",
        "00ee14b183d8614585923e67df44d2fe8db3bde8b8f51b3b8e067ac5d883b68de829bfabb48aebe9a022588c7769250120f28f6a2e3e5918430c434b710f7a86b1"
    ],
    "signer_signature_hash": "0xe012ca1ad766b2abe03c1cb661930af72fd29f6d197a7d8e4280b54bf2883dec",
    "transactions": [
        {
            "burnchain_op": null,
            "contract_abi": null,
            "execution_cost": {
                "read_count": 0,
                "read_length": 0,
                "runtime": 0,
                "write_count": 0,
                "write_length": 0
            },
            "microblock_hash": null,
            "microblock_parent_hash": null,
            "microblock_sequence": null,
            "raw_result": "0x0703",
            "raw_tx": "0x80800000000400ad08341feab8ea788ef8045c343d21dcedc4483e000000000000008a000000000000012c000157158fca569bb7f69bd3e19f08723f1d9fee55dd017c3a8471586d123fe948531d24539ed08fa8498ab0d5ab9d215296c74b2c1896e3fe03c96e51aed66c4f3203020000000000051a62b0e91cc557e583c3d1f9dfe468ace76d2f037400000000000003e800000000000000000000000000000000000000000000000000000000000000000000",
            "status": "success",
            "tx_index": 0,
            "txid": "0xa17854a5c99a99940fbd42df6d964c5ef3afab6b6744f1c4be5912cf90ecd1f9"
        }
    ]
}"#;

    /// Test all deserialization functions.
    #[test]
    fn test_new_block_event_deserialization() {
        // Does it work?
        let event: NewBlockEvent = serde_json::from_str(WEBHOOK_PAYLOAD).unwrap();

        // Okay now we take some random fields and "manually" deserialize
        // them and check that things match up.
        let expected_block_hash = BlockHeaderHash::from_hex(
            "e012ca1ad766b2abe03c1cb661930af72fd29f6d197a7d8e4280b54bf2883dec",
        )
        .unwrap();
        let expected_txid = deserialize_codec::<Txid>(
            "a17854a5c99a99940fbd42df6d964c5ef3afab6b6744f1c4be5912cf90ecd1f9",
        )
        .unwrap();

        // We test some fields to make sure that everything is okay.
        assert_eq!(event.block_height, 449);
        assert_eq!(event.block_hash, expected_block_hash);
        assert_eq!(event.transactions.first().unwrap().txid, expected_txid);
    }
}
