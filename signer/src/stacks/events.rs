//! For deconstructing print events emitted from in the sbtc-registry smart
//! contract.
//!
//! Print events from the sBTC registry come in as [`TupleData`] clarity
//! values. Each tuple has a topic field that takes one of four values. We
//! deconstruct the tuple data based on the topic.
//!
//! This module attempts to use only types that are found in the
//! stacks-core crates, the rust-bitcoin crate, and the bitvec crate.

use std::collections::BTreeMap;

use bitcoin::hashes::Hash;
use bitcoin::BlockHash as BitcoinBlockHash;
use bitcoin::OutPoint;
use bitcoin::PubkeyHash;
use bitcoin::ScriptBuf;
use bitcoin::ScriptHash;
use bitcoin::Txid as BitcoinTxid;
use bitcoin::WitnessProgram;
use bitcoin::WitnessVersion;
use bitvec::array::BitArray;
use blockstack_lib::burnchains::Txid as StacksTxid;
use clarity::vm::types::CharType;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::SequenceData;
use clarity::vm::types::TupleData;
use clarity::vm::ClarityName;
use clarity::vm::Value as ClarityValue;
use secp256k1::PublicKey;
use stacks_common::types::chainstate::StacksBlockId;

/// An error when trying to parse an sBTC event into a concrete type.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    /// This error is thrown when trying to convert an u128 into some other
    /// smaller type. It should never be thrown
    #[error("Could not convert an integer in clarity event into the expected integer {0}")]
    ClarityIntConversion(#[source] std::num::TryFromIntError),
    /// This is a slice conversion that happens when generating an address
    /// from validated user inputs. It shouldn't happen since we validate
    /// the user's inputs in the contract call.
    #[error("slice conversion failed: {0}")]
    ClaritySliceConversion(#[source] std::array::TryFromSliceError),
    /// This happens when we attempt to create s String from the raw bytes
    /// returned in a Clarity [`Value`](clarity::vm::Value).
    #[error("Could not convert ASCII or UTF8 bytes into a String: {0}")]
    ClarityStringConversion(#[source] std::string::FromUtf8Error),
    /// This can only be thrown when the number of bytes for a txid or
    /// block hash field is not exactly equal to 32. This should never occur.
    #[error("Could not convert a hash in clarity event into the expected hash {0}")]
    ClarityHashConversion(#[source] bitcoin::hashes::FromSliceError),
    /// This error is thrown when trying to convert a public key from a
    /// Clarity buffer into a proper public key. It should never be thrown.
    #[error("Could not convert a public key in clarity event into the expected public key {0}")]
    ClarityPublicKeyConversion(#[source] secp256k1::Error),
    /// This should never happen, but happens when one of the given topics
    /// is not on the list of expected topics.
    #[error("Got an unexpected event topic: {0}")]
    ClarityUnexpectedEventTopic(String),
    /// This happens when we expect one clarity variant but got another.
    #[error("Got an unexpected clarity value: {0:?}; {1}")]
    ClarityUnexpectedValue(ClarityValue, TxInfo),
    /// This should never happen, since  our witness programs are under the
    /// maximum length.
    #[error("tried to create an invalid witness program {0}")]
    InvalidWitnessProgram(#[source] bitcoin::witness_program::Error),
    /// This a programmer error bug that should never be thrown.
    #[error("The field {0} was missing from the print event for topic; {1}")]
    TupleEventField(&'static str, TxInfo),
    /// This should never happen, we check the version in the smart
    /// contract.
    #[error("the given raw recipient is unexpected. version: {0:?}, hashbytes: {1:?} ")]
    UnhandledRecipient(Vec<u8>, Vec<u8>),
}

/// The print events emitted by the sbtc-registry clarity smart contract.
#[derive(Debug)]
pub enum RegistryEvent {
    /// For the `completed-deposit` topic
    CompletedDeposit(CompletedDepositEvent),
    /// For the `withdrawal-accept` topic
    WithdrawalAccept(WithdrawalAcceptEvent),
    /// For the `withdrawal-reject` topic
    WithdrawalReject(WithdrawalRejectEvent),
    /// For the `withdrawal-create` topic
    WithdrawalCreate(WithdrawalCreateEvent),
    /// For the `key-rotation` topic
    KeyRotation(KeyRotationEvent),
}

/// A type that points to a transaction in a stacks block.
#[derive(Debug, Copy, Clone)]
pub struct TxInfo {
    /// The transaction ID
    pub txid: StacksTxid,
    /// The globally unique stacks block identifier.
    pub block_id: StacksBlockId,
}

impl std::fmt::Display for TxInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "txid: {}, block_id: {}", self.txid, self.block_id)
    }
}

impl RegistryEvent {
    /// Transform the [`ClarityValue`] from the sbtc-registry event into a
    /// proper type.
    pub fn try_new(value: ClarityValue, tx_info: TxInfo) -> Result<Self, EventError> {
        match value {
            ClarityValue::Tuple(TupleData { data_map, .. }) => {
                let mut event_map = RawTupleData::new(data_map, tx_info);
                // Lucky for us, each sBTC print event in the sbtc-registry
                // smart contract has a topic. We use that to match on what
                // to expect when decomposing the event from a
                // [`ClarityValue`] into a proper type.
                let topic = event_map.remove_string("topic")?;

                match topic.as_str() {
                    "completed-deposit" => event_map.completed_deposit(),
                    "withdrawal-accept" => event_map.withdrawal_accept(),
                    "withdrawal-create" => event_map.withdrawal_create(),
                    "withdrawal-reject" => event_map.withdrawal_reject(),
                    "key-rotation" => event_map.key_rotation(),
                    _ => Err(EventError::ClarityUnexpectedEventTopic(topic)),
                }
            }
            value => Err(EventError::ClarityUnexpectedValue(value, tx_info)),
        }
    }
}

/// This is the event that is emitted from the `create-withdrawal-request`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct CompletedDepositEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockId,
    /// This is the amount of sBTC to mint to the intended recipient.
    pub amount: u64,
    /// This is the outpoint of the original bitcoin deposit transaction.
    pub outpoint: OutPoint,
    /// The bitcoin block hash where the sweep transaction was included.
    pub sweep_block_hash: BitcoinBlockHash,
    /// The bitcoin block height where the sweep transaction was included.
    pub sweep_block_height: u64,
    /// The transaction id of the bitcoin transaction that fulfilled the
    /// deposit.
    pub sweep_txid: BitcoinTxid,
}

/// This is the event that is emitted from the `create-withdrawal-request`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalCreateEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockId,
    /// This is the unique identifier of the withdrawal request.
    pub request_id: u64,
    /// This is the amount of sBTC that is locked and requested to be
    /// withdrawal as sBTC.
    pub amount: u64,
    /// This is the principal who has their sBTC locked up.
    pub sender: PrincipalData,
    /// This is the address to send the BTC to when fulfilling the
    /// withdrawal request.
    pub recipient: ScriptBuf,
    /// This is the maximum amount of BTC "spent" to the miners for the
    /// transaction fee.
    pub max_fee: u64,
    /// The block height of the bitcoin blockchain when the stacks
    /// transaction that emitted this event was executed.
    pub block_height: u64,
}

/// This is the event that is emitted from the `complete-withdrawal-accept`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalAcceptEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockId,
    /// This is the unique identifier of the withdrawal request.
    pub request_id: u64,
    /// The bitmap of how the signers voted for the withdrawal request.
    /// Here, a 1 (or true) implies that the signer did *not* vote to
    /// accept the request.
    pub signer_bitmap: BitArray<[u8; 16]>,
    /// This is the outpoint for the bitcoin transaction that serviced the
    /// request.
    pub outpoint: OutPoint,
    /// This is the fee that was spent to the bitcoin miners to confirm the
    /// withdrawal request.
    pub fee: u64,
    /// The bitcoin block hash where the sweep transaction was included.
    pub sweep_block_hash: BitcoinBlockHash,
    /// The bitcoin block height where the sweep transaction was included.
    pub sweep_block_height: u64,
    /// The transaction id of the bitcoin transaction that fulfilled the
    /// withdrawal request.
    pub sweep_txid: BitcoinTxid,
}

/// This is the event that is emitted from the `complete-withdrawal-reject`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalRejectEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// The block ID of the block for this event.
    pub block_id: StacksBlockId,
    /// This is the unique identifier of user created the withdrawal
    /// request.
    pub request_id: u64,
    /// The bitmap of how the signers voted for the withdrawal request.
    /// Here, a 1 (or true) implies that the signer did *not* vote to
    /// accept the request.
    pub signer_bitmap: BitArray<[u8; 16]>,
}

/// This is the event that is emitted from the `rotate-keys`
/// public function in the sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct KeyRotationEvent {
    /// The new set of public keys for all known signers during this
    /// PoX cycle.
    pub new_keys: Vec<PublicKey>,
    /// The address that deployed the contract.
    pub new_address: PrincipalData,
    /// The new aggregate key created by combining the above public keys.
    pub new_aggregate_pubkey: PublicKey,
    /// The number of signatures required for the multi-sig wallet.
    pub new_signature_threshold: u16,
}

#[derive(Debug)]
struct RawTupleData {
    data_map: BTreeMap<ClarityName, ClarityValue>,
    tx_info: TxInfo,
}

impl RawTupleData {
    fn new(data_map: BTreeMap<ClarityName, ClarityValue>, tx_info: TxInfo) -> Self {
        Self { data_map, tx_info }
    }
    /// Extract the u128 value from the given field
    fn remove_u128(&mut self, field: &'static str) -> Result<u128, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::UInt(val)) => Ok(val),
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }
    /// Extract the buff value from the given field
    fn remove_buff(&mut self, field: &'static str) -> Result<Vec<u8>, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Sequence(SequenceData::Buffer(buf))) => Ok(buf.data),
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }
    /// Extract the principal value from the given field
    fn remove_principal(&mut self, field: &'static str) -> Result<PrincipalData, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Principal(principal)) => Ok(principal),
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }
    /// Extract the string value from the given field
    fn remove_string(&mut self, field: &'static str) -> Result<String, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Sequence(SequenceData::String(CharType::ASCII(ascii)))) => {
                String::from_utf8(ascii.data).map_err(EventError::ClarityStringConversion)
            }
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }
    /// Extract the tuple value from the given field
    fn remove_tuple(&mut self, field: &'static str) -> Result<Self, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Tuple(TupleData { data_map, .. })) => {
                Ok(Self::new(data_map, self.tx_info))
            }
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }

    /// Extract the list value from the given field
    fn remove_list(&mut self, field: &'static str) -> Result<Vec<ClarityValue>, EventError> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Sequence(SequenceData::List(list))) => Ok(list.data),
            _ => Err(EventError::TupleEventField(field, self.tx_info)),
        }
    }

    /// This function is for transforming the print events of the
    /// complete-deposit function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for complete-deposit calls are structured like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "completed-deposit",
    ///   bitcoin-txid: (buff 32),
    ///   output-index: uint,
    ///   amount: uint
    ///   burn-hash: (buff 32),
    ///   burn-height: uint,
    ///   sweep-txid: (buff 32),
    /// })
    /// ```
    ///
    /// The above event is emitted after the indicated amount of sBTC has
    /// been emitted to the recipient.
    fn completed_deposit(mut self) -> Result<RegistryEvent, EventError> {
        let amount = self.remove_u128("amount")?;
        let vout = self.remove_u128("output-index")?;
        let txid_bytes = self.remove_buff("bitcoin-txid")?;
        let mut sweep_block_hash = self.remove_buff("burn-hash")?;
        let sweep_block_height = self.remove_u128("burn-height")?;
        let sweep_txid = self.remove_buff("sweep-txid")?;

        // The `sweep_block_hash` we receive is reversed, so we reverse it here
        // so that we store it in an ordering consistent with the rest of our db.
        sweep_block_hash.reverse();

        Ok(RegistryEvent::CompletedDeposit(CompletedDepositEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error, since this amount is set from the u64
            // amount of sats by us.
            amount: u64::try_from(amount).map_err(EventError::ClarityIntConversion)?,
            outpoint: OutPoint {
                // This shouldn't error, this is set from a proper [`Txid`]
                // in a contract call.
                txid: BitcoinTxid::from_slice(&txid_bytes)
                    .map_err(EventError::ClarityHashConversion)?,
                // This shouldn't actually error, we cast u32s to u128s
                // before making the contract call, and that is the value
                // that gets emitted here.
                vout: u32::try_from(vout).map_err(EventError::ClarityIntConversion)?,
            },
            sweep_block_hash: BitcoinBlockHash::from_slice(&sweep_block_hash)
                .map_err(EventError::ClarityHashConversion)?,
            sweep_block_height: u64::try_from(sweep_block_height)
                .map_err(EventError::ClarityIntConversion)?,
            sweep_txid: BitcoinTxid::from_slice(&sweep_txid)
                .map_err(EventError::ClarityHashConversion)?,
        }))
    }

    /// This function is for transforming the print events of the
    /// `complete-withdrawal-accept` function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for `create-withdrawal-request` calls are structured
    /// like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "withdrawal-create",
    ///   amount: uint,
    ///   request-id: uint,
    ///   sender: principal,
    ///   recipient: { version: (buff 1), hashbytes: (buff 32) },
    ///   block-height: uint,
    ///   max-fee: uint,
    /// })
    /// ```
    fn withdrawal_create(mut self) -> Result<RegistryEvent, EventError> {
        let request_id = self.remove_u128("request-id")?;
        let amount = self.remove_u128("amount")?;
        let max_fee = self.remove_u128("max-fee")?;
        let block_height = self.remove_u128("block-height")?;
        let sender = self.remove_principal("sender")?;
        let recipient = self.remove_tuple("recipient")?;

        Ok(RegistryEvent::WithdrawalCreate(WithdrawalCreateEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error, practically speaking. Each withdrawal
            // request increments the integer by one, so we'd have to do many
            // orders of magnitude more requests than there are bitcoin
            // transactions, ever.
            request_id: u64::try_from(request_id).map_err(EventError::ClarityIntConversion)?,
            amount: u64::try_from(amount).map_err(EventError::ClarityIntConversion)?,
            max_fee: u64::try_from(max_fee).map_err(EventError::ClarityIntConversion)?,
            block_height: u64::try_from(block_height).map_err(EventError::ClarityIntConversion)?,
            recipient: recipient.try_into_script_pub_key()?,
            sender,
        }))
    }

    /// This function takes in a recipient as a Clarity Value and returns a
    /// bitcoin address, where the clarity value is:
    /// ```clarity
    /// { version: (buff 1), hashbytes: (buff 32) }
    /// ```
    /// This function gives a breakdown of the acceptable inputs for the
    /// recipient in the `initiate-withdrawal-request` contract call. The
    /// permissible values and their meaning closely tracks the meaning of
    /// [`PoxAddress`](blockstack_lib::chainstate::stacks::address::PoxAddress)es
    /// in stacks core. This meaning is summarized as:
    ///
    /// ```text
    /// version == 0x00 and (len hashbytes) == 20 => P2PKH
    /// version == 0x01 and (len hashbytes) == 20 => P2SH
    /// version == 0x02 and (len hashbytes) == 20 => P2SH-P2WPKH
    /// version == 0x03 and (len hashbytes) == 20 => P2SH-P2WSH
    /// version == 0x04 and (len hashbytes) == 20 => P2WPKH
    /// version == 0x05 and (len hashbytes) == 32 => P2WSH
    /// version == 0x06 and (len hashbytes) == 32 => P2TR
    /// ```
    ///
    /// Also see <https://docs.stacks.co/clarity/functions#get-burn-block-info>
    ///
    /// Below is a detailed breakdown of bitcoin address types and how they
    /// map to the clarity value. In what follows below, the network used
    /// for the human-readable parts is inherited from the network of the
    /// underlying transaction itself (basically, on stacks mainnet we send
    /// to mainnet bitcoin addresses and similarly on stacks testnet we
    /// send to bitcoin testnet addresses).
    ///
    /// ## P2PKH
    ///
    /// Generally speaking, Pay-to-Public-Key-Hash addresses are formed by
    /// taking the Hash160 of the public key, prefixing it with one byte
    /// (0x00 on mainnet and 0x6F on testing) and then base58 encoding the
    /// result.
    ///
    /// To specify this address type in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x00 and the `hashbytes` is the
    /// Hash160 of the public key.
    ///
    ///
    /// ## P2SH, P2SH-P2WPKH, and P2SH-P2WSH
    ///
    /// Pay-to-script-hash-* addresses are formed by taking the Hash160 of
    /// the locking script, prefixing it with one byte (0x05 on mainnet and
    /// 0xC4 on testnet) and base58 encoding the result. The difference
    /// between them lies with the locking script. For P2SH-P2WPKH
    /// addresses, the locking script is:
    /// ```text
    /// 0 || <Hash160 of the compressed public key>
    /// ```
    /// For P2SH-P2WSH addresses, the locking script is:
    /// ```text
    /// 0 || <sha256 of the redeem script>
    /// ```
    /// And for P2SH addresses you get to choose the locking script in its
    /// entirety.
    ///
    /// Again, after you construct the locking script you take its Hash160,
    /// prefix it with one byte and base58 encode it to form the address.
    /// To specify these address types in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x01, 0x02, and 0x03 (for P2SH,
    /// P2SH-P2WPKH, and P2SH-P2WSH respectively) with the `hashbytes` is
    /// the Hash160 of the locking script.
    ///
    ///
    /// ## P2WPKH
    ///
    /// Pay-to-witness-public-key-hash addresses are formed by creating a
    /// witness program made entirely of the Hash160 of the compressed
    /// public key.
    ///
    /// To specify this address type in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x04 and the `hashbytes` is the
    /// Hash160 of the compressed public key.
    ///
    ///
    /// ## P2WSH
    ///
    /// Pay-to-witness-script-hash addresses are formed by taking a witness
    /// program that is compressed entirely of the SHA256 of the redeem
    /// script.
    ///
    /// To specify this address type in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x05 and the `hashbytes` is the
    /// SHA256 of the redeem script.
    ///
    ///
    /// ## P2TR
    ///
    /// Pay-to-taproot addresses are formed by "tweaking" the x-coordinate
    /// of a public key with a merkle tree. The result of the tweak is used
    /// as the witness program for the address.
    ///
    /// To specify this address type in the `initiate-withdrawal-request`
    /// contract call, the `version` is 0x06 and the `hashbytes` is the
    /// "tweaked" public key.
    fn try_into_script_pub_key(mut self) -> Result<ScriptBuf, EventError> {
        let version = self.remove_buff("version")?;
        let hash_bytes_buf = self.remove_buff("hashbytes")?;
        let hash_bytes = hash_bytes_buf.as_slice();

        match version.as_slice() {
            // version == 0x00 and (len hashbytes) == 20 => P2PKH
            [0x00] => {
                let bytes =
                    <[u8; 20]>::try_from(hash_bytes).map_err(EventError::ClaritySliceConversion)?;
                let pubkey_hash = PubkeyHash::from_byte_array(bytes);
                Ok(ScriptBuf::new_p2pkh(&pubkey_hash))
            }
            // ```
            // version == 0x01 and (len hashbytes) == 20 => P2SH
            // version == 0x02 and (len hashbytes) == 20 => P2SH-P2WPKH
            // version == 0x03 and (len hashbytes) == 20 => P2SH-P2WSH
            // ```
            //
            // In these cases we assume the `hashbytes` is the Hash160 of
            // the redeem script.
            [0x01] | [0x02] | [0x03] => {
                let bytes =
                    <[u8; 20]>::try_from(hash_bytes).map_err(EventError::ClaritySliceConversion)?;
                let script_hash = ScriptHash::from_byte_array(bytes);
                Ok(ScriptBuf::new_p2sh(&script_hash))
            }
            // version == 0x04 and (len hashbytes) == 20 => P2WPKH
            [0x04] if hash_bytes.len() == 20 => {
                let program = WitnessProgram::new(WitnessVersion::V0, hash_bytes)
                    .map_err(EventError::InvalidWitnessProgram)?;
                Ok(ScriptBuf::new_witness_program(&program))
            }
            // version == 0x05 and (len hashbytes) == 32 => P2WSH
            [0x05] if hash_bytes.len() == 32 => {
                let program = WitnessProgram::new(WitnessVersion::V0, hash_bytes)
                    .map_err(EventError::InvalidWitnessProgram)?;
                Ok(ScriptBuf::new_witness_program(&program))
            }
            // version == 0x06 and (len hashbytes) == 32 => P2TR
            [0x06] if hash_bytes.len() == 32 => {
                let program = WitnessProgram::new(WitnessVersion::V1, hash_bytes)
                    .map_err(EventError::InvalidWitnessProgram)?;
                Ok(ScriptBuf::new_witness_program(&program))
            }
            // We make sure that the version and hash byte lengths conform
            // to the above expectations in the smart contract, so this
            // should never happen.
            _ => Err(EventError::UnhandledRecipient(version, hash_bytes_buf)),
        }
    }

    /// This function is for transforming the print events of the
    /// `complete-withdrawal-accept` function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for `complete-withdrawal-accept` calls are
    /// structured like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "withdrawal-accept",
    ///   request-id: uint,
    ///   bitcoin-txid: (buff 32),
    ///   signer-bitmap: uint,
    ///   bitcoin-index: uint,
    ///   fee: uint,
    ///   burn-hash: (buff 32),
    ///   burn-height: uint,
    ///   sweep-txid: (buff 32),
    /// })
    /// ```
    fn withdrawal_accept(mut self) -> Result<RegistryEvent, EventError> {
        let request_id = self.remove_u128("request-id")?;
        let bitmap = self.remove_u128("signer-bitmap")?;
        let fee = self.remove_u128("fee")?;
        let vout = self.remove_u128("output-index")?;
        let txid_bytes = self.remove_buff("bitcoin-txid")?;
        let mut sweep_block_hash = self.remove_buff("burn-hash")?;
        let sweep_block_height = self.remove_u128("burn-height")?;
        let sweep_txid = self.remove_buff("sweep-txid")?;

        // The `sweep_block_hash` we receive is reversed, so we reverse it here
        // so that we store it in an ordering consistent with the rest of our db.
        sweep_block_hash.reverse();

        Ok(RegistryEvent::WithdrawalAccept(WithdrawalAcceptEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error for the reasons noted in
            // [`withdrawal_create`].
            request_id: u64::try_from(request_id).map_err(EventError::ClarityIntConversion)?,
            signer_bitmap: BitArray::new(bitmap.to_le_bytes()),
            outpoint: OutPoint {
                // This shouldn't error, this is set from a proper [`Txid`] in
                // a contract call.
                txid: BitcoinTxid::from_slice(&txid_bytes)
                    .map_err(EventError::ClarityHashConversion)?,
                // This shouldn't actually error, we cast u32s to u128s before
                // making the contract call, and that is the value that gets
                // emitted here.
                vout: u32::try_from(vout).map_err(EventError::ClarityIntConversion)?,
            },
            // This shouldn't error, since this amount is set from the u64
            // amount of sats by us.
            fee: u64::try_from(fee).map_err(EventError::ClarityIntConversion)?,

            sweep_block_hash: BitcoinBlockHash::from_slice(&sweep_block_hash)
                .map_err(EventError::ClarityHashConversion)?,

            sweep_block_height: u64::try_from(sweep_block_height)
                .map_err(EventError::ClarityIntConversion)?,

            sweep_txid: BitcoinTxid::from_slice(&sweep_txid)
                .map_err(EventError::ClarityHashConversion)?,
        }))
    }

    /// This function is for transforming the print events of the
    /// `complete-withdrawal-reject` function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for `complete-withdrawal-reject` calls are structured
    /// like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "withdrawal-reject",
    ///   request-id: uint,
    ///   signer-bitmap: uint,
    /// })
    /// ```
    ///
    /// The above event is emitted after the locked sBTC has been unlocked back
    /// to the account that initiated the request.
    fn withdrawal_reject(mut self) -> Result<RegistryEvent, EventError> {
        let request_id = self.remove_u128("request-id")?;
        let bitmap = self.remove_u128("signer-bitmap")?;

        Ok(RegistryEvent::WithdrawalReject(WithdrawalRejectEvent {
            txid: self.tx_info.txid,
            block_id: self.tx_info.block_id,
            // This shouldn't error for the reasons noted in
            // [`withdrawal_create`].
            request_id: u64::try_from(request_id).map_err(EventError::ClarityIntConversion)?,
            signer_bitmap: BitArray::new(bitmap.to_le_bytes()),
        }))
    }

    /// This function is for transforming the print events of the
    /// `rotate-keys` function in the sbtc-registry.
    ///
    /// # Notes
    ///
    /// The print events for `rotate-keys` calls are structured like so:
    ///
    /// ```clarity
    /// (print {
    ///   topic: "key-rotation",
    ///   new-keys: (list 128 (buff 33))
    ///   new-address: principal
    ///   new-aggregate-pubkey: (buff 33)
    ///   new-signature-threshold: uint
    /// })
    /// ```
    ///
    /// The above event is emitted after the keys for the multi-sig wallet
    /// have been rotated.
    fn key_rotation(mut self) -> Result<RegistryEvent, EventError> {
        let new_keys = self
            .remove_list("new-keys")?
            .into_iter()
            .map(|val| match val {
                ClarityValue::Sequence(SequenceData::Buffer(buf)) => {
                    PublicKey::from_slice(&buf.data).map_err(EventError::ClarityPublicKeyConversion)
                }
                _ => Err(EventError::ClarityUnexpectedValue(val, self.tx_info)),
            })
            .collect::<Result<Vec<PublicKey>, EventError>>()?;

        let new_address = self.remove_principal("new-address")?;
        let new_aggregate_pubkey = self.remove_buff("new-aggregate-pubkey")?;
        let new_signature_threshold = self.remove_u128("new-signature-threshold")?;

        Ok(RegistryEvent::KeyRotation(KeyRotationEvent {
            new_keys,
            new_address,
            new_aggregate_pubkey: PublicKey::from_slice(&new_aggregate_pubkey)
                .map_err(EventError::ClarityPublicKeyConversion)?,
            new_signature_threshold: u16::try_from(new_signature_threshold)
                .map_err(EventError::ClarityIntConversion)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bitcoin::key::CompressedPublicKey;
    use bitcoin::key::TweakedPublicKey;
    use bitvec::field::BitField as _;
    use clarity::vm::types::ListData;
    use clarity::vm::types::ListTypeData;
    use clarity::vm::types::BUFF_33;
    use rand::rngs::OsRng;
    use secp256k1::SECP256K1;

    use super::*;

    use test_case::test_case;

    const TX_INFO: TxInfo = TxInfo {
        txid: StacksTxid([0; 32]),
        block_id: StacksBlockId([0; 32]),
    };

    #[test]
    fn signer_bitmap_conversion() {
        // This test checks that converting from an integer to the bitmap
        // works the way that we expect.
        let bitmap_number: u128 = 3;
        let bitmap: BitArray<[u8; 16]> = BitArray::new(bitmap_number.to_le_bytes());

        assert_eq!(bitmap.load_le::<u128>(), bitmap_number);

        // This is basically a test of the same thing as the above, except
        // that we explicitly create the signer bitmap.
        let mut bitmap: BitArray<[u8; 16]> = BitArray::ZERO;
        bitmap.set(0, true);
        bitmap.set(1, true);

        assert_eq!(bitmap.load_le::<u128>(), bitmap_number);
    }

    #[test]
    fn complete_deposit_event() {
        let amount = 123654789;
        let event = [
            (ClarityName::from("amount"), ClarityValue::UInt(amount)),
            (
                ClarityName::from("bitcoin-txid"),
                ClarityValue::buff_from(vec![1; 32]).unwrap(),
            ),
            (ClarityName::from("output-index"), ClarityValue::UInt(3)),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("completed-deposit".as_bytes().to_vec())
                    .unwrap(),
            ),
            (
                ClarityName::from("burn-hash"),
                ClarityValue::buff_from(vec![2; 32]).unwrap(),
            ),
            (ClarityName::from("burn-height"), ClarityValue::UInt(139)),
            (
                ClarityName::from("sweep-txid"),
                ClarityValue::buff_from(vec![3; 32]).unwrap(),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::CompletedDeposit(event) => {
                assert_eq!(event.amount, amount as u64);
                assert_eq!(event.outpoint.txid, BitcoinTxid::from_byte_array([1; 32]));
                assert_eq!(event.outpoint.vout, 3);
                assert_eq!(
                    event.sweep_block_hash,
                    BitcoinBlockHash::from_byte_array([2; 32])
                );
                assert_eq!(event.sweep_block_height, 139);
                assert_eq!(event.sweep_txid, BitcoinTxid::from_byte_array([3; 32]));
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    #[test]
    fn create_withdrawal_event() {
        let amount = 24681012;
        let request_id = 1;
        let sender = PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap();
        let block_height = 139;
        let max_fee = 369;
        let recipient_address = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([0; 20]));
        let recipient = vec![
            (
                ClarityName::from("version"),
                ClarityValue::buff_from_byte(0),
            ),
            (
                ClarityName::from("hashbytes"),
                ClarityValue::buff_from(vec![0; 20]).unwrap(),
            ),
        ];
        let event = [
            (
                ClarityName::from("request-id"),
                ClarityValue::UInt(request_id),
            ),
            (
                ClarityName::from("signer-bitmap"),
                ClarityValue::UInt(13579),
            ),
            (ClarityName::from("max-fee"), ClarityValue::UInt(max_fee)),
            (ClarityName::from("output-index"), ClarityValue::UInt(2)),
            (ClarityName::from("amount"), ClarityValue::UInt(amount)),
            (
                ClarityName::from("block-height"),
                ClarityValue::UInt(block_height),
            ),
            (
                ClarityName::from("bitcoin-txid"),
                ClarityValue::buff_from(vec![1; 32]).unwrap(),
            ),
            (
                ClarityName::from("sender"),
                ClarityValue::Principal(sender.clone()),
            ),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("withdrawal-create".as_bytes().to_vec())
                    .unwrap(),
            ),
            (
                ClarityName::from("recipient"),
                ClarityValue::Tuple(TupleData::from_data(recipient).unwrap()),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        // let res = transform_value(value, NetworkKind::Regtest).unwrap();
        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::WithdrawalCreate(event) => {
                assert_eq!(event.amount, amount as u64);
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.block_height, block_height as u64);
                assert_eq!(event.max_fee, max_fee as u64);
                assert_eq!(event.sender, sender.into());
                assert_eq!(event.recipient, recipient_address);
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    #[test]
    fn accept_withdrawal_event() {
        let request_id = 1;
        let bitmap = 13579;
        let fee = 369;
        let vout = 20;
        let event = [
            (
                ClarityName::from("request-id"),
                ClarityValue::UInt(request_id),
            ),
            (
                ClarityName::from("signer-bitmap"),
                ClarityValue::UInt(bitmap),
            ),
            (ClarityName::from("fee"), ClarityValue::UInt(fee)),
            (
                ClarityName::from("bitcoin-txid"),
                ClarityValue::buff_from(vec![1; 32]).unwrap(),
            ),
            (ClarityName::from("output-index"), ClarityValue::UInt(vout)),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("withdrawal-accept".as_bytes().to_vec())
                    .unwrap(),
            ),
            (
                ClarityName::from("burn-hash"),
                ClarityValue::buff_from(vec![2; 32]).unwrap(),
            ),
            (ClarityName::from("burn-height"), ClarityValue::UInt(139)),
            (
                ClarityName::from("sweep-txid"),
                ClarityValue::buff_from(vec![3; 32]).unwrap(),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        // let res = transform_value(value, NetworkKind::Regtest).unwrap();
        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::WithdrawalAccept(event) => {
                let expected_bitmap = BitArray::<[u8; 16]>::new(bitmap.to_le_bytes());
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.outpoint.txid, BitcoinTxid::from_byte_array([1; 32]));
                assert_eq!(event.outpoint.vout, vout as u32);
                assert_eq!(event.fee, fee as u64);
                assert_eq!(event.signer_bitmap, expected_bitmap);
                assert_eq!(
                    event.sweep_block_hash,
                    BitcoinBlockHash::from_byte_array([2; 32])
                );
                assert_eq!(event.sweep_block_height, 139);
                assert_eq!(event.sweep_txid, BitcoinTxid::from_byte_array([3; 32]));
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    #[test]
    fn reject_withdrawal_event() {
        let request_id = 1;
        let bitmap = 13579;
        let event = [
            (
                ClarityName::from("request-id"),
                ClarityValue::UInt(request_id),
            ),
            (
                ClarityName::from("signer-bitmap"),
                ClarityValue::UInt(bitmap),
            ),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("withdrawal-reject".as_bytes().to_vec())
                    .unwrap(),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        // let res = transform_value(value, NetworkKind::Regtest).unwrap();
        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::WithdrawalReject(event) => {
                let expected_bitmap = BitArray::<[u8; 16]>::new(bitmap.to_le_bytes());
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.signer_bitmap, expected_bitmap);
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    #[test]
    fn test_key_rotation_event() {
        let new_keys: Vec<PublicKey> = (0..3)
            .map(|_| SECP256K1.generate_keypair(&mut OsRng).1)
            .collect();
        let new_address =
            PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap();
        let new_aggregate_pubkey = SECP256K1.generate_keypair(&mut OsRng).1;
        let new_signature_threshold = 2;

        let event = [
            (
                ClarityName::from("new-keys"),
                ClarityValue::Sequence(SequenceData::List(ListData {
                    data: new_keys
                        .iter()
                        .map(|key| ClarityValue::buff_from(key.serialize().into()).unwrap())
                        .collect(),
                    type_signature: ListTypeData::new_list(BUFF_33.clone(), 128)
                        .expect("Expected list"),
                })),
            ),
            (
                ClarityName::from("new-address"),
                ClarityValue::Principal(new_address.clone()),
            ),
            (
                ClarityName::from("new-aggregate-pubkey"),
                ClarityValue::buff_from(new_aggregate_pubkey.serialize().into()).unwrap(),
            ),
            (
                ClarityName::from("new-signature-threshold"),
                ClarityValue::UInt(new_signature_threshold as u128),
            ),
            (
                ClarityName::from("topic"),
                ClarityValue::string_ascii_from_bytes("key-rotation".as_bytes().to_vec()).unwrap(),
            ),
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        match RegistryEvent::try_new(value, TX_INFO).unwrap() {
            RegistryEvent::KeyRotation(event) => {
                assert_eq!(event.new_keys, new_keys);
                assert_eq!(event.new_address, new_address);
                assert_eq!(event.new_aggregate_pubkey, new_aggregate_pubkey);
                assert_eq!(event.new_signature_threshold, new_signature_threshold);
            }
            e => panic!("Got the wrong event variant: {e:?}"),
        };
    }

    // Just a random public key to make the test case definitions below a
    // little tidier.
    static PUBLIC_KEY: LazyLock<CompressedPublicKey> = LazyLock::new(|| {
        CompressedPublicKey(secp256k1::SecretKey::new(&mut OsRng).public_key(SECP256K1))
    });

    // A "tweaked" public key that is used to make the test case
    // definition below a little easier on the eyes.
    static TWEAKED_PUBLIC_KEY: LazyLock<TweakedPublicKey> =
        LazyLock::new(|| TweakedPublicKey::dangerous_assume_tweaked((*PUBLIC_KEY).into()));

    // A helper function for creating "P2SH-P2WPKH" and "P2SH-P2WSH" script
    // hashes.
    fn new_p2sh_segwit<T: AsRef<bitcoin::script::PushBytes>>(data: T) -> ScriptHash {
        ScriptBuf::builder()
            .push_int(0)
            .push_slice(data)
            .into_script()
            .script_hash()
    }

    impl RawTupleData {
        fn new_recipient<const N: usize>(version: u8, hash: [u8; N]) -> Self {
            let recipient = [
                (
                    ClarityName::from("version"),
                    ClarityValue::buff_from_byte(version),
                ),
                (
                    ClarityName::from("hashbytes"),
                    ClarityValue::buff_from(hash.to_vec()).unwrap(),
                ),
            ]
            .into_iter()
            .collect();

            RawTupleData::new(recipient, TX_INFO)
        }
    }

    #[test_case(
        0x00,
        PubkeyHash::from(*PUBLIC_KEY).to_byte_array(),
        ScriptBuf::new_p2pkh(&PUBLIC_KEY.pubkey_hash());
    "P2PKH")]
    #[test_case(
        0x01,
        ScriptHash::from(ScriptBuf::new_op_return([1; 5])).to_byte_array(),
        ScriptBuf::new_p2sh(&ScriptBuf::new_op_return([1; 5]).script_hash());
    "P2SH")]
    #[test_case(
        0x02,
        new_p2sh_segwit(PUBLIC_KEY.wpubkey_hash()).to_byte_array(),
        ScriptBuf::new_p2sh(&new_p2sh_segwit(PUBLIC_KEY.wpubkey_hash()));
    "P2SH-P2WPKH")]
    #[test_case(
        0x03,
        new_p2sh_segwit(ScriptBuf::new_op_return([1; 5]).wscript_hash()).to_byte_array(),
        ScriptBuf::new_p2sh(&new_p2sh_segwit(ScriptBuf::new_op_return([1; 5]).wscript_hash()));
    "P2SH-P2WSH")]
    #[test_case(
        0x04,
        PubkeyHash::from(*PUBLIC_KEY).to_byte_array(),
        ScriptBuf::new_p2wpkh(&PUBLIC_KEY.wpubkey_hash());
    "P2WPKH")]
    #[test_case(
        0x05,
        ScriptBuf::new_op_return([1; 5]).wscript_hash().to_byte_array(),
        ScriptBuf::new_p2wsh(&ScriptBuf::new_op_return([1; 5]).wscript_hash());
    "P2WSH")]
    #[test_case(
        0x06,
        TWEAKED_PUBLIC_KEY.serialize(),
        ScriptBuf::new_p2tr_tweaked(*TWEAKED_PUBLIC_KEY);
    "P2TR")]
    fn recipient_to_script_pub_key<const N: usize>(version: u8, hash: [u8; N], script: ScriptBuf) {
        // For these tests, we show what is expected for the hashbytes for
        // each of the address types and check that the result of the
        // `RawTupleData::try_into_script_pub_key` function matches what
        // the corresponding ScriptBuf function would return.
        //
        // First make a clarity tuple from the input data.
        let map = RawTupleData::new_recipient(version, hash);
        // Now test the function output matches what we expect.
        let actual_script_pub_key = map.try_into_script_pub_key().unwrap();
        assert_eq!(actual_script_pub_key, script);
    }

    #[test_case(0x06, [1; 33]; "hash 33 bytes P2TR")]
    #[test_case(0x06, [1; 20]; "hash 20 bytes P2TR")]
    #[test_case(0x07, [1; 20]; "incorrect version 1")]
    #[test_case(0x07, [1; 32]; "incorrect version 2")]
    #[test_case(0x05, [1; 20]; "bad p2wsh hash length")]
    #[test_case(0x00, [1; 32]; "bad p2pkh 1")]
    #[test_case(0x00, [1; 21]; "bad p2pkh 2")]
    fn bad_recipient_cases<const N: usize>(version: u8, hash: [u8; N]) {
        // For these tests, we show what is unexpected lengths in the
        // hashbytes leads to the `RawTupleData::try_into_script_pub_key`
        // returning an error.
        let map = RawTupleData::new_recipient(version, hash);
        let res = map.try_into_script_pub_key();
        assert!(res.is_err());
    }
}
