//! For deconstructing print events emitted from in the sbtc-registry smart
//! contract.
//!
//! Print events from the sBTC registry come in as [`TupleData`] clarity
//! values. Each tuple has a topic field that takes one of four values. We
//! deconstruct the tuple data based on the topic.

use std::collections::BTreeMap;

use bitcoin::hashes::Hash;
use bitcoin::params::Params;
use bitcoin::Address;
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

use crate::config::NetworkKind;
use crate::error::Error;

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
}

impl RegistryEvent {
    /// Transform the [`ClarityValue`] from the sbtc-registry event into a
    /// proper type.
    pub fn try_new(
        value: ClarityValue,
        txid: StacksTxid,
        network: NetworkKind,
    ) -> Result<Self, Error> {
        match value {
            ClarityValue::Tuple(TupleData { data_map, .. }) => {
                let mut event_map = RawTupleData::new(data_map, txid);
                // Lucky for us, each sBTC print event in the sbtc-registry
                // smart contract has a topic. We use that to match on what
                // to expect when decomposing the event from a
                // [`ClarityValue`] into a proper type.
                let topic = event_map.remove_string("topic")?;

                match topic.as_str() {
                    "completed-deposit" => event_map.completed_deposit(),
                    "withdrawal-accept" => event_map.withdrawal_accept(),
                    "withdrawal-create" => event_map.withdrawal_create(network),
                    "withdrawal-reject" => event_map.withdrawal_reject(),
                    _ => Err(Error::ClarityUnexpectedEventTopic(topic)),
                }
            }
            value => Err(Error::ClarityUnexpectedValue(value, txid)),
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
    /// This is the amount of sBTC to mint to the intended recipient.
    pub amount: u64,
    /// This is the outpoint of the original bitcoin deposit transaction.
    pub outpoint: OutPoint,
}

/// This is the event that is emitted from the `create-withdrawal-request`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalCreateEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// This is the unique identifier of the withdrawal request.
    pub request_id: u64,
    /// This is the amount of sBTC that is locked and requested to be
    /// withdrawal as sBTC.
    pub amount: u64,
    /// This is the principal who has their sBTC locked up.
    pub sender: PrincipalData,
    /// This is the address to send the BTC to when fulfilling the
    /// withdrawal request.
    pub recipient: Address,
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
}

/// This is the event that is emitted from the `complete-withdrawal-reject`
/// public function in sbtc-registry smart contract.
#[derive(Debug, Clone)]
pub struct WithdrawalRejectEvent {
    /// The transaction id of the stacks transaction that generated this
    /// event.
    pub txid: StacksTxid,
    /// This is the unique identifier of user created the withdrawal
    /// request.
    pub request_id: u64,
    /// The bitmap of how the signers voted for the withdrawal request.
    /// Here, a 1 (or true) implies that the signer did *not* vote to
    /// accept the request.
    pub signer_bitmap: BitArray<[u8; 16]>,
}

#[derive(Debug)]
struct RawTupleData {
    data_map: BTreeMap<ClarityName, ClarityValue>,
    txid: StacksTxid,
}

impl RawTupleData {
    fn new(data_map: BTreeMap<ClarityName, ClarityValue>, txid: StacksTxid) -> Self {
        Self { data_map, txid }
    }
    /// Extract the u128 value from the given field
    fn remove_u128(&mut self, field: &'static str) -> Result<u128, Error> {
        match self.data_map.remove(field) {
            Some(ClarityValue::UInt(val)) => Ok(val),
            _ => Err(Error::TupleEventField(field, self.txid)),
        }
    }
    /// Extract the buff value from the given field
    fn remove_buff(&mut self, field: &'static str) -> Result<Vec<u8>, Error> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Sequence(SequenceData::Buffer(buf))) => Ok(buf.data),
            _ => Err(Error::TupleEventField(field, self.txid)),
        }
    }
    /// Extract the principal value from the given field
    fn remove_principal(&mut self, field: &'static str) -> Result<PrincipalData, Error> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Principal(principal)) => Ok(principal),
            _ => Err(Error::TupleEventField(field, self.txid)),
        }
    }
    /// Extract the string value from the given field
    fn remove_string(&mut self, field: &'static str) -> Result<String, Error> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Sequence(SequenceData::String(CharType::ASCII(ascii)))) => {
                String::from_utf8(ascii.data).map_err(Error::ClarityStringConversion)
            }
            _ => Err(Error::TupleEventField(field, self.txid)),
        }
    }
    /// Extract the tuple value from the given field
    fn remove_tuple(&mut self, field: &'static str) -> Result<Self, Error> {
        match self.data_map.remove(field) {
            Some(ClarityValue::Tuple(TupleData { data_map, .. })) => {
                Ok(Self::new(data_map, self.txid))
            }
            _ => Err(Error::TupleEventField(field, self.txid)),
        }
    }

    /// This function if for transforming the print events of the
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
    /// })
    /// ```
    ///
    /// The above event is emitted after the indicated amount of sBTC has
    /// been emitted to the recipient.
    fn completed_deposit(mut self) -> Result<RegistryEvent, Error> {
        let amount = self.remove_u128("amount")?;
        let vout = self.remove_u128("output-index")?;
        let txid_bytes = self.remove_buff("bitcoin-txid")?;

        Ok(RegistryEvent::CompletedDeposit(CompletedDepositEvent {
            txid: self.txid,
            // This shouldn't error, since this amount is set from the u64
            // amount of sats by us.
            amount: u64::try_from(amount).map_err(Error::ClarityIntConversion)?,
            outpoint: OutPoint {
                // This shouldn't error, this is set from a proper [`Txid`]
                // in a contract call.
                txid: BitcoinTxid::from_slice(&txid_bytes).map_err(Error::ClarityTxidConversion)?,
                // This shouldn't actually error, we cast u32s to u128s
                // before making the contract call, and that is the value
                // that gets emitted here.
                vout: u32::try_from(vout).map_err(Error::ClarityIntConversion)?,
            },
        }))
    }

    /// This function if for transforming the print events of the
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
    fn withdrawal_create(mut self, network: NetworkKind) -> Result<RegistryEvent, Error> {
        let request_id = self.remove_u128("request-id")?;
        let amount = self.remove_u128("amount")?;
        let max_fee = self.remove_u128("max-fee")?;
        let block_height = self.remove_u128("block-height")?;
        let sender = self.remove_principal("sender")?;
        let recipient = self.remove_tuple("recipient")?;

        Ok(RegistryEvent::WithdrawalCreate(WithdrawalCreateEvent {
            txid: self.txid,
            // This shouldn't error, practically speaking. Each withdrawal
            // request increments the integer by one, so we'd have to do many
            // orders of magnitude more requests than there are bitcoin
            // transactions, ever.
            request_id: u64::try_from(request_id).map_err(Error::ClarityIntConversion)?,
            amount: u64::try_from(amount).map_err(Error::ClarityIntConversion)?,
            max_fee: u64::try_from(max_fee).map_err(Error::ClarityIntConversion)?,
            block_height: u64::try_from(block_height).map_err(Error::ClarityIntConversion)?,
            recipient: recipient.try_into_address(network)?,
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
    fn try_into_address(mut self, network: NetworkKind) -> Result<Address, Error> {
        let version = self.remove_buff("version")?;
        let hash_bytes_buf = self.remove_buff("hashbytes")?;
        let hash_bytes = hash_bytes_buf.as_slice();

        match version.as_slice() {
            // version == 0x00 and (len hashbytes) == 20 => P2PKH
            [0x00] => {
                let bytes =
                    <[u8; 20]>::try_from(hash_bytes).map_err(Error::ClaritySliceConversion)?;
                let pk_hash = PubkeyHash::from_byte_array(bytes);
                Ok(Address::p2pkh(pk_hash, network))
            }
            // ```
            // version == 0x01 and (len hashbytes) == 20 => P2SH
            // version == 0x02 and (len hashbytes) == 20 => P2SH-P2WPKH
            // version == 0x03 and (len hashbytes) == 20 => P2SH-P2WSH
            // ```
            //
            // In this case we assume that the `hashbytes` is the Hash160
            // of the redeem script.
            //
            // We'd like to just use [`Address::p2sh_from_hash`] on our
            // given script hash but that method is private. So instead we
            // create a full P2SH Script and have [`Address::from_script`]
            // extract the script hash from the full script.
            [0x01] | [0x02] | [0x03] => {
                let bytes =
                    <[u8; 20]>::try_from(hash_bytes).map_err(Error::ClaritySliceConversion)?;
                let script_hash = ScriptHash::from_byte_array(bytes);
                let script = ScriptBuf::new_p2sh(&script_hash);
                let params = match network {
                    NetworkKind::Mainnet => Params::BITCOIN,
                    NetworkKind::Testnet => Params::TESTNET,
                    NetworkKind::Regtest => Params::REGTEST,
                };
                Address::from_script(script.as_script(), params).map_err(Error::InvalidScript)
            }
            // version == 0x04 and (len hashbytes) == 20 => P2WPKH
            [0x04] if hash_bytes.len() == 20 => {
                let program = WitnessProgram::new(WitnessVersion::V0, hash_bytes)
                    .map_err(Error::InvalidWitnessProgram)?;
                Ok(Address::from_witness_program(program, network))
            }
            // version == 0x05 and (len hashbytes) == 32 => P2WSH
            [0x05] if hash_bytes.len() == 32 => {
                let program = WitnessProgram::new(WitnessVersion::V0, hash_bytes)
                    .map_err(Error::InvalidWitnessProgram)?;
                Ok(Address::from_witness_program(program, network))
            }
            // version == 0x06 and (len hashbytes) == 32 => P2TR
            [0x06] if hash_bytes.len() == 32 => {
                let program = WitnessProgram::new(WitnessVersion::V1, hash_bytes)
                    .map_err(Error::InvalidWitnessProgram)?;
                Ok(Address::from_witness_program(program, network))
            }
            // We make sure that the version and hash byte lengths conform
            // to the above expectations in the smart contract, so this
            // should never happen.
            _ => Err(Error::UnhandledRecipient(version, hash_bytes_buf)),
        }
    }

    /// This function if for transforming the print events of the
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
    ///   fee: fee
    /// })
    /// ```
    fn withdrawal_accept(mut self) -> Result<RegistryEvent, Error> {
        let request_id = self.remove_u128("request-id")?;
        let bitmap = self.remove_u128("signer-bitmap")?;
        let fee = self.remove_u128("fee")?;
        let vout = self.remove_u128("output-index")?;
        let txid_bytes = self.remove_buff("bitcoin-txid")?;

        Ok(RegistryEvent::WithdrawalAccept(WithdrawalAcceptEvent {
            txid: self.txid,
            // This shouldn't error for the reasons noted in
            // [`withdrawal_create`].
            request_id: u64::try_from(request_id).map_err(Error::ClarityIntConversion)?,
            signer_bitmap: BitArray::new(bitmap.to_le_bytes()),
            outpoint: OutPoint {
                // This shouldn't error, this is set from a proper [`Txid`] in
                // a contract call.
                txid: BitcoinTxid::from_slice(&txid_bytes).map_err(Error::ClarityTxidConversion)?,
                // This shouldn't actually error, we cast u32s to u128s before
                // making the contract call, and that is the value that gets
                // emitted here.
                vout: u32::try_from(vout).map_err(Error::ClarityIntConversion)?,
            },
            // This shouldn't error, since this amount is set from the u64
            // amount of sats by us.
            fee: u64::try_from(fee).map_err(Error::ClarityIntConversion)?,
        }))
    }

    /// This function if for transforming the print events of the
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
    fn withdrawal_reject(mut self) -> Result<RegistryEvent, Error> {
        let request_id = self.remove_u128("request-id")?;
        let bitmap = self.remove_u128("signer-bitmap")?;

        Ok(RegistryEvent::WithdrawalReject(WithdrawalRejectEvent {
            txid: self.txid,
            // This shouldn't error for the reasons noted in
            // [`withdrawal_create`].
            request_id: u64::try_from(request_id).map_err(Error::ClarityIntConversion)?,
            signer_bitmap: BitArray::new(bitmap.to_le_bytes()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bitcoin::key::CompressedPublicKey;
    use bitcoin::key::TweakedPublicKey;
    use bitvec::field::BitField as _;
    use rand::rngs::OsRng;
    use secp256k1::SECP256K1;

    use super::*;

    use test_case::test_case;

    const TXID: StacksTxid = StacksTxid([0; 32]);

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
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        // let res = transform_value(value, NetworkKind::Regtest).unwrap();
        match RegistryEvent::try_new(value, TXID, NetworkKind::Regtest).unwrap() {
            RegistryEvent::CompletedDeposit(event) => {
                assert_eq!(event.amount, amount as u64);
                assert_eq!(event.outpoint.txid, BitcoinTxid::from_byte_array([1; 32]));
                assert_eq!(event.outpoint.vout, 3);
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
        let recipient_address =
            Address::p2pkh(PubkeyHash::from_byte_array([0; 20]), NetworkKind::Regtest);
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
        match RegistryEvent::try_new(value, TXID, NetworkKind::Regtest).unwrap() {
            RegistryEvent::WithdrawalCreate(event) => {
                assert_eq!(event.amount, amount as u64);
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.block_height, block_height as u64);
                assert_eq!(event.max_fee, max_fee as u64);
                assert_eq!(event.sender, sender);
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
        ];
        let tuple_data = TupleData::from_data(event.to_vec()).unwrap();
        let value = ClarityValue::Tuple(tuple_data);

        // let res = transform_value(value, NetworkKind::Regtest).unwrap();
        match RegistryEvent::try_new(value, TXID, NetworkKind::Regtest).unwrap() {
            RegistryEvent::WithdrawalAccept(event) => {
                let expected_bitmap = BitArray::<[u8; 16]>::new(bitmap.to_le_bytes());
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.outpoint.txid, BitcoinTxid::from_byte_array([1; 32]));
                assert_eq!(event.outpoint.vout, vout as u32);
                assert_eq!(event.fee, fee as u64);
                assert_eq!(event.signer_bitmap, expected_bitmap);
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
        match RegistryEvent::try_new(value, TXID, NetworkKind::Regtest).unwrap() {
            RegistryEvent::WithdrawalReject(event) => {
                let expected_bitmap = BitArray::<[u8; 16]>::new(bitmap.to_le_bytes());
                assert_eq!(event.request_id, request_id as u64);
                assert_eq!(event.signer_bitmap, expected_bitmap);
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

            RawTupleData::new(recipient, TXID)
        }
    }

    #[test_case(
        0x00,
        PubkeyHash::from(*PUBLIC_KEY).to_byte_array(),
        Address::p2pkh(*PUBLIC_KEY, NetworkKind::Regtest) ; "P2PKH")]
    #[test_case(
        0x01,
        ScriptHash::from(ScriptBuf::new_op_return([1; 5])).to_byte_array(),
        Address::p2sh(&ScriptBuf::new_op_return([1; 5]), NetworkKind::Regtest).unwrap() ; "P2SH")]
    #[test_case(
        0x02,
        new_p2sh_segwit(PUBLIC_KEY.wpubkey_hash()).to_byte_array(),
        Address::p2shwpkh(&*PUBLIC_KEY, NetworkKind::Regtest) ; "P2SH-P2WPKH")]
    #[test_case(
        0x03,
        new_p2sh_segwit(ScriptBuf::new_op_return([1; 5]).wscript_hash()).to_byte_array(),
        Address::p2shwsh(&ScriptBuf::new_op_return([1; 5]), NetworkKind::Regtest) ; "P2SH-P2WSH")]
    #[test_case(
        0x04,
        PubkeyHash::from(*PUBLIC_KEY).to_byte_array(),
        Address::p2wpkh(&*PUBLIC_KEY, NetworkKind::Regtest) ; "P2WPKH")]
    #[test_case(
        0x05,
        ScriptBuf::new_op_return([1; 5]).wscript_hash().to_byte_array(),
        Address::p2wsh(&ScriptBuf::new_op_return([1; 5]), NetworkKind::Regtest) ; "P2WSH")]
    #[test_case(
        0x06,
        TWEAKED_PUBLIC_KEY.serialize(),
        Address::p2tr_tweaked(*TWEAKED_PUBLIC_KEY, NetworkKind::Regtest) ; "P2TR")]
    fn recipient_to_btc_address<const N: usize>(version: u8, hash: [u8; N], address: Address) {
        // For these tests, we show what is expected for the hashbytes for
        // each of the address types and check that the result of the
        // [`RawTupleData::try_into_address`] function matches what the
        // corresponding Address function would return.
        let map = RawTupleData::new_recipient(version, hash);
        let actual_address = map.try_into_address(NetworkKind::Regtest).unwrap();
        assert_eq!(actual_address, address);
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
        // hashbytes leads to the [`RawTupleData::try_into_address`]
        // returning an error.
        let map = RawTupleData::new_recipient(version, hash);
        let res = map.try_into_address(NetworkKind::Regtest);
        assert!(res.is_err());
    }
}
