//! This is the transaction analysis module
//!

use bitcoin::hashes::Hash as _;
use bitcoin::opcodes;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::Address;
use bitcoin::KnownHrp;
use bitcoin::Network;
use bitcoin::PubkeyHash;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use secp256k1::SECP256K1;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::chainstate::STACKS_ADDRESS_ENCODED_SIZE;

/// This is the length of the fixed portion of the deposit script, which
/// is:
/// ```text
///  OP_DROP OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
/// ```
/// Although this reads as though it is 25 bytes (20 bytes for the Hash160
/// of the public key and 5 bytes of opcodes), the public key hash data is
/// 21 bytes, since data is prefixed with the size of the data in bitcoin
/// script. Thus its 5 bytes for the opcodes, 1 byte for the length of the
/// public key hash data and 20 bytes for the actual public key hash.
const DEPOSI_SCRIPT_FIXED_LENGTH: usize = 26;

/// This is the typical number of bytes of a deposit script. It's 1 byte
/// for the length of the following 29 bytes of data, which is 8 bytes for
/// the max fee followed by 21 bytes for a standard stacks address,
/// followed by 26 bytes for the fixed length portion of the deposit
/// script. So we have the standard length is 1 + 8 + 21 + 26 = 56.
const STANDARD_SCRIPT_LENGTH: usize = 1 + 8 +
    STACKS_ADDRESS_ENCODED_SIZE as usize + DEPOSI_SCRIPT_FIXED_LENGTH;

/// Error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The script tree contained more than the allowed elements
    #[error("")]
    BadScriptTree,
    /// The deposit script was invalid
    #[error("")]
    BadDepositScript,
    /// The reclaim script was invalid
    #[error("")]
    BadReclaimScript,
    /// The script tree did not hash the the correct merkle root
    #[error("")]
    BadMerkleRoot,
    /// The script tree did not hash the the correct merkle root
    #[error("")]
    PushBytes(#[source] bitcoin::script::PushBytesError),
}

/// This struct contains the key variable inputs when constructing a
/// deposit address.
#[derive(Debug, Clone)]
pub struct DepositInputs {
    /// The last known public key of the signers.
    pub signers_public_key: XOnlyPublicKey,
    /// The stacks address to deposit the sBTC to. This can be either a
    /// standard address (which is 21 bytes), or a contract address (which
    /// is between 23 and 150 bytes)
    pub stacks_address: Vec<u8>,
    /// The reclaim script.
    pub reclaim_script: ScriptBuf,
    /// The max fee amount to use for the BTC deposit transaction.
    pub max_fee: u64,
}

/// This struct contains the key variable inputs when constructing a
/// deposit address.
#[derive(Debug, Clone)]
pub struct DepositExtracts {
    /// The last known public key of the signers.
    pub signers_pubkey_hash: PubkeyHash,
    /// The stacks address to deposit the sBTC to. This can be either a
    /// standard address (which is 21 bytes), or a contract address (which
    /// is between 23 and 150 bytes)
    pub stacks_address: StacksAddress,
    /// The reclaim script.
    pub reclaim_script: ScriptBuf,
    ///
    pub deposit_script: ScriptBuf,
    /// The max fee amount to use for the BTC deposit transaction.
    pub max_fee: u64,
}

impl DepositInputs {
    /// Construct a bitcoin address for a deposit transaction on the given
    /// network.
    pub fn to_address(&self, network: Network) -> Result<Address, Error> {
        let deposit_script = self.deposit_script()?;
        let ver = LeafVersion::TapScript;

        // For such a simple tree, we construct it by hand.
        let leaf1 = NodeInfo::new_leaf_with_ver(deposit_script, ver);
        let leaf2 = NodeInfo::new_leaf_with_ver(self.reclaim_script.clone(), ver);

        // A Result::Err is returned by NodeInfo::combine if the depth of
        // our taproot tree exceeds the maximum depth of taproot trees,
        // which is 128. We have two nodes so the depth is 1 so this will
        // never panic.
        let node =
            NodeInfo::combine(leaf1, leaf2).expect("Tree depth is greater than the max of 128");
        let internal_key = crate::unspendable_taproot_key();

        let merkle_root =
            TaprootSpendInfo::from_node_info(SECP256K1, *internal_key, node).merkle_root();
        let hrp = KnownHrp::from(network);
        Ok(Address::p2tr(SECP256K1, *internal_key, merkle_root, hrp))
    }

    fn deposit_script(&self) -> Result<ScriptBuf, Error> {
        // The format of the OP_DROP data is shown in
        // https://github.com/stacks-network/sbtc/issues/30
        let mut op_drop_data = PushBytesBuf::with_capacity(self.stacks_address.len() + 8);
        op_drop_data
            .extend_from_slice(&self.max_fee.to_be_bytes())
            .map_err(Error::PushBytes)?;
        op_drop_data
            .extend_from_slice(&self.stacks_address)
            .map_err(Error::PushBytes)?;

        // When using the bitcoin::script::Builder, push_slice
        // automatically inserts the appropriate opcodes based on the data
        // size to be pushed onto the stack. For example, OP_PUSHDATA1 is
        // used if the data length is between 76 and 255 bytes.
        // OP_PUSHDATA2 is used for slice lengths that require 2 bytes to
        // express, and so on.
        Ok(ScriptBuf::builder()
            .push_slice(op_drop_data)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(PubkeyHash::hash(&self.signers_public_key.serialize()))
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script())
    }
}

///
pub fn extract(deposit: ScriptBuf, reclaim: ScriptBuf) -> Result<DepositExtracts, Error> {
    let script_bytes = deposit.as_bytes();
    match script_bytes.len() {
        STANDARD_SCRIPT_LENGTH => {
            let max_fee = u64::from_be_bytes(*script_bytes[1..9].first_chunk().unwrap());
            let address_version: u8 = script_bytes[9];
            let address_hash160: [u8; 20] = *script_bytes[10..30].first_chunk().unwrap();
            let pubkey_hash_bytes: [u8; 20] = *script_bytes[34..54].first_chunk().unwrap();

            Ok(DepositExtracts {
                signers_pubkey_hash: PubkeyHash::from_byte_array(pubkey_hash_bytes),
                stacks_address: StacksAddress::new(address_version, address_hash160.into()),
                deposit_script: deposit,
                max_fee,
                reclaim_script: reclaim,
            })
        }
        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use secp256k1::SecretKey;

    use super::*;

    #[test]
    fn test() {
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = secret_key.x_only_public_key(SECP256K1).0;
        let script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(PubkeyHash::hash(&public_key.serialize()))
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        println!("{}", script.len());
    }
}
