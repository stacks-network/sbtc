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
const DEPOSIT_SCRIPT_FIXED_LENGTH: usize = 26;

/// This is the typical number of bytes of a deposit script. It's 1 byte
/// for the length of the following 29 bytes of data, which is 8 bytes for
/// the max fee followed by 21 bytes for a standard stacks address,
/// followed by 26 bytes for the fixed length portion of the deposit
/// script. So we have the standard length is 1 + 8 + 21 + 26 = 56.
const STANDARD_SCRIPT_LENGTH: usize =
    1 + 8 + STACKS_ADDRESS_ENCODED_SIZE as usize + DEPOSIT_SCRIPT_FIXED_LENGTH;

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
pub struct DepositScript {
    /// The last known public key of the signers.
    pub signers_pubkey_hash: PubkeyHash,
    /// The stacks address to deposit the sBTC to. This can be either a
    /// standard address (which is 21 bytes), or a contract address (which
    /// is between 23 and 150 bytes)
    pub stacks_address: StacksAddress,
    /// The name of the contract if this is a contract address.
    pub contract_name: Option<String>,
    /// The reclaim script.
    // pub reclaim_script: ScriptBuf,
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
pub const DROP: u8 = opcodes::all::OP_DROP.to_u8();
///
pub const DUP: u8 = opcodes::all::OP_DUP.to_u8();
///
pub const HASH160: u8 = opcodes::all::OP_HASH160.to_u8();
///
pub const EQUALVERIFY: u8 = opcodes::all::OP_EQUALVERIFY.to_u8();
///
pub const CHECKSIG: u8 = opcodes::all::OP_CHECKSIG.to_u8();

/// This function checks that the deposit script is valid. Specifically, it
/// checks that it follows the format laid out in (TODO).
pub fn extract(deposit: ScriptBuf) -> Result<DepositScript, Error> {
    let script_bytes = deposit.as_bytes();

    // Valid deposit scripts cannot be less than this length.
    if script_bytes.len() < STANDARD_SCRIPT_LENGTH {
        return Err(Error::BadReclaimScript);
    }
    match script_bytes.split_at(script_bytes.len() - DEPOSIT_SCRIPT_FIXED_LENGTH) {
        // This case is for when we are dealing with a standard address.
        // Standard addresses are encoded as a 1-byte version number, a
        // 20-byte Hash160.
        //
        // We always know the second slice has length
        // DEPOSIT_SCRIPT_FIXED_LENGTH, so we know the pubkey_hash variable
        // has length 20. We also know that params has length 29 because of
        // the check. In bitcoin script, bytes `20` and `29` correspond to
        // the OP_PUSHBYTES_20 and OP_PUSHBYTES_29 opcodes respectively.
        ([29, params @ ..], [DROP, DUP, HASH160, 20, pubkey_hash @ .., EQUALVERIFY, CHECKSIG])
            if params.len() == 29 =>
        {
            // The `slice::first_chunk` and `slice::last_chunk` functions
            // return Option<&[u8; N]>, and None is returend if the length
            // of the slice is less than N. Here N is 8 and the params
            // variable has a length of 29, so we can safely get the first
            // 8 bytes without issue.
            let max_fee = u64::from_be_bytes(*params.first_chunk::<8>().unwrap());
            // This cannot panic, params contains 29 bytes.
            let address_version: u8 = params[8];
            // This cannot panic, params contains 29 bytes.
            let address_hash160: [u8; 20] = *params.last_chunk::<20>().unwrap();

            Ok(DepositScript {
                // This cannot panic, pubkey_hash must have a size of 20 bytes.
                signers_pubkey_hash: PubkeyHash::from_slice(pubkey_hash).unwrap(),
                deposit_script: deposit,
                stacks_address: StacksAddress::new(address_version, address_hash160.into()),
                contract_name: None,
                max_fee,
            })
        }
        // This case is for when we are dealing with a contract address.
        // Contract addresses are encoded as a 1-byte version number, a
        // 20-byte Hash160, a 1-byte name length up to 128, and a
        // variable-length name in UTF-8 of up to 128 characters. This
        // string must be accepted by the regex
        // ^[a-zA-Z]([a-zA-Z0-9]|[-_])*$.
        //
        // Like in the above case, we always know the second slice has
        // length DEPOSIT_SCRIPT_FIXED_LENGTH, so we know the pubkey_hash
        // variable has length 20. We also know that params has length 29
        // because of the check.
        ([n, params @ ..], [DROP, DUP, HASH160, 20, pubkeykash @ .., EQUALVERIFY, CHECKSIG])
            if 30 < params.len() && params.len() < 76 =>
        {
            unimplemented!()
        }
        _ => unimplemented!(),
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use secp256k1::SecretKey;
    use stacks_common::codec::StacksMessageCodec;

    use super::*;

    #[test]
    fn test() {
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = secret_key.x_only_public_key(SECP256K1).0;

        let mut deposit_data = 15000u64.to_be_bytes().to_vec();
        let address = StacksAddress::burn_address(false);
        deposit_data.extend_from_slice(&address.serialize_to_vec());

        let deposit_data: [u8; 29] = deposit_data.try_into().unwrap();

        let script = ScriptBuf::builder()
            .push_slice(deposit_data)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(PubkeyHash::hash(&public_key.serialize()))
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        println!("{}", script.len());
        let extracts = dbg!(extract(script).unwrap());
    }
}
