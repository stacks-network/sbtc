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
use clarity::codec::StacksMessageCodec;
use clarity::vm::types::PrincipalData;
use clarity::vm::ContractName;
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
/// script. Thus, its 5 bytes for the opcodes, 1 byte for the length of the
/// public key hash data and 20 bytes for the actual public key hash.
const DEPOSIT_SCRIPT_FIXED_LENGTH: usize = 26;

/// This is the typical number of bytes of a deposit script. It's 1 byte
/// for the length of the following 30 bytes of data, which is 8 bytes for
/// the max fee followed by 1 byte for the address type, 21 bytes the
/// actual standard stacks address, followed by 26 bytes for the fixed
/// length portion of the deposit script. So we have the standard length is
/// 1 + 1 + 8 + 21 + 26 = 57.
const STANDARD_SCRIPT_LENGTH: usize =
    1 + 1 + 8 + STACKS_ADDRESS_ENCODED_SIZE as usize + DEPOSIT_SCRIPT_FIXED_LENGTH;

/// Error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The deposit script was invalid
    #[error("")]
    BadDepositScript,
    /// The reclaim script was invalid
    #[error("")]
    BadReclaimScript,
    /// Could not parse the Stacks principal address.
    #[error("")]
    ParseStacksAddress(#[source] stacks_common::codec::Error),
    /// Error when trying to push too many bytes on the stack in a bitcoin
    /// script.
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
    pub contract_name: Option<ContractName>,
    /// The raw deposit script
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

/// Drops the top stack item
pub const DROP: u8 = opcodes::all::OP_DROP.to_u8();
/// Duplicate the top stack item and puts it on the stack.
pub const DUP: u8 = opcodes::all::OP_DUP.to_u8();
/// Pop the top stack item and push its RIPEMD-160(SHA256) hash.
pub const HASH160: u8 = opcodes::all::OP_HASH160.to_u8();
/// Returns success if the inputs are exactly equal, failure otherwise.
pub const EQUALVERIFY: u8 = opcodes::all::OP_EQUALVERIFY.to_u8();
/// <https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for
/// success/failure.
pub const CHECKSIG: u8 = opcodes::all::OP_CHECKSIG.to_u8();
/// Read the next byte as N; push the next N bytes as an array onto the
/// stack.
pub const OP_PUSHDATA1: u8 = opcodes::all::OP_PUSHDATA1.to_u8();

/// This function checks that the deposit script is valid. Specifically, it
/// checks that it follows the format laid out in (TODO).
pub fn parse_deposit_script(deposit_script: &ScriptBuf) -> Result<DepositScript, Error> {
    let script_bytes = deposit_script.as_bytes();

    // Valid deposit scripts cannot be less than this length.
    if script_bytes.len() < STANDARD_SCRIPT_LENGTH {
        return Err(Error::BadReclaimScript);
    }
    // This cannot panic because of the above check and the fact that
    // DEPOSIT_SCRIPT_FIXED_LENGTH < STANDARD_SCRIPT_LENGTH.
    let (params, script) = script_bytes.split_at(script_bytes.len() - DEPOSIT_SCRIPT_FIXED_LENGTH);
    // Below, we know the script length is DEPOSIT_SCRIPT_FIXED_LENGTH,
    // because of how `slice::split_at` works, so we know the pubkey_hash
    // variable has length 20.
    let [DROP, DUP, HASH160, 20, pubkey_hash @ .., EQUALVERIFY, CHECKSIG] = script else {
        return Err(Error::BadDepositScript);
    };

    // In bitcoin script, the code for pushing N bytes onto the stack is
    // OP_PUSHBYTES_N where N is between 1 and 75 inclusive. The byte
    // representation of these opcodes is the byte representation of N. If
    // you need to push between 76 and 255 bytes of data then you need to
    // use the OP_PUSHDATA1 opcode (you can also use this opcode to push
    // between 1 and 75 bytes on the stack, but it's cheaper to use the
    // OP_PUSHBYTES_N opcodes when you can). When need to check all cases
    // contract addresses can have a size of up to 150 bytes.
    let data = match params {
        // This branch represents a contract address.
        [OP_PUSHDATA1, n, data @ ..] if data.len() == *n as usize && 30 < *n && *n < 159 => data,
        // This branch can be a standard (non-contract) Stacks addresses
        // when n == 29 and is a contract address otherwise.
        [n, data @ ..] if data.len() == *n as usize && 29 < *n && *n < 76 => data,
        _ => return Err(Error::BadDepositScript),
    };
    // Here, `split_first_chunk::<N>` returns Option<(&[u8; N], &[u8])>,
    // where None is returned if the length of the slice is less than N.
    // Since N is 8 and the data variable has a length 30 or greater, the
    // error path cannot happen.
    let Some((max_fee_bytes, mut address)) = data.split_first_chunk::<8>() else {
        return Err(Error::BadDepositScript);
    };
    let principal =
        PrincipalData::consensus_deserialize(&mut address).map_err(Error::ParseStacksAddress)?;
    let (stacks_address, contract_name) = match principal {
        PrincipalData::Standard(s) => (StacksAddress::from(s), None),
        PrincipalData::Contract(c) => (StacksAddress::from(c.issuer), Some(c.name)),
    };

    Ok(DepositScript {
        // This cannot panic, pubkey_hash must have a size of 20 bytes
        // given the let else check above.
        signers_pubkey_hash: PubkeyHash::from_slice(pubkey_hash)
            .map_err(|_| Error::BadDepositScript)?,
        max_fee: u64::from_be_bytes(*max_fee_bytes),
        deposit_script: deposit_script.clone(),
        stacks_address,
        contract_name,
    })
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
        let pubkey_hash = PubkeyHash::hash(&public_key.serialize());
        let max_fee: u64 = 15000;

        let mut deposit_data = max_fee.to_be_bytes().to_vec();
        let address = PrincipalData::from(StacksAddress::burn_address(false));
        deposit_data.extend_from_slice(&address.serialize_to_vec());

        let deposit_data: [u8; 30] = deposit_data.try_into().unwrap();

        let script = ScriptBuf::builder()
            .push_slice(deposit_data)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(pubkey_hash)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        assert_eq!(script.len(), STANDARD_SCRIPT_LENGTH);

        let extracts = parse_deposit_script(&script).unwrap();
        assert_eq!(extracts.signers_pubkey_hash, pubkey_hash);
        assert_eq!(extracts.contract_name, None);
        assert_eq!(extracts.stacks_address, StacksAddress::burn_address(false));
        assert_eq!(extracts.max_fee, max_fee);
        assert_eq!(extracts.deposit_script, script);
    }
}
