//! This is the transaction analysis module
//!

use bitcoin::opcodes::all as opcodes;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::Address;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::XOnlyPublicKey;
use clarity::codec::StacksMessageCodec;
use clarity::vm::types::PrincipalData;
use secp256k1::SECP256K1;
use stacks_common::types::chainstate::STACKS_ADDRESS_ENCODED_SIZE;

/// This is the length of the fixed portion of the deposit script, which
/// is:
/// ```text
///  OP_DROP OP_PUSHBYTES_32 <x-only-public-key> OP_CHECKSIG
/// ```
/// Since we are using Schnorr signatures, we only use the x-coordinate of
/// the public key. The full public key is assumed to be even.
const DEPOSIT_SCRIPT_FIXED_LENGTH: usize = 35;

/// This is the typical number of bytes of a deposit script. It's 1 byte
/// for the length of the following 30 bytes of data, which is 8 bytes for
/// the max fee followed by 1 byte for the address type, 21 bytes the
/// actual standard stacks address, followed by 34 bytes for the fixed
/// length portion of the deposit script. So we have the standard length is
/// 1 + 1 + 8 + 21 + 34 = 65.
const STANDARD_SCRIPT_LENGTH: usize =
    1 + 1 + 8 + STACKS_ADDRESS_ENCODED_SIZE as usize + DEPOSIT_SCRIPT_FIXED_LENGTH;

/// Errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The deposit script was invalid
    #[error("Invalid deposit script")]
    InvalidDepositScript,
    /// The X-only public key was invalid
    #[error("the x-only public key in the script was invalid: {0}")]
    InvalidXOnlyPublicKey(#[source] secp256k1::Error),
    /// Could not parse the Stacks principal address.
    #[error("could not parse the stacks principal address: {0}")]
    ParseStacksAddress(#[source] stacks_common::codec::Error),
}

/// This struct contains the key variable inputs when constructing a
/// deposit script address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositScriptInputs {
    /// The last known public key of the signers.
    pub signers_public_key: XOnlyPublicKey,
    /// The stacks address to deposit the sBTC to. This can be either a
    /// standard address or a contract address.
    pub recipient: PrincipalData,
    /// The max fee amount to use for the BTC deposit transaction.
    pub max_fee: u64,
}

impl DepositScriptInputs {
    /// Construct a bitcoin address for a deposit transaction on the given
    /// network.
    pub fn to_address(&self, reclaim_script: ScriptBuf, network: Network) -> Address {
        let deposit_script = self.deposit_script();
        let ver = LeafVersion::TapScript;

        // For such a simple tree, we construct it by hand.
        let leaf1 = NodeInfo::new_leaf_with_ver(deposit_script, ver);
        let leaf2 = NodeInfo::new_leaf_with_ver(reclaim_script, ver);

        // A Result::Err is returned by NodeInfo::combine if the depth of
        // our taproot tree exceeds the maximum depth of taproot trees,
        // which is 128. We have two nodes so the depth is 1 so this will
        // never panic.
        let node =
            NodeInfo::combine(leaf1, leaf2).expect("Tree depth is greater than the max of 128");
        let internal_key = crate::unspendable_taproot_key();

        let merkle_root =
            TaprootSpendInfo::from_node_info(SECP256K1, *internal_key, node).merkle_root();
        Address::p2tr(SECP256K1, *internal_key, merkle_root, network)
    }

    /// Construct a deposit script from the inputs
    pub fn deposit_script(&self) -> ScriptBuf {
        // The format of the OP_DROP data, as shown in
        // https://github.com/stacks-network/sbtc/issues/30, is 8 bytes for
        // the max fee followed by up to 151 bytes for the stacks address.
        let recipient_bytes = self.recipient.serialize_to_vec();
        let mut op_drop_data = PushBytesBuf::with_capacity(recipient_bytes.len() + 8);
        // These should never fail. The PushBytesBuf type only
        // errors if the total length of the buffer is greater than
        // u32::MAX. We're pushing a max of 159 bytes.
        op_drop_data
            .extend_from_slice(&self.max_fee.to_be_bytes())
            .expect("8 is greater than u32::MAX?");
        op_drop_data
            .extend_from_slice(&recipient_bytes)
            .expect("159 is greater than u32::MAX?");

        // When using the bitcoin::script::Builder, push_slice
        // automatically inserts the appropriate opcodes based on the data
        // size to be pushed onto the stack. Here, OP_PUSHBYTES_32 is
        // pushed before the public key. Also, OP_PUSHBYTES_N is used if
        // the OP_DROP data length is between 1 and 75 otherwise
        // OP_PUSHDATA1 is used since the data length is less than 255.
        ScriptBuf::builder()
            .push_slice(op_drop_data)
            .push_opcode(opcodes::OP_DROP)
            .push_slice(self.signers_public_key.serialize())
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script()
    }
}

/// Drops the top stack item
pub const OP_DROP: u8 = opcodes::OP_DROP.to_u8();
/// <https://en.bitcoin.it/wiki/OP_CHECKSIG> pushing 1/0 for
/// success/failure.
pub const OP_CHECKSIG: u8 = opcodes::OP_CHECKSIG.to_u8();
/// Read the next byte as N; push the next N bytes as an array onto the
/// stack.
pub const OP_PUSHDATA1: u8 = opcodes::OP_PUSHDATA1.to_u8();

/// This function checks that the deposit script is valid. Specifically, it
/// checks that it follows the format laid out in
/// https://github.com/stacks-network/sbtc/issues/30, where the script is
/// expected to be
/// ```text
///  <deposit-data> OP_DROP OP_PUSHBYTES_32 <x-only-public-key> OP_CHECKSIG
/// ```
pub fn parse_deposit_script(deposit_script: &ScriptBuf) -> Result<DepositScriptInputs, Error> {
    let script = deposit_script.as_bytes();

    // Valid deposit scripts cannot be less than this length.
    if script.len() < STANDARD_SCRIPT_LENGTH {
        return Err(Error::InvalidDepositScript);
    }
    // This cannot panic because of the above check and the fact that
    // DEPOSIT_SCRIPT_FIXED_LENGTH < STANDARD_SCRIPT_LENGTH.
    let (params, check) = script.split_at(script.len() - DEPOSIT_SCRIPT_FIXED_LENGTH);
    // Below, we know the script length is DEPOSIT_SCRIPT_FIXED_LENGTH,
    // because of how `slice::split_at` works, so we know the pubkey_hash
    // variable has length 32.
    let [OP_DROP, 32, public_key @ .., OP_CHECKSIG] = check else {
        return Err(Error::InvalidDepositScript);
    };

    // In bitcoin script, the code for pushing N bytes onto the stack is
    // OP_PUSHBYTES_N where N is between 1 and 75 inclusive. The byte
    // representation of these opcodes is the byte representation of N. If
    // you need to push between 76 and 255 bytes of data then you need to
    // use the OP_PUSHDATA1 opcode (you can also use this opcode to push
    // between 1 and 75 bytes on the stack, but it's cheaper to use the
    // OP_PUSHBYTES_N opcodes when you can). When need to check all cases
    // contract addresses can have a size of up to 151 bytes.
    let data = match params {
        // This branch represents a contract address.
        [OP_PUSHDATA1, n, data @ ..] if data.len() == *n as usize && *n < 160 => data,
        // This branch can be a standard (non-contract) Stacks addresses
        // when n == 29 and is a contract address otherwise.
        [n, data @ ..] if data.len() == *n as usize && *n < 76 => data,
        _ => return Err(Error::InvalidDepositScript),
    };
    // Here, `split_first_chunk::<N>` returns Option<(&[u8; N], &[u8])>,
    // where None is returned if the length of the slice is less than N.
    // Since N is 8 and the data variable has a length 30 or greater, the
    // error path cannot happen.
    let Some((max_fee_bytes, mut address)) = data.split_first_chunk::<8>() else {
        return Err(Error::InvalidDepositScript);
    };
    let stacks_address =
        PrincipalData::consensus_deserialize(&mut address).map_err(Error::ParseStacksAddress)?;

    Ok(DepositScriptInputs {
        signers_public_key: XOnlyPublicKey::from_slice(public_key)
            .map_err(Error::InvalidXOnlyPublicKey)?,
        max_fee: u64::from_be_bytes(*max_fee_bytes),
        recipient: stacks_address,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::AddressType;
    use rand::rngs::OsRng;
    use secp256k1::SecretKey;
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::types::chainstate::StacksAddress;

    use super::*;

    use test_case::test_case;

    const CONTRACT_ADDRESS: &str = "ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y.contract-name";

    /// Check that manually creating the expected script can correctly be
    /// parsed.
    #[test_case(PrincipalData::from(StacksAddress::burn_address(false)) ; "standard address")]
    #[test_case(PrincipalData::parse(CONTRACT_ADDRESS).unwrap(); "contract address")]
    fn deposit_script_parsing_works_standard_principal(recipient: PrincipalData) {
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = secret_key.x_only_public_key(SECP256K1).0;
        let max_fee: u64 = 15000;

        let mut deposit_data = max_fee.to_be_bytes().to_vec();
        deposit_data.extend_from_slice(&recipient.serialize_to_vec());

        let deposit_data: PushBytesBuf = deposit_data.try_into().unwrap();

        let script = ScriptBuf::builder()
            .push_slice(deposit_data)
            .push_opcode(opcodes::OP_DROP)
            .push_slice(public_key.serialize())
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script();

        if matches!(recipient, PrincipalData::Standard(_)) {
            assert_eq!(script.len(), STANDARD_SCRIPT_LENGTH);
        }

        let extracts = parse_deposit_script(&script).unwrap();
        assert_eq!(extracts.signers_public_key, public_key);
        assert_eq!(extracts.recipient, recipient);
        assert_eq!(extracts.max_fee, max_fee);
        assert_eq!(extracts.deposit_script(), script);
    }

    /// Check that `DepositScript::deposit_script` and the
    /// `parse_deposit_script` function are inverses of one another.
    #[test_case(PrincipalData::from(StacksAddress::burn_address(false)) ; "standard address")]
    #[test_case(PrincipalData::parse(CONTRACT_ADDRESS).unwrap(); "contract address")]
    fn deposit_script_parsing_and_creation_are_inverses(recipient: PrincipalData) {
        let secret_key = SecretKey::new(&mut OsRng);

        let deposit = DepositScriptInputs {
            signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
            max_fee: 15000,
            recipient,
        };

        let deposit_script = deposit.deposit_script();
        let parsed_deposit = parse_deposit_script(&deposit_script).unwrap();

        assert_eq!(deposit, parsed_deposit);
    }

    /// Basic check that we can create an address without any issues
    #[test_case(PrincipalData::from(StacksAddress::burn_address(false)) ; "standard address")]
    #[test_case(PrincipalData::parse(CONTRACT_ADDRESS).unwrap(); "contract address")]
    fn btc_address(recipient: PrincipalData) {
        let secret_key = SecretKey::new(&mut OsRng);

        let deposit = DepositScriptInputs {
            signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
            max_fee: 15000,
            recipient,
        };

        let address = deposit.to_address(ScriptBuf::new(), Network::Regtest);
        assert_eq!(address.address_type(), Some(AddressType::P2tr));
    }
}
