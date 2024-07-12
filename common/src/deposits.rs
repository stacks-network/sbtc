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
use secp256k1::PublicKey;
use secp256k1::SECP256K1;

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
    pub signers_public_key: PublicKey,
    /// The stacks address to deposit the sBTC to. This can be either a
    /// standard address (which is 21 bytes), or a contract address (which
    /// is between 23 and 150 bytes)
    pub stacks_address: Vec<u8>,
    /// The reclaim script.
    pub reclaim_script: ScriptBuf,
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
            NodeInfo::combine(leaf1, leaf2).expect("This tree depth greater than max of 128");
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
