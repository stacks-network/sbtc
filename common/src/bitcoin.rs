//! This is the transaction analysis module
//!

use bitcoin::Address;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use secp256k1::PublicKey;

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
}

/// This struct contains the key variable inputs when constructing a
/// deposit address.
#[derive(Debug, Clone)]
pub struct DepositInputs {
    /// The last known public key of the signers.
    pub signer_key: PublicKey,
    /// The stacks address to deposit the sBTC to. This can be either a
    /// standard address (which is 21 bytes), or a contract address (which
    /// is between 22 and 150 bytes)
    pub stacks_address: Vec<u8>,
    /// The reclaim script.
    pub reclaim_script: ScriptBuf,
    /// The max fee amount to use for the BTC deposit transaction.
    pub max_fee: u64,
}

impl DepositInputs {
    /// Construct a bitcoin address for a deposit transaction on the given
    /// network.
    pub fn to_address(&self, _network: Network) -> Result<Address, Error> {
        unimplemented!()
    }
}
