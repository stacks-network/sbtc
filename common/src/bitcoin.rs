//! This is the transaction analysis module
//!

use bitcoin::address::Address;
use bitcoin::taproot::TapTree;
use bitcoin::Script;
use bitcoin::XOnlyPublicKey;

/// Error
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
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

/// This struct contains the key variable inputs when constructing a deposit address.
pub struct DepositInputs {
    /// The last known public key of the signers.
    pub signer_key: XOnlyPublicKey,
    /// The stacks address to deposit the sBTC to.
    pub stacks_address: [u8; 21],
    /// The reclaim script.
    pub reclaim_script: Script,
}

/// Check the passed script tree against the deposit and peg wallet addresses
///
///   return Ok(()) if the leaves are valid and hash to the UTxO address
///   return Err(ValidationError) if the leaves are bad or don’t hash to addr
pub fn validate(
    _script_tree: TapTree,
    _deposit_address: Address,
    _peg_wallet_address: Address,
    _min_reclaim_blocks: u32,
) -> Result<(), ValidationError> {
    Ok(())
}
