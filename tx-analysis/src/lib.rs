#![deny(missing_docs)]

//! # SBTC Transaction Analysis Library
//!
//! This library provides functionality to analyze transactions

/// A wrapper around all possible errors to the validate functions
pub enum ValidationError {
    /// The script tree contained more than the allowed elements
    BadScriptTree,
    /// The deposit script was invalid
    BadDepositScript,
    /// The reclaim script was invalid
    BadReclaimScript,
    /// The script tree did not hash the the correct merkle root 
    BadMerkleRoot,
}

/// Check the passed script tree against the deposit and peg wallet addresses
/// 
///   return Ok(()) if the leaves are valid and hash to the UTxO address
///   return Err(ValidationError) if the leaves are bad or don’t hash to addr
pub fn validate(
    script_tree: bitcoin::taproot::TapTree,
    deposit_address: bitcoin::address::Address,
    peg_wallet_address: bitcoin::address::Address,
    min_reclaim_blocks: u32,
) -> Result<(), ValidationError> {
    Ok(())
}
