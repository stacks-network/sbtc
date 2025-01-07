//! This module contains functions and structs for the Signer API.
//!

mod new_block;
mod router;
mod status;

pub use new_block::new_block_handler;
pub use router::get_router;

/// A struct with state data necessary for runtime operation.
#[derive(Debug, Clone)]
pub struct ApiState<C> {
    /// For writing to the database.
    pub ctx: C,
}

/// The name of the sbtc registry smart contract.
const SBTC_REGISTRY_CONTRACT_NAME: &str = "sbtc-registry";
