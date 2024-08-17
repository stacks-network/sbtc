//! This module contains functions and structs for the Signer API.
//!

pub mod new_block;
pub mod status;

pub use new_block::new_block_handler;
pub use status::status_handler;
