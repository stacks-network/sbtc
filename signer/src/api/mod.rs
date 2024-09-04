//! This module contains functions and structs for the Signer API.
//!

pub mod new_block;
pub mod status;

pub use new_block::new_block_handler;
pub use status::status_handler;

use crate::config::Settings;

/// A struct with state data necessary for runtime operation.
#[derive(Debug, Clone)]
pub struct ApiState<S> {
    /// For writing to the database.
    pub db: S,
    /// The runtime settings of the system.
    pub settings: Settings,
}
