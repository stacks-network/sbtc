//! This module contains functions and structs for the Signer API.
//!

pub mod new_block;
pub mod status;

use std::sync::Arc;

pub use new_block::new_block_handler;
pub use status::status_handler;

use crate::{config::Settings, storage::DbReadWrite};

/// A struct with state data necessary for runtime operation.
#[derive(Clone)]
pub struct ApiState {
    /// For writing to the database.
    pub db: Arc<dyn DbReadWrite>,
    /// The runtime settings of the system.
    pub settings: Settings,
}
