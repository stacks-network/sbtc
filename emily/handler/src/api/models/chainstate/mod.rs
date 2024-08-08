//! Request structures for chainstate api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

use crate::api::models::common::*;

/// Requests.
pub mod requests;
/// Responses.
pub mod responses;

/// Chainstate.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
#[serde(rename_all = "camelCase")]
pub struct Chainstate {
    /// Stacks block height.
    pub stacks_block_height: BlockHeight,
    /// Stacks block hash at the height.
    pub stacks_block_hash: StacksBlockHash,
}
