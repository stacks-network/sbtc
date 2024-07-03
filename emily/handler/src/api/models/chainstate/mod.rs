//! Request structures for chainstate api calls.

use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};

use crate::api::models::common::*;

/// Requests.
pub mod requests;
/// Responses.
pub mod responses;

/// Deposit.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct Chainstate {
    /// Stacks block height.
    pub block_height: BlockHeight,
    /// Stacks block hash at the height.
    pub block_hash: StacksBlockHash,
}
