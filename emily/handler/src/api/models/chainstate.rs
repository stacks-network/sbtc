//! Request structures for chainstate api calls.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{ToResponse, ToSchema};

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
    pub stacks_block_height: u64,
    /// Stacks block hash at the height.
    pub stacks_block_hash: String,
}

/// Update heights mapping request body
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct HeightsMapping {
    /// An update mapping, update all entries or add new ones
    pub mapping: HashMap<u64, u64>,
}

/// Update bitcoin chaintip request body
#[derive(Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, ToResponse)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBitcoinChaintip {
    /// A new bitcoin chaintip height
    pub height: u64,
    /// A new bitcoin chaintip hash
    pub hash: String,
}
