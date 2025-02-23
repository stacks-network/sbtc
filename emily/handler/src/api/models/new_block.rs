//! This module contains structs that represent the payload for new block
//! webhooks from a stacks node.
use serde::Deserialize;
use utoipa::ToSchema;

use sbtc::webhooks::NewBlockEvent;

#[derive(Debug, Deserialize, ToSchema)]
/// The raw payload of a new block event from a stacks node.
/// This is the raw JSON string that is sent to the webhook.
/// Ideally, NewBlockEvent would be used directly, but because of the
/// the imported data types, we can't derive ToSchema for it to be used
/// in the OpenAPI spec.
pub struct NewBlockEventRaw(pub String);

impl NewBlockEventRaw {
    /// Deserialize the raw payload into a NewBlockEvent.
    pub fn deserialize(&self) -> Result<NewBlockEvent, serde_json::Error> {
        serde_json::from_str(&self.0)
    }
}
