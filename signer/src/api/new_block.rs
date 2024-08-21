//! This module contains the handler for the `POST /new_block` endpoint,
//! which is for processing new block webhooks from a stacks node.
//!

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::stacks::webhooks::NewBlockEvent;
use crate::storage::DbWrite;

/// We denote the stacks node payload by this type so that our handler
/// always gets to handle the request, regardless of whether there is a
/// failure deserializing or not. This is so that we can return a `200 OK`
/// status code on deserialization errors, so that the stacks node does not
/// retry them.
pub type StacksNodePayload = Result<Json<serde_json::Value>, JsonRejection>;

/// A handler of `POST /new_block` webhook events.
///
/// # Notes
///
/// The event dispatcher functionality in a stacks node attempts to send
/// the payload to all interested observers, one-by-one. If the node fails
/// to connect to one of the observers, or if the response from the
/// observer is not a 200-299 response code, then it sleeps for 1 second
/// and tries again[^1]. From the looks of it, the node will stop trying to
/// send the webhook when it receives a success response or if we've
/// reached the `retry_count` that is configured in the stacks node config.
/// Because of this, unless we encounter an error where retrying it a
/// second might succeed, we will return a 200 OK status code.
///
/// [^1]: <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L317-L385>
pub async fn new_block_handler<S>(_state: State<S>, body: StacksNodePayload) -> StatusCode
where
    S: DbWrite,
{
    tracing::info!("Received a new block event from stacks-core");

    let _event: NewBlockEvent = match body {
        Ok(Json(value)) => {
            // We print out the raw string if there are any errors during
            // deserialization, but only for non-release builds.
            #[cfg(debug_assertions)]
            let raw_payload = serde_json::to_string(&value).unwrap();

            match serde_json::from_value(value) {
                Ok(event) => event,
                Err(error) => {
                    tracing::error!("could not deserialize POST /new_block webhook: {error}");

                    #[cfg(debug_assertions)]
                    println!("raw payload: {raw_payload}");
                    return StatusCode::OK;
                }
            }
        }
        // If we are here, then we failed to deserialize the webhook body
        // into the expected type. It's unlikely that retying this webhook
        // will lead to success, so we log the error and return `200 OK` so
        // that the node does not retry the webhook.
        Err(error) => {
            tracing::error!("could not deserialize POST /new_block webhook: {error:?}");
            return StatusCode::OK;
        }
    };

    StatusCode::OK
}
