//! This module contains the handler for the `POST /new_block` endpoint,
//! which is for processing new block webhooks from a stacks node.
//!

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::stacks::webhooks::NewBlockEvent;
use crate::storage::DbWrite;

/// A handler of `POST /new_block` webhook events.
///
/// # Notes
///
/// The event dispatcher functionality in a stacks node attempts to send
/// the payload to all interested observers, sequentially one-by-one. If
/// the node fails to connect to one of the observers, or if the response
/// from the observer is not a 200-299 response code, then it sleeps for 1
/// second and tries again[^1]. From the looks of it, the node will not
/// stop trying to send the webhook until there is a success. Because of
/// this, unless we encounter an error where retrying in a second might
/// succeed, we will return a 200 OK status code. Also, we will only return
/// a Non-success status a maximum of 3 times.
///
/// I need to find out what happens if we continually return 400 for
/// webhooks.
///
/// [^1]: https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L317-L385
pub async fn new_block_handler<S>(_state: State<S>, _body: Json<NewBlockEvent>) -> StatusCode
where
    S: DbWrite,
{
    StatusCode::OK
}
