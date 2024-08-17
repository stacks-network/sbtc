//! This module is contains the handler for the POST /new_block endpoint,
//! which is for processing new block webhooks from a stacks node.

use axum::http::StatusCode;

/// A basic handler that responds with 200 OK
pub async fn new_block_handler() -> StatusCode {
    StatusCode::OK
}

/// The Schema for new block events are defined in the source here:
/// https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L644-L687
pub struct NewBlockEvent {

}

/// https://github.com/stacks-network/stacks-core/blob/develop/clarity/src/vm/events.rs#L358-L363
/// https://github.com/stacks-network/stacks-core/blob/develop/clarity/src/vm/events.rs#L45-L51
pub struct SmartContractEvent {

}
