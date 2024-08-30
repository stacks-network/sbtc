//! This module contains the handler for the `POST /new_block` endpoint,
//! which is for processing new block webhooks from a stacks node.
//!

use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::stacks::events::RegistryEvent;
use crate::stacks::webhooks::NewBlockEvent;
use crate::storage::DbWrite;

use super::ApiState;

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
pub async fn new_block_handler<S>(state: State<ApiState<S>>, body: String) -> StatusCode
where
    S: DbWrite,
{
    tracing::info!("Received a new block event from stacks-core");
    let api = state.0;
    let network = api.settings.signer.network;

    let new_block_event: NewBlockEvent = match serde_json::from_str(&body) {
        Ok(value) => value,
        // If we are here, then we failed to deserialize the webhook body
        // into the expected type. It's unlikely that retying this webhook
        // will lead to success, so we log the error and return `200 OK` so
        // that the node does not retry the webhook.
        Err(error) => {
            tracing::error!("could not deserialize POST /new_block webhook: {body}, error {error}");
            return StatusCode::OK;
        }
    };

    let events = new_block_event
        .events
        .into_iter()
        .filter_map(|x| x.contract_event);

    for ev in events {
        let res = match RegistryEvent::try_from_value(ev.value, network) {
            Ok(RegistryEvent::CompletedDeposit(event)) => {
                api.db.write_completed_deposit_event(&event).await
            }
            Ok(RegistryEvent::WithdrawalAccept(event)) => {
                api.db.write_withdrawal_accept_event(&event).await
            }
            Ok(RegistryEvent::WithdrawalCreate(event)) => {
                api.db.write_withdrawal_create_event(&event).await
            }
            Ok(RegistryEvent::WithdrawalReject(event)) => {
                api.db.write_withdrawal_reject_event(&event).await
            }
            Err(err) => {
                tracing::error!("Got an error when transforming the event ClarityValue: {err}");
                return StatusCode::OK;
            }
        };
        // If we got an error writing to the database, this might be an
        // issue that will resolve itself if we try again in a few moments.
        if let Err(err) = res {
            tracing::error!("Got an error when writting event to database: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    StatusCode::OK
}
