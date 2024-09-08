//! This module contains the handler for the `POST /new_block` endpoint,
//! which is for processing new block webhooks from a stacks node.
//!

use std::sync::LazyLock;

use axum::extract::State;
use axum::http::StatusCode;

use crate::stacks::events::RegistryEvent;
use crate::stacks::webhooks::NewBlockEvent;

use super::ApiState;

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
pub async fn new_block_handler(state: State<ApiState>, body: String) -> StatusCode {
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

    // Although transactions can fail, only successful transactions emit
    // sBTC print events, since those events are emitted at the very end of
    // the contract call.
    let events = new_block_event
        .events
        .into_iter()
        .filter(|x| x.committed)
        .filter_map(|x| x.contract_event.map(|ev| (ev, x.txid)));

    for (ev, txid) in events {
        let res = match RegistryEvent::try_new(ev.value, txid, network) {
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
        // So we return a non success status code so that the node retries
        // in a second.
        if let Err(err) = res {
            tracing::error!("Got an error when writing event to database: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use super::*;

    use bitcoin::OutPoint;
    use test_case::test_case;
    use tokio::runtime::Handle;

    use crate::config::Settings;
    use crate::error::Error;
    use crate::storage::in_memory::Store;
    use crate::storage::model::CompletedDepositEvent;
    use crate::storage::DbReadWrite;

    /// These were generated from a stacks node after running the
    /// "complete-deposit standard recipient", "accept-withdrawal",
    /// "create-withdrawal", and "reject-withdrawal" variants,
    /// respectively, of the `complete_deposit_wrapper_tx_accepted`
    /// integration test.
    const COMPLETED_DEPOSIT_WEBHOOK: &str =
        include_str!("../../tests/fixtures/completed-deposit-event.json");

    const WITHDRAWAL_ACCEPT_WEBHOOK: &str =
        include_str!("../../tests/fixtures/withdrawal-accept-event.json");

    const WITHDRAWAL_CREATE_WEBHOOK: &str =
        include_str!("../../tests/fixtures/withdrawal-create-event.json");

    const WITHDRAWAL_REJECT_WEBHOOK: &str =
        include_str!("../../tests/fixtures/withdrawal-reject-event.json");

    #[test_case(COMPLETED_DEPOSIT_WEBHOOK, |db: Arc<dyn DbReadWrite>| {
        Box::pin(async move {
            db.get_completed_deposit_event(&OutPoint::null()).await
        })
    }; "completed-deposit")]
    // #[test_case(WITHDRAWAL_CREATE_WEBHOOK, |db: Arc<dyn DbReadWrite>| {
    //     Box::pin(async move {
    //         db.get_withdrawal_created_event(&1).await //.is_none()
    //     })
    // }; "withdrawal-create")]
    // #[test_case(WITHDRAWAL_ACCEPT_WEBHOOK, |db: Arc<dyn DbReadWrite>| {
    //     Box::pin(async move {
    //         db.get_withdrawal_accepted_event.get(&1).await //.is_none()
    //     })
    // }; "withdrawal-accept")]
    //#[test_case(WITHDRAWAL_REJECT_WEBHOOK, |db: Arc<dyn DbReadWrite>| db.withdrawal_reject_events.get(&2).is_none(); "withdrawal-reject")]
    #[tokio::test]
    async fn test_events<F, T>(body_str: &str, table_is_empty: F)
    where
        F: Fn(
            Arc<dyn DbReadWrite>,
        ) -> Pin<Box<dyn futures::Future<Output = Result<Option<T>, Error>> + Send>>,
    {
        let api = ApiState {
            db: Arc::new(Store::new_shared()),
            settings: Settings::new(crate::testing::DEFAULT_CONFIG_PATH).unwrap(),
        };

        // Hey look, there is nothing here!
        assert!(table_is_empty(Arc::clone(&api.db))
            .await
            .expect("failed to query db")
            .is_none());

        let state = State(api.clone());
        let body = body_str.to_string();

        let res = new_block_handler(state, body).await;
        assert_eq!(res, StatusCode::OK);

        // Now there should be something here
        assert!(!table_is_empty(Arc::clone(&api.db))
            .await
            .expect("failed to query db")
            .is_none());
    }
}
