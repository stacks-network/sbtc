//! This module contains the handler for the `POST /new_block` endpoint,
//! which is for processing new block webhooks from a stacks node.
//!

use axum::extract::State;
use axum::http::StatusCode;
use bitcoin::Txid;
use clarity::vm::representations::ContractName;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::types::StandardPrincipalData;
use emily_client::models::Chainstate;
use emily_client::models::CreateWithdrawalRequestBody;
use emily_client::models::DepositUpdate;
use emily_client::models::Fulfillment;
use emily_client::models::Status;
use emily_client::models::WithdrawalParameters;
use emily_client::models::WithdrawalUpdate;
use futures::FutureExt;
use std::sync::OnceLock;

use crate::api::UpdateResult;
use crate::context::Context;
use crate::emily_client::EmilyInteract;
use crate::error::Error;
use crate::stacks::events::CompletedDepositEvent;
use crate::stacks::events::RegistryEvent;
use crate::stacks::events::TxInfo;
use crate::stacks::events::WithdrawalAcceptEvent;
use crate::stacks::events::WithdrawalCreateEvent;
use crate::stacks::events::WithdrawalRejectEvent;
use crate::stacks::webhooks::NewBlockEvent;
use crate::storage::model::BitcoinBlock;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::StacksBlock;
use crate::storage::model::StacksBlockHash;
use crate::storage::DbRead;
use crate::storage::DbWrite;

use super::ApiState;
use super::SBTC_REGISTRY_CONTRACT_NAME;

/// The address for the sbtc-registry smart contract. This value is
/// populated using the deployer variable in the config.
///
/// Although the stacks node is supposed to only send sbtc-registry events,
/// the node can be misconfigured or have some bug where it sends other
/// events as well. Accepting such events would be a security issue, so we
/// filter out events that are not from the sbtc-registry.
///
/// See https://github.com/stacks-network/sbtc/issues/501.
static SBTC_REGISTRY_IDENTIFIER: OnceLock<QualifiedContractIdentifier> = OnceLock::new();

/// A handler of `POST /new_block` webhook events.
///
/// # Notes
///
/// The event dispatcher functionality in a stacks node attempts to send
/// the payload to all interested observers, one-by-one. If the node fails
/// to connect to one of the observers, or if the response from the
/// observer is not a 200-299 response code, then it sleeps for 1 second
/// and tries again[^1]. From the looks of it, the node will not stop
/// trying to send the webhook until there is a success. Because of this,
/// unless we encounter an error where retrying in a second might succeed,
/// we will return a 200 OK status code.
///
/// TODO: We need to be careful to only return a non success status code a
/// fixed number of times.
///
/// [^1]: <https://github.com/stacks-network/stacks-core/blob/09c4b066e25104be8b066e8f7530ff0c6df4ccd5/testnet/stacks-node/src/event_dispatcher.rs#L317-L385>
pub async fn new_block_handler(state: State<ApiState<impl Context>>, body: String) -> StatusCode {
    tracing::debug!("Received a new block event from stacks-core");
    let api = state.0;

    let registry_address = SBTC_REGISTRY_IDENTIFIER.get_or_init(|| {
        // Although the following line can panic, our unit tests hit this
        // code path so if tests pass then this will work in production.
        let contract_name = ContractName::from(SBTC_REGISTRY_CONTRACT_NAME);
        let issuer = StandardPrincipalData::from(api.ctx.config().signer.deployer);
        QualifiedContractIdentifier::new(issuer, contract_name)
    });

    let new_block_event: NewBlockEvent = match serde_json::from_str(&body) {
        Ok(value) => value,
        // If we are here, then we failed to deserialize the webhook body
        // into the expected type. It's unlikely that retying this webhook
        // will lead to success, so we log the error and return `200 OK` so
        // that the node does not retry the webhook.
        Err(error) => {
            tracing::error!(%body, %error, "could not deserialize POST /new_block webhook:");
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
        .filter_map(|x| x.contract_event.map(|ev| (ev, x.txid)))
        .filter(|(ev, _)| &ev.contract_identifier == registry_address && ev.topic == "print");

    let stacks_chaintip = StacksBlock {
        block_hash: StacksBlockHash::from(new_block_event.index_block_hash),
        block_height: new_block_event.block_height,
        parent_hash: StacksBlockHash::from(new_block_event.parent_index_block_hash),
    };
    let block_id = new_block_event.index_block_hash;

    // Create vectors to store the processed events for Emily.
    let mut completed_deposits = Vec::new();
    let mut updated_withdrawals = Vec::new();
    let mut created_withdrawals = Vec::new();

    for (ev, txid) in events {
        let tx_info = TxInfo { txid, block_id };
        let res = match RegistryEvent::try_new(ev.value, tx_info) {
            Ok(RegistryEvent::CompletedDeposit(event)) => {
                handle_completed_deposit(&api.ctx, event, &stacks_chaintip, &mut completed_deposits)
                    .await
            }
            Ok(RegistryEvent::WithdrawalAccept(event)) => {
                handle_withdrawal_accept(
                    &api.ctx,
                    event,
                    &stacks_chaintip,
                    &mut updated_withdrawals,
                )
                .await
            }
            Ok(RegistryEvent::WithdrawalCreate(event)) => {
                handle_withdrawal_create(&api.ctx, event, &mut created_withdrawals).await
            }
            Ok(RegistryEvent::WithdrawalReject(event)) => {
                handle_withdrawal_reject(
                    &api.ctx,
                    event,
                    &stacks_chaintip,
                    &mut updated_withdrawals,
                )
                .await
            }
            Err(error) => {
                tracing::error!(%error, "Got an error when transforming the event ClarityValue");
                return StatusCode::OK;
            }
        };
        // If we got an error writing to the database, this might be an
        // issue that will resolve itself if we try again in a few moments.
        // So we return a non success status code so that the node retries
        // in a second.
        if let Err(error) = res {
            tracing::error!(%error, "Got an error when writing event to database");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    // Send the updates to Emily.
    let emily_client = api.ctx.get_emily_client();
    let chainstate = Chainstate::new(block_id.to_string(), new_block_event.block_height);

    let futures = vec![
        emily_client
            .update_deposits(completed_deposits)
            .map(UpdateResult::Deposit)
            .boxed(),
        emily_client
            .update_withdrawals(updated_withdrawals)
            .map(UpdateResult::Withdrawal)
            .boxed(),
        emily_client
            .create_withdrawals(created_withdrawals)
            .map(UpdateResult::CreatedWithdrawal)
            .boxed(),
        emily_client
            .set_chainstate(chainstate)
            .map(UpdateResult::Chainstate)
            .boxed(),
    ];
    let results = futures::future::join_all(futures).await;

    // Log any errors that occurred while updating Emily.
    // We don't return a non-success status code here because we rely on
    // the redundancy of the other sBTC signers to ensure that the update
    // is sent to Emily.
    for result in results {
        if let UpdateResult::Chainstate(Err(error)) = result {
            tracing::warn!(%error, "Failed to set chainstate in emily");
        } else if let UpdateResult::Deposit(Err(error)) = result {
            tracing::warn!(%error, "Failed to update deposits in emily");
        } else if let UpdateResult::Withdrawal(Err(error)) = result {
            tracing::warn!(%error, "Failed to update withdrawals in emily");
        } else if let UpdateResult::CreatedWithdrawal(results) = result {
            for result in results {
                if let Err(error) = result {
                    tracing::warn!(%error, "Failed to create withdrawals in emily");
                }
            }
        }
    }
    StatusCode::OK
}

/// Fetches Bitcoin block information based on a transaction ID from the database.
///
/// # Parameters
/// - `tx_id`: The transaction ID used to look up the Bitcoin block data.
/// - `db`: Database access to retrieve the Bitcoin block information.
///
/// # Returns
///
/// If the block information is successfully retrieved, it returns `Some(BtcBlockInfo)`.
/// If no block is found for the provided transaction ID, it returns `None`.
/// Any database errors encountered during the operation result in an `None`.
///
/// # Notes
///
/// If an error occurs while writing to the database, the caller should return
/// a non-success status code to ensure the node retries the webhook event later.
async fn fetch_btc_block_from_txid(db: &impl DbRead, txid: Txid) -> Option<BitcoinBlock> {
    let btc_txid = BitcoinTxId::from(txid);
    let blocks_hashes = db
        .get_bitcoin_blocks_with_transaction(&btc_txid)
        .await
        .ok()?;

    let block_hash = blocks_hashes.last()?;
    db.get_bitcoin_block(&block_hash).await.ok()?
}

/// Processes a completed deposit event by updating relevant deposit records
/// and preparing data to be sent to Emily.
///
/// # Parameters
/// - `ctx`: Shared application context containing configuration and database access.
/// - `event`: The deposit event to be processed.
/// - `stacks_chaintip`: Current chaintip information for the Stacks blockchain,
///   including block height and hash.
/// - `completed_deposits`: A mutable vector where the processed deposit update
///   will be stored to be sent to Emily.
///
/// # Notes
///
/// If an error occurs while writing to the database, the caller should return
/// a non-success status code to ensure the node retries the webhook event later.
async fn handle_completed_deposit(
    ctx: &impl Context,
    event: CompletedDepositEvent,
    stacks_chaintip: &StacksBlock,
    completed_deposits: &mut Vec<DepositUpdate>,
) -> Result<(), Error> {
    ctx.get_storage_mut()
        .write_completed_deposit_event(&event)
        .await?;
    // Need to fetch the block to get the block hash and height.
    if let Some(btc_block) =
        fetch_btc_block_from_txid(&ctx.get_storage(), event.outpoint.txid).await
    {
        completed_deposits.push(DepositUpdate {
            bitcoin_tx_output_index: event.outpoint.vout,
            bitcoin_txid: event.outpoint.txid.to_string(),
            status: Status::Confirmed,
            fulfillment: Some(Some(Box::new(Fulfillment {
                bitcoin_block_hash: btc_block.block_hash.to_string(),
                bitcoin_block_height: btc_block.block_height,
                bitcoin_tx_index: event.outpoint.vout,
                bitcoin_txid: event.outpoint.txid.to_string(),
                btc_fee: 1, // TODO: We need to get the fee from the transaction. Currently missing from the event.
                stacks_txid: event.txid.to_hex(),
            }))),
            status_message: format!("Included in block {}", event.block_id.to_hex()),
            last_update_block_hash: stacks_chaintip.block_hash.to_hex(),
            last_update_height: stacks_chaintip.block_height,
        });
    }
    // Just skip the event if we can't find the block.
    // We rely on the redundancy of the other sBTC signers to
    // ensure that the update is sent to Emily.
    else {
        tracing::warn!(
            "Could not find bitcoin block for transaction {}",
            event.outpoint.txid
        );
    }
    Ok(())
}

/// Handles a withdrawal acceptance event, updating database records and
/// preparing a response for Emily.
///
/// # Parameters
/// - `ctx`: Shared application context with configuration and database access.
/// - `event`: The withdrawal acceptance event to be processed.
/// - `stacks_chaintip`: Current Stacks blockchain chaintip information for
///   context on block height and hash.
/// - `updated_withdrawals`: A mutable vector where the processed withdrawal
///   acceptance update will be stored for later transmission to Emily.

/// # Notes
///
/// If an error occurs while writing to the database, the caller should return
/// a non-success status code to ensure the node retries the webhook event later.
async fn handle_withdrawal_accept(
    ctx: &impl Context,
    event: WithdrawalAcceptEvent,
    stacks_chaintip: &StacksBlock,
    updated_withdrawals: &mut Vec<WithdrawalUpdate>,
) -> Result<(), Error> {
    ctx.get_storage_mut()
        .write_withdrawal_accept_event(&event)
        .await?;

    if let Some(btc_block) =
        fetch_btc_block_from_txid(&ctx.get_storage(), event.outpoint.txid).await
    {
        updated_withdrawals.push(WithdrawalUpdate {
            request_id: event.request_id,
            status: Status::Confirmed,
            fulfillment: Some(Some(Box::new(Fulfillment {
                bitcoin_block_hash: btc_block.block_hash.to_string(),
                bitcoin_block_height: btc_block.block_height,
                bitcoin_tx_index: event.outpoint.vout,
                bitcoin_txid: event.outpoint.txid.to_string(),
                btc_fee: event.fee,
                stacks_txid: event.txid.to_hex(),
            }))),
            status_message: format!("Included in block {}", event.block_id.to_hex()),
            last_update_block_hash: stacks_chaintip.block_hash.to_hex(),
            last_update_height: stacks_chaintip.block_height,
        });
    } else {
        tracing::warn!(
            "Could not find bitcoin block for transaction {}",
            event.outpoint.txid
        );
    }
    Ok(())
}

/// Processes a withdrawal creation event, adding new withdrawal records to the
/// database and preparing the data for Emily.
///
/// # Parameters
/// - `ctx`: Shared application context containing configuration and database access.
/// - `event`: The withdrawal creation event to be processed.
/// - `created_withdrawals`: A mutable vector where the newly created withdrawal
///   update will be stored for eventual transmission to Emily.
///
/// # Notes
///
/// If an error occurs while writing to the database, the caller should return
/// a non-success status code to ensure the node retries the webhook event later.
async fn handle_withdrawal_create(
    ctx: &impl Context,
    event: WithdrawalCreateEvent,
    created_withdrawals: &mut Vec<CreateWithdrawalRequestBody>,
) -> Result<(), Error> {
    ctx.get_storage_mut()
        .write_withdrawal_create_event(&event)
        .await?;

    if let Ok(Some(stx_block)) = ctx
        .get_storage()
        .get_stacks_block(&StacksBlockHash::from(event.block_id))
        .await
    {
        created_withdrawals.push(CreateWithdrawalRequestBody {
            amount: event.amount,
            parameters: Box::new(WithdrawalParameters { max_fee: event.max_fee }),
            recipient: event.recipient.to_string(),
            request_id: event.request_id,
            stacks_block_hash: event.block_id.to_hex(),
            stacks_block_height: stx_block.block_height,
        });
    } else {
        tracing::warn!(
            "Could not find Stacks block for block hash {}",
            event.block_id.to_hex()
        );
    }
    Ok(())
}

/// Processes a withdrawal rejection event by updating records and preparing
/// the response data to be sent to Emily.
///
/// # Parameters
/// - `ctx`: Shared application context containing configuration and database access.
/// - `event`: The withdrawal rejection event to be processed.
/// - `stacks_chaintip`: Information about the current chaintip of the Stacks blockchain,
///   such as block height and hash.
/// - `updated_withdrawals`: A mutable vector where the processed withdrawal
///   rejection update will be stored for future transmission to Emily.
///
/// # Notes
///
/// If an error occurs while writing to the database, the caller should return
/// a non-success status code to ensure the node retries the webhook event later.
async fn handle_withdrawal_reject(
    ctx: &impl Context,
    event: WithdrawalRejectEvent,
    stacks_chaintip: &StacksBlock,
    updated_withdrawals: &mut Vec<WithdrawalUpdate>,
) -> Result<(), Error> {
    ctx.get_storage_mut()
        .write_withdrawal_reject_event(&event)
        .await?;

    updated_withdrawals.push(WithdrawalUpdate {
        fulfillment: None,
        last_update_block_hash: stacks_chaintip.block_hash.to_hex(),
        last_update_height: stacks_chaintip.block_height,
        request_id: event.request_id,
        status: Status::Failed,
        status_message: "Rejected".to_string(),
    });

    Ok(())
}

// async fn get_tx_fee(
//     db: &(impl DbRead + Sync + 'static),
//     txid: Txid,
//     block_hash: &BitcoinBlockHash,
// ) -> Option<u64> {
//     let btc_txid = BitcoinTxId::from(txid);
//     let tx = db.get_bitcoin_tx(&btc_txid, block_hash).await.ok()??;

//     let mut set_fetch_txout = JoinSet::new();

//     for txin in tx.input.iter() {
//         // let db_clone = db.clone();
//         set_fetch_txout.spawn(async move { fetch_txout(db, txin.previous_output).await });
//         // .map(|input| fetch_txout(db, input.previous_output)).collect();
//     }

//     // .0
//     // .into_iter()
//     // .map(|txout| txout.value)
//     // .sum::<u64>()
//     // .checked_sub(tx.output.iter().map(|txout| txout.value).sum::<u64>())
//     Some(1)
// }

// async fn fetch_txout(db: &(impl DbRead + Sync + 'static), out_point: OutPoint) -> Option<TxOut> {
//     let txid = out_point.txid;
//     let vout = out_point.vout;

//     let block = fetch_btc_block_from_txid(db, txid.into()).await?;
//     let tx = db
//         .get_bitcoin_tx(&txid.into(), &block.block_hash)
//         .await
//         .ok()??;
//     tx.output.get(vout as usize).cloned()
// }

// async fn fetch_btc_block_from_txid(ctx: impl Context, txid: Txid) -> Result<BitcoinBlockHash, Error> {
//     let btc_txid = BitcoinTxId::from(txid);
//     let db = ctx.get_storage();

//     let btc_blocks = db.get_bitcoin_blocks_with_transaction(&btc_txid).await;
//     if let Err(error) = btc_blocks {
//         let btc_client = ctx.get_bitcoin_client();
//         let btc_block = btc_client
//             .get_tx(&txid)
//             .await?
//             .ok_or(Error::BitcoinTxMissing(txid, None))?;
//         if btc_block.block_hash.is_none() {
//             return Err(Error::BitcoinTxMissing(txid, btc_block.block_hash));
//         }
//         let db = ctx.get_storage_mut();
//         db.write_bitcoin_block(btc_block)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::OutPoint;
    use clarity::vm::types::PrincipalData;
    use emily_client::models::UpdateDepositsResponse;
    use emily_client::models::UpdateWithdrawalsResponse;
    use fake::Fake;
    use rand::rngs::OsRng;
    use test_case::test_case;

    use crate::storage::in_memory::Store;
    use crate::storage::model::StacksPrincipal;
    use crate::testing::context::*;

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

    #[test_case(COMPLETED_DEPOSIT_WEBHOOK, |db| db.completed_deposit_events.get(&OutPoint::null()).is_none(); "completed-deposit")]
    #[test_case(WITHDRAWAL_CREATE_WEBHOOK, |db| db.withdrawal_create_events.get(&1).is_none(); "withdrawal-create")]
    #[test_case(WITHDRAWAL_ACCEPT_WEBHOOK, |db| db.withdrawal_accept_events.get(&1).is_none(); "withdrawal-accept")]
    #[test_case(WITHDRAWAL_REJECT_WEBHOOK, |db| db.withdrawal_reject_events.get(&2).is_none(); "withdrawal-reject")]
    #[tokio::test]
    async fn test_events<F>(body_str: &str, table_is_empty: F)
    where
        F: Fn(tokio::sync::MutexGuard<'_, Store>) -> bool,
    {
        let mut ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let api = ApiState { ctx: ctx.clone() };

        let db = ctx.inner_storage();

        // Hey look, there is nothing here!
        assert!(table_is_empty(db.lock().await));

        let state = State(api);
        let body = body_str.to_string();

        let new_block_event = serde_json::from_str::<NewBlockEvent>(&body).unwrap();
        // Set up the mock expectation for set_chainstate
        let chainstate = Chainstate::new(
            new_block_event.index_block_hash.to_string(),
            new_block_event.block_height,
        );
        ctx.with_emily_client(|client| {
            client.expect_set_chainstate().times(1).returning(move |_| {
                let chainstate = chainstate.clone();
                Box::pin(async { Ok(chainstate) })
            });
            client
                .expect_update_deposits()
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(UpdateDepositsResponse { deposits: vec![] }) })
                });
            client
                .expect_update_withdrawals()
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(UpdateWithdrawalsResponse { withdrawals: vec![] }) })
                });
            client
                .expect_create_withdrawals()
                .times(1)
                .returning(move |_| Box::pin(async { vec![] }));
        })
        .await;

        let res = new_block_handler(state, body).await;
        assert_eq!(res, StatusCode::OK);

        // Now there should be something here
        assert!(!table_is_empty(db.lock().await));
    }

    #[test_case(COMPLETED_DEPOSIT_WEBHOOK, |db| db.completed_deposit_events.get(&OutPoint::null()).is_none(); "completed-deposit")]
    #[test_case(WITHDRAWAL_CREATE_WEBHOOK, |db| db.withdrawal_create_events.get(&1).is_none(); "withdrawal-create")]
    #[test_case(WITHDRAWAL_ACCEPT_WEBHOOK, |db| db.withdrawal_accept_events.get(&1).is_none(); "withdrawal-accept")]
    #[test_case(WITHDRAWAL_REJECT_WEBHOOK, |db| db.withdrawal_reject_events.get(&2).is_none(); "withdrawal-reject")]
    #[tokio::test]
    async fn test_fishy_events<F>(body_str: &str, table_is_empty: F)
    where
        F: Fn(tokio::sync::MutexGuard<'_, Store>) -> bool,
    {
        let mut ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let api = ApiState { ctx: ctx.clone() };

        let db = ctx.inner_storage();

        // Hey look, there is nothing here!
        assert!(table_is_empty(db.lock().await));

        // Okay, we want to make sure that events that are from an
        // unexpected contract are filtered out. So we manually switch the
        // address to some random one and check the output. To do that we
        // do a string replace for the expected one with the fishy one.
        let issuer = StandardPrincipalData::from(ctx.config().signer.deployer);
        let contract_name = ContractName::from(SBTC_REGISTRY_CONTRACT_NAME);
        let identifier = QualifiedContractIdentifier::new(issuer, contract_name.clone());

        let fishy_principal: StacksPrincipal = fake::Faker.fake_with_rng(&mut OsRng);
        let fishy_issuer = match PrincipalData::from(fishy_principal) {
            PrincipalData::Contract(contract) => contract.issuer,
            PrincipalData::Standard(standard) => standard,
        };
        let fishy_identifier = QualifiedContractIdentifier::new(fishy_issuer, contract_name);

        let body = body_str.replace(&identifier.to_string(), &fishy_identifier.to_string());
        // Okay let's check that it was actually replaced.
        assert!(body.contains(&fishy_identifier.to_string()));

        // Let's check that we can still deserialize the JSON string since
        // the `new_block_handler` function will return early with
        // StatusCode::OK on failure to deserialize.
        let new_block_event = serde_json::from_str::<NewBlockEvent>(&body).unwrap();
        let events: Vec<_> = new_block_event
            .events
            .into_iter()
            .filter_map(|x| x.contract_event)
            .collect();

        // An extra check that we have events with our fishy identifier.
        assert!(!events.is_empty());
        assert!(events
            .iter()
            .all(|x| x.contract_identifier == fishy_identifier));

        // Set up the mock expectation for set_chainstate
        let chainstate = Chainstate::new(
            new_block_event.index_block_hash.to_string(),
            new_block_event.block_height,
        );

        ctx.with_emily_client(|client| {
            client.expect_set_chainstate().times(1).returning(move |_| {
                let chainstate = chainstate.clone();
                Box::pin(async { Ok(chainstate) })
            });
            client
                .expect_update_deposits()
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(UpdateDepositsResponse { deposits: vec![] }) })
                });
            client
                .expect_update_withdrawals()
                .times(1)
                .returning(move |_| {
                    Box::pin(async { Ok(UpdateWithdrawalsResponse { withdrawals: vec![] }) })
                });
            client
                .expect_create_withdrawals()
                .times(1)
                .returning(move |_| Box::pin(async { vec![] }));
        })
        .await;
        // Okay now to do the check.
        let state = State(api.clone());
        let res = new_block_handler(state, body).await;
        assert_eq!(res, StatusCode::OK);

        // This event should be filtered out, so the table should still be
        // empty.
        assert!(table_is_empty(db.lock().await));
    }
}
