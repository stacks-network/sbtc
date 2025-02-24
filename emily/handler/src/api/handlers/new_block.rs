//! Handlers for limits endpoints.
use std::future::Future;
use std::sync::OnceLock;

use bitcoin::params;
use tracing::instrument;
use warp::reply::Reply;

use clarity::vm::types::{QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::ContractName;
use sbtc::events::{
    CompletedDepositEvent, RegistryEvent, TxInfo, WithdrawalAcceptEvent, WithdrawalCreateEvent,
    WithdrawalRejectEvent,
};

use crate::api::handlers::chainstate::set_chainstate;
use crate::api::handlers::deposit::update_deposits;
use crate::api::handlers::withdrawal::{create_withdrawal, update_withdrawals};
use crate::api::models::chainstate::Chainstate;
use crate::api::models::common::Fulfillment;
use crate::api::models::common::Status;
use crate::api::models::deposit::requests::{DepositUpdate, UpdateDepositsRequestBody};
use crate::api::models::new_block::NewBlockEventRaw;
use crate::api::models::withdrawal::requests::{
    CreateWithdrawalRequestBody, UpdateWithdrawalsRequestBody, WithdrawalUpdate,
};
use crate::api::models::withdrawal::WithdrawalParameters;
use crate::database::entries::deposit::DepositEntryKey;
use crate::{common::error::Error, context::EmilyContext, database::accessors};

/// The name of the sbtc registry smart contract.
const SBTC_REGISTRY_CONTRACT_NAME: &str = "sbtc-registry";

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

/// Maximum request body size for the event observer endpoint.
///
/// Stacks blocks have a limit of 2 MB, which is enforced at the p2p level, but
/// event observer events can be larger than that since they contain the
/// subscribed sbtc events. Luckily, the size of the sbtc events themselves are
/// bounded by the size of the transactions that create them, so a limit of 8 MB
/// will be fine since it is twice as high as required.
pub const EVENT_OBSERVER_BODY_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct StacksBlock {
    pub block_hash: String,
    pub block_height: u64,
}

/// Get limits handler.
#[utoipa::path(
    post,
    operation_id = "newBlock",
    path = "/new_block",
    tag = "new_block",
    request_body = NewBlockEventRaw,
    responses(
        (status = 200, description = "New Block event received successfully"),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip_all, name = "new-block")]
pub async fn new_block(
    context: EmilyContext,
    new_block_event: NewBlockEventRaw,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        new_block_event: NewBlockEventRaw,
    ) -> Result<impl warp::reply::Reply, Error> {
        let new_block_event = match new_block_event.deserialize() {
            Ok(event) => event,
            Err(error) => {
                tracing::error!(%error, "failed to deserialize new block event");
                return Err(error.into());
            }
        };
        // Set the global limits.
        let registry_address = SBTC_REGISTRY_IDENTIFIER.get_or_init(|| {
            // Although the following line can panic, our unit tests hit this
            // code path so if tests pass then this will work in production.
            let contract_name = ContractName::from(SBTC_REGISTRY_CONTRACT_NAME);
            let issuer = StandardPrincipalData::from(context.settings.deployer_address);
            QualifiedContractIdentifier::new(issuer, contract_name)
        });

        let stacks_chaintip = StacksBlock {
            block_hash: new_block_event.index_block_hash.to_hex(),
            block_height: new_block_event.block_height,
        };

        tracing::debug!(
            block_height = stacks_chaintip.block_height,
            block_hash = %stacks_chaintip.block_hash,
            "received a new block event from stacks-core");

        // Although transactions can fail, only successful transactions emit
        // sBTC print events, since those events are emitted at the very end of
        // the contract call.
        let events = new_block_event
            .events
            .into_iter()
            .filter(|x| x.committed)
            .filter_map(|x| x.contract_event.map(|ev| (ev, x.txid)))
            .filter(|(ev, _)| &ev.contract_identifier == registry_address && ev.topic == "print")
            .collect::<Vec<_>>();

        tracing::debug!(block = %events.len(), "received events from stacks-core");

        // Set the chainstate
        handle_internal_call(
            set_chainstate(
                context.clone(),
                context.settings.trusted_reorg_api_key.clone(),
                Chainstate {
                    stacks_block_height: stacks_chaintip.block_height,
                    stacks_block_hash: stacks_chaintip.block_hash.clone(),
                },
            ),
            "failed to update chainstate in Emily",
        )
        .await?;

        if events.is_empty() {
            // If there are no events to process, we return early with a 200 OK
            // status code so that the node does not retry the webhook.
            return Ok(warp::reply());
        }

        tracing::debug!(count = %events.len(), "processing events for new stacks block");

        // Create vectors to store the processed events for Emily.
        let mut completed_deposits = Vec::new();
        let mut updated_withdrawals = Vec::new();
        let mut created_withdrawals = Vec::new();

        for (ev, txid) in events {
            let tx_info = TxInfo {
                txid: sbtc::events::StacksTxid(txid.0),
                block_id: new_block_event.index_block_hash,
            };
            match RegistryEvent::try_new(ev.value, tx_info) {
                Ok(RegistryEvent::CompletedDeposit(event)) => {
                    let deposit_maybe =
                        handle_completed_deposit(&context, event, stacks_chaintip.clone()).await;
                    match deposit_maybe {
                        Ok(deposit) => completed_deposits.push(deposit),
                        Err(error) => {
                            // If we fail to process a deposit, we log the error and continue.
                            // We don't want the sidecar to retry the webhook because this error
                            // is likely to be persistent. This should never happen.
                            tracing::error!(%error, %txid, "failed to handle completed deposit event");
                            continue;
                        }
                    }
                }
                Ok(RegistryEvent::WithdrawalAccept(event)) => updated_withdrawals
                    .push(handle_withdrawal_accept(event, stacks_chaintip.clone())),
                Ok(RegistryEvent::WithdrawalReject(event)) => updated_withdrawals
                    .push(handle_withdrawal_reject(event, stacks_chaintip.clone())),
                Ok(RegistryEvent::WithdrawalCreate(event)) => {
                    let event_maybe = handle_withdrawal_create(
                        event,
                        stacks_chaintip.block_height,
                        context.settings.is_mainnet,
                    );
                    match event_maybe {
                        Ok(withdrawal) => created_withdrawals.push(withdrawal),
                        Err(error) => {
                            // If we fail to create a withdrawal, we log the error and continue.
                            // We don't want the sidecar to retry the webhook because this error
                            // is likely to be persistent. This should never happen.
                            tracing::error!(%error, %txid, "failed to handle withdrawal create event");
                            continue;
                        }
                    }
                }
                Ok(RegistryEvent::KeyRotation(_)) => continue,
                Err(error) => {
                    tracing::error!(%error, %txid, "got an error when transforming the event ClarityValue");
                    continue;
                }
            };
        }

        if completed_deposits.is_empty()
            && updated_withdrawals.is_empty()
            && created_withdrawals.is_empty()
        {
            tracing::debug!("no sBTC events to process");
            return Ok(warp::reply());
        } else {
            tracing::debug!(
                num_completed_deposits = completed_deposits.len(),
                num_created_withdrawals = created_withdrawals.len(),
                num_updated_withdrawals = updated_withdrawals.len(),
                "there are sBTC events to process"
            );
        }

        if !completed_deposits.is_empty() {
            handle_internal_call(
                update_deposits(
                    context.clone(),
                    context.settings.trusted_reorg_api_key.clone(),
                    UpdateDepositsRequestBody { deposits: completed_deposits },
                ),
                "failed to update deposits in Emily",
            )
            .await?;
        }

        // Create any new withdrawal instances. We do this before performing any updates
        // because a withdrawal needs to exist in the Emily API database in order for it
        // to be updated.
        for withdrawal in created_withdrawals {
            handle_internal_call(
                create_withdrawal(context.clone(), withdrawal),
                "failed to create withdrawal in Emily",
            )
            .await?;
        }

        if !updated_withdrawals.is_empty() {
            handle_internal_call(
                update_withdrawals(
                    context.clone(),
                    context.settings.trusted_reorg_api_key.clone(),
                    UpdateWithdrawalsRequestBody {
                        withdrawals: updated_withdrawals,
                    },
                ),
                "failed to update withdrawals in Emily",
            )
            .await?;
        }

        // Respond.
        Ok(warp::reply())
    }
    // Handle and respond.
    handler(context, new_block_event)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Processes a completed deposit event by preparing the data to be stored.
///
/// # Parameters
/// - `contex`: Application context needed for database access.
/// - `event`: The deposit event to be processed.
/// - `stacks_chaintip`: Current chaintip information for the Stacks blockchain,
///   including block height and hash.
///
/// # Returns
/// - `Result<DepositUpdate, Error>`:  On success, returns a `DepositUpdate`
///   In case no associated deposit was found, returns an `Error`
#[tracing::instrument(skip_all, fields(
    bitcoin_outpoint = %event.outpoint,
    stacks_txid = %event.txid
))]
async fn handle_completed_deposit(
    context: &EmilyContext,
    event: CompletedDepositEvent,
    stacks_chaintip: StacksBlock,
) -> Result<DepositUpdate, Error> {
    tracing::debug!(topic = "completed-deposit", "handled stacks event");

    // It should be impossible for a deposit to be completed without a corresponding
    // deposit request, but we handle this case just in case.
    let deposit = accessors::get_deposit_entry(
        context,
        &DepositEntryKey {
            bitcoin_txid: event.outpoint.txid.to_string(),
            bitcoin_tx_output_index: event.outpoint.vout,
        },
    )
    .await?;

    // The fee paid by the user is the difference between the deposit request amount
    // and the amount minted in the completed deposit event.
    // This should never be negative, but we use saturating_sub just in case.
    let btc_fee = deposit.amount.saturating_sub(event.amount);

    Ok(DepositUpdate {
        bitcoin_tx_output_index: event.outpoint.vout,
        bitcoin_txid: event.outpoint.txid.to_string(),
        status: Status::Confirmed,
        fulfillment: Some(Fulfillment {
            bitcoin_block_hash: event.sweep_block_hash.to_string(),
            bitcoin_block_height: event.sweep_block_height,
            bitcoin_tx_index: 0, // TODO: We don't have this information in the event
            bitcoin_txid: event.sweep_txid.to_string(),
            btc_fee,
            stacks_txid: hex::encode(event.txid.0),
        }),
        status_message: format!("Included in block {}", event.block_id.to_hex()),
        last_update_block_hash: stacks_chaintip.block_hash,
        last_update_height: stacks_chaintip.block_height,
    })
}

/// Handles a withdrawal acceptance event preparing a response to be stored.
///
/// # Parameters
/// - `event`: The withdrawal acceptance event to be processed.
/// - `stacks_chaintip`: Current Stacks blockchain chaintip information for
///   context on block height and hash.
///
/// # Returns
/// - `WithdrawalUpdate`: the struct containing relevant withdrawal information.
#[tracing::instrument(skip_all, fields(
    stacks_txid = %event.txid,
    request_id = %event.request_id
))]
fn handle_withdrawal_accept(
    event: WithdrawalAcceptEvent,
    stacks_chaintip: StacksBlock,
) -> WithdrawalUpdate {
    tracing::debug!(topic = "withdrawal-accept", "handled stacks event");

    WithdrawalUpdate {
        request_id: event.request_id,
        status: Status::Confirmed,
        fulfillment: Some(Fulfillment {
            bitcoin_block_hash: event.sweep_block_hash.to_string(),
            bitcoin_block_height: event.sweep_block_height,
            bitcoin_tx_index: event.outpoint.vout, // TODO: We don't have this information in the event
            bitcoin_txid: event.sweep_txid.to_string(),
            btc_fee: event.fee,
            stacks_txid: hex::encode(event.txid.0),
        }),
        status_message: format!("Included in block {}", event.block_id.to_hex()),
        last_update_block_hash: stacks_chaintip.block_hash,
        last_update_height: stacks_chaintip.block_height,
    }
}

/// Processes a withdrawal creation event by preparing the data to be stored.
///
/// # Parameters
/// - `event`: The withdrawal creation event to be processed.
/// - `stacks_block_height`: The height of the Stacks block containing the withdrawal tx.
/// - `is_mainnet`: Whether the event is on mainnet or regtest.
///
/// # Returns
/// - `Result<CreateWithdrawalRequestBody, Error>`: On success, returns a `CreateWithdrawalRequestBody`
///   with withdrawal information. In case of a address conversion error, returns an `Error`
#[tracing::instrument(skip_all, fields(
    stacks_txid = %event.txid,
    request_id = %event.request_id
))]
fn handle_withdrawal_create(
    event: WithdrawalCreateEvent,
    stacks_block_height: u64,
    is_mainnet: bool,
) -> Result<CreateWithdrawalRequestBody, Error> {
    tracing::debug!(topic = "withdrawal-create", "handled stacks event");
    let params = if is_mainnet {
        &params::MAINNET
    } else {
        &params::REGTEST
    };
    let recipient = bitcoin::Address::from_script(&event.recipient, params)
        // This should never happen since the recipient address is already validated
        .map_err(|e| Error::Debug(format!("Failed to create recipient address: {}", e)))?;
    Ok(CreateWithdrawalRequestBody {
        amount: event.amount,
        parameters: WithdrawalParameters { max_fee: event.max_fee },
        recipient: recipient.to_string(),
        request_id: event.request_id,
        stacks_block_hash: event.block_id.to_hex(),
        stacks_block_height,
    })
}

/// Processes a withdrawal rejection event by preparing the data to be stored.
///
/// # Parameters
/// - `event`: The withdrawal rejection event to be processed.
/// - `stacks_chaintip`: Information about the current chaintip of the Stacks blockchain,
///   such as block height and hash.
///
/// # Returns
/// - `WithdrawalUpdate`: Returns a `WithdrawalUpdate` with rejection information.
#[tracing::instrument(skip_all, fields(
    stacks_txid = %event.txid,
    request_id = %event.request_id
))]
fn handle_withdrawal_reject(
    event: WithdrawalRejectEvent,
    stacks_chaintip: StacksBlock,
) -> WithdrawalUpdate {
    tracing::debug!(topic = "withdrawal-reject", "handled stacks event");

    WithdrawalUpdate {
        fulfillment: None,
        last_update_block_hash: stacks_chaintip.block_hash,
        last_update_height: stacks_chaintip.block_height,
        request_id: event.request_id,
        status: Status::Failed,
        status_message: "Rejected".to_string(),
    }
}

/// Helper function to handle internal API calls with error handling.
async fn handle_internal_call<F, R>(api_call: F, error_msg: &str) -> Result<(), Error>
where
    F: Future<Output = R>,
    R: Reply,
{
    let response = api_call.await.into_response();
    if !response.status().is_success() {
        tracing::error!("{}", error_msg);
        return Err(Error::InternalServer);
    }
    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;
    use bitcoin::{
        hashes::Hash,
        hex::DisplayHex,
        key::rand::{random, rngs::OsRng},
        params::Params,
        secp256k1, BlockHash, OutPoint, ScriptBuf, Txid,
    };
    use clarity::{types::chainstate::StacksBlockId, vm::types::PrincipalData};
    use sbtc::events::StacksTxid;
    use test_case::test_case;

    fn make_random_hex_string() -> String {
        let random_bytes: [u8; 32] = random();
        random_bytes.to_hex_string(bitcoin::hex::Case::Lower)
    }

    fn make_stacks_block() -> StacksBlock {
        StacksBlock {
            block_hash: make_random_hex_string(),
            block_height: random(),
        }
    }

    #[tokio::test]
    async fn test_handle_withdrawal_reject() {
        let stacks_chaintip = make_stacks_block();

        let event = WithdrawalRejectEvent {
            request_id: random(),
            block_id: StacksBlockId::from_hex(&stacks_chaintip.block_hash).unwrap(),
            txid: StacksTxid(random()),
            signer_bitmap: 0,
        };

        // Expected struct to be added to the rejected_withdrawals vector
        let expectation = WithdrawalUpdate {
            request_id: event.request_id,
            status: Status::Failed,
            fulfillment: None,
            last_update_block_hash: stacks_chaintip.block_hash.clone(),
            last_update_height: stacks_chaintip.block_height,
            status_message: "Rejected".to_string(),
        };

        let res = handle_withdrawal_reject(event, stacks_chaintip.clone());

        assert_eq!(res, expectation);
    }

    #[tokio::test]
    async fn test_handle_withdrawal_accept() {
        let stacks_chaintip = make_stacks_block();
        let event = WithdrawalAcceptEvent {
            request_id: random(),
            outpoint: OutPoint::null(),
            txid: StacksTxid(random()),
            block_id: StacksBlockId::from_hex(&stacks_chaintip.block_hash).unwrap(),
            fee: random(),
            signer_bitmap: 0,
            sweep_block_hash: BlockHash::all_zeros(),
            sweep_block_height: random(),
            sweep_txid: Txid::all_zeros(),
        };

        let expectation = WithdrawalUpdate {
            request_id: event.request_id,
            status: Status::Confirmed,
            fulfillment: Some(Fulfillment {
                bitcoin_block_hash: event.sweep_block_hash.to_string(),
                bitcoin_block_height: event.sweep_block_height,
                bitcoin_tx_index: event.outpoint.vout,
                bitcoin_txid: event.sweep_txid.to_string(),
                btc_fee: event.fee,
                stacks_txid: event.txid.to_string(),
            }),
            status_message: format!("Included in block {}", event.block_id.to_hex()),
            last_update_block_hash: stacks_chaintip.block_hash.clone(),
            last_update_height: stacks_chaintip.block_height,
        };

        let res = handle_withdrawal_accept(event, stacks_chaintip.clone());

        assert_eq!(res, expectation);
    }

    #[test_case(false; "regtest")]
    #[test_case(true; "mainnet")]
    #[tokio::test]
    async fn test_handle_withdrawal_create_happy_path(is_mainnet: bool) {
        let stacks_chaintip = make_stacks_block();
        let keys = secp256k1::Keypair::new_global(&mut OsRng);
        let pk = bitcoin::CompressedPublicKey(keys.public_key());
        let script_pubkey = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
        let params = if is_mainnet {
            &Params::MAINNET
        } else {
            &Params::REGTEST
        };
        let recipient = bitcoin::Address::from_script(script_pubkey.as_script(), params).unwrap();

        let event = WithdrawalCreateEvent {
            request_id: random(),
            amount: random(),
            max_fee: random(),
            recipient: script_pubkey,
            txid: StacksTxid(random()),
            block_id: StacksBlockId::from_hex(&stacks_chaintip.block_hash).unwrap(),
            sender: PrincipalData::Standard(StandardPrincipalData::transient()).into(),
            block_height: random(),
        };

        let expectation = CreateWithdrawalRequestBody {
            amount: event.amount,
            parameters: WithdrawalParameters { max_fee: event.max_fee },
            recipient: recipient.to_string(),
            request_id: event.request_id,
            stacks_block_hash: stacks_chaintip.block_hash,
            stacks_block_height: stacks_chaintip.block_height,
        };
        let res = handle_withdrawal_create(event, stacks_chaintip.block_height, is_mainnet);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), expectation);
    }

    #[tokio::test]
    async fn test_handle_withdrawal_create_invalid_address() {
        let stacks_chaintip = make_stacks_block();
        let event = WithdrawalCreateEvent {
            request_id: random(),
            amount: random(),
            max_fee: random(),
            recipient: ScriptBuf::new(),
            txid: StacksTxid(random()),
            block_id: StacksBlockId::from_hex(&stacks_chaintip.block_hash).unwrap(),
            sender: PrincipalData::Standard(StandardPrincipalData::transient()).into(),
            block_height: random(),
        };

        let res = handle_withdrawal_create(event, stacks_chaintip.block_height, false);
        assert!(res.is_err());
    }
}
