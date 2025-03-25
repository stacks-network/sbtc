use core::panic;

use bitcoin::PublicKey;
use bitcoin::ScriptBuf;

use sbtc::events::RegistryEvent;
use sbtc::events::TxInfo;
use sbtc::webhooks::NewBlockEvent;
use testing_emily_client::apis::{deposit_api, new_block_api, withdrawal_api};
use testing_emily_client::models::{
    CreateDepositRequestBody, CreateWithdrawalRequestBody, Status, WithdrawalParameters,
};

use crate::common::clean_setup;

const CREATE_DEPOSIT_VALID: &str = include_str!("../fixtures/create-deposit-valid-testnet.json");

const COMPLETED_VALID_DEPOSIT_WEBHOOK: &str =
    include_str!("../fixtures/completed-deposit-testnet-event.json");

const WITHDRAWAL_ACCEPT_WEBHOOK: &str =
    include_str!("../../../../signer/tests/fixtures/withdrawal-accept-event.json");

const WITHDRAWAL_CREATE_WEBHOOK: &str =
    include_str!("../../../../signer/tests/fixtures/withdrawal-create-event.json");

const WITHDRAWAL_REJECT_WEBHOOK: &str =
    include_str!("../../../../signer/tests/fixtures/withdrawal-reject-event.json");

/// Utility function to parse the webhook body and extract the RegistryEvent variant
/// that matches the expected variant.
fn get_registry_event_from_webhook<T>(
    body: &str,
    is_expected_variant: fn(&RegistryEvent) -> Option<&T>, // This function checks for the expected variant
) -> T
where
    T: Clone, // Cloning is needed to return a copy of the matched variant
{
    let new_block_event = serde_json::from_str::<NewBlockEvent>(body).unwrap();
    let deposit_event = new_block_event.events.first().unwrap();
    let tx_info = TxInfo {
        txid: sbtc::events::StacksTxid(deposit_event.txid.0.clone()),
        block_id: new_block_event.index_block_hash,
    };
    let deposit_event = deposit_event.contract_event.as_ref().unwrap();
    let registry_event = RegistryEvent::try_new(deposit_event.value.clone(), tx_info)
        .expect("Failed to parse RegistryEvent");

    // Check if registry_event matches the expected variant
    is_expected_variant(&registry_event)
        .cloned() // Return a copy of the variant if it matches
        .expect("Expected specified RegistryEvent variant")
}

/// Test that the handler can handle a new block event with a valid payload
/// that contains a CompletedDeposit event.
/// The handler should update the chain state in Emily and mark the deposit as confirmed.
#[tokio::test]
async fn test_new_blocks_sends_update_deposits_to_emily() {
    let configuration = clean_setup().await;

    let body = COMPLETED_VALID_DEPOSIT_WEBHOOK.to_string();
    let deposit_completed_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::CompletedDeposit(event) => Some(event),
        _ => panic!("Expected CompletedDeposit event"),
    });
    let bitcoin_txid = deposit_completed_event.outpoint.txid.to_string();

    // Add the deposit request to Emily
    let request: CreateDepositRequestBody =
        serde_json::from_str(CREATE_DEPOSIT_VALID).expect("failed to parse request");
    let create_deposity_req = CreateDepositRequestBody {
        bitcoin_tx_output_index: deposit_completed_event.outpoint.vout as u32,
        bitcoin_txid: bitcoin_txid.clone(),
        deposit_script: request.deposit_script,
        reclaim_script: request.reclaim_script,
        transaction_hex: request.transaction_hex,
    };
    deposit_api::create_deposit(&configuration, create_deposity_req)
        .await
        .expect("Failed to create deposit request");

    new_block_api::new_block(&configuration, &body)
        .await
        .expect("Failed to send new block event");

    // Check that the deposit is confirmed
    let resp = deposit_api::get_deposit(
        &configuration,
        &bitcoin_txid,
        &deposit_completed_event.outpoint.vout.to_string(),
    )
    .await
    .expect("Failed to get deposit request");

    assert_eq!(resp.bitcoin_txid, bitcoin_txid);
    assert_eq!(resp.status, Status::Confirmed);
    assert!(resp.fulfillment.is_some());
}

/// Test that the handler can handle a new block event with a valid payload
/// that contains a WithdrawalCreate event.
/// The handler should update the chain state in Emily and mark the withdrawal as pending.
#[tokio::test]
async fn test_new_blocks_sends_create_withdrawal_request() {
    let configuration = clean_setup().await;
    let body = WITHDRAWAL_CREATE_WEBHOOK.to_string();
    let withdrawal_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::WithdrawalCreate(event) => Some(event),
        _ => panic!("Expected WithdrawalCreate event"),
    });

    new_block_api::new_block(&configuration, &body)
        .await
        .expect("Failed to send new block event");

    let withdrawal = withdrawal_api::get_withdrawal(&configuration, withdrawal_event.request_id)
        .await
        .expect("Failed to get withdrawal request");
    // Check that the withdrawal is confirmed
    assert_eq!(withdrawal.amount, withdrawal_event.amount);
    assert!(withdrawal.fulfillment.is_none());
    assert_eq!(
        withdrawal.last_update_block_hash,
        withdrawal_event.block_id.to_hex()
    );
    assert_eq!(withdrawal.last_update_height, 253);
    assert_eq!(withdrawal.parameters.max_fee, withdrawal_event.max_fee);
    assert_eq!(
        withdrawal.recipient,
        withdrawal_event.recipient.to_hex_string()
    );
    assert_eq!(withdrawal.sender, withdrawal_event.sender.to_string());
    assert_eq!(withdrawal.request_id, withdrawal_event.request_id);
    assert_eq!(
        withdrawal.stacks_block_hash,
        withdrawal_event.block_id.to_hex()
    );
    assert_eq!(withdrawal.stacks_block_height, 253);
    assert_eq!(withdrawal.status, Status::Pending);
}

/// Test that the handler can handle a new block event with a valid payload
/// that contains a WithdrawalAccept event.
/// The handler should update the chain state in Emily and mark the withdrawal as confirmed.
#[tokio::test]
async fn test_new_blocks_sends_withdrawal_accept_update() {
    let configuration = clean_setup().await;

    let body = WITHDRAWAL_ACCEPT_WEBHOOK.to_string();
    let new_block_event = serde_json::from_str::<NewBlockEvent>(&body).unwrap();
    let withdrawal_accept_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::WithdrawalAccept(event) => Some(event),
        _ => panic!("Expected WithdrawalAccept event"),
    });
    let pubkey = PublicKey::from_slice(&[0x02; 33]).unwrap();
    // Add the withdrawal request to Emily
    let withdrawal_request = CreateWithdrawalRequestBody {
        amount: 100,
        parameters: Box::new(WithdrawalParameters { max_fee: 10 }),
        recipient: ScriptBuf::new_p2pk(&pubkey).to_hex_string(),
        sender: "SN1Z0WW5SMN4J99A1G1725PAB8H24CWNA7Z8H7214.my-contract".to_string(),
        request_id: withdrawal_accept_event.request_id,
        stacks_block_hash: withdrawal_accept_event.block_id.to_hex(),
        stacks_block_height: new_block_event.block_height,
    };

    withdrawal_api::create_withdrawal(&configuration, withdrawal_request)
        .await
        .expect("Failed to create withdrawal request");

    new_block_api::new_block(&configuration, &body)
        .await
        .expect("Failed to send new block event");

    // Check that the withdrawal is confirmed
    let resp =
        withdrawal_api::get_withdrawal(&configuration, withdrawal_accept_event.request_id).await;
    assert!(resp.is_ok());
    let withdrawal = resp.unwrap();
    assert_eq!(withdrawal.status, Status::Confirmed);
    assert!(withdrawal.fulfillment.is_some());
}

/// Test that the handler can handle a new block event with a valid payload
/// that contains a WithdrawalReject event.
/// The handler should update the chain state in Emily and mark the withdrawal as failed.
#[tokio::test]
async fn test_new_blocks_sends_withdrawal_reject_update() {
    let configuration = clean_setup().await;

    let body = WITHDRAWAL_REJECT_WEBHOOK.to_string();
    let new_block_event = serde_json::from_str::<NewBlockEvent>(&body).unwrap();
    let withdrawal_reject_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::WithdrawalReject(event) => Some(event),
        _ => panic!("Expected WithdrawalReject event"),
    });

    let pubkey = PublicKey::from_slice(&[0x02; 33]).unwrap();
    // Add the withdrawal request to Emily
    let withdrawal_request = CreateWithdrawalRequestBody {
        amount: 100,
        parameters: Box::new(WithdrawalParameters { max_fee: 10 }),
        recipient: ScriptBuf::new_p2pk(&pubkey).to_hex_string(),
        sender: "SN1Z0WW5SMN4J99A1G1725PAB8H24CWNA7Z8H7214.my-contract".to_string(),
        request_id: withdrawal_reject_event.request_id,
        stacks_block_hash: withdrawal_reject_event.block_id.to_hex(),
        stacks_block_height: new_block_event.block_height,
    };
    withdrawal_api::create_withdrawal(&configuration, withdrawal_request)
        .await
        .expect("Failed to create withdrawal request");

    new_block_api::new_block(&configuration, &body)
        .await
        .expect("Failed to send new block event");

    // Check that the withdrawal is failed and has no fulfillment
    let resp =
        withdrawal_api::get_withdrawal(&configuration, withdrawal_reject_event.request_id).await;
    assert!(resp.is_ok());
    let withdrawal = resp.unwrap();
    assert_eq!(withdrawal.status, Status::Failed);
    assert!(withdrawal.fulfillment.is_none());
}
