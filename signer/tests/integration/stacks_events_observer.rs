use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use bitcoin::ScriptBuf;
use core::panic;
use emily_client::apis::deposit_api::create_deposit;
use emily_client::apis::deposit_api::get_deposit;
use emily_client::apis::testing_api::wipe_databases;
use emily_client::apis::withdrawal_api::create_withdrawal;
use emily_client::apis::withdrawal_api::get_withdrawal;
use emily_client::models::CreateDepositRequestBody;
use emily_client::models::CreateWithdrawalRequestBody;
use emily_client::models::Status;
use emily_client::models::WithdrawalParameters;
use fake::Fake;
use rand::rngs::OsRng;
use sbtc::testing::deposits::TxSetup;
use signer::api::new_block_handler;
use signer::api::ApiState;
use signer::bitcoin::MockBitcoinInteract;
use signer::context::Context;
use signer::emily_client::EmilyClient;
use signer::stacks::api::MockStacksInteract;
use signer::stacks::events::RegistryEvent;
use signer::stacks::events::TxInfo;
use signer::stacks::webhooks::NewBlockEvent;
use signer::storage::in_memory::Store;
use signer::storage::model::DepositRequest;
use signer::storage::DbWrite as _;
use signer::testing::context::BuildContext;
use signer::testing::context::ConfigureBitcoinClient;
use signer::testing::context::ConfigureEmilyClient;
use signer::testing::context::ConfigureStacksClient;
use signer::testing::context::ConfigureStorage;
use signer::testing::context::TestContext;
use signer::testing::context::WrappedMock;
use url::Url;

async fn test_context() -> TestContext<
    Arc<tokio::sync::Mutex<Store>>,
    WrappedMock<MockBitcoinInteract>,
    WrappedMock<MockStacksInteract>,
    EmilyClient,
> {
    let emily_client =
        EmilyClient::try_from(&Url::parse("http://testApiKey@localhost:3031").unwrap()).unwrap();
    let stacks_client = WrappedMock::default();

    TestContext::builder()
        .with_in_memory_storage()
        // .with_storage(db.clone())
        .with_mocked_bitcoin_client()
        .with_stacks_client(stacks_client.clone())
        .with_emily_client(emily_client.clone())
        .build()
}

const COMPLETED_DEPOSIT_WEBHOOK: &str =
    include_str!("../../tests/fixtures/completed-deposit-event.json");

const WITHDRAWAL_ACCEPT_WEBHOOK: &str =
    include_str!("../../tests/fixtures/withdrawal-accept-event.json");

const WITHDRAWAL_CREATE_WEBHOOK: &str =
    include_str!("../../tests/fixtures/withdrawal-create-event.json");

const WITHDRAWAL_REJECT_WEBHOOK: &str =
    include_str!("../../tests/fixtures/withdrawal-reject-event.json");

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
        txid: deposit_event.txid.clone(),
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_new_blocks_sends_update_deposits_to_emily() {
    let context = test_context().await;
    let state = State(ApiState { ctx: context.clone() });
    let emily_context = state.ctx.emily_client.config();

    // Wipe the Emily database to start fresh
    wipe_databases(&emily_context)
        .await
        .expect("Wiping Emily database in test setup failed.");

    let body = COMPLETED_DEPOSIT_WEBHOOK.to_string();
    let deposit_completed_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::CompletedDeposit(event) => Some(event),
        _ => panic!("Expected CompletedDeposit event"),
    });

    let bitcoin_txid = deposit_completed_event.outpoint.txid.to_string();

    // Insert a dummy deposit request into the database. This will be retrieved by
    // handle_completed_deposit to compute the fee paid.
    let mut deposit: DepositRequest = fake::Faker.fake_with_rng(&mut OsRng);
    deposit.amount = deposit_completed_event.amount + 100;
    deposit.txid = deposit_completed_event.outpoint.txid.into();
    deposit.output_index = deposit_completed_event.outpoint.vout;

    context
        .get_storage_mut()
        .write_deposit_request(&deposit)
        .await
        .expect("failed to insert dummy deposit request");

    // Add the deposit request to Emily
    let tx_setup: TxSetup = sbtc::testing::deposits::tx_setup(15_000, 500_000, 150);
    let create_deposity_req = CreateDepositRequestBody {
        bitcoin_tx_output_index: deposit_completed_event.outpoint.vout as u32,
        bitcoin_txid: bitcoin_txid.clone(),
        deposit_script: tx_setup.deposit.deposit_script().to_hex_string(),
        reclaim_script: tx_setup.reclaim.reclaim_script().to_hex_string(),
    };
    let resp = create_deposit(&emily_context, create_deposity_req).await;
    assert!(resp.is_ok());

    let resp = new_block_handler(state.clone(), body).await;
    assert_eq!(resp, StatusCode::OK);

    // Check that the deposit is confirmed
    let resp = get_deposit(
        &emily_context,
        &bitcoin_txid,
        &deposit_completed_event.outpoint.vout.to_string(),
    )
    .await;
    assert!(resp.is_ok());

    let resp = resp.unwrap();
    assert_eq!(resp.bitcoin_txid, bitcoin_txid);
    assert_eq!(resp.status, Status::Confirmed);
    assert!(resp.fulfillment.is_some());
}

/// Test that the handler can handle a new block event with a valid payload
/// that contains a WithdrawalCreate event.
/// The handler should update the chain state in Emily and mark the withdrawal as pending.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_new_blocks_sends_create_withdrawal_request() {
    let context = test_context().await;
    let state = State(ApiState { ctx: context.clone() });
    let emily_context = state.ctx.emily_client.config();

    // Wipe the Emily database to start fresh
    wipe_databases(&emily_context)
        .await
        .expect("Wiping Emily database in test setup failed.");

    let body = WITHDRAWAL_CREATE_WEBHOOK.to_string();
    let withdrawal_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::WithdrawalCreate(event) => Some(event),
        _ => panic!("Expected WithdrawalCreate event"),
    });

    let resp = new_block_handler(state.clone(), body).await;
    assert_eq!(resp, StatusCode::OK);

    // Check that the withdrawal is confirmed
    let resp = get_withdrawal(&emily_context, withdrawal_event.request_id).await;
    assert!(resp.is_ok());
    let withdrawal = resp.unwrap();
    assert_eq!(withdrawal.status, Status::Pending);
    assert!(withdrawal.fulfillment.is_none());
}

/// Test that the handler can handle a new block event with a valid payload
/// that contains a WithdrawalAccept event.
/// The handler should update the chain state in Emily and mark the withdrawal as confirmed.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_new_blocks_sends_withdrawal_accept_update() {
    let context = test_context().await;
    let state = State(ApiState { ctx: context.clone() });
    let emily_context = state.ctx.emily_client.config();

    // Wipe the Emily database to start fresh
    wipe_databases(&emily_context)
        .await
        .expect("Wiping Emily database in test setup failed.");

    let body = WITHDRAWAL_ACCEPT_WEBHOOK.to_string();
    let new_block_event = serde_json::from_str::<NewBlockEvent>(&body).unwrap();
    let withdrawal_accept_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::WithdrawalAccept(event) => Some(event),
        _ => panic!("Expected WithdrawalAccept event"),
    });

    // Add the withdrawal request to Emily
    let withdrawal_request = CreateWithdrawalRequestBody {
        amount: 100,
        parameters: Box::new(WithdrawalParameters { max_fee: 10 }),
        recipient: ScriptBuf::default().to_hex_string(),
        request_id: withdrawal_accept_event.request_id,
        stacks_block_hash: withdrawal_accept_event.block_id.to_hex(),
        stacks_block_height: new_block_event.block_height,
    };
    let resp = create_withdrawal(&emily_context, withdrawal_request).await;
    assert!(resp.is_ok());

    let resp = new_block_handler(state.clone(), body).await;
    assert_eq!(resp, StatusCode::OK);

    // Check that the withdrawal is confirmed
    let resp = get_withdrawal(&emily_context, withdrawal_accept_event.request_id).await;
    assert!(resp.is_ok());
    let withdrawal = resp.unwrap();
    assert_eq!(withdrawal.status, Status::Confirmed);
    assert!(withdrawal.fulfillment.is_some());
}

/// Test that the handler can handle a new block event with a valid payload
/// that contains a WithdrawalReject event.
/// The handler should update the chain state in Emily and mark the withdrawal as failed.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_new_blocks_sends_withdrawal_reject_update() {
    let context = test_context().await;
    let state = State(ApiState { ctx: context.clone() });
    let emily_context = state.ctx.emily_client.config();

    // Wipe the Emily database to start fresh
    wipe_databases(&emily_context)
        .await
        .expect("Wiping Emily database in test setup failed.");

    let body = WITHDRAWAL_REJECT_WEBHOOK.to_string();
    let new_block_event = serde_json::from_str::<NewBlockEvent>(&body).unwrap();
    let withdrawal_reject_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::WithdrawalReject(event) => Some(event),
        _ => panic!("Expected WithdrawalReject event"),
    });

    // Add the withdrawal request to Emily
    let withdrawal_request = CreateWithdrawalRequestBody {
        amount: 100,
        parameters: Box::new(WithdrawalParameters { max_fee: 10 }),
        recipient: ScriptBuf::default().to_hex_string(),
        request_id: withdrawal_reject_event.request_id,
        stacks_block_hash: withdrawal_reject_event.block_id.to_hex(),
        stacks_block_height: new_block_event.block_height,
    };
    let resp = create_withdrawal(&emily_context, withdrawal_request).await;
    assert!(resp.is_ok());

    let resp = new_block_handler(state.clone(), body).await;
    assert_eq!(resp, StatusCode::OK);

    // Check that the withdrawal is failed and has no fulfillment
    let resp = get_withdrawal(&emily_context, withdrawal_reject_event.request_id).await;
    assert!(resp.is_ok());
    let withdrawal = resp.unwrap();
    assert_eq!(withdrawal.status, Status::Failed);
    assert!(withdrawal.fulfillment.is_none());
}
