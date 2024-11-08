use axum::extract::State;
use axum::http::StatusCode;
use bitcoin::ScriptBuf;
use core::panic;
use emily_client::apis::chainstate_api::get_chain_tip;
use emily_client::apis::deposit_api::create_deposit;
use emily_client::apis::deposit_api::get_deposit;
use emily_client::apis::testing_api::wipe_databases;
use emily_client::apis::withdrawal_api::create_withdrawal;
use emily_client::apis::withdrawal_api::get_withdrawal;
use emily_client::models::CreateDepositRequestBody;
use emily_client::models::CreateWithdrawalRequestBody;
use emily_client::models::Status;
use emily_client::models::WithdrawalParameters;
use rand::SeedableRng;
use sbtc::testing::deposits::TxSetup;
use signer::api::new_block_handler;
use signer::api::ApiState;
use signer::bitcoin::MockBitcoinInteract;
use signer::emily_client::EmilyClient;
use signer::stacks::api::MockStacksInteract;
use signer::stacks::events::RegistryEvent;
use signer::stacks::events::TxInfo;
use signer::stacks::webhooks::NewBlockEvent;
use signer::storage::in_memory::Store;
use signer::testing;
use signer::testing::context::BuildContext;
use signer::testing::context::ConfigureBitcoinClient;
use signer::testing::context::ConfigureEmilyClient;
use signer::testing::context::ConfigureStacksClient;
use signer::testing::context::ConfigureStorage;
use signer::testing::context::TestContext;
use signer::testing::context::WrappedMock;
use std::sync::Arc;
use url::Url;

async fn test_context() -> TestContext<
    Arc<tokio::sync::Mutex<Store>>,
    WrappedMock<MockBitcoinInteract>,
    WrappedMock<MockStacksInteract>,
    EmilyClient,
> {
    let emily_client =
        EmilyClient::try_from(&Url::parse("http://localhost:3031").unwrap()).unwrap();
    let stacks_client = WrappedMock::default();

    TestContext::builder()
        .with_in_memory_storage()
        // .with_storage(db.clone())
        .with_mocked_bitcoin_client()
        .with_stacks_client(stacks_client.clone())
        .with_emily_client(emily_client.clone())
        .build()
}

struct TestNewBlockEvent {
    index_block_hash_hex: String,
    block_height: u64,
    parent_index_block_hash_hex: String,
    burn_block_hash_hex: String,
    burn_block_height: u64,
    parent_burn_block_hash_hex: String,
}

impl TestNewBlockEvent {
    fn new(
        index_block_hash_hex: &str,
        block_height: u64,
        parent_index_block_hash_hex: &str,
        burn_block_hash_hex: &str,
        burn_block_height: u64,
        parent_burn_block_hash_hex: &str,
    ) -> Self {
        Self {
            index_block_hash_hex: index_block_hash_hex.to_string(),
            block_height,
            parent_index_block_hash_hex: parent_index_block_hash_hex.to_string(),
            burn_block_hash_hex: burn_block_hash_hex.to_string(),
            burn_block_height,
            parent_burn_block_hash_hex: parent_burn_block_hash_hex.to_string(),
        }
    }

    fn to_payload(&self) -> String {
        format!(
            r#"{{
        "anchored_cost": {{
            "read_count": 0,
            "read_length": 0,
            "runtime": 0,
            "write_count": 0,
            "write_length": 0
        }},
        "block_hash": "0xe012ca1ad766b2abe03c1cb661930af72fd29f6d197a7d8e4280b54bf2883dec",
        "block_height": {block_height},
        "burn_block_hash": "{burn_block_hash_hex}",
        "burn_block_height": {burn_block_height},
        "burn_block_time": 1724181975,
        "confirmed_microblocks_cost": {{
            "read_count": 0,
            "read_length": 0,
            "runtime": 0,
            "write_count": 0,
            "write_length": 0
        }},
        "cycle_number": null,
        "events": [],
        "index_block_hash": "{index_block_hash_hex}",
        "matured_miner_rewards": [],
        "miner_signature": "0x011e8135ba62a248ff78daf9e7ac9c2da2f6b8cf3b28cb1082d259db2f3a9c297816a667e09579065de2820866ca90b8eea4b43a3a2bfc350874cd11d28e251165",
        "miner_txid": "0x7d53908d95c98e5479582074e4d8eee4e417265610b128c0c603d168ff97cb56",
        "parent_block_hash": "0x1a02201a746c0ff9abd2c81c40ba31f8a4b22f893007f6931e1aef1d70edcf0b",
        "parent_burn_block_hash": "{parent_burn_block_hash_hex}",
        "parent_burn_block_height": {parent_burn_block_height},
        "parent_burn_block_timestamp": 1724181975,
        "parent_index_block_hash": "{parent_index_block_hash_hex}",
        "parent_microblock": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "parent_microblock_sequence": 0,
        "pox_v1_unlock_height": 104,
        "pox_v2_unlock_height": 106,
        "pox_v3_unlock_height": 109,
        "reward_set": null,
        "signer_bitvec": "000800000001ff",
        "signer_signature": [
            "01555a3544f68a067c7e08392c07c1259cc7176d692250966bf82f828a84a653f8371b51a0922fc50756cad3d50a7f0b26955394294b7deb8e686029dbbdbb5755",
            "00ee14b183d8614585923e67df44d2fe8db3bde8b8f51b3b8e067ac5d883b68de829bfabb48aebe9a022588c7769250120f28f6a2e3e5918430c434b710f7a86b1"
        ],
        "signer_signature_hash": "0xe012ca1ad766b2abe03c1cb661930af72fd29f6d197a7d8e4280b54bf2883dec",
        "transactions": [
            {{
                "burnchain_op": null,
                "contract_abi": null,
                "execution_cost": {{
                    "read_count": 0,
                    "read_length": 0,
                    "runtime": 0,
                    "write_count": 0,
                    "write_length": 0
                }},
                "microblock_hash": null,
                "microblock_parent_hash": null,
                "microblock_sequence": null,
                "raw_result": "0x0703",
                "raw_tx": "0x80800000000400ad08341feab8ea788ef8045c343d21dcedc4483e000000000000008a000000000000012c000157158fca569bb7f69bd3e19f08723f1d9fee55dd017c3a8471586d123fe948531d24539ed08fa8498ab0d5ab9d215296c74b2c1896e3fe03c96e51aed66c4f3203020000000000051a62b0e91cc557e583c3d1f9dfe468ace76d2f037400000000000003e800000000000000000000000000000000000000000000000000000000000000000000",
                "status": "success",
                "tx_index": 0,
                "txid": "0xa17854a5c99a99940fbd42df6d964c5ef3afab6b6744f1c4be5912cf90ecd1f9"
            }}
        ]
    }}"#,
            index_block_hash_hex = self.index_block_hash_hex,
            block_height = self.block_height,
            parent_index_block_hash_hex = self.parent_index_block_hash_hex,
            burn_block_hash_hex = self.burn_block_hash_hex,
            burn_block_height = self.burn_block_height,
            parent_burn_block_hash_hex = self.parent_burn_block_hash_hex,
            parent_burn_block_height = self.burn_block_height - 1
        )
    }
}

fn generate_test_events(
    rng: &mut impl rand::RngCore,
    num_bitcoin_blocks: usize,
    num_stacks_blocks_per_bitcoin_block: std::ops::Range<usize>,
) -> Vec<TestNewBlockEvent> {
    let test_harness = testing::block_observer::TestHarness::generate(
        rng,
        num_bitcoin_blocks,
        num_stacks_blocks_per_bitcoin_block,
    );
    let stx_blocks = test_harness.stacks_blocks().to_owned();
    let btc_blocks = test_harness.bitcoin_blocks().to_owned();

    stx_blocks
        .iter()
        .enumerate()
        .map(|(index, (id, block, btc_hash))| {
            TestNewBlockEvent::new(
                &id.to_hex(),
                block.header.chain_length,
                &block.header.parent_block_id.to_hex(),
                &btc_hash.to_string(),
                (1 + (index / 2)) as u64,
                &btc_blocks[index / 2].header.prev_blockhash.to_string(),
            )
        })
        .collect()
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_new_blocks_sends_set_chainstate_to_emily_happy_path() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(46);
    let events = generate_test_events(&mut rng, 5, 1..3);
    let context = test_context().await;
    let state = State(ApiState { ctx: context.clone() });
    let emily_context = state.ctx.emily_client.config();

    // Wipe the Emily database to start fresh
    wipe_databases(&emily_context)
        .await
        .expect("Wiping Emily database in test setup failed.");

    // Get the initial chain tip
    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, 0);
    assert_eq!(resp.stacks_block_hash, "");

    // Send blocks to the handler and check the chain state
    for event in events.iter() {
        let status_code = new_block_handler(state.clone(), event.to_payload()).await;
        assert_eq!(status_code, StatusCode::OK);

        let resp = get_chain_tip(&emily_context).await.unwrap();
        assert_eq!(resp.stacks_block_height, event.block_height);
        assert_eq!(resp.stacks_block_hash, event.index_block_hash_hex);
    }
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_new_blocks_sends_set_chainstate_to_emily_repeated_messages() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(46);
    let events = generate_test_events(&mut rng, 1, 2..3);
    let context = test_context().await;
    let state = State(ApiState { ctx: context.clone() });
    let emily_context = state.ctx.emily_client.config();

    // Wipe the Emily database to start fresh
    wipe_databases(&emily_context)
        .await
        .expect("Wiping Emily database in test setup failed.");

    let mut events_iter = events.into_iter();
    // Send the same block 5 times and ensure chain tip does not change
    let event = events_iter.next().unwrap(); // pick an arbitrary event (5th block)
    for _ in 0..5 {
        let status_code = new_block_handler(state.clone(), event.to_payload()).await;
        assert_eq!(status_code, StatusCode::OK);

        let resp = get_chain_tip(&emily_context).await.unwrap();
        assert_eq!(resp.stacks_block_height, event.block_height);
        assert_eq!(resp.stacks_block_hash, event.index_block_hash_hex);
    }

    // Send the next block and ensure chain tip changes
    let event = events_iter.next().unwrap(); // pick an arbitrary event (6th block)
    let status_code = new_block_handler(state.clone(), event.to_payload()).await;
    assert_eq!(status_code, StatusCode::OK);

    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, event.block_height);
    assert_eq!(resp.stacks_block_hash, event.index_block_hash_hex);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_new_blocks_sends_set_chainstate_to_emily_skip_messages() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(46);
    let events = generate_test_events(&mut rng, 2, 2..3);
    let context = test_context().await;
    let state = State(ApiState { ctx: context.clone() });
    let emily_context = state.ctx.emily_client.config();

    // Wipe the Emily database to start fresh
    wipe_databases(&emily_context)
        .await
        .expect("Wiping Emily database in test setup failed.");

    let mut events_iter = events.into_iter();
    // Send first event
    let event_1 = events_iter.next().unwrap();
    let status_code = new_block_handler(state.clone(), event_1.to_payload()).await;
    assert_eq!(status_code, StatusCode::OK);

    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, event_1.block_height);
    assert_eq!(resp.stacks_block_hash, event_1.index_block_hash_hex);

    // Skip sending the 2nd event
    let skipped_event = events_iter.next().unwrap();

    // Send 3th block event, should be ignored
    let event_3 = events_iter.next().unwrap();
    let status_code = new_block_handler(state.clone(), event_3.to_payload()).await;
    assert_eq!(status_code, StatusCode::OK);

    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, event_1.block_height);
    assert_eq!(resp.stacks_block_hash, event_1.index_block_hash_hex);

    // Now send 2nd block, tip should change
    let status_code = new_block_handler(state.clone(), skipped_event.to_payload()).await;
    assert_eq!(status_code, StatusCode::OK);

    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, skipped_event.block_height);
    assert_eq!(resp.stacks_block_hash, skipped_event.index_block_hash_hex);

    // Send 3th block again, tip should change
    let status_code = new_block_handler(state.clone(), event_3.to_payload()).await;
    assert_eq!(status_code, StatusCode::OK);

    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, event_3.block_height);
    assert_eq!(resp.stacks_block_hash, event_3.index_block_hash_hex);
}

const COMPLETED_DEPOSIT_WEBHOOK: &str =
    include_str!("../../tests/fixtures/completed-deposit-event.json");

const WITHDRAWAL_ACCEPT_WEBHOOK: &str =
    include_str!("../../tests/fixtures/withdrawal-accept-event.json");

const WITHDRAWAL_CREATE_WEBHOOK: &str =
    include_str!("../../tests/fixtures/withdrawal-create-event.json");

const WITHDRAWAL_REJECT_WEBHOOK: &str =
    include_str!("../../tests/fixtures/withdrawal-reject-event.json");

/// Test that the handler can handle a new block event with a valid payload
/// and update the chain state in Emily.
/// This test simulates a reorg by sending a forked block with the same hash as the previous block.
/// The chain tip should be updated to the forked block.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_new_blocks_sends_set_chainstate_to_emily_starts_reorg() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(46);
    let events = generate_test_events(&mut rng, 5, 2..3);
    let context = test_context().await;
    let state = State(ApiState { ctx: context.clone() });
    let emily_context = state.ctx.emily_client.config();

    // Wipe the Emily database to start fresh
    wipe_databases(&emily_context)
        .await
        .expect("Wiping Emily database in test setup failed.");

    // Send initial 3 blocks
    for event in events.iter().take(3) {
        let status_code = new_block_handler(state.clone(), event.to_payload()).await;
        assert_eq!(status_code, StatusCode::OK);

        let resp = get_chain_tip(&emily_context).await.unwrap();
        assert_eq!(resp.stacks_block_height, event.block_height);
        assert_eq!(resp.stacks_block_hash, event.index_block_hash_hex);
    }

    let mut events_iter = events.into_iter().skip(1);
    // Simulate fork at block_height 2 with a new valid hash that matches the previous block
    let mut fork_event = events_iter.next().unwrap();
    events_iter.next();
    let event_4 = events_iter.next().unwrap();

    fork_event.index_block_hash_hex = event_4.index_block_hash_hex.clone();

    // Send the forked block
    let status_code = new_block_handler(state.clone(), fork_event.to_payload()).await;
    assert_eq!(status_code, StatusCode::OK);

    // Check that the chain tip is updated with the new fork's hash
    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, fork_event.block_height);
    assert_eq!(resp.stacks_block_hash, fork_event.index_block_hash_hex);
}

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
    let new_block_event = serde_json::from_str::<NewBlockEvent>(&body).unwrap();
    let deposit_completed_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::CompletedDeposit(event) => Some(event),
        _ => panic!("Expected CompletedDeposit event"),
    });

    let bitcoin_txid = deposit_completed_event.outpoint.txid.to_string();

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

    // Get the initial chain tip
    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, 0);
    assert_eq!(resp.stacks_block_hash, "");

    let resp = new_block_handler(state.clone(), body).await;
    assert_eq!(resp, StatusCode::OK);

    // Check that the chain tip is updated
    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, new_block_event.block_height);
    assert_eq!(
        resp.stacks_block_hash,
        new_block_event.index_block_hash.to_hex()
    );

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
    let new_block_event = serde_json::from_str::<NewBlockEvent>(&body).unwrap();
    let withdrawal_event = get_registry_event_from_webhook(&body, |event| match event {
        RegistryEvent::WithdrawalCreate(event) => Some(event),
        _ => panic!("Expected WithdrawalCreate event"),
    });

    let resp = new_block_handler(state.clone(), body).await;
    assert_eq!(resp, StatusCode::OK);

    // Check that the chain tip is updated
    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, new_block_event.block_height);
    assert_eq!(
        resp.stacks_block_hash,
        new_block_event.index_block_hash.to_hex()
    );
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
    // Check that the chain tip is updated
    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, new_block_event.block_height);
    assert_eq!(
        resp.stacks_block_hash,
        new_block_event.index_block_hash.to_hex()
    );
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

    // Check that the chain tip is updated
    let resp = get_chain_tip(&emily_context).await.unwrap();
    assert_eq!(resp.stacks_block_height, new_block_event.block_height);
    assert_eq!(
        resp.stacks_block_hash,
        new_block_event.index_block_hash.to_hex()
    );
    // Check that the withdrawal is failed and has no fulfillment
    let resp = get_withdrawal(&emily_context, withdrawal_reject_event.request_id).await;
    assert!(resp.is_ok());
    let withdrawal = resp.unwrap();
    assert_eq!(withdrawal.status, Status::Failed);
    assert!(withdrawal.fulfillment.is_none());
}
