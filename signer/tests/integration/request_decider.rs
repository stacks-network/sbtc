use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::consensus::encode::serialize_hex;
use fake::Fake;
use fake::Faker;
use mockito::Server;
use rand::SeedableRng as _;
use serde_json::json;
use url::Url;

use emily_client::apis::deposit_api;
use emily_client::models::CreateDepositRequestBody;
use signer::bitcoin::MockBitcoinInteract;
use signer::blocklist_client::BlocklistClient;
use signer::context::Context;
use signer::emily_client::EmilyClient;
use signer::emily_client::MockEmilyInteract;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::message::SignerDepositDecision;
use signer::network::in_memory2::SignerNetwork;
use signer::network::InMemoryNetwork;
use signer::request_decider::RequestDeciderEventLoop;
use signer::stacks::api::MockStacksInteract;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead as _;
use signer::testing;
use signer::testing::context::*;
use signer::testing::request_decider::TestEnvironment;
use testing_emily_client::apis::testing_api;

use crate::setup::backfill_bitcoin_blocks;
use crate::setup::IntoEmilyTestingConfig as _;
use crate::setup::TestSweepSetup;

fn test_environment(
    db: PgStore,
    signing_threshold: u32,
    num_signers: usize,
) -> TestEnvironment<
    TestContext<
        PgStore,
        WrappedMock<MockBitcoinInteract>,
        WrappedMock<MockStacksInteract>,
        WrappedMock<MockEmilyInteract>,
    >,
> {
    let context_window = 6;
    let deposit_decisions_retry_window = 1;

    let test_model_parameters = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };

    let context = TestContext::builder()
        .with_storage(db)
        .with_mocked_clients()
        .build();

    TestEnvironment {
        context,
        num_signers,
        context_window,
        deposit_decisions_retry_window,
        signing_threshold,
        test_model_parameters,
    }
}

async fn create_signer_database() -> PgStore {
    signer::testing::storage::new_test_database().await
}

#[test_log::test(tokio::test)]
async fn should_store_decisions_for_pending_deposit_requests() {
    let num_signers = 3;
    let signing_threshold = 2;

    let db = create_signer_database().await;
    // We need to clone the connection so that we can drop the associated
    // databases later.
    test_environment(db.clone(), signing_threshold, num_signers)
        .assert_should_store_decisions_for_pending_deposit_requests()
        .await;

    // Now drop the database that we just created.
    signer::testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn should_store_decisions_for_pending_withdraw_requests() {
    let num_signers = 3;
    let signing_threshold = 2;

    let db = create_signer_database().await;
    // We need to clone the connection so that we can drop the associated
    // databases later.
    test_environment(db.clone(), signing_threshold, num_signers)
        .assert_should_store_decisions_for_pending_withdrawal_requests()
        .await;

    // Now drop the database that we just created.
    signer::testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn should_store_decisions_received_from_other_signers() {
    let num_signers = 3;
    let signing_threshold = 2;

    let db = create_signer_database().await;
    // We need to clone the connection so that we can drop the associated
    // databases later.
    test_environment(db.clone(), signing_threshold, num_signers)
        .assert_should_store_decisions_received_from_other_signers()
        .await;

    // Now drop the database that we just created.
    signer::testing::storage::drop_db(db).await;
}

/// Test that [`TxSignerEventLoop::handle_pending_deposit_request`] does
/// not error when attempting to check the scriptPubKeys of the
/// inputs of a deposit.
#[tokio::test]
async fn handle_pending_deposit_request_address_script_pub_key() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    // This confirms a deposit transaction, and has a nice helper function
    // for storing a real deposit.
    let setup = TestSweepSetup::new_setup(rpc, faucet, 10000, &mut rng);

    // Let's get the blockchain data into the database.
    let chain_tip: BitcoinBlockHash = setup.sweep_block_hash.into();
    backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;

    // We need to store the deposit request because of the foreign key
    // constraint on the deposit_signers table.
    setup.store_deposit_request(&db).await;

    // In order to fetch the deposit request that we just store, we need to
    // store the deposit transaction.
    setup.store_deposit_tx(&db).await;

    // When we run TxSignerEventLoop::handle_pending_deposit_request, we
    // check if the current signer is in the signing set. For this check we
    // need a row in the dkg_shares table.
    setup.store_dkg_shares(&db).await;

    let signer_public_key = setup.aggregated_signer.keypair.public_key().into();
    let mut requests = db
        .get_pending_deposit_requests(&chain_tip, 100, &signer_public_key)
        .await
        .unwrap();
    // There should only be the one deposit request that we just fetched.
    assert_eq!(requests.len(), 1);
    let request = requests.pop().unwrap();

    let network = InMemoryNetwork::new();
    let mut tx_signer = RequestDeciderEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        deposit_decisions_retry_window: 1,
        blocklist_checker: Some(()),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
    };

    // We need this so that there is a live "network". Otherwise,
    // TxSignerEventLoop::handle_pending_deposit_request will error when
    // trying to send a message at the end.
    let _rec = ctx.get_signal_receiver();

    // We don't want this to error. There was a bug before, see
    // https://github.com/stacks-network/sbtc/issues/674.
    tx_signer
        .handle_pending_deposit_request(request, &chain_tip)
        .await
        .unwrap();

    // A decision should get stored and there should only be one
    let outpoint = setup.deposit_request.outpoint;
    let mut votes = db
        .get_deposit_signers(&outpoint.txid.into(), outpoint.vout)
        .await
        .unwrap();
    assert_eq!(votes.len(), 1);

    // The blocklist checker that we have configured accepts all deposits.
    // Also we are in the signing set so we can sign for the deposit.
    let vote = votes.pop().unwrap();
    assert!(vote.can_sign);
    assert!(vote.can_accept);

    testing::storage::drop_db(db).await;
}

/// Test that [`RequestDeciderEventLoop::handle_pending_deposit_request`]
/// will write the can_sign field to be false if the current signer is not
/// part of the signing set locking the deposit transaction.
#[tokio::test]
async fn handle_pending_deposit_request_not_in_signing_set() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    // This confirms a deposit transaction, and has a nice helper function
    // for storing a real deposit.
    let setup = TestSweepSetup::new_setup(rpc, faucet, 10000, &mut rng);

    // Let's get the blockchain data into the database.
    let chain_tip: BitcoinBlockHash = setup.sweep_block_hash.into();
    backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;

    // We need to store the deposit request because of the foreign key
    // constraint on the deposit_signers table.
    setup.store_deposit_request(&db).await;

    // In order to fetch the deposit request that we just store, we need to
    // store the deposit transaction.
    setup.store_deposit_tx(&db).await;

    // When we run RequestDeciderEventLoop::handle_pending_deposit_request, we
    // check if the current signer is in the signing set and this adds a
    // signing set.
    setup.store_dkg_shares(&db).await;

    let signer_public_key = setup.aggregated_signer.keypair.public_key().into();
    let mut requests = db
        .get_pending_deposit_requests(&chain_tip, 100, &signer_public_key)
        .await
        .unwrap();
    // There should only be the one deposit request that we just fetched.
    assert_eq!(requests.len(), 1);
    let request = requests.pop().unwrap();

    let network = InMemoryNetwork::new();
    let mut tx_signer = RequestDeciderEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        deposit_decisions_retry_window: 1,
        blocklist_checker: Some(()),
        // We generate a new private key here so that we know (with very
        // high probability) that this signer is not in the signer set.
        signer_private_key: PrivateKey::new(&mut rng),
    };

    // We need this so that there is a live "network". Otherwise,
    // TxSignerEventLoop::handle_pending_deposit_request will error when
    // trying to send a message at the end.
    let _rec = ctx.get_signal_receiver();

    tx_signer
        .handle_pending_deposit_request(request, &chain_tip)
        .await
        .unwrap();

    // A decision should get stored and there should only be one
    let outpoint = setup.deposit_request.outpoint;
    let mut votes = db
        .get_deposit_signers(&outpoint.txid.into(), outpoint.vout)
        .await
        .unwrap();
    assert_eq!(votes.len(), 1);

    // can_sign should be false since the public key associated with our
    // random private key is not in the signing set. And can_accept is
    // always true with the given blocklist client.
    let vote = votes.pop().unwrap();
    assert!(!vote.can_sign);
    assert!(vote.can_accept);

    testing::storage::drop_db(db).await;
}

/// Test that
/// [`RequestDeciderEventLoop::persist_received_deposit_decision`] will
/// fetch the deposit request from emily if does not have a record of it.
#[tokio::test]
async fn persist_received_deposit_decision_fetches_missing_deposit_requests() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let emily_client = EmilyClient::try_new(
        &Url::parse("http://testApiKey@localhost:3031").unwrap(),
        Duration::from_secs(1),
        None,
    )
    .unwrap();

    testing_api::wipe_databases(&emily_client.config().as_testing())
        .await
        .unwrap();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_emily_client(emily_client.clone())
        .with_mocked_stacks_client()
        .build();

    // We need this so that there is a live "network". Otherwise,
    // RequestDeciderEventLoop::persist_received_deposit_decision will
    // error when trying to send a message at the end.
    let _rec = ctx.get_signal_receiver();

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    // This confirms a deposit transaction, and has a nice helper function
    // for storing a real deposit.
    let setup = TestSweepSetup::new_setup(rpc, faucet, 10000, &mut rng);

    // Let's get the blockchain data into the database.
    let chain_tip: BitcoinBlockHash = setup.sweep_block_hash.into();
    backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;

    let network = SignerNetwork::single(&ctx);

    let mut decider = RequestDeciderEventLoop {
        network: network.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        deposit_decisions_retry_window: 1,
        blocklist_checker: Some(()),
        signer_private_key: PrivateKey::new(&mut rng),
    };
    let txid = setup.deposit_request.outpoint.txid.into();
    let output_index = setup.deposit_request.outpoint.vout;

    let votes = db.get_deposit_signers(&txid, output_index).await.unwrap();
    assert!(votes.is_empty());

    let decision = SignerDepositDecision {
        txid: *txid,
        output_index,
        can_accept: true,
        can_sign: true,
    };
    let sender_pub_key: PublicKey = Faker.fake_with_rng(&mut rng);
    // Emily doesn't know about the deposit request so nothing should be
    // written.
    decider
        .persist_received_deposit_decision(&decision, sender_pub_key)
        .await
        .unwrap();

    // A decision should get stored and there should only be one
    let votes = db.get_deposit_signers(&txid, output_index).await.unwrap();
    assert!(votes.is_empty());

    // Now let's tell emily about the deposit request
    let body = CreateDepositRequestBody {
        bitcoin_tx_output_index: setup.deposit_request.outpoint.vout,
        bitcoin_txid: setup.deposit_request.outpoint.txid.to_string(),
        deposit_script: setup.deposit_request.deposit_script.to_hex_string(),
        reclaim_script: setup.deposit_request.reclaim_script.to_hex_string(),
        transaction_hex: serialize_hex(&setup.deposit_tx_info.tx),
    };
    let _ = deposit_api::create_deposit(emily_client.config(), body)
        .await
        .unwrap();

    // Okay now before we attempt to fetch the decision, we'll ask emily,
    // get the deposit reqeust, validate it, persist the request and
    // persist the decision.
    decider
        .persist_received_deposit_decision(&decision, sender_pub_key)
        .await
        .unwrap();

    // A decision should get stored and there should only be one
    let votes = db.get_deposit_signers(&txid, output_index).await.unwrap();
    assert_eq!(votes.len(), 1);

    let vote = &votes[0];
    assert_eq!(vote.signer_pub_key, sender_pub_key);
    assert_eq!(vote.can_accept, decision.can_accept);
    assert_eq!(vote.can_sign, decision.can_sign);
    assert_eq!(vote.output_index, decision.output_index);

    let deposit_request_exists = db
        .deposit_request_exists(&txid, output_index)
        .await
        .unwrap();
    assert!(deposit_request_exists);

    testing::storage::drop_db(db).await;
}

/// Test `RequestDeciderEventLoop` behaviour in case of blocklist client
/// failures. It should try to contact the blocklist client twice per bitcoin
/// block, and in case of errors it should try again at the next block without
/// voting.
#[test_case::test_case(0, 0; "0 failures")]
#[test_case::test_case(1, 0; "1 failure")]
#[test_case::test_case(2, 1; "2 failures")]
#[test_case::test_case(3, 1; "3 failures")]
#[test_case::test_case(4, 2; "4 failures")]
#[tokio::test]
async fn blocklist_client_retry(num_failures: u8, failing_iters: u8) {
    let db = testing::storage::new_test_database().await;
    let network = InMemoryNetwork::new();

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    // This confirms a deposit transaction, and has a nice helper function
    // for storing a real deposit.
    let setup = TestSweepSetup::new_setup(rpc, faucet, 10000, &mut rng);

    // Let's get the blockchain data into the database.
    let chain_tip: BitcoinBlockHash = setup.sweep_block_hash.into();
    backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;

    // We need to store the deposit request because of the foreign key
    // constraint on the deposit_signers table.
    setup.store_deposit_request(&db).await;

    // In order to fetch the deposit request that we just stored, we need to
    // store the deposit transaction.
    setup.store_deposit_tx(&db).await;

    // We check if the current signer is in the signing set. For this check we
    // need a row in the dkg_shares table.
    setup.store_dkg_shares(&db).await;

    let signer_public_key = setup.aggregated_signer.keypair.public_key().into();
    let mut requests = db
        .get_pending_deposit_requests(&chain_tip, 100, &signer_public_key)
        .await
        .unwrap();
    // There should only be the one deposit request that we just fetched.
    assert_eq!(requests.len(), 1);
    let request = requests.pop().unwrap();
    let outpoint = setup.deposit_request.outpoint;

    let bitcoin_network = bitcoin::Network::from(ctx.config().signer.network);
    let sender_address =
        bitcoin::Address::from_script(&request.sender_script_pub_keys[0], bitcoin_network.params())
            .unwrap();

    // Now we mock the blocklist client: we want it to fail for the first
    // `num_failures` calls, then succeed (with the following mock)
    let mut blocklist_server = Server::new_async().await;
    let mock_json = json!({
        "is_blocklisted": false,
        "severity": "Low",
        "accept": true,
        "reason": null
    })
    .to_string();

    let counter = Arc::new(AtomicU8::new(0));
    blocklist_server
        .mock("GET", format!("/screen/{sender_address}").as_str())
        .match_request(move |_| counter.fetch_add(1, Ordering::SeqCst) >= num_failures)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&mock_json)
        .create_async()
        .await;

    let blocklist_client = BlocklistClient::with_base_url(blocklist_server.url());

    let mut request_decider = RequestDeciderEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        blocklist_checker: Some(blocklist_client),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
        deposit_decisions_retry_window: 1,
    };

    // We need this so that there is a live "network". Otherwise we will error
    // when trying to send a message at the end.
    let _rec = ctx.get_signal_receiver();

    // We shouldn't have any decision at the beginning
    let votes = db
        .get_deposit_signers(&outpoint.txid.into(), outpoint.vout)
        .await
        .unwrap();
    assert!(votes.is_empty());

    // Iterations with failing blocklist client
    for _ in 0..failing_iters {
        request_decider.handle_new_requests().await.unwrap();

        // We shouldn't have any decision yet
        let votes = db
            .get_deposit_signers(&outpoint.txid.into(), outpoint.vout)
            .await
            .unwrap();
        assert!(votes.is_empty());
    }

    // Final iteration with (at least one) blocklist success
    request_decider.handle_new_requests().await.unwrap();

    // A decision should get stored and there should only be one
    let votes = db
        .get_deposit_signers(&outpoint.txid.into(), outpoint.vout)
        .await
        .unwrap();
    assert_eq!(votes.len(), 1);

    testing::storage::drop_db(db).await;
}
