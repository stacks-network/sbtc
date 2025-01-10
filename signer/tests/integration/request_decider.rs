use emily_client::apis::deposit_api;
use emily_client::apis::testing_api;
use emily_client::models::CreateDepositRequestBody;
use fake::Fake;
use fake::Faker;
use rand::SeedableRng as _;

use signer::bitcoin::MockBitcoinInteract;
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
use url::Url;

use crate::setup::backfill_bitcoin_blocks;
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

    let test_model_parameters = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
    };

    let context = TestContext::builder()
        .with_storage(db)
        .with_mocked_clients()
        .build();

    TestEnvironment {
        context,
        num_signers,
        context_window,
        signing_threshold,
        test_model_parameters,
    }
}

async fn create_signer_database() -> PgStore {
    signer::testing::storage::new_test_database().await
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn persist_received_deposit_decision_fetches_missing_deposit_requests() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let emily_client =
        EmilyClient::try_from(&Url::parse("http://testApiKey@localhost:3031").unwrap()).unwrap();

    testing_api::wipe_databases(emily_client.config())
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
