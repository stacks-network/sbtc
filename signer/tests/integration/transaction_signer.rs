use std::collections::HashMap;
use std::sync::atomic::Ordering;

use fake::Fake as _;
use fake::Faker;
use futures::StreamExt;
use rand::SeedableRng as _;

use signer::context::Context as _;
use signer::emily_client::MockEmilyInteract;
use signer::keys::PublicKey;
use signer::network::InMemoryNetwork;
use signer::stacks::api::MockStacksInteract;
use signer::storage::model;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::RotateKeysTransaction;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::testing;
use signer::testing::context::*;
use signer::testing::storage::model::TestData;
use signer::testing::transaction_signer::TestEnvironment;
use signer::transaction_signer::TxSignerEventLoop;
use signer::{bitcoin::MockBitcoinInteract, storage::postgres::PgStore};

use crate::setup::backfill_bitcoin_blocks;
use crate::setup::TestSweepSetup;
use crate::DATABASE_NUM;

async fn test_environment(
    mut signer_connections: Vec<PgStore>,
    signing_threshold: u32,
) -> TestEnvironment<
    TestContext<
        PgStore,
        WrappedMock<MockBitcoinInteract>,
        WrappedMock<MockStacksInteract>,
        WrappedMock<MockEmilyInteract>,
    >,
> {
    let context_window = 3;

    let test_model_parameters = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
    };

    let context = TestContext::builder()
        .with_storage(signer_connections.pop().unwrap())
        .with_mocked_clients()
        .build();

    testing::transaction_signer::TestEnvironment {
        context,
        num_signers: signer_connections.len(),
        context_window,
        signing_threshold,
        test_model_parameters,
    }
}

async fn create_signer_databases(num_signers: usize) -> Vec<PgStore> {
    let get_next_num = || DATABASE_NUM.fetch_add(1, Ordering::SeqCst);

    futures::stream::repeat_with(get_next_num)
        .then(|i| signer::testing::storage::new_test_database(i, true))
        .take(num_signers)
        .collect()
        .await
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_for_pending_deposit_requests() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_store_decisions_for_pending_deposit_requests()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_for_pending_withdraw_requests() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_store_decisions_for_pending_withdraw_requests()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_received_from_other_signers() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_store_decisions_received_from_other_signers()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_respond_to_bitcoin_transaction_sign_request() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_respond_to_bitcoin_transaction_sign_requests()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_be_able_to_participate_in_signing_round() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_be_able_to_participate_in_signing_round()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

/// Test that [`TxSignerEventLoop::get_signer_public_keys`] falls back to
/// the bootstrap config if there is no rotate-keys transaction in the
/// database.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_signer_public_keys_and_aggregate_key_falls_back() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let network = InMemoryNetwork::new();

    let coord = TxSignerEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        blocklist_checker: Some(()),
        wsts_state_machines: HashMap::new(),
        signer_private_key: ctx.config().signer.private_key,
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
    };

    // We need stacks blocks for the rotate-keys transactions.
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_params);
    test_data.write_to(&db).await;

    // We always need the chain tip.
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();

    // We have no transactions in the database, just blocks header hashes
    // and block heights. The `get_signer_public_keys` function falls back
    // to the config for keys if no rotate-keys transaction can be found.
    // So this function almost never errors.
    let bootstrap_signer_set = coord.get_signer_public_keys(&chain_tip).await.unwrap();
    // We check that the signer set can form a valid wallet when we load
    // the config. In particular, the signing set should not be empty.
    assert!(!bootstrap_signer_set.is_empty());

    let config_signer_set = ctx.config().signer.bootstrap_signing_set();
    assert_eq!(bootstrap_signer_set, config_signer_set);

    // Okay not we write a rotate-keys transaction into the database. To do
    // that we need the stacks chain tip, and a something in 3 different
    // tables...
    let stacks_chain_tip = db.get_stacks_chain_tip(&chain_tip).await.unwrap().unwrap();

    let rotate_keys: RotateKeysTransaction = Faker.fake_with_rng(&mut rng);
    let transaction = model::Transaction {
        txid: rotate_keys.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::RotateKeys,
        block_hash: stacks_chain_tip.block_hash.into_bytes(),
    };
    let tx = model::StacksTransaction {
        txid: rotate_keys.txid,
        block_hash: stacks_chain_tip.block_hash,
    };

    db.write_transaction(&transaction).await.unwrap();
    db.write_stacks_transaction(&tx).await.unwrap();
    db.write_rotate_keys_transaction(&rotate_keys)
        .await
        .unwrap();

    // Alright, now that we have a rotate-keys transaction, we can check if
    // it is preferred over the config.
    let signer_set: Vec<PublicKey> = coord
        .get_signer_public_keys(&chain_tip)
        .await
        .unwrap()
        .into_iter()
        .collect();

    assert_eq!(rotate_keys.signer_set, signer_set);

    testing::storage::drop_db(db).await;
}

/// Test that [`TxSignerEventLoop::handle_pending_deposit_request`] does
/// not error when attempting to check the scriptPubKeys of any of the
/// inputs of a deposit.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn handle_pending_deposit_request_address_script_pub_key() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;

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

    let mut requests = db
        .get_pending_deposit_requests(&chain_tip, 100)
        .await
        .unwrap();
    // There should only be the one deposit request that we just fetched.
    assert_eq!(requests.len(), 1);
    let request = requests.pop().unwrap();

    let network = InMemoryNetwork::new();
    let mut tx_signer = TxSignerEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        blocklist_checker: Some(()),
        wsts_state_machines: HashMap::new(),
        signer_private_key: ctx.config().signer.private_key,
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
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
    let vote = votes.pop().unwrap();
    assert!(vote.is_accepted);

    testing::storage::drop_db(db).await;
}
