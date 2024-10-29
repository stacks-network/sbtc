use std::collections::HashMap;
use std::sync::atomic::Ordering;

use fake::Fake as _;
use fake::Faker;
use rand::SeedableRng as _;

use signer::context::Context as _;
use signer::emily_client::MockEmilyInteract;
use signer::error::Error;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::message::StacksTransactionSignRequest;
use signer::network::InMemoryNetwork;
use signer::stacks::api::MockStacksInteract;
use signer::storage::model;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::RotateKeysTransaction;
use signer::storage::model::StacksTxId;
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

    testing::transaction_signer::TestEnvironment {
        context,
        num_signers,
        context_window,
        signing_threshold,
        test_model_parameters,
    }
}

async fn create_signer_database() -> PgStore {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    signer::testing::storage::new_test_database(db_num, true).await
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
        .await
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
        .await
        .assert_should_store_decisions_for_pending_withdraw_requests()
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
        .await
        .assert_should_store_decisions_received_from_other_signers()
        .await;

    // Now drop the database that we just created.
    signer::testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_respond_to_bitcoin_transaction_sign_request() {
    let num_signers = 3;
    let signing_threshold = 2;

    let db = create_signer_database().await;
    // We need to clone the connection so that we can drop the associated
    // databases later.
    test_environment(db.clone(), signing_threshold, num_signers)
        .await
        .assert_should_respond_to_bitcoin_transaction_sign_requests()
        .await;

    // Now drop the database that we just created.
    signer::testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_be_able_to_participate_in_signing_round() {
    let num_signers = 3;
    let signing_threshold = 2;

    let db = create_signer_database().await;
    // We need to clone the connection so that we can drop the associated
    // databases later.
    test_environment(db.clone(), signing_threshold, num_signers)
        .await
        .assert_should_be_able_to_participate_in_signing_round()
        .await;

    // Now drop the database that we just created.
    signer::testing::storage::drop_db(db).await;
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

    // Okay now we write a rotate-keys transaction into the database. To do
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

    let mut rotate_keys_signer_set = rotate_keys.signer_set.clone();
    rotate_keys_signer_set.sort();

    assert_eq!(rotate_keys_signer_set, signer_set);

    testing::storage::drop_db(db).await;
}

/// Test that [`TxSignerEventLoop::handle_pending_deposit_request`] does
/// not error when attempting to check the scriptPubKeys of the
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

    // When we run TxSignerEventLoop::handle_pending_deposit_request, we
    // check if the current signer is in the signing set. For this check we
    // need a row in the dkg_shares table.
    setup.store_dkg_shares(&db).await;

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
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
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
    // Also we are in the signing set so we can sign for the deposit.
    let vote = votes.pop().unwrap();
    assert!(vote.can_sign);
    assert!(vote.is_accepted);

    testing::storage::drop_db(db).await;
}

/// Test that [`TxSignerEventLoop::handle_pending_deposit_request`] will
/// write the can_sign field to be false if the current signer is not part
/// of the signing set locking the deposit transaction.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn handle_pending_deposit_request_not_in_signing_set() {
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

    // When we run TxSignerEventLoop::handle_pending_deposit_request, we
    // check if the current signer is in the signing set and this adds a
    // signing set.
    setup.store_dkg_shares(&db).await;

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
        // We generate a new private key here so that we know (with very
        // high probability) that this signer is not in the signer set.
        signer_private_key: PrivateKey::new(&mut rng),
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
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
    // random private key is not in the signing set. And is_accepted is
    // false whenever can_sign is false.
    let vote = votes.pop().unwrap();
    assert!(!vote.can_sign);
    assert!(!vote.is_accepted);

    testing::storage::drop_db(db).await;
}

/// Test that [`TxSignerEventLoop::assert_valid_stacks_tx_sign_request`]
/// errors when the signer is not in the signer set.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn signing_set_validation_check_for_stacks_transactions() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();
    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    // This confirms a deposit transaction, and has a nice helper function
    // for storing a real deposit.
    let setup = TestSweepSetup::new_setup(rpc, faucet, 10000, &mut rng);

    // Let's get the blockchain data into the database.
    let chain_tip: BitcoinBlockHash = setup.sweep_block_hash.into();
    backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;

    // This is all normal things that need to happen in order to pass
    // validation.
    setup.store_happy_path_data(&db).await;

    let (mut req, _) = crate::complete_deposit::make_complete_deposit(&setup);

    req.deployer = ctx.config().signer.deployer;
    let network = InMemoryNetwork::new();
    let mut tx_signer = TxSignerEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        blocklist_checker: Some(()),
        wsts_state_machines: HashMap::new(),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
    };

    // Let's create a proper sign request.
    let request = StacksTransactionSignRequest {
        aggregate_key: setup.aggregated_signer.keypair.public_key().into(),
        contract_call: signer::stacks::contracts::ContractCall::CompleteDepositV1(req),
        // The nonce and tx_fee aren't really validated against anything at
        // the moment.
        nonce: 1,
        tx_fee: 100_000,
        // TODO(412): This can probably be removed, but it's not important
        // to remove now, we should switch to protobuf messages and remove
        // it then.
        digest: [0; 32],
        txid: Faker.fake_with_rng::<StacksTxId, _>(&mut rng).into(),
    };

    // We can sign a transaction generated by a coordinator who is not in
    // the signer set, so the origin doesn't matter much for this function
    // call.
    let origin_public_key: PublicKey = Faker.fake_with_rng(&mut rng);
    // This is all happy path, there shouldn't be any errors here
    tx_signer
        .assert_valid_stacks_tx_sign_request(&request, &chain_tip, &origin_public_key)
        .await
        .unwrap();

    // Now we make sure that the current signer is not in the current
    // signing set.
    tx_signer.signer_private_key = PrivateKey::new(&mut rng);

    // Okay now that we have changed the fact that we are not in the
    // signing set, we should get an error now.
    let validation = tx_signer
        .assert_valid_stacks_tx_sign_request(&request, &chain_tip, &origin_public_key)
        .await
        .unwrap_err();
    assert!(matches!(validation, Error::ValidationSignerSet(_)));

    testing::storage::drop_db(db).await;
}
