use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use fake::Fake as _;
use fake::Faker;
use futures::future::join_all;
use rand::SeedableRng as _;

use secp256k1::Keypair;
use signer::context::Context;
use signer::context::SignerEvent;
use signer::context::SignerSignal;
use signer::context::TxSignerEvent;
use signer::ecdsa::SignEcdsa as _;
use signer::emily_client::MockEmilyInteract;
use signer::error::Error;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::message;
use signer::message::StacksTransactionSignRequest;
use signer::network::in_memory2::WanNetwork;
use signer::network::InMemoryNetwork;
use signer::network::MessageTransfer;
use signer::stacks::api::MockStacksInteract;
use signer::stacks::contracts::ContractCall;
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
use signer::transaction_coordinator;
use signer::transaction_signer::TxSignerEventLoop;
use signer::{bitcoin::MockBitcoinInteract, storage::postgres::PgStore};
use test_log::test;

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

fn sweep_transaction_info<R: rand::RngCore>(
    rng: &mut R,
    created_at_block_hash: bitcoin::BlockHash,
    deposit_requests: &[model::DepositRequest],
    withdrawal_requests: &[model::WithdrawalRequest],
) -> message::SweepTransactionInfo {
    let txid = testing::dummy::txid(&fake::Faker, rng);
    message::SweepTransactionInfo {
        txid,
        created_at_block_hash,
        amount: 100,
        fee: 1,
        vsize: 50,
        market_fee_rate: 1.2,
        signer_prevout_txid: testing::dummy::txid(&fake::Faker, rng),
        signer_prevout_amount: 1,
        signer_prevout_output_index: 0,
        signer_prevout_script_pubkey: bitcoin::ScriptBuf::default(),
        swept_deposits: deposit_requests
            .iter()
            .enumerate()
            .map(|(ix, req)| message::SweptDeposit {
                deposit_request_output_index: req.output_index,
                deposit_request_txid: *req.txid,
                input_index: ix as u32 + 1,
            })
            .collect(),
        swept_withdrawals: withdrawal_requests
            .iter()
            .enumerate()
            .map(|(ix, req)| message::SweptWithdrawal {
                withdrawal_request_id: req.request_id,
                output_index: ix as u32 + 2,
                withdrawal_request_block_hash: *req.block_hash.as_bytes(),
            })
            .collect(),
    }
}

#[ignore = "we have a test for this"]
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

#[ignore = "we have a test for this"]
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

/// Test that transaction signers can receive [`SweepTransactionInfo`] messages
/// from other signers and store the information in their respective databases.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test(tokio::test)]
async fn should_store_sweep_transaction_info_from_other_signers() {
    let (_, signer_key_pairs): (_, [Keypair; 3]) = testing::wallet::regtest_bootstrap_wallet();
    let mut rng = rand::rngs::StdRng::seed_from_u64(46);
    let network = WanNetwork::default();
    let signer_set_pubkeys = signer_key_pairs
        .iter()
        .map(|kp| kp.public_key().into())
        .collect();

    let mut signers = Vec::new();
    let mut contexts = Vec::new();

    // Instantiate a new database for each signer. This must be done sequentially,
    // it fails if done concurrently.
    //
    // Create a new event-loop for each signer, based on the number of signers
    // defined in `self.num_signers`. Note that it is important that each
    // signer has its own context (and thus storage and signalling channel).
    //
    // Each signer also gets its own `MpscBroadcaster` instance, which is
    // backed by the `network` instance, simulating a network connection.
    for key_pair in signer_key_pairs {
        let db = create_signer_database().await;
        let private_key = key_pair.secret_key().into();
        let ctx = TestContext::builder()
            .with_storage(db.clone())
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = private_key;
                settings.signer.bootstrap_signing_set = signer_key_pairs
                    .iter()
                    .map(|kp| kp.public_key().into())
                    .collect();
            })
            .build();

        let net = network.connect(&ctx);

        let ev = TxSignerEventLoop {
            network: net.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            wsts_state_machines: HashMap::new(),
            signer_private_key: private_key,
            threshold: 2,
            rng: rand::rngs::StdRng::seed_from_u64(51),
            dkg_begin_pause: None,
        };

        contexts.push((ctx, db, net));
        signers.push(ev);
    }

    // Generate test data. We'll generate two blocks and include all outstanding
    // deposit and withdraw requests in the sweep transaction info we broadcast.
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 2,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 2,
        num_withdraw_requests_per_block: 2,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_params);

    // Write the same test data to each signer's storage
    for (_, db, _) in contexts.iter() {
        test_data.write_to(db).await;
    }

    // Get the bitcoin chain tip from the first signer's storage
    let bitcoin_chain_tip = contexts
        .first()
        .unwrap()
        .0
        .get_storage()
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("failed to get bitcoin chain tip")
        .expect("no bitcoin chain tip found");

    // Find the coordinator signer
    let coordinator_signer_info = signer_key_pairs
        .iter()
        .find(|kep_pair| {
            let pk = kep_pair.public_key().into();
            transaction_coordinator::given_key_is_coordinator(
                pk,
                &bitcoin_chain_tip,
                &signer_set_pubkeys,
            )
        })
        .expect("could not determine coordinator");

    // Start listening for the signers' `EventLoopStarted` signals with a 1s
    // timeout. We use `join_all` to wait for all signers to signal their start.
    let wait_for_signers = signers
        .iter()
        .map(|signer| {
            let ctx = signer.context.clone();
            tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(1), async {
                    let mut recv = ctx.get_signal_receiver();
                    while let Ok(signal) = recv.recv().await {
                        if let SignerSignal::Event(SignerEvent::TxSigner(
                            TxSignerEvent::EventLoopStarted,
                        )) = signal
                        {
                            break;
                        }
                    }
                })
                .await
                .expect("failed to start event loop");
            })
        })
        .collect::<Vec<_>>();

    // Start the event loops for each signer
    let _ = signers
        .into_iter()
        .map(|signer| tokio::spawn(signer.run()))
        .collect::<Vec<_>>();

    // Wait for all signers to signal that they have started
    join_all(wait_for_signers).await;

    // Create a `SweepTransactionInfo` message and broadcast it to the network
    let sweep_tx_info = sweep_transaction_info(
        &mut rng,
        *bitcoin_chain_tip,
        &test_data.deposit_requests,
        &test_data.withdraw_requests,
    );

    // Convert the `SweepTransactionInfo` into a `Payload` and sign it using
    // the coordinator's keys.
    let payload: message::Payload = sweep_tx_info.clone().into();
    let msg = payload
        .to_message(bitcoin_chain_tip)
        .sign_ecdsa(&coordinator_signer_info.secret_key().into())
        .expect("failed to sign message");

    // Broadcast the message to the network. We create a new instance so
    // that the message gets broadcast to all signers.
    let ctx = TestContext::default_mocked();
    let new_signer = network.connect(&ctx);
    let mut net = new_signer.spawn();
    net.broadcast(msg).await.expect("broadcast failed");

    // Give the event loops some time to process the message
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Ensure that the sweep transaction info has been stored in each signer's
    // database and is the "latest" sweep transaction.
    for (_, db, _) in contexts.iter() {
        let retrieved_tx = db
            .get_latest_sweep_transaction(&bitcoin_chain_tip, 10)
            .await
            .expect("failed to get sweep transaction")
            .expect("no sweep transaction found");

        assert_eq!(retrieved_tx, (&sweep_tx_info).into());
    }

    // Drop the databases
    for (_, db, _) in contexts.into_iter() {
        signer::testing::storage::drop_db(db).await;
    }
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
        wsts_state_machines: HashMap::new(),
        signer_private_key: ctx.config().signer.private_key,
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
        dkg_begin_pause: None,
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
    let mut setup = TestSweepSetup::new_setup(rpc, faucet, 10000, &mut rng);

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
        wsts_state_machines: HashMap::new(),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
        dkg_begin_pause: None,
    };

    // Let's create a proper sign request.
    let request = StacksTransactionSignRequest {
        aggregate_key: setup.aggregated_signer.keypair.public_key().into(),
        contract_tx: ContractCall::CompleteDepositV1(req).into(),
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
