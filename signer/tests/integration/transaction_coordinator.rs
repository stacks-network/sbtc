use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::consensus::Encodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::Transaction;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use fake::Fake as _;
use fake::Faker;
use futures::StreamExt;
use rand::rngs::OsRng;
use rand::SeedableRng as _;
use sbtc::testing::regtest;
use secp256k1::Keypair;
use sha2::Digest as _;

use signer::context::Context;
use signer::context::SignerEvent;
use signer::context::TxSignerEvent;
use signer::keys;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::network;
use signer::network::in_memory::InMemoryNetwork;
use signer::stacks::api::AccountInfo;
use signer::stacks::api::SubmitTxResponse;
use signer::stacks::contracts::AsContractCall as _;
use signer::stacks::contracts::CompleteDepositV1;
use signer::storage::model;
use signer::storage::model::EncryptedDkgShares;
use signer::storage::model::RotateKeysTransaction;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::testing;
use signer::testing::context::TestContext;
use signer::testing::context::*;
use signer::testing::storage::model::TestData;
use signer::testing::transaction_signer::TxSignerEventLoopHarness;
use signer::testing::wsts::SignerSet;
use signer::transaction_coordinator;
use signer::transaction_coordinator::TxCoordinatorEventLoop;
use signer::transaction_signer::TxSignerEventLoop;

use crate::complete_deposit::make_complete_deposit;
use crate::setup::backfill_bitcoin_blocks;
use crate::setup::TestSweepSetup;
use crate::DATABASE_NUM;

async fn run_dkg<Rng, C>(
    ctx: &C,
    rng: &mut Rng,
    signer_set: &mut SignerSet,
) -> (keys::PublicKey, model::BitcoinBlockRef)
where
    C: Context + Send + Sync,
    Rng: rand::CryptoRng + rand::RngCore,
{
    let storage = ctx.get_storage_mut();

    let bitcoin_chain_tip = storage
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("storage error")
        .expect("no chain tip");

    let bitcoin_chain_tip_ref = storage
        .get_bitcoin_block(&bitcoin_chain_tip)
        .await
        .expect("storage failure")
        .expect("missing block")
        .into();

    let dkg_txid = testing::dummy::txid(&fake::Faker, rng);
    let (aggregate_key, all_dkg_shares) =
        signer_set.run_dkg(bitcoin_chain_tip, dkg_txid, rng).await;

    let encrypted_dkg_shares = all_dkg_shares.first().unwrap();
    signer_set
        .write_as_rotate_keys_tx(&storage, &bitcoin_chain_tip, encrypted_dkg_shares, rng)
        .await;

    let encrypted_dkg_shares = all_dkg_shares.first().unwrap();

    storage
        .write_encrypted_dkg_shares(encrypted_dkg_shares)
        .await
        .expect("failed to write encrypted shares");

    (aggregate_key, bitcoin_chain_tip_ref)
}

fn select_coordinator(
    bitcoin_chain_tip: &model::BitcoinBlockHash,
    signer_info: &[testing::wsts::SignerInfo],
) -> keys::PrivateKey {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bitcoin_chain_tip.into_bytes());
    let digest = hasher.finalize();
    let index = usize::from_be_bytes(*digest.first_chunk().expect("unexpected digest size"));
    signer_info
        .get(index % signer_info.len())
        .expect("missing signer info")
        .signer_private_key
}

async fn push_utxo_donation<C>(ctx: &C, aggregate_key: &PublicKey, block_hash: &bitcoin::BlockHash)
where
    C: Context + Send + Sync,
{
    let tx = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1_337_000_000_000),
            script_pubkey: aggregate_key.signers_script_pubkey(),
        }],
    };

    let mut tx_bytes = Vec::new();
    tx.consensus_encode(&mut tx_bytes).unwrap();

    let tx = model::Transaction {
        txid: tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::Donation,
        block_hash: *block_hash.as_byte_array(),
    };

    let bitcoin_transaction = model::BitcoinTxRef {
        txid: tx.txid.into(),
        block_hash: (*block_hash).into(),
    };

    ctx.get_storage_mut().write_transaction(&tx).await.unwrap();
    ctx.get_storage_mut()
        .write_bitcoin_transaction(&bitcoin_transaction)
        .await
        .unwrap();
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn process_complete_deposit() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    setup.store_deposit_tx(&db).await;
    setup.store_sweep_tx(&db).await;
    setup.store_dkg_shares(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Ensure a stacks tip exists
    let stacks_block = model::StacksBlock {
        block_hash: Faker.fake_with_rng(&mut OsRng),
        block_height: setup.sweep_block_height,
        parent_hash: Faker.fake_with_rng(&mut OsRng),
    };
    db.write_stacks_block(&stacks_block).await.unwrap();

    sqlx::query(
        r#"
        UPDATE sbtc_signer.bitcoin_blocks
        SET confirms = array_append(confirms, $1)
        WHERE block_height = $2;
        "#,
    )
    .bind(&stacks_block.block_hash)
    .bind(setup.sweep_block_height as i64)
    .execute(db.pool())
    .await
    .unwrap();
    //

    let mut context = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let nonce = 12;
    // Mock required stacks client functions
    context
        .with_stacks_client(|client| {
            client.expect_get_account().once().returning(move |_| {
                Box::pin(async move {
                    Ok(AccountInfo {
                        balance: 0,
                        locked: 0,
                        unlock_height: 0,
                        // The nonce is used to create the stacks tx
                        nonce,
                    })
                })
            });

            // Dummy value
            client
                .expect_estimate_fees()
                .once()
                .returning(move |_, _| Box::pin(async move { Ok(25505) }));
        })
        .await;

    let num_signers = 7;
    let signing_threshold = 5;
    let context_window = 10;

    let network = network::in_memory::InMemoryNetwork::new();
    let signer_info = testing::wsts::generate_signer_info(&mut rng, num_signers);

    let mut testing_signer_set =
        testing::wsts::SignerSet::new(&signer_info, signing_threshold, || network.connect());

    let (aggregate_key, bitcoin_chain_tip) =
        run_dkg(&context, &mut rng, &mut testing_signer_set).await;

    // Ensure we have a signers UTXO (as a donation, to not mess with the current
    // temporary `get_swept_deposit_requests` implementation)
    push_utxo_donation(&context, &aggregate_key, &setup.sweep_block_hash).await;

    assert_eq!(
        context
            .get_storage()
            .get_swept_deposit_requests(&bitcoin_chain_tip.block_hash, context_window)
            .await
            .expect("failed to get swept deposits")
            .len(),
        1
    );

    let (broadcasted_transaction_tx, _broadcasted_transaction_rxeiver) =
        tokio::sync::broadcast::channel(1);

    // This task logs all transactions broadcasted by the coordinator.
    let mut wait_for_transaction_rx = broadcasted_transaction_tx.subscribe();
    let wait_for_transaction_task =
        tokio::spawn(async move { wait_for_transaction_rx.recv().await });

    // Setup the stacks client mock to broadcast the transaction to our channel.
    context
        .with_stacks_client(|client| {
            client.expect_submit_tx().once().returning(move |tx| {
                let tx = tx.clone();
                let txid = tx.txid();
                let broadcasted_transaction_tx = broadcasted_transaction_tx.clone();
                Box::pin(async move {
                    broadcasted_transaction_tx
                        .send(tx)
                        .expect("Failed to send result");
                    Ok(SubmitTxResponse::Acceptance(txid))
                })
            });
        })
        .await;

    // Get the private key of the coordinator of the signer set.
    let private_key = select_coordinator(&setup.sweep_block_hash.into(), &signer_info);

    // Bootstrap the tx coordinator event loop
    let tx_coordinator = transaction_coordinator::TxCoordinatorEventLoop {
        context: context.clone(),
        network: network.connect(),
        private_key,
        context_window,
        threshold: signing_threshold as u16,
        signing_round_max_duration: Duration::from_secs(10),
        dkg_max_duration: Duration::from_secs(10),
    };
    let tx_coordinator_handle = tokio::spawn(async move { tx_coordinator.run().await });

    // TODO: here signers use all the same storage, should we use separate ones?
    let event_loop_handles: Vec<_> = signer_info
        .clone()
        .into_iter()
        .map(|signer_info| {
            let event_loop_harness = TxSignerEventLoopHarness::create(
                context.clone(),
                network.connect(),
                context_window,
                signer_info.signer_private_key,
                signing_threshold,
                rng.clone(),
            );

            event_loop_harness.start()
        })
        .collect();

    // Yield to get signers ready
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Wake coordinator up
    context
        .signal(SignerEvent::TxSigner(TxSignerEvent::NewRequestsHandled).into())
        .expect("failed to signal");

    // Await the `wait_for_tx_task` to receive the first transaction broadcasted.
    let broadcasted_tx = tokio::time::timeout(Duration::from_secs(10), wait_for_transaction_task)
        .await
        .unwrap()
        .expect("failed to receive message")
        .expect("no message received");

    // Stop event loops
    tx_coordinator_handle.abort();
    event_loop_handles.iter().for_each(|h| h.abort());

    broadcasted_tx.verify().unwrap();

    assert_eq!(broadcasted_tx.get_origin_nonce(), nonce);

    let (complete_deposit, _) = make_complete_deposit(&setup);
    let TransactionPayload::ContractCall(contract_call) = broadcasted_tx.payload else {
        panic!("unexpected tx payload")
    };
    assert_eq!(
        contract_call.contract_name.to_string(),
        CompleteDepositV1::CONTRACT_NAME
    );
    assert_eq!(
        contract_call.function_name.to_string(),
        CompleteDepositV1::FUNCTION_NAME
    );
    assert_eq!(
        contract_call.function_args,
        complete_deposit.as_contract_args()
    );

    testing::storage::drop_db(db).await;
}

/// The [`TxCoordinatorEventLoop::get_signer_set_and_aggregate_key`]
/// function is supposed to fetch the "current" signing set and the
/// aggregate key to use for bitcoin transactions. It attempts to get the
/// latest rotate-keys contract call transaction confirmed on the canonical
/// Stacks blockchain and falls back to the DKG shares table if no such
/// transaction can be found.
///
/// This tests that we prefer rotate keys transactions if it's available
/// but will use the DKG shares behavior is indeed the case.
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

    let coord = TxCoordinatorEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        private_key: ctx.config().signer.private_key,
        signing_round_max_duration: Duration::from_secs(10),
        threshold: 2,
        dkg_max_duration: Duration::from_secs(10),
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

    // We have no rows in the DKG shares table and no rotate-keys
    // transactions, so there should be no aggregate key, since that only
    // happens after DKG, but we should always know the current signer set.
    let (maybe_aggregate_key, signer_set) = coord
        .get_signer_set_and_aggregate_key(&chain_tip)
        .await
        .unwrap();
    assert!(maybe_aggregate_key.is_none());
    assert!(!signer_set.is_empty());

    // Alright, lets write some DKG shares into the database. When we do
    // that the signer set should be considered whatever the signer set is
    // from our DKG shares.
    let shares: EncryptedDkgShares = Faker.fake_with_rng(&mut rng);
    db.write_encrypted_dkg_shares(&shares).await.unwrap();

    let (aggregate_key, signer_set) = coord
        .get_signer_set_and_aggregate_key(&chain_tip)
        .await
        .unwrap();

    let shares_signer_set: BTreeSet<PublicKey> =
        shares.signer_set_public_keys.iter().copied().collect();

    assert_eq!(shares.aggregate_key, aggregate_key.unwrap());
    assert_eq!(shares_signer_set, signer_set);

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
    // it is preferred over the DKG shares table.
    let (aggregate_key, signer_set) = coord
        .get_signer_set_and_aggregate_key(&chain_tip)
        .await
        .unwrap();

    let rotate_keys_signer_set: BTreeSet<PublicKey> =
        rotate_keys.signer_set.iter().copied().collect();

    assert_eq!(rotate_keys.aggregate_key, aggregate_key.unwrap());
    assert_eq!(rotate_keys_signer_set, signer_set);

    testing::storage::drop_db(db).await;
}

/// Test that we run DKG if the coordinator notices that DKG has not been
/// run yet.
///
/// This test proceeds by doing the following:
/// 1. Create a database, an associated context, and a Keypair for each of
///    the signers in the signing set.
/// 2. Populate each database with the same data, so that they have the
///    same view of the canonical bitcoin blockchain. This ensures that
///    they participate in DKG.
/// 3. Check that there are no DKG shares in the database.
/// 4. Start the [`TxCoordinatorEventLoop`] and [`TxSignerEventLoop`]
///    processes for each signer.
/// 5. Once they are all running, signal that DKG should be run. We signal
///    them all because we do not know which one is the coordinator.
/// 6. Check that we have exactly one row in the `dkg_shares` table.
/// 7. Check that they all have the same aggregate key in the `dkg_shares`
///    table.
///
/// Some of the preconditions for this test to run successfully includes
/// having bootstrap public keys that align with the [`Keypair`] returned
/// from the [`testing::wallet::regtest_bootstrap_wallet`] function.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn run_dkg_from_scratch() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (_, signer_key_pairs): (_, [Keypair; 3]) = testing::wallet::regtest_bootstrap_wallet();

    // We need to populate our databases, so let's generate some data.
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_params);

    let iter: Vec<(Keypair, TestData)> = signer_key_pairs
        .iter()
        .copied()
        .zip(std::iter::repeat_with(|| test_data.clone()))
        .collect();

    // 1. Create a database, an associated context, and a Keypair for each of
    //    the signers in the signing set.
    let signers: Vec<(_, PgStore, Keypair)> = futures::stream::iter(iter)
        .then(|(kp, data)| async move {
            let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
            let db = testing::storage::new_test_database(db_num, true).await;
            let ctx = TestContext::builder()
                .with_storage(db.clone())
                .with_mocked_clients()
                .build();

            // 2. Populate each database with the same data, so that they
            //    have the same view of the canonical bitcoin blockchain.
            //    This ensures that they participate in DKG.
            data.write_to(&db).await;

            (ctx, db, kp)
        })
        .collect::<Vec<_>>()
        .await;

    let network = InMemoryNetwork::new();

    // 3. Check that there are no DKG shares in the database.
    for (_, db, _) in signers.iter() {
        let some_shares = db.get_latest_encrypted_dkg_shares().await.unwrap();
        assert!(some_shares.is_none());
    }

    // 4. Start the [`TxCoordinatorEventLoop`] and [`TxSignerEventLoop`]
    //    processes for each signer.
    let tx_coordinator_processes = signers.iter().map(|(ctx, _, kp)| TxCoordinatorEventLoop {
        network: network.connect(),
        context: ctx.clone(),
        context_window: 10000,
        private_key: kp.secret_key().into(),
        signing_round_max_duration: Duration::from_secs(10),
        threshold: ctx.config().signer.bootstrap_signatures_required,
        dkg_max_duration: Duration::from_secs(10),
    });

    let tx_signer_processes = signers.iter().map(|(context, _, kp)| TxSignerEventLoop {
        network: network.connect(),
        threshold: context.config().signer.bootstrap_signatures_required as u32,
        context: context.clone(),
        context_window: 10000,
        blocklist_checker: Some(()),
        wsts_state_machines: HashMap::new(),
        signer_private_key: kp.secret_key().into(),
        rng: rand::rngs::OsRng,
    });

    // We only proceed with the test after all processes have started, and
    // we use this counter to notify us when that happens.
    let start_count = Arc::new(AtomicU8::new(0));

    tx_coordinator_processes.for_each(|ev| {
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });
    });

    tx_signer_processes.for_each(|ev| {
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });
    });

    while start_count.load(Ordering::SeqCst) < 6 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 5. Once they are all running, signal that DKG should be run. We
    //    signal them all because we do not know which one is the
    //    coordinator.
    signers.iter().for_each(|(ctx, _, _)| {
        ctx.get_signal_sender()
            .send(TxSignerEvent::NewRequestsHandled.into())
            .unwrap();
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut aggregate_keys = BTreeSet::new();

    for (_, db, _) in signers.iter() {
        let mut aggregate_key =
            sqlx::query_as::<_, (PublicKey,)>("SELECT aggregate_key FROM sbtc_signer.dkg_shares")
                .fetch_all(db.pool())
                .await
                .unwrap();

        // 6. Check that we have exactly one row in the `dkg_shares` table.
        assert_eq!(aggregate_key.len(), 1);

        // An additional sanity check that the query in
        // get_last_encrypted_dkg_shares gets the right thing (which is the
        // only thing in this case.)
        let key = aggregate_key.pop().unwrap().0;
        let shares = db.get_latest_encrypted_dkg_shares().await.unwrap().unwrap();
        assert_eq!(shares.aggregate_key, key);
        aggregate_keys.insert(key);
    }

    // 7. Check that they all have the same aggregate key in the
    //    `dkg_shares` table.
    assert_eq!(aggregate_keys.len(), 1);

    for (_, db, _) in signers {
        testing::storage::drop_db(db).await;
    }
}
