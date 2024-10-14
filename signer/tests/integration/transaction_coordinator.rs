use std::sync::atomic::Ordering;
use std::time::Duration;

use bitcoin::consensus::Encodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::Transaction;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use fake::Faker;
use rand::rngs::OsRng;
use rand::SeedableRng;

use sbtc::testing::regtest;
use sha2::Digest;
use signer::context::Context;
use signer::context::SignerEvent;
use signer::context::TxSignerEvent;
use signer::keys;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::network;
use signer::stacks::api::AccountInfo;
use signer::stacks::api::SubmitTxResponse;
use signer::stacks::contracts::AsContractCall;
use signer::stacks::contracts::CompleteDepositV1;
use signer::storage::model;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::testing;
use signer::testing::context::*;

use fake::Fake;
use signer::testing::transaction_signer::TxSignerEventLoopHarness;
use signer::testing::wsts::SignerSet;
use signer::transaction_coordinator;

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
