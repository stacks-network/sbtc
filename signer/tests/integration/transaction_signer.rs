use std::num::NonZeroUsize;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoincore_rpc::RpcApi;
use fake::Fake as _;
use fake::Faker;
use lru::LruCache;
use rand::SeedableRng as _;

use signer::bitcoin::utxo::RequestRef;
use signer::bitcoin::utxo::Requests;
use signer::bitcoin::utxo::UnsignedTransaction;
use signer::bitcoin::validation::TxRequestIds;
use signer::context::Context;
use signer::context::SbtcLimits;
use signer::error::Error;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::message::BitcoinPreSignRequest;
use signer::message::StacksTransactionSignRequest;
use signer::message::WstsMessage;
use signer::network::in_memory2::WanNetwork;
use signer::network::InMemoryNetwork;
use signer::network::MessageTransfer;
use signer::stacks::contracts::ContractCall;
use signer::storage::model;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::BitcoinTxId;
use signer::storage::model::BitcoinTxSigHash;
use signer::storage::model::RotateKeysTransaction;
use signer::storage::model::SigHash;
use signer::storage::model::StacksTxId;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::testing;
use signer::testing::context::*;
use signer::testing::storage::model::TestData;
use signer::transaction_signer::ChainTipStatus;
use signer::transaction_signer::MsgChainTipReport;
use signer::transaction_signer::TxSignerEventLoop;
use signer::wsts_state_machine::StateMachineId;
use wsts::net::DkgBegin;
use wsts::net::NonceRequest;

use crate::setup::backfill_bitcoin_blocks;
use crate::setup::fill_signers_utxo;
use crate::setup::TestSignerSet;
use crate::setup::TestSweepSetup;
use crate::setup::TestSweepSetup2;

/// Test that [`TxSignerEventLoop::get_signer_public_keys`] falls back to
/// the bootstrap config if there is no rotate-keys transaction in the
/// database.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_signer_public_keys_and_aggregate_key_falls_back() {
    let db = testing::storage::new_test_database().await;

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
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
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
    let db = testing::storage::new_test_database().await;

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
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
pub async fn assert_should_be_able_to_handle_sbtc_requests() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let fee_rate = 1.3;
    // Build the test context with mocked clients
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_bitcoin_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();
    ctx.state().update_current_limits(SbtcLimits::unlimited());

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    // Create a test setup with a confirmed deposit transaction
    let setup = TestSweepSetup::new_setup(rpc, faucet, 10000, &mut rng);
    // Backfill the blockchain data into the database
    let chain_tip: BitcoinBlockHash = setup.sweep_block_hash.into();
    backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;
    let bitcoin_block = db.get_bitcoin_block(&chain_tip).await.unwrap();

    let public_aggregate_key = setup.aggregated_signer.keypair.public_key().into();

    // // Fill the signer's UTXO in the database
    fill_signers_utxo(&db, bitcoin_block.unwrap(), &public_aggregate_key, &mut rng).await;

    // Store the necessary data for passing validation
    setup.store_deposit_tx(&db).await;
    setup.store_dkg_shares(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Initialize the transaction signer event loop
    let network = WanNetwork::default();

    let net = network.connect(&ctx);
    let mut tx_signer = TxSignerEventLoop {
        network: net.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        signer_private_key: setup.aggregated_signer.keypair.secret_key().into(),
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
        dkg_begin_pause: None,
    };

    let sbtc_requests: TxRequestIds = TxRequestIds {
        deposits: vec![setup.deposit_request.outpoint.into()],
        withdrawals: vec![],
    };

    let sbtc_context = BitcoinPreSignRequest {
        request_package: vec![sbtc_requests],
        fee_rate,
        last_fees: None,
    };

    let sbtc_state = signer::bitcoin::utxo::SignerBtcState {
        utxo: ctx
            .get_storage()
            .get_signer_utxo(&chain_tip)
            .await
            .unwrap()
            .unwrap(),
        fee_rate,
        last_fees: None,
        public_key: setup.aggregated_signer.keypair.public_key().into(),
        magic_bytes: [b'T', b'3'],
    };

    // Create an unsigned transaction with the deposit request
    // to obtain the sighashes and corresponding txid that should
    // be stored in the database
    let unsigned_tx = UnsignedTransaction::new(
        Requests::new(vec![RequestRef::Deposit(&setup.deposit_request)]),
        &sbtc_state,
    )
    .unwrap();

    let digests = unsigned_tx.construct_digests().unwrap();
    let signer_digest = digests.signer_sighash();
    let deposit_digest = digests.deposit_sighashes();
    assert_eq!(deposit_digest.len(), 1);
    let deposit_digest = deposit_digest[0];

    let mut handle = network.connect(&ctx).spawn();

    let result = tx_signer
        .handle_bitcoin_pre_sign_request(&sbtc_context, &chain_tip)
        .await;

    // check if we are receving an Ack from the signer
    tokio::time::timeout(Duration::from_secs(2), async move {
        handle.receive().await.unwrap();
    })
    .await
    .unwrap();

    assert!(result.is_ok());

    // Check that the intentions to sign the requests sighashes
    // are stored in the database
    let (will_sign, _) = db
        .will_sign_bitcoin_tx_sighash(&signer_digest.sighash.into())
        .await
        .expect("query to check if signer sighash is stored failed")
        .expect("signer sighash not stored");

    assert!(will_sign);
    let (will_sign, _) = db
        .will_sign_bitcoin_tx_sighash(&deposit_digest.sighash.into())
        .await
        .expect("query to check if deposit sighash is stored failed")
        .expect("deposit sighash not stored");

    assert!(will_sign);

    testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn new_state_machine_per_valid_sighash() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    // Build the test context with mocked clients
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_bitcoin_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();

    let (_, faucet) = sbtc::testing::regtest::initialize_blockchain();

    let signers = TestSignerSet::new(&mut rng);
    // Create a test setup object so that we can simply create proper DKG
    // shares in the database. Note that calling TestSweepSetup2::new_setup
    // creates two bitcoin block.
    let setup = TestSweepSetup2::new_setup(signers, faucet, &[]);

    // Store the necessary data for passing validation
    setup.store_dkg_shares(&db).await;

    // Initialize the transaction signer event loop
    let network = WanNetwork::default();

    let net = network.connect(&ctx);
    let mut tx_signer = TxSignerEventLoop {
        network: net.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        // We use this private key because it needs to be associated with
        // one of the public keys that we stored in the DKG shares table.
        signer_private_key: setup.signers.signer.keypair.secret_key().into(),
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
        dkg_begin_pause: None,
    };

    // We need to convince the signer event loop that it should accept the
    // message that we are going to send it.
    let report = MsgChainTipReport {
        sender_is_coordinator: true,
        chain_tip_status: ChainTipStatus::Canonical,
        chain_tip: BitcoinBlockHash::from([0; 32]),
    };

    // The message that we will send is for the following sighash. We'll
    // need to make sure that it is in our database first
    let sighash_message = [1; 32];
    let row = BitcoinTxSigHash {
        txid: BitcoinTxId::from([0; 32]),
        chain_tip: BitcoinBlockHash::from([0; 32]),
        prevout_txid: BitcoinTxId::from([0; 32]),
        prevout_output_index: 0,
        sighash: SigHash::from(bitcoin::TapSighash::from_byte_array(sighash_message)),
        prevout_type: model::TxPrevoutType::Deposit,
        validation_result: signer::bitcoin::validation::InputValidationResult::Ok,
        is_valid_tx: true,
        will_sign: true,
        aggregate_key: PublicKey::from_private_key(&tx_signer.signer_private_key).into(),
    };

    db.write_bitcoin_txs_sighashes(&[row]).await.unwrap();

    // Now for the nonce request message
    let mut nonce_request_msg = WstsMessage {
        txid: bitcoin::Txid::all_zeros(),
        inner: wsts::net::Message::NonceRequest(NonceRequest {
            dkg_id: 1,
            sign_id: 1,
            sign_iter_id: 1,
            message: sighash_message.to_vec(),
            signature_type: wsts::net::SignatureType::Schnorr,
        }),
    };
    let msg_public_key = PublicKey::from_private_key(&PrivateKey::new(&mut rng));

    // Sanity check, the state machines cache should be empty.
    assert!(tx_signer.wsts_state_machines.is_empty());

    tx_signer
        .handle_wsts_message(
            &nonce_request_msg,
            &report.chain_tip,
            msg_public_key,
            &report,
        )
        .await
        .unwrap();

    // We should have a state machine associated with the sighash nonce
    // request message that we just received.
    let id1 = StateMachineId::new(sighash_message);
    assert!(tx_signer.wsts_state_machines.contains(&id1));
    assert_eq!(tx_signer.wsts_state_machines.len(), 1);

    // Now let's see what happens when we receive a nonce request message
    // for a sighash that we do not know about. Since the nonce request is
    // not in the database we should return an error, and the state machine
    // should not be in the local cache.
    let random_message: [u8; 32] = Faker.fake_with_rng(&mut rng);
    match &mut nonce_request_msg.inner {
        wsts::net::Message::NonceRequest(NonceRequest { message, .. }) => {
            *message = random_message.to_vec();
        }
        _ => panic!("You forgot to update the variant"),
    };

    let response = tx_signer
        .handle_wsts_message(
            &nonce_request_msg,
            &report.chain_tip,
            msg_public_key,
            &report,
        )
        .await;

    let id2 = StateMachineId::new(random_message);
    assert!(response.is_err());
    assert!(tx_signer.wsts_state_machines.contains(&id1));
    assert!(!tx_signer.wsts_state_machines.contains(&id2));
    assert_eq!(tx_signer.wsts_state_machines.len(), 1);

    testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn max_one_state_machine_per_bitcoin_block_hash_for_dkg() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    // Build the test context with mocked clients
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_bitcoin_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();

    // Let's make sure that the database has the chain tip.
    let (rpc, _) = sbtc::testing::regtest::initialize_blockchain();
    let chain_tip: BitcoinBlockHash = rpc.get_best_block_hash().unwrap().into();
    backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;

    // Initialize the transaction signer event loop
    let network = WanNetwork::default();
    let net = network.connect(&ctx);
    let mut tx_signer = TxSignerEventLoop {
        network: net.spawn(),
        context: ctx.clone(),
        context_window: 10000,
        wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
        signer_private_key: ctx.config().signer.private_key,
        threshold: 2,
        rng: rand::rngs::StdRng::seed_from_u64(51),
        dkg_begin_pause: None,
    };

    // We need to convince the signer event loop that it should accept the
    // message that we are going to send it. DkgBegin messages are only
    // accepted from the coordinator on the canonical chain tip.
    let report = MsgChainTipReport {
        sender_is_coordinator: true,
        chain_tip_status: ChainTipStatus::Canonical,
        chain_tip,
    };

    // Now for the DKG begin message. We pick an arbitrary dkg_id, and an
    // arbitrary transaction ID.
    let dkg_id = 2;
    let dkg_begin_msg = WstsMessage {
        txid: bitcoin::Txid::all_zeros(),
        inner: wsts::net::Message::DkgBegin(DkgBegin { dkg_id }),
    };
    let msg_public_key = PublicKey::from_private_key(&PrivateKey::new(&mut rng));

    // Sanity check, the state machines cache should be empty.
    assert!(tx_signer.wsts_state_machines.is_empty());

    tx_signer
        .handle_wsts_message(&dkg_begin_msg, &chain_tip, msg_public_key, &report)
        .await
        .unwrap();

    // We should have a state machine associated with the current chain tip
    // request message that we just received.
    let id1 = StateMachineId::from(&chain_tip);
    let state_machine = tx_signer.wsts_state_machines.get(&id1).unwrap();
    assert_eq!(state_machine.dkg_id, dkg_id);
    assert_eq!(tx_signer.wsts_state_machines.len(), 1);

    // Now let's see what happens when we receive another dkg message with
    // a different `dkg_id`. The expected behavior is that a new state
    // machine gets created, overwriting any existing one.
    let dkg_id = 1234;
    let dkg_begin_msg = WstsMessage {
        txid: bitcoin::Txid::from_byte_array(Faker.fake_with_rng(&mut rng)),
        inner: wsts::net::Message::DkgBegin(DkgBegin { dkg_id }),
    };

    tx_signer
        .handle_wsts_message(&dkg_begin_msg, &chain_tip, msg_public_key, &report)
        .await
        .unwrap();

    let state_machine = tx_signer.wsts_state_machines.get(&id1).unwrap();
    assert_eq!(state_machine.dkg_id, dkg_id);
    assert_eq!(tx_signer.wsts_state_machines.len(), 1);

    // If we say the current chain tip is something else, a new state
    // machine will be created associated with that chain tip
    let random_block: model::BitcoinBlock = Faker.fake_with_rng(&mut rng);
    let chain_tip = random_block.block_hash;
    db.write_bitcoin_block(&random_block).await.unwrap();

    tx_signer
        .handle_wsts_message(&dkg_begin_msg, &chain_tip, msg_public_key, &report)
        .await
        .unwrap();

    let id2 = StateMachineId::from(&chain_tip);
    let state_machine = tx_signer.wsts_state_machines.get(&id2).unwrap();
    assert_eq!(state_machine.dkg_id, dkg_id);
    assert_eq!(tx_signer.wsts_state_machines.len(), 2);

    testing::storage::drop_db(db).await;
}
