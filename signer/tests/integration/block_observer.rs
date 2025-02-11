use std::collections::BTreeSet;
use std::collections::HashSet;
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoincore_rpc::RpcApi as _;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::getpoxinfo::RPCPoxInfoData;
use emily_client::apis::deposit_api;
use emily_client::apis::testing_api;
use emily_client::models::CreateDepositRequestBody;
use fake::Fake as _;
use fake::Faker;
use rand::SeedableRng as _;
use sbtc::testing::regtest;
use sbtc::testing::regtest::Recipient;
use signer::bitcoin::utxo::SbtcRequests;
use signer::bitcoin::utxo::SignerBtcState;
use signer::block_observer::get_signer_set_and_aggregate_key;
use signer::context::SbtcLimits;
use signer::emily_client::EmilyClient;
use signer::error::Error;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::stacks::api::TenureBlocks;
use signer::storage::model;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::DkgSharesStatus;
use signer::storage::model::EncryptedDkgShares;
use signer::storage::model::RotateKeysTransaction;
use signer::storage::model::StacksBlock;
use signer::storage::model::TxOutput;
use signer::storage::model::TxOutputType;
use signer::storage::model::TxPrevout;
use signer::storage::model::TxPrevoutType;
use signer::storage::postgres::PgStore;
use signer::storage::DbWrite;
use signer::testing::stacks::DUMMY_SORTITION_INFO;
use signer::testing::stacks::DUMMY_TENURE_INFO;

use signer::block_observer::BlockObserver;
use signer::context::Context as _;
use signer::context::SignerEvent;
use signer::context::SignerSignal;
use signer::stacks::api::StacksClient;
use signer::storage::DbRead as _;
use signer::testing;
use signer::testing::context::TestContext;
use signer::testing::context::*;
use signer::testing::storage::model::TestData;
use signer::transaction_coordinator::should_coordinate_dkg;
use signer::transaction_signer::assert_allow_dkg_begin;
use url::Url;

use crate::setup::TestSweepSetup;
use crate::transaction_coordinator::mock_reqwests_status_code_error;
use crate::utxo_construction::make_deposit_request;
use crate::zmq::BITCOIN_CORE_ZMQ_ENDPOINT;

pub const GET_POX_INFO_JSON: &str =
    include_str!("../../tests/fixtures/stacksapi-get-pox-info-test-data.json");

/// The [`BlockObserver::load_latest_deposit_requests`] function is
/// supposed to fetch all deposit requests from Emily and persist the ones
/// that pass validation, regardless of when they were confirmed.
#[test_case::test_case(1; "one block ago")]
#[test_case::test_case(5; "five blocks ago")]
#[test_log::test(tokio::test)]
async fn load_latest_deposit_requests_persists_requests_from_past(blocks_ago: u64) {
    // We start with the typical setup with a fresh database and context
    // with a real bitcoin core client and a real connection to our
    // database.
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let db = testing::storage::new_test_database().await;
    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();
    ctx.state().update_current_limits(SbtcLimits::unlimited());

    // We're going to create two confirmed deposits. This also generates
    // sweep transactions, but this information is not in our database, so
    // it doesn't matter for this test.
    let setup0 = TestSweepSetup::new_setup(rpc, faucet, 100_000, &mut rng);
    let setup1 = TestSweepSetup::new_setup(rpc, faucet, 200_000, &mut rng);

    // Let's prep Emily with information about these deposits.
    ctx.with_emily_client(|client| {
        let emily_client_response = vec![
            setup0.emily_deposit_request(),
            setup1.emily_deposit_request(),
        ];
        client
            .expect_get_deposits()
            .times(1..)
            .returning(move || Box::pin(std::future::ready(Ok(emily_client_response.clone()))));

        client
            .expect_get_limits()
            .times(1..)
            .returning(|| Box::pin(async { Ok(SbtcLimits::unlimited()) }));
    })
    .await;

    // We need to set up the stacks client as well. We use it to fetch
    // information about the Stacks blockchain, so we need to prep it, even
    // though it isn't necessary for our test.
    ctx.with_stacks_client(|client| {
        client
            .expect_get_tenure_info()
            .returning(move || Box::pin(std::future::ready(Ok(DUMMY_TENURE_INFO.clone()))));

        client.expect_get_block().returning(|_| {
            let response = Ok(NakamotoBlock {
                header: NakamotoBlockHeader::empty(),
                txs: Vec::new(),
            });
            Box::pin(std::future::ready(response))
        });

        client
            .expect_get_tenure()
            .returning(|_| Box::pin(std::future::ready(TenureBlocks::nearly_empty())));

        client.expect_get_pox_info().returning(|| {
            let response = serde_json::from_str::<RPCPoxInfoData>(GET_POX_INFO_JSON)
                .map_err(Error::JsonSerialize);
            Box::pin(std::future::ready(response))
        });

        client
            .expect_get_sortition_info()
            .returning(move |_| Box::pin(std::future::ready(Ok(DUMMY_SORTITION_INFO.clone()))));
    })
    .await;

    faucet.generate_blocks(blocks_ago);

    // We only proceed with the test after the BlockObserver "process" has
    // started, and we use this counter to notify us when that happens.
    let start_flag = Arc::new(AtomicBool::new(false));
    let flag = start_flag.clone();

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: testing::btc::new_zmq_block_hash_stream(BITCOIN_CORE_ZMQ_ENDPOINT).await,
    };

    // We need at least one receiver
    let _signal = ctx.get_signal_receiver();

    // Our database shouldn't have any deposit requests. In fact, our
    // database doesn't have any blockchain data at all.
    let db2 = &ctx.storage;
    assert!(db2
        .get_bitcoin_canonical_chain_tip()
        .await
        .unwrap()
        .is_none());

    tokio::spawn(async move {
        flag.store(true, Ordering::Relaxed);
        block_observer.run().await
    });

    // Wait for the task to start.
    while !start_flag.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let chain_tip_info = rpc.get_chain_tips().unwrap().pop().unwrap();
    let deposit_requests = db2
        .get_deposit_requests(&chain_tip_info.hash.into(), 100)
        .await
        .unwrap();

    assert!(deposit_requests.is_empty());

    // Let's generate a new block and wait for our block observer to send a
    // BitcoinBlockObserved signal.
    let chain_tip: BitcoinBlockHash = faucet.generate_blocks(1).pop().unwrap().into();

    // We need to wait for the bitcoin-core to send us all the
    // notifications so that we are up to date with the expected chain tip.
    // For that we just wait until we know that we're up-to-date
    let mut current_chain_tip = db2.get_bitcoin_canonical_chain_tip().await.unwrap();

    let waiting_fut = async {
        let db2 = db2.clone();
        while current_chain_tip != Some(chain_tip) {
            current_chain_tip = db2.get_bitcoin_canonical_chain_tip().await.unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };

    tokio::time::timeout(Duration::from_secs(3), waiting_fut)
        .await
        .unwrap();

    // Okay now lets check if we have these deposit requests in our
    // database. It should also have bitcoin blockchain data

    assert!(db2
        .get_bitcoin_canonical_chain_tip()
        .await
        .unwrap()
        .is_some());
    let deposit_requests = db2.get_deposit_requests(&chain_tip, 100).await.unwrap();

    assert_eq!(deposit_requests.len(), 2);
    let req_outpoints: HashSet<OutPoint> =
        deposit_requests.iter().map(|req| req.outpoint()).collect();

    assert!(req_outpoints.contains(&setup0.deposit_info.outpoint));
    assert!(req_outpoints.contains(&setup1.deposit_info.outpoint));

    testing::storage::drop_db(db).await;
}

/// Integration test for bitcoin and stack blocks link.
///
/// To run this test first run:
///  - docker compose -f docker/docker-compose.yml up
/// and wait for nakamoto to kick in.
#[ignore = "This is an integration test that requires devenv running"]
#[tokio::test]
async fn link_blocks() {
    let db = testing::storage::new_test_database().await;

    let stacks_client = StacksClient::new(Url::parse("http://localhost:20443").unwrap()).unwrap();

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_stacks_client(stacks_client.clone())
        .with_mocked_emily_client()
        .build();

    // No need for deposits here
    ctx.with_emily_client(|client| {
        client
            .expect_get_deposits()
            .returning(move || Box::pin(std::future::ready(Ok(vec![]))));
    })
    .await;

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: testing::btc::new_zmq_block_hash_stream(BITCOIN_CORE_ZMQ_ENDPOINT).await,
    };

    let mut signal_rx = ctx.get_signal_receiver();
    let block_observer_handle = tokio::spawn(async move { block_observer.run().await });

    // Wait for new block; when running in devenv, it should take <30s
    loop {
        let signal = signal_rx.recv().await.expect("failed to get signal");
        if let SignerSignal::Event(SignerEvent::BitcoinBlockObserved) = signal {
            break;
        }
    }
    block_observer_handle.abort();

    // Check blocks are linked
    let bitcoin_tip_hash = ctx
        .get_storage()
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("missing bitcoin tip")
        .expect("missing bitcoin tip");

    let stacks_tip = ctx
        .get_storage()
        .get_stacks_chain_tip(&bitcoin_tip_hash)
        .await
        .expect("error getting stacks tip")
        .expect("missing stacks tip");

    let bitcoin_tip_block = ctx
        .get_storage()
        .get_bitcoin_block(&bitcoin_tip_hash)
        .await
        .expect("missing parent block")
        .expect("missing parent block");

    assert_eq!(stacks_tip.bitcoin_anchor, bitcoin_tip_block.parent_hash);

    testing::storage::drop_db(db).await;
}

async fn fetch_output(db: &PgStore, output_type: TxOutputType) -> Vec<TxOutput> {
    sqlx::query_as::<_, TxOutput>(
        r#"
        SELECT
            txid
          , output_index
          , amount
          , script_pubkey
          , output_type
        FROM sbtc_signer.bitcoin_tx_outputs
        WHERE output_type = $1
        "#,
    )
    .bind(output_type)
    .fetch_all(db.pool())
    .await
    .unwrap()
}

async fn fetch_input(db: &PgStore, output_type: TxPrevoutType) -> Vec<TxPrevout> {
    sqlx::query_as::<_, TxPrevout>(
        r#"
        SELECT
            txid
          , prevout_txid
          , prevout_output_index
          , amount
          , script_pubkey
          , prevout_type
        FROM sbtc_signer.bitcoin_tx_inputs
        WHERE prevout_type = $1
        "#,
    )
    .bind(output_type)
    .fetch_all(db.pool())
    .await
    .unwrap()
}

/// The function tests that the block observer:
/// 1. picks up donations and inserts the expected rows into the
///    `bitcoin_tx_outputs` table,
/// 2. for sbtc transactions it picks out the signers' UTXO, deposits, and
///    sbtc related outputs and puts them in either the
///    `bitcoin_tx_inputs` or `bitcoin_tx_outputs` tables.
///
/// To run the test first do:
/// - make integration-env-up-ci
///
/// Then you should be good to go.
#[tokio::test]
async fn block_observer_stores_donation_and_sbtc_utxos() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    // We need to populate our databases, so let's fetch the data.
    let emily_client = EmilyClient::try_new(
        &Url::parse("http://testApiKey@localhost:3031").unwrap(),
        Duration::from_secs(1),
        None,
    )
    .unwrap();

    testing_api::wipe_databases(emily_client.config())
        .await
        .unwrap();

    let chain_tip_info = rpc.get_chain_tips().unwrap().pop().unwrap();

    // 1. Create a database, an associated context for the block observer.

    let db = testing::storage::new_test_database().await;
    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_emily_client(emily_client.clone())
        .with_mocked_stacks_client()
        .build();

    let mut signal_receiver = ctx.get_signal_receiver();

    // The block observer reaches out to the stacks node to get the most
    // up-to-date information. We don't have stacks-core running so we mock
    // these calls.
    ctx.with_stacks_client(|client| {
        client
            .expect_get_tenure_info()
            .returning(move || Box::pin(std::future::ready(Ok(DUMMY_TENURE_INFO.clone()))));

        let chain_tip = BitcoinBlockHash::from(chain_tip_info.hash);
        client.expect_get_tenure().returning(move |_| {
            let mut tenure = TenureBlocks::nearly_empty().unwrap();
            tenure.anchor_block_hash = chain_tip;
            Box::pin(std::future::ready(Ok(tenure)))
        });

        client.expect_get_pox_info().returning(|| {
            let response = serde_json::from_str::<RPCPoxInfoData>(GET_POX_INFO_JSON)
                .map_err(Error::JsonSerialize);
            Box::pin(std::future::ready(response))
        });
    })
    .await;

    // ** Step 2 **
    //
    // Start the BlockObserver
    //
    // We only proceed with the test after the process has started, and
    // we use this counter to notify us when that happens.
    let start_flag = Arc::new(AtomicBool::new(false));
    let flag = start_flag.clone();

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: testing::btc::new_zmq_block_hash_stream(BITCOIN_CORE_ZMQ_ENDPOINT).await,
    };

    tokio::spawn(async move {
        flag.store(true, Ordering::Relaxed);
        block_observer.run().await
    });

    while !start_flag.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Let's do a sanity check that we do not have any rows in our output
    // tables.
    assert!(fetch_output(&db, TxOutputType::Donation).await.is_empty());
    assert!(fetch_output(&db, TxOutputType::SignersOpReturn)
        .await
        .is_empty());
    assert!(fetch_output(&db, TxOutputType::SignersOutput)
        .await
        .is_empty());
    assert!(fetch_input(&db, TxPrevoutType::Deposit).await.is_empty());
    assert!(fetch_input(&db, TxPrevoutType::SignersInput)
        .await
        .is_empty());

    // ** Step 3 **
    //
    // Make a donation to the address controlled by signers. In this case
    // there is only one signer in the signer set.
    let signer = Recipient::new(AddressType::P2tr);

    // We need to have run DKG in order for the block observer to know
    // which addresses to filter on.
    let mut shares: EncryptedDkgShares = Faker.fake_with_rng(&mut rng);
    shares.aggregate_key = signer.keypair.public_key().into();
    shares.script_pubkey = shares.aggregate_key.signers_script_pubkey().into();
    shares.dkg_shares_status = model::DkgSharesStatus::Verified;
    db.write_encrypted_dkg_shares(&shares).await.unwrap();

    // Okay, now to make the actual donation. We send some funds to their
    // address.
    let script_pub_key = shares.script_pubkey.deref();
    let network = bitcoin::Network::Regtest;
    let address = Address::from_script(script_pub_key, network).unwrap();

    let donation_amount = 100_000;
    let donation_outpoint = faucet.send_to(donation_amount, &address);

    faucet.generate_blocks(1);

    // Let's wait for the block observer to signal that it has finished
    // processing everything.
    let signal = signal_receiver.recv();
    let Ok(SignerSignal::Event(SignerEvent::BitcoinBlockObserved)) = signal.await else {
        panic!("Not the right signal")
    };

    // Okay now we check whether the we have a donation. The details should
    // match what we expect. All other input and output types should not be
    // in the database.
    assert!(fetch_output(&db, TxOutputType::SignersOpReturn)
        .await
        .is_empty());
    assert!(fetch_output(&db, TxOutputType::SignersOutput)
        .await
        .is_empty());
    assert!(fetch_input(&db, TxPrevoutType::Deposit).await.is_empty());
    assert!(fetch_input(&db, TxPrevoutType::SignersInput)
        .await
        .is_empty());

    let TxOutput { txid, output_index, amount, .. } =
        fetch_output(&db, TxOutputType::Donation).await[0];

    assert_eq!(amount, donation_amount);
    assert_eq!(output_index, donation_outpoint.vout);
    assert_eq!(txid.deref(), &donation_outpoint.txid);

    // ** Step 4 **
    //
    // Setup an actual deposit.
    //
    // For a real deposit we need to create a depositor and have them make
    // an actual deposit. For this step we create the sweep transaction
    // "manually".
    let depositor = Recipient::new(AddressType::P2tr);

    // Start off with some initial UTXOs to work with.
    faucet.send_to(50_000_000, &depositor.address);

    let chain_tip = faucet.generate_blocks(1).pop().unwrap().into();

    let signal = signal_receiver.recv();
    let Ok(SignerSignal::Event(SignerEvent::BitcoinBlockObserved)) = signal.await else {
        panic!("Not the right signal")
    };

    // Now lets make a deposit transaction and submit it. First we get some
    // sats.
    let depositor_utxo = depositor.get_utxos(rpc, None).pop().unwrap();

    let deposit_amount = 2_500_000;
    let max_fee = deposit_amount / 2;
    let signers_public_key = shares.aggregate_key.into();
    let (deposit_tx, deposit_request, _) = make_deposit_request(
        &depositor,
        deposit_amount,
        depositor_utxo,
        max_fee,
        signers_public_key,
    );
    rpc.send_raw_transaction(&deposit_tx).unwrap();

    // Now build the struct with the outstanding peg-in and peg-out requests.
    let requests = SbtcRequests {
        deposits: vec![deposit_request.clone()],
        withdrawals: Vec::new(),
        signer_state: SignerBtcState {
            utxo: db.get_signer_utxo(&chain_tip).await.unwrap().unwrap(),
            fee_rate: 10.0,
            public_key: signers_public_key,
            last_fees: None,
            magic_bytes: [b'T', b'3'],
        },
        accept_threshold: 4,
        num_signers: 7,
        sbtc_limits: SbtcLimits::unlimited(),
        max_deposits_per_bitcoin_tx: ctx.config().signer.max_deposits_per_bitcoin_tx.get(),
    };

    let mut transactions = requests.construct_transactions().unwrap();
    assert_eq!(transactions.len(), 1);
    let mut unsigned = transactions.pop().unwrap();

    // Add the signature and/or other required information to the witness data.
    signer::testing::set_witness_data(&mut unsigned, signer.keypair);

    // Does the network accept the transaction? It had better.
    rpc.send_raw_transaction(&unsigned.tx).unwrap();

    // ** Step 5 **
    //
    // Inform emily about the deposit
    let body = CreateDepositRequestBody {
        bitcoin_tx_output_index: deposit_request.outpoint.vout,
        bitcoin_txid: deposit_request.outpoint.txid.to_string(),
        deposit_script: deposit_request.deposit_script.to_hex_string(),
        reclaim_script: deposit_request.reclaim_script.to_hex_string(),
        transaction_hex: serialize_hex(&deposit_tx),
    };
    deposit_api::create_deposit(emily_client.config(), body)
        .await
        .unwrap();

    // ** Step 6 **
    //
    // Check that the block observer populates the tables correctly
    faucet.generate_blocks(1);

    // Okay now there is a deposit, and it has been confirmed. We should
    // pick it up automatically.
    let signal = signal_receiver.recv();
    let Ok(SignerSignal::Event(SignerEvent::BitcoinBlockObserved)) = signal.await else {
        panic!("Not the right signal")
    };

    // Okay now we should see the signers output with the expected values.
    let TxOutput { txid, output_index, amount, .. } =
        fetch_output(&db, TxOutputType::SignersOutput).await[0];

    assert_eq!(amount, unsigned.tx.output[0].value.to_sat());
    assert_eq!(output_index, 0);
    assert_eq!(txid.deref(), &unsigned.tx.compute_txid());

    // We should also pick up the OP_RETURN output.
    let TxOutput { txid, output_index, amount, .. } =
        fetch_output(&db, TxOutputType::SignersOpReturn).await[0];

    assert_eq!(amount, unsigned.tx.output[1].value.to_sat());
    assert_eq!(amount, 0);
    assert_eq!(output_index, 1);
    assert_eq!(txid.deref(), &unsigned.tx.compute_txid());

    // We should also have a row in the inputs table.
    let TxPrevout {
        txid,
        prevout_txid,
        prevout_output_index,
        amount,
        ..
    } = fetch_input(&db, TxPrevoutType::SignersInput).await[0];

    assert_eq!(amount, donation_amount);
    assert_eq!(prevout_txid.deref(), &donation_outpoint.txid);
    assert_eq!(prevout_output_index, donation_outpoint.vout);
    assert_eq!(txid.deref(), &unsigned.tx.compute_txid());

    let TxPrevout { txid, prevout_txid, amount, .. } =
        fetch_input(&db, TxPrevoutType::Deposit).await[0];

    assert_eq!(amount, deposit_amount);
    assert_eq!(prevout_txid.deref(), &deposit_tx.compute_txid());
    assert_eq!(txid.deref(), &unsigned.tx.compute_txid());

    testing::storage::drop_db(db).await;
}

#[test_case::test_case(false, SbtcLimits::unlimited(); "no contracts, default limits")]
#[test_case::test_case(false, SbtcLimits::new(Some(bitcoin::Amount::from_sat(1_000)), None, None, None, None); "no contracts, total cap limit")]
#[test_case::test_case(true, SbtcLimits::unlimited(); "deployed contracts, default limits")]
#[test_case::test_case(true, SbtcLimits::new(Some(bitcoin::Amount::from_sat(1_000)), None, None, None, None); "deployed contracts, total cap limit")]
#[tokio::test]
async fn block_observer_handles_update_limits(deployed: bool, sbtc_limits: SbtcLimits) {
    // We start with the typical setup with a fresh database and context
    // with a real bitcoin core client and a real connection to our
    // database.
    let (_, faucet) = regtest::initialize_blockchain();
    let db = testing::storage::new_test_database().await;
    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();

    // We need to set up the stacks client as well. We use it to fetch
    // information about the Stacks blockchain, so we need to prep it, even
    // though it isn't necessary for our test.
    ctx.with_stacks_client(|client| {
        client
            .expect_get_tenure_info()
            .returning(move || Box::pin(std::future::ready(Ok(DUMMY_TENURE_INFO.clone()))));
        client.expect_get_block().returning(|_| {
            let response = Ok(NakamotoBlock {
                header: NakamotoBlockHeader::empty(),
                txs: Vec::new(),
            });
            Box::pin(std::future::ready(response))
        });
        client
            .expect_get_tenure()
            .returning(|_| Box::pin(std::future::ready(TenureBlocks::nearly_empty())));
        client.expect_get_pox_info().returning(|| {
            let response = serde_json::from_str::<RPCPoxInfoData>(GET_POX_INFO_JSON)
                .map_err(Error::JsonSerialize);
            Box::pin(std::future::ready(response))
        });
        client
            .expect_get_sortition_info()
            .returning(move |_| Box::pin(std::future::ready(Ok(DUMMY_SORTITION_INFO.clone()))));
    })
    .await;

    ctx.with_emily_client(|client| {
        client
            .expect_get_deposits()
            .returning(move || Box::pin(std::future::ready(Ok(vec![]))));
    })
    .await;

    // Now we do the actual test case setup.

    ctx.with_emily_client(|client| {
        client
            .expect_get_limits()
            .once()
            .returning(move || Box::pin(std::future::ready(Ok(sbtc_limits.clone()))));
    })
    .await;

    if deployed {
        ctx.with_stacks_client(move |client| {
            client
                .expect_get_sbtc_total_supply()
                .returning(|_| Box::pin(std::future::ready(Ok(Amount::from_sat(1)))));
        })
        .await;
        ctx.state().set_sbtc_contracts_deployed();
    } else {
        ctx.with_stacks_client(|client| {
            client.expect_get_sbtc_total_supply().returning(|_| {
                // The real error is `UnexpectedStacksResponse`: error decoding
                // response body: missing field `result` at line 1 column 108
                Box::pin(std::future::ready(Err(Error::InvalidStacksResponse(""))))
            });
            client.expect_get_contract_source().returning(|_, _| {
                Box::pin(async {
                    Err(Error::StacksNodeResponse(
                        mock_reqwests_status_code_error(404).await,
                    ))
                })
            });
        })
        .await;
    }

    // We only proceed with the test after the BlockObserver "process" has
    // started, and we use this counter to notify us when that happens.
    let start_flag = Arc::new(AtomicBool::new(false));
    let flag = start_flag.clone();

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: testing::btc::new_zmq_block_hash_stream(BITCOIN_CORE_ZMQ_ENDPOINT).await,
    };

    let mut signal_receiver = ctx.get_signal_receiver();

    tokio::spawn(async move {
        flag.store(true, Ordering::Relaxed);
        block_observer.run().await
    });

    // Wait for the task to start.
    while !start_flag.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Let's generate a new block and wait for our block observer to send a
    // BitcoinBlockObserved signal.
    let expected_tip = faucet.generate_blocks(1).pop().unwrap();

    let waiting_fut = async {
        let signal = signal_receiver.recv();
        let Ok(SignerSignal::Event(SignerEvent::BitcoinBlockObserved)) = signal.await else {
            panic!("Not the right signal")
        };
    };

    tokio::time::timeout(Duration::from_secs(3), waiting_fut)
        .await
        .unwrap();

    // If we pass the above without panicking it should be fine, this is just a
    // sanity check.
    let db_chain_tip = db
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("cannot get chain tip");
    assert_eq!(db_chain_tip, Some(expected_tip.into()));

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn next_headers_to_process_gets_all_headers() {
    // We start with the typical setup with a fresh database and context
    // with a real bitcoin core client and a real connection to our
    // database.
    const START_HEIGHT: u64 = 103;

    let (_, faucet) = regtest::initialize_blockchain();
    let db = testing::storage::new_test_database().await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .modify_settings(|settings| settings.signer.sbtc_bitcoin_start_height = Some(START_HEIGHT))
        .with_first_bitcoin_core_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();

    // We set the start height to 103 above but only starts with 101
    // blocks, so we need to create two more blocks.
    let chain_tip = faucet.generate_blocks(2)[1];

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: (),
    };

    let headers = block_observer
        .next_headers_to_process(chain_tip)
        .await
        .unwrap();
    assert!(!headers.is_empty());

    // The headers should be sorted by block height ascending, let's
    // check.
    let mut sorted_headers = headers.clone();
    sorted_headers.sort_by_key(|header| header.height);
    assert_eq!(headers, sorted_headers);

    let start_height = ctx.state().get_sbtc_bitcoin_start_height();
    assert_eq!(start_height, START_HEIGHT);
    assert_eq!(START_HEIGHT, headers[0].height);
    assert_eq!(headers.last().map(|header| header.hash), Some(chain_tip));

    // Let's make sure that if we generate a new block, that we
    // `next_headers_to_process` picks up the new block headers all the way
    // back to the start height.
    let chain_tip = faucet.generate_blocks(1)[0];

    let headers2 = block_observer
        .next_headers_to_process(chain_tip)
        .await
        .unwrap();
    assert_eq!(START_HEIGHT, headers[0].height);
    assert_eq!(headers2.len(), headers.len() + 1);
    assert_eq!(headers2.last().map(|header| header.hash), Some(chain_tip));

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn next_headers_to_process_ignores_known_headers() {
    // We start with the typical setup with a fresh database and context
    // with a real bitcoin core client and a real connection to our
    // database.
    let (rpc, _) = regtest::initialize_blockchain();
    let db = testing::storage::new_test_database().await;
    let context = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();

    let block_observer = BlockObserver { context, bitcoin_blocks: () };

    let chain_tip_block_hash = rpc.get_best_block_hash().unwrap();
    let headers = block_observer
        .next_headers_to_process(chain_tip_block_hash)
        .await
        .unwrap();
    let last_header = headers.last().map(|header| header.hash);

    assert_eq!(last_header, Some(chain_tip_block_hash));

    // Okay let's make sure that we don't get blocks that are already
    // known.
    let chain_tip_header = headers.last().cloned().unwrap();
    let block = model::BitcoinBlock::from(chain_tip_header);
    db.write_bitcoin_block(&block).await.unwrap();

    // We know about the chain tip now, so we should return an empty vector
    // of next headers to processes.
    let headers = block_observer
        .next_headers_to_process(chain_tip_block_hash)
        .await
        .unwrap();
    assert!(headers.is_empty());

    testing::storage::drop_db(db).await;
}

/// The [`get_signer_set_and_aggregate_key`] function is supposed to fetch
/// the "current" signing set and the aggregate key to use for bitcoin
/// transactions. It attempts to get the latest rotate-keys contract call
/// transaction confirmed on the canonical Stacks blockchain and falls back
/// to the DKG shares table if no such transaction can be found.
///
/// This tests that we prefer rotate keys transactions if it's available
/// but will use the DKG shares behavior is indeed the case.
#[tokio::test]
async fn get_signer_public_keys_and_aggregate_key_falls_back() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    // We need stacks blocks for the rotate-keys transactions.
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_params);
    test_data.write_to(&db).await;

    // We always need the chain tip.
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();

    // We have no rows in the DKG shares table and no rotate-keys
    // transactions, so there should be no aggregate key, since that only
    // happens after DKG, but we should always know the current signer set.
    let (maybe_aggregate_key, signer_set) = get_signer_set_and_aggregate_key(&ctx, chain_tip)
        .await
        .unwrap();
    assert!(maybe_aggregate_key.is_none());
    assert!(!signer_set.is_empty());

    // Alright, lets write some DKG shares into the database. When we do
    // that the signer set should be considered whatever the signer set is
    // from our DKG shares.
    let mut shares: EncryptedDkgShares = Faker.fake_with_rng(&mut rng);
    shares.dkg_shares_status = model::DkgSharesStatus::Verified;
    db.write_encrypted_dkg_shares(&shares).await.unwrap();

    let (aggregate_key, signer_set) = get_signer_set_and_aggregate_key(&ctx, chain_tip)
        .await
        .unwrap();

    let shares_signer_set: BTreeSet<PublicKey> =
        shares.signer_set_public_keys.iter().copied().collect();

    assert_eq!(shares.aggregate_key, aggregate_key.unwrap());
    assert_eq!(shares_signer_set, signer_set);

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
    // it is preferred over the DKG shares table.
    let (aggregate_key, signer_set) = get_signer_set_and_aggregate_key(&ctx, chain_tip)
        .await
        .unwrap();

    let rotate_keys_signer_set: BTreeSet<PublicKey> =
        rotate_keys.signer_set.iter().copied().collect();

    assert_eq!(rotate_keys.aggregate_key, aggregate_key.unwrap());
    assert_eq!(rotate_keys_signer_set, signer_set);

    testing::storage::drop_db(db).await;
}

/// This test checks that the signer state is updated with the latest the
/// sbtc limits, current signer set, and current aggregate key after the
/// block observer processes a bitcoin block.
#[tokio::test]
async fn block_observer_updates_state_after_observing_bitcoin_block() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(512);
    // We start with the typical setup with a fresh database and context
    // with a real bitcoin core client and a real connection to our
    // database.
    let (_, faucet) = regtest::initialize_blockchain();
    let db = testing::storage::new_test_database().await;
    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();

    // We need to set up the stacks client as well. We use it to fetch
    // information about the Stacks blockchain, so we need to prep it, even
    // though it isn't necessary for our test.
    ctx.with_stacks_client(|client| {
        client
            .expect_get_tenure_info()
            .returning(|| Box::pin(std::future::ready(Ok(DUMMY_TENURE_INFO.clone()))));
        client.expect_get_block().returning(|_| {
            let response = Ok(NakamotoBlock {
                header: NakamotoBlockHeader::empty(),
                txs: Vec::new(),
            });
            Box::pin(std::future::ready(response))
        });
        client
            .expect_get_tenure()
            .returning(|_| Box::pin(std::future::ready(TenureBlocks::nearly_empty())));
        client.expect_get_pox_info().returning(|| {
            let response = serde_json::from_str::<RPCPoxInfoData>(GET_POX_INFO_JSON)
                .map_err(Error::JsonSerialize);
            Box::pin(std::future::ready(response))
        });
        client
            .expect_get_sortition_info()
            .returning(|_| Box::pin(std::future::ready(Ok(DUMMY_SORTITION_INFO.clone()))));
    })
    .await;

    ctx.with_emily_client(|client| {
        client
            .expect_get_deposits()
            .returning(|| Box::pin(std::future::ready(Ok(vec![]))));

        client
            .expect_get_limits()
            .returning(|| Box::pin(std::future::ready(Ok(SbtcLimits::unlimited()))));
    })
    .await;

    // We only proceed with the test after the BlockObserver "process" has
    // started, and we use this counter to notify us when that happens.
    let start_flag = Arc::new(AtomicBool::new(false));
    let flag = start_flag.clone();

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: testing::btc::new_zmq_block_hash_stream(BITCOIN_CORE_ZMQ_ENDPOINT).await,
    };

    // In this test the signer set public keys start empty. When running
    // the signer binary the signer starts as the bootstrap signing set.
    // Also, the sbtc limits start off as "zero" and then get updated by
    // the block observer.
    let state = ctx.state();
    assert_eq!(state.get_current_limits(), SbtcLimits::zero());
    assert!(state.current_signer_public_keys().is_empty());
    assert!(state.current_aggregate_key().is_none());

    tokio::spawn(async move {
        flag.store(true, Ordering::Relaxed);
        block_observer.run().await
    });

    // Wait for the task to start.
    while !start_flag.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Let's generate a new block and wait for our block observer to send a
    // BitcoinBlockObserved signal.
    let chain_tip = faucet.generate_blocks(1).pop().unwrap().into();

    ctx.wait_for_signal(Duration::from_secs(3), |signal| {
        matches!(
            signal,
            SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
        )
    })
    .await
    .unwrap();

    // If we pass the above without panicking it should be fine, this is just a
    // sanity check.
    let db_chain_tip = db
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("cannot get chain tip");
    assert_eq!(db_chain_tip, Some(chain_tip));

    // There is no aggregate key since there aren't any key rotation
    // contract calls and no DKG shares. But the current signer set should
    // be the bootstrap signing set now.
    let bootstrap_signing_set = ctx.config().signer.bootstrap_signing_set();
    assert_eq!(state.get_current_limits(), SbtcLimits::unlimited());
    assert!(state.current_aggregate_key().is_none());
    assert_eq!(state.current_signer_public_keys(), bootstrap_signing_set);

    // Okay now let's add in some DKG shares into the database. This should
    // take precedence over what is configured as the bootstrap signing
    // set.
    let mut dkg_shares: EncryptedDkgShares = Faker.fake_with_rng(&mut rng);
    let mut public_keys: Vec<PublicKey> = std::iter::repeat_with(|| Faker.fake_with_rng(&mut rng))
        .take(12)
        .collect();
    public_keys.sort();
    dkg_shares.signer_set_public_keys = public_keys;
    dkg_shares.dkg_shares_status = model::DkgSharesStatus::Verified;
    db.write_encrypted_dkg_shares(&dkg_shares).await.unwrap();

    // Sanity check that the signing set in the DKG shares are different
    // from the bootstrap signing set.
    let dkg_public_keys = dkg_shares.signer_set_public_keys.iter().copied().collect();
    assert_ne!(dkg_public_keys, bootstrap_signing_set);

    // Let's generate a new block and wait for our block observer to send a
    // BitcoinBlockObserved signal. Then after we received the signal that
    // a bitcoin block has been observed we check the signer state.
    let chain_tip = faucet.generate_blocks(1).pop().unwrap().into();

    ctx.wait_for_signal(Duration::from_secs(3), |signal| {
        matches!(
            signal,
            SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
        )
    })
    .await
    .unwrap();

    // Check that the chain tip has been updated.
    let db_chain_tip = db
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("cannot get chain tip");
    assert_eq!(db_chain_tip, Some(chain_tip));

    let dkg_aggregate_key = Some(dkg_shares.aggregate_key);
    assert_eq!(state.get_current_limits(), SbtcLimits::unlimited());
    assert_eq!(state.current_aggregate_key(), dkg_aggregate_key);
    assert_eq!(state.current_signer_public_keys(), dkg_public_keys);

    // Okay now we're going to show what happens if we have received a key
    // rotation event. Such events take priority over DKG shares, even if
    // the DKG shares are newer. So let's add such an event to the
    // database. First we need a stacks block for the join.
    let stacks_block = StacksBlock {
        bitcoin_anchor: chain_tip,
        ..Faker.fake_with_rng(&mut rng)
    };

    db.write_stacks_block(&stacks_block).await.unwrap();

    let rotate_keys: RotateKeysTransaction = Faker.fake_with_rng(&mut rng);
    let transaction = model::Transaction {
        txid: rotate_keys.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::RotateKeys,
        block_hash: stacks_block.block_hash.into_bytes(),
    };
    let tx = model::StacksTransaction {
        txid: rotate_keys.txid,
        block_hash: stacks_block.block_hash,
    };

    db.write_transaction(&transaction).await.unwrap();
    db.write_stacks_transaction(&tx).await.unwrap();
    db.write_rotate_keys_transaction(&rotate_keys)
        .await
        .unwrap();

    // Let's add some DKG shares after the insertion of the rotate keys
    // transaction.
    let mut dkg_shares: EncryptedDkgShares = Faker.fake_with_rng(&mut rng);
    dkg_shares.dkg_shares_status = model::DkgSharesStatus::Verified;
    db.write_encrypted_dkg_shares(&dkg_shares).await.unwrap();

    // Let's generate a new block and wait for our block observer to send a
    // BitcoinBlockObserved signal.
    let chain_tip = faucet.generate_blocks(1).pop().unwrap().into();

    ctx.wait_for_signal(Duration::from_secs(3), |signal| {
        matches!(
            signal,
            SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
        )
    })
    .await
    .unwrap();

    let db_chain_tip = db
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("cannot get chain tip");
    assert_eq!(db_chain_tip, Some(chain_tip));

    // We expect the signer state to be the same as what is in the rotate
    // keys event in the database.
    let rotate_keys_aggregate_key = Some(rotate_keys.aggregate_key);
    let rotate_keys_public_keys = rotate_keys.signer_set.iter().copied().collect();

    assert_eq!(state.current_aggregate_key(), rotate_keys_aggregate_key);
    assert_eq!(state.current_signer_public_keys(), rotate_keys_public_keys);
    assert_ne!(rotate_keys_public_keys, dkg_public_keys);
    assert_ne!(rotate_keys_aggregate_key, dkg_aggregate_key);

    testing::storage::drop_db(db).await;
}

/// This test checks that the block observer correctly update the state of
/// pending DKG shares once they exit the verification window
#[tokio::test]
async fn block_observer_updates_dkg_shares_after_observing_bitcoin_block() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(512);
    // We start with the typical setup with a fresh database and context
    // with a real bitcoin core client and a real connection to our
    // database.
    let (_, faucet) = regtest::initialize_blockchain();
    let db = testing::storage::new_test_database().await;
    let verification_window = 5;
    let mut ctx = TestContext::builder()
        .modify_settings(|config| config.signer.dkg_verification_window = verification_window)
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();

    // We need to set up the stacks client as well. We use it to fetch
    // information about the Stacks blockchain, so we need to prep it, even
    // though it isn't necessary for our test.
    ctx.with_stacks_client(|client| {
        client
            .expect_get_tenure_info()
            .returning(|| Box::pin(std::future::ready(Ok(DUMMY_TENURE_INFO.clone()))));
        client.expect_get_block().returning(|_| {
            let response = Ok(NakamotoBlock {
                header: NakamotoBlockHeader::empty(),
                txs: Vec::new(),
            });
            Box::pin(std::future::ready(response))
        });
        client
            .expect_get_tenure()
            .returning(|_| Box::pin(std::future::ready(TenureBlocks::nearly_empty())));
        client.expect_get_pox_info().returning(|| {
            let response = serde_json::from_str::<RPCPoxInfoData>(GET_POX_INFO_JSON)
                .map_err(Error::JsonSerialize);
            Box::pin(std::future::ready(response))
        });
        client
            .expect_get_sortition_info()
            .returning(|_| Box::pin(std::future::ready(Ok(DUMMY_SORTITION_INFO.clone()))));
    })
    .await;

    ctx.with_emily_client(|client| {
        client
            .expect_get_deposits()
            .returning(|| Box::pin(std::future::ready(Ok(vec![]))));

        client
            .expect_get_limits()
            .returning(|| Box::pin(std::future::ready(Ok(SbtcLimits::unlimited()))));
    })
    .await;

    // We only proceed with the test after the BlockObserver "process" has
    // started, and we use this counter to notify us when that happens.
    let start_flag = Arc::new(AtomicBool::new(false));
    let flag = start_flag.clone();

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: testing::btc::new_zmq_block_hash_stream(BITCOIN_CORE_ZMQ_ENDPOINT).await,
    };

    // In this test the signer set public keys start empty. When running
    // the signer binary the signer starts as the bootstrap signing set.
    // Also, the sbtc limits start off as "zero" and then get updated by
    // the block observer.
    let state = ctx.state();
    assert_eq!(state.get_current_limits(), SbtcLimits::zero());
    assert!(state.current_signer_public_keys().is_empty());
    assert!(state.current_aggregate_key().is_none());

    let storage = ctx.get_storage();
    // Initially, we have no dkg shares
    assert!(storage
        .get_latest_encrypted_dkg_shares()
        .await
        .unwrap()
        .is_none());

    tokio::spawn(async move {
        flag.store(true, Ordering::Relaxed);
        block_observer.run().await
    });

    // Wait for the task to start.
    while !start_flag.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Let's generate a new block and wait for our block observer to send a
    // BitcoinBlockObserved signal.
    let chain_tip = faucet.generate_blocks(1).pop().unwrap().into();

    ctx.wait_for_signal(Duration::from_secs(3), |signal| {
        matches!(
            signal,
            SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
        )
    })
    .await
    .unwrap();

    // If we pass the above without panicking it should be fine, this is just a
    // sanity check.
    let db_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .expect("cannot get chain tip")
        .expect("missing chain tip");
    assert_eq!(db_chain_tip.block_hash, chain_tip);

    // Still no dkg shares
    assert!(storage
        .get_latest_encrypted_dkg_shares()
        .await
        .unwrap()
        .is_none());
    assert_eq!(storage.get_encrypted_dkg_shares_count().await.unwrap(), 0);

    // Signers and coordinator should allow DKG
    assert!(should_coordinate_dkg(&ctx, &db_chain_tip.block_hash)
        .await
        .unwrap());
    assert!(assert_allow_dkg_begin(&ctx, &db_chain_tip).await.is_ok());

    // Okay now let's add in some DKG shares into the database.
    let mut dkg_shares: EncryptedDkgShares = Faker.fake_with_rng(&mut rng);
    dkg_shares.started_at_bitcoin_block_height = db_chain_tip.block_height;
    dkg_shares.dkg_shares_status = DkgSharesStatus::Unverified;

    db.write_encrypted_dkg_shares(&dkg_shares).await.unwrap();

    // Now we have a DKG shares entry
    assert_eq!(storage.get_encrypted_dkg_shares_count().await.unwrap(), 1);

    // Signers and coordinator should NOT allow DKG
    assert!(!should_coordinate_dkg(&ctx, &db_chain_tip.block_hash)
        .await
        .unwrap());
    assert!(assert_allow_dkg_begin(&ctx, &db_chain_tip).await.is_err());

    // While in the verification window, we expect the share to stay in pending
    for _ in 0..verification_window {
        let chain_tip = faucet.generate_blocks(1).pop().unwrap().into();

        ctx.wait_for_signal(Duration::from_secs(3), |signal| {
            matches!(
                signal,
                SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
            )
        })
        .await
        .unwrap();

        // Check that the chain tip has been updated (sanity check)
        let db_chain_tip = db
            .get_bitcoin_canonical_chain_tip_ref()
            .await
            .expect("cannot get chain tip")
            .expect("missing chain tip");
        assert_eq!(db_chain_tip.block_hash, chain_tip);

        let latest_dkg = storage
            .get_latest_encrypted_dkg_shares()
            .await
            .expect("cannot get latest dkg shares")
            .expect("missing latest dkg shares");
        assert_eq!(latest_dkg, dkg_shares);
        assert_eq!(storage.get_encrypted_dkg_shares_count().await.unwrap(), 1);

        // Signers and coordinator should NOT allow DKG
        assert!(!should_coordinate_dkg(&ctx, &db_chain_tip.block_hash)
            .await
            .unwrap());
        assert!(assert_allow_dkg_begin(&ctx, &db_chain_tip).await.is_err());
    }

    // With this block we exit the verification window
    let chain_tip = faucet.generate_blocks(1).pop().unwrap().into();

    ctx.wait_for_signal(Duration::from_secs(3), |signal| {
        matches!(
            signal,
            SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
        )
    })
    .await
    .unwrap();

    // Check that the chain tip has been updated (sanity check)
    let db_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .expect("cannot get chain tip")
        .expect("missing chain tip");
    assert_eq!(db_chain_tip.block_hash, chain_tip);

    let latest_dkg = storage
        .get_latest_encrypted_dkg_shares()
        .await
        .expect("cannot get latest dkg shares")
        .expect("missing latest dkg shares");

    // And now the DKG shares should be marked as failed
    assert_eq!(latest_dkg.dkg_shares_status, DkgSharesStatus::Failed);
    assert_eq!(storage.get_encrypted_dkg_shares_count().await.unwrap(), 0);

    // Signers and coordinator should allow again DKG
    assert!(should_coordinate_dkg(&ctx, &db_chain_tip.block_hash)
        .await
        .unwrap());
    assert!(assert_allow_dkg_begin(&ctx, &db_chain_tip).await.is_ok());

    testing::storage::drop_db(db).await;
}
