use std::collections::HashSet;
use std::ops::Deref;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::OutPoint;
use bitcoincore_rpc::RpcApi as _;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::getpoxinfo::RPCPoxInfoData;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo;
use emily_client::apis::deposit_api;
use emily_client::apis::testing_api;
use emily_client::models::CreateDepositRequestBody;
use fake::Fake as _;
use fake::Faker;
use futures::StreamExt;
use rand::SeedableRng as _;
use sbtc::testing::regtest;
use sbtc::testing::regtest::Recipient;
use signer::bitcoin::utxo::SbtcRequests;
use signer::bitcoin::utxo::SignerBtcState;
use signer::emily_client::EmilyClient;
use signer::error::Error;
use signer::keys::SignerScriptPubKey as _;
use signer::logging::setup_logging;
use signer::stacks::api::TenureBlocks;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::EncryptedDkgShares;
use signer::storage::model::TxOutput;
use signer::storage::model::TxOutputType;
use signer::storage::model::TxPrevout;
use signer::storage::model::TxPrevoutType;
use signer::storage::postgres::PgStore;
use signer::storage::DbWrite;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::types::chainstate::StacksBlockId;

use signer::bitcoin::zmq::BitcoinCoreMessageStream;
use signer::block_observer::BlockObserver;
use signer::context::Context as _;
use signer::context::SignerEvent;
use signer::context::SignerSignal;
use signer::stacks::api::StacksClient;
use signer::storage::DbRead as _;
use signer::testing;
use signer::testing::context::TestContext;
use signer::testing::context::*;
use tokio_stream::wrappers::ReceiverStream;
use url::Url;

use crate::setup::TestSweepSetup;
use crate::utxo_construction::make_deposit_request;
use crate::zmq::BITCOIN_CORE_ZMQ_ENDPOINT;
use crate::DATABASE_NUM;

pub const GET_POX_INFO_JSON: &str =
    include_str!("../../tests/fixtures/stacksapi-get-pox-info-test-data.json");

/// The [`BlockObserver::load_latest_deposit_requests`] function is
/// supposed to fetch all deposit requests from Emily and persist the ones
/// that pass validation, regardless of when they were confirmed.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case::test_case(1, 10; "one block ago")]
#[test_case::test_case(5, 10; "five blocks ago")]
#[tokio::test]
async fn load_latest_deposit_requests_persists_requests_from_past(blocks_ago: u64, horizon: u32) {
    // We start with the typical setup with a fresh database and context
    // with a real bitcoin core client and a real connection to our
    // database.
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_emily_client()
        .with_mocked_stacks_client()
        .build();

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
    })
    .await;

    // We need to set up the stacks client as well. We use it to fetch
    // information about the Stacks blockchain, so we need to prep it, even
    // though it isn't necessary for our test.
    ctx.with_stacks_client(|client| {
        client.expect_get_tenure_info().returning(move || {
            let response = Ok(RPCGetTenureInfo {
                consensus_hash: ConsensusHash([0; 20]),
                tenure_start_block_id: StacksBlockId([0; 32]),
                parent_consensus_hash: ConsensusHash([0; 20]),
                parent_tenure_start_block_id: StacksBlockId::first_mined(),
                tip_block_id: StacksBlockId([0; 32]),
                tip_height: 0,
                reward_cycle: 0,
            });
            Box::pin(std::future::ready(response))
        });

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

        client.expect_get_sortition_info().returning(move |_| {
            let response = Ok(SortitionInfo {
                burn_block_hash: BurnchainHeaderHash([0; 32]),
                burn_block_height: 0,
                burn_header_timestamp: 0,
                sortition_id: SortitionId([0; 32]),
                parent_sortition_id: SortitionId([0; 32]),
                consensus_hash: ConsensusHash([0; 20]),
                was_sortition: true,
                miner_pk_hash160: None,
                stacks_parent_ch: None,
                last_sortition_ch: None,
                committed_block_hash: None,
            });
            Box::pin(std::future::ready(response))
        });
    })
    .await;

    faucet.generate_blocks(blocks_ago);

    // We only proceed with the test after the BlockObserver "process" has
    // started, and we use this counter to notify us when that happens.
    let start_flag = Arc::new(AtomicBool::new(false));
    let flag = start_flag.clone();

    // We jump through all of these hoops to make sure that the block
    // stream object is Send + Sync.
    let zmq_stream =
        BitcoinCoreMessageStream::new_from_endpoint(BITCOIN_CORE_ZMQ_ENDPOINT, &["hashblock"])
            .await
            .unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(100);

    tokio::spawn(async move {
        let mut stream = zmq_stream.to_block_hash_stream();
        while let Some(block) = stream.next().await {
            sender.send(block).await.unwrap();
        }
    });

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: ReceiverStream::new(receiver),
        horizon,
    };

    // We need at least one receiver
    let _signal = ctx.get_signal_receiver();

    // Our database shouldn't have any deposit requests. In fact, our
    // database doesn't have any blockchain data at all.
    let db = &ctx.storage;
    assert!(db
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
    let deposit_requests = db
        .get_deposit_requests(&chain_tip_info.hash.into(), 100)
        .await
        .unwrap();

    assert!(deposit_requests.is_empty());

    // Let's generate a new block and wait for out block observer to send a
    // BitcoinBlockObserved signal.
    let chain_tip: BitcoinBlockHash = faucet.generate_blocks(1).pop().unwrap().into();

    // We need to wait for the bitcoin-core to send us all the
    // notifications so that we are up to date with the expected chain tip.
    // For that we just wait until we know that we're up-to-date
    let mut current_chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap();

    let waiting_fut = async {
        let db = db.clone();
        while current_chain_tip != Some(chain_tip) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            current_chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap();
        }
    };

    tokio::time::timeout(Duration::from_secs(3), waiting_fut)
        .await
        .unwrap();

    // Okay now lets check if we have these deposit requests in our
    // database. It should also have bitcoin blockchain data

    assert!(db
        .get_bitcoin_canonical_chain_tip()
        .await
        .unwrap()
        .is_some());
    let deposit_requests = db.get_deposit_requests(&chain_tip, 100).await.unwrap();

    assert_eq!(deposit_requests.len(), 2);
    let req_outpoints: HashSet<OutPoint> =
        deposit_requests.iter().map(|req| req.outpoint()).collect();

    assert!(req_outpoints.contains(&setup0.deposit_info.outpoint));
    assert!(req_outpoints.contains(&setup1.deposit_info.outpoint));
}

/// Integration test for bitcoin and stack blocks link.
///
/// To run this test first run:
///  - docker compose -f docker/docker-compose.yml up
/// and wait for nakamoto to kick in.
#[ignore = "This is an integration test that requires devenv running"]
#[tokio::test]
async fn link_blocks() {
    setup_logging("info", true);

    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;

    let nakamoto_start_height = 30;
    let stacks_client = StacksClient::new(
        Url::parse("http://localhost:20443").unwrap(),
        nakamoto_start_height,
    )
    .unwrap();

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

    let zmq_stream =
        BitcoinCoreMessageStream::new_from_endpoint(BITCOIN_CORE_ZMQ_ENDPOINT, &["hashblock"])
            .await
            .unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(100);

    tokio::spawn(async move {
        let mut stream = zmq_stream.to_block_hash_stream();
        while let Some(block) = stream.next().await {
            sender.send(block).await.unwrap();
        }
    });

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: ReceiverStream::new(receiver),
        horizon: 10,
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn block_observer_stores_donation_and_sbtc_utxos() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    // signer::logging::setup_logging("info,signer=debug", false);

    // We need to populate our databases, so let's fetch the data.
    let emily_client =
        EmilyClient::try_from(&Url::parse("http://localhost:3031").unwrap()).unwrap();

    testing_api::wipe_databases(emily_client.config())
        .await
        .unwrap();

    let chain_tip_info = rpc.get_chain_tips().unwrap().pop().unwrap();

    // 1. Create a database, an associated context for the block observer.

    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
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
        client.expect_get_tenure_info().returning(move || {
            let response = Ok(RPCGetTenureInfo {
                consensus_hash: ConsensusHash([0; 20]),
                tenure_start_block_id: StacksBlockId([0; 32]),
                parent_consensus_hash: ConsensusHash([0; 20]),
                parent_tenure_start_block_id: StacksBlockId::first_mined(),
                tip_block_id: StacksBlockId([0; 32]),
                tip_height: 0,
                reward_cycle: 0,
            });
            Box::pin(std::future::ready(response))
        });

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

    // We jump through all of these hoops to make sure that the block
    // stream object is Send + Sync.
    let zmq_stream =
        BitcoinCoreMessageStream::new_from_endpoint(BITCOIN_CORE_ZMQ_ENDPOINT, &["hashblock"])
            .await
            .unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(1000);

    tokio::spawn(async move {
        let mut stream = zmq_stream.to_block_hash_stream();
        while let Some(block) = stream.next().await {
            sender.send(block).await.unwrap();
        }
    });

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: ReceiverStream::new(receiver),
        horizon: 2,
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
            utxo: db.get_signer_utxo(&chain_tip, 10).await.unwrap().unwrap(),
            fee_rate: 10.0,
            public_key: signers_public_key,
            last_fees: None,
            magic_bytes: [b'T', b'3'],
        },
        accept_threshold: 4,
        num_signers: 7,
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
