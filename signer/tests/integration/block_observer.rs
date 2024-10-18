use std::collections::HashSet;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::OutPoint;
use bitcoincore_rpc::RpcApi as _;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::net::api::getpoxinfo::RPCPoxInfoData;
use blockstack_lib::net::api::gettenureinfo::RPCGetTenureInfo;
use futures::StreamExt;
use rand::SeedableRng as _;
use sbtc::testing::regtest;
use signer::error::Error;
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::types::chainstate::StacksBlockId;

use signer::bitcoin::zmq::BitcoinCoreMessageStream;
use signer::block_observer::BlockObserver;
use signer::context::Context as _;
use signer::context::SignerEvent;
use signer::context::SignerSignal;
use signer::storage::DbRead as _;
use signer::testing;
use signer::testing::context::TestContext;
use signer::testing::context::*;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::ReceiverStream;

use crate::setup::TestSweepSetup;
use crate::zmq::BITCOIN_CORE_ZMQ_ENDPOINT;
use crate::DATABASE_NUM;

pub const GET_POX_INFO_JSON: &str =
    include_str!("../../tests/fixtures/stacksapi-get-pox-info-test-data.json");

/// The [`BlockObserver::load_latest_deposit_requests`] function is
/// supposed to fetch all deposit requests from Emily and persist the ones
/// that pass validation, regardless of when they were confirmed.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn load_latest_deposit_requests_persists_requests_added_long_ago() {
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
            .once()
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

        client.expect_get_tenure().returning(|_| {
            let response = Ok(Vec::new());
            Box::pin(std::future::ready(response))
        });

        client.expect_get_pox_info().returning(|| {
            let response = serde_json::from_str::<RPCPoxInfoData>(GET_POX_INFO_JSON)
                .map_err(Error::JsonSerialize);
            Box::pin(std::future::ready(response))
        });
    })
    .await;

    // We only proceed with the test after the BlockObserver "process" has
    // started, and we use this counter to notify us when that happens.
    let start_count = Arc::new(AtomicU8::new(0));
    let counter = start_count.clone();

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
        stacks_client: ctx.stacks_client.clone(),
        emily_client: ctx.emily_client.clone(),
        bitcoin_blocks: ReceiverStream::new(receiver),
        horizon: 10,
    };

    tokio::spawn(async move {
        counter.fetch_add(1, Ordering::Relaxed);
        block_observer.run().await
    });

    // Wait for the task to start.
    while start_count.load(Ordering::SeqCst) < 1 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Our database shouldn't have any deposit requests. In fact, our
    // database doesn't have any blockchain data at all.
    let db = &ctx.storage;
    assert!(db.get_bitcoin_canonical_chain_tip().await.unwrap().is_none());

    let chain_tip_info = rpc.get_chain_tips().unwrap().pop().unwrap();
    let deposit_requests = db
        .get_pending_deposit_requests(&chain_tip_info.hash.into(), 20)
        .await
        .unwrap();

    assert!(deposit_requests.is_empty());

    // Let's generate a new block and wait for out block observer to send a
    // BitcoinBlockObserved signal.
    let chain_tip = faucet.generate_blocks(1).pop().unwrap().into();

    let receiver = ctx.get_signal_receiver();

    let stream = BroadcastStream::new(receiver)
        .filter_map(|signal| match signal {
            Ok(SignerSignal::Event(SignerEvent::BitcoinBlockObserved)) => {
                std::future::ready(Some(()))
            }
            _ => std::future::ready(None),
        })
        .fuse();
    // We need it to implement UnPin for StreamExt::select_next_some, same
    // for StreamExt::next.
    tokio::pin!(stream);

    tokio::time::timeout(Duration::from_secs(10), stream.select_next_some())
        .await
        .unwrap();

    // Okay now lets check if we have these deposit requests in our
    // database. It should also have bitcoin blockchain data

    assert!(db.get_bitcoin_canonical_chain_tip().await.unwrap().is_some());
    let deposit_requests = db
        .get_pending_deposit_requests(&chain_tip, 20)
        .await
        .unwrap();


    assert_eq!(deposit_requests.len(), 2);
    let req_outpoints: HashSet<OutPoint> =
        deposit_requests.iter().map(|req| req.outpoint()).collect();

    assert!(req_outpoints.contains(&setup0.deposit_info.outpoint));
    assert!(req_outpoints.contains(&setup1.deposit_info.outpoint));
}
