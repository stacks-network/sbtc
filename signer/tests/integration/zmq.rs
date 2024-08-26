use bitcoin::Block;
use bitcoin::BlockHash;
use futures::StreamExt;
use sbtc::testing::regtest;
use signer::bitcoin::zmq::BitcoinCoreMessageStream;

const BITCOIN_CORE_ZMQ_ENDPOINT: &str = "tcp://localhost:28332";

/// This tests that out bitcoin block stream receives new blocks from
/// bitcoin-core as it receives them. We create the stream, generate
/// bitcoin blocks, and wait for the blocks to be received from the stream.
#[tokio::test]
#[cfg_attr(not(feature = "integration-tests"), ignore)]
async fn block_stream_streams_blocks() {
    let (_, faucet) = regtest::initialize_blockchain();

    let stream =
        BitcoinCoreMessageStream::new_from_endpoint(BITCOIN_CORE_ZMQ_ENDPOINT, &["rawblock"])
            .await
            .unwrap();

    let mut block_stream = stream.to_block_stream();

    // We want to have our stream always waiting for blocks so that we get
    // them as they arise. The issue is that await points essentially block
    // progress on the current code execution path. So we spawn a new task
    // to handle the blocking part, and have the task send us blocks
    // through a channel as they arrive.
    let (sx, mut rx) = tokio::sync::mpsc::channel::<Block>(100);

    // This task will "watch" for bitcoin blocks and send them to us.
    tokio::spawn(async move {
        while let Some(Ok(block)) = block_stream.next().await {
            if sx.is_closed() {
                break;
            }

            tracing::info!("Sending block {:?}", block.block_hash());
            sx.send(block).await.unwrap();
        }
    });

    // When the faucet generates a block it returns the block hash of the
    // generated block. We'll match this hash with the hash of the block
    // received from our task above.
    let block_hashes = faucet.generate_blocks(1);
    let item = rx.recv().await;

    // We only generated one block, so we should only have one block hash.
    assert_eq!(block_hashes.len(), 1);
    assert_eq!(block_hashes[0], item.unwrap().block_hash());

    // Let's try again for good measure, couldn't hurt.
    let block_hashes = faucet.generate_blocks(1);
    let item = rx.recv().await;

    assert_eq!(block_hashes.len(), 1);
    assert_eq!(block_hashes[0], item.unwrap().block_hash());
}

/// This tests that out bitcoin block hash stream receives new block hashes
/// from bitcoin-core as it receives blocks. We create the stream, generate
/// bitcoin blocks, and wait for the block hashes to be received from the
/// stream. This also checks that we parse block hashes correctly, since
/// they are supposed to be little-endian formatted.
#[tokio::test]
#[cfg_attr(not(feature = "integration-tests"), ignore)]
async fn block_hash_stream_streams_block_hashes() {
    let (_, faucet) = regtest::initialize_blockchain();

    let stream =
        BitcoinCoreMessageStream::new_from_endpoint(BITCOIN_CORE_ZMQ_ENDPOINT, &["hashblock"])
            .await
            .unwrap();

    let mut block_hash_stream = stream.to_block_hash_stream();

    // We want to have our stream always waiting for block hashes so that
    // we get them as they arise. The issue is that await points
    // essentially block progress on the current code execution path. So we
    // spawn a new task to handle the blocking part, and have the task send
    // us blocks through a channel as they arrive.
    let (sx, mut rx) = tokio::sync::mpsc::channel::<BlockHash>(100);

    // This task will "watch" for bitcoin blocks and send them to us.
    tokio::spawn(async move {
        while let Some(Ok(block_hash)) = block_hash_stream.next().await {
            if sx.is_closed() {
                break;
            }

            tracing::info!("Sending block hash {block_hash}");
            sx.send(block_hash).await.unwrap();
        }
    });

    // When the faucet generates a block it returns the block hash of the
    // generated block. We'll match this hash with the hash received from
    // our task above.
    let block_hashes = faucet.generate_blocks(1);
    let item = rx.recv().await;

    // We only generated one block, so we should only have one block hash.
    assert_eq!(block_hashes.len(), 1);
    assert_eq!(block_hashes[0], item.unwrap());

    // Let's try again for good measure, couldn't hurt.
    let block_hashes = faucet.generate_blocks(1);
    let item = rx.recv().await;

    assert_eq!(block_hashes.len(), 1);
    assert_eq!(block_hashes[0], item.unwrap());
}
