use std::time::Duration;

use bitcoin::Block;
use bitcoin::BlockHash;
use futures::StreamExt;
use signer::bitcoin::zmq::BitcoinCoreMessageStream;

use crate::docker;

/// This tests that out bitcoin block stream receives new blocks from
/// bitcoin-core as it receives them. We create the stream, generate
/// bitcoin blocks, and wait for the blocks to be received from the stream.
#[tokio::test]
async fn block_stream_streams_blocks() -> Result<(), Box<dyn std::error::Error>> {
    let bitcoind = docker::BitcoinCore::start().await;
    let faucet = bitcoind.initialize_blockchain();
    let zmq_endpoint = bitcoind.zmq_endpoint();

    // Ensure ZMQ endpoint is ready before proceeding
    ensure_zmq_ready(zmq_endpoint.as_str(), Duration::from_secs(2)).await?;

    let stream = BitcoinCoreMessageStream::new_from_endpoint(zmq_endpoint.as_str())
        .await
        .map_err(|e| format!("Failed to create message stream: {}", e))?;

    let mut block_stream = stream.to_block_stream();
    let (sx, mut rx) = tokio::sync::mpsc::channel::<Block>(100);

    // Clean up any existing notifications first
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            match rx.try_recv() {
                Ok(_) => continue, // Keep draining
                Err(_) => break,   // Empty or closed
            }
        }
    })
    .await
    .map_err(|_| "Timeout while draining channel")?;

    // Start receiving new blocks only
    let _task_handle = tokio::spawn(async move {
        while let Some(Ok(block)) = block_stream.next().await {
            if let Err(_) = sx.send(block).await {
                break; // Channel closed
            }
        }
    });

    // Test with multiple block generation and verification cycles
    for i in 1..=3 {
        // Generate a new block and get its hash
        let block_hashes = faucet.generate_blocks(1);
        tracing::info!("Generated block #{} with hash: {}", i, block_hashes[0]);

        // Use a timeout to avoid hanging if notification never arrives
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(block)) => {
                let received_hash = block.block_hash();
                tracing::info!("Received block #{} with hash: {}", i, received_hash);

                // Verify it matches what we generated
                assert_eq!(
                    block_hashes[0], received_hash,
                    "Block hash mismatch in iteration {}",
                    i
                );
            }
            Ok(None) => return Err("Channel closed unexpectedly".into()),
            Err(_) => return Err(format!("Timeout waiting for block notification #{}", i).into()),
        }
    }

    Ok(())
}

/// This tests that out bitcoin block hash stream receives new block hashes
/// from bitcoin-core as it receives blocks. We create the stream, generate
/// bitcoin blocks, and wait for the block hashes to be received from the
/// stream. This also checks that we parse block hashes correctly, since
/// they are supposed to be little-endian formatted.
#[tokio::test]
async fn block_hash_stream_streams_block_hashes() -> Result<(), Box<dyn std::error::Error>> {
    let bitcoind = docker::BitcoinCore::start().await;
    let faucet = bitcoind.initialize_blockchain();
    let zmq_endpoint = bitcoind.zmq_endpoint();

    // Ensure ZMQ endpoint is ready before proceeding
    ensure_zmq_ready(zmq_endpoint.as_str(), Duration::from_secs(2)).await?;

    let stream = BitcoinCoreMessageStream::new_from_endpoint(zmq_endpoint.as_str())
        .await
        .map_err(|e| format!("Failed to create message stream: {}", e))?;

    let mut block_hash_stream = stream.to_block_hash_stream();

    // Set up channel for communication between the stream task and test
    let (sx, mut rx) = tokio::sync::mpsc::channel::<BlockHash>(100);

    // Clean up any potentially lingering notifications from the faucet first
    tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            match rx.try_recv() {
                Ok(_) => continue, // Keep draining
                Err(_) => break,   // Empty or closed
            }
        }
    })
    .await
    .map_err(|_| "Timeout while draining channel")?;

    // This task will "watch" for bitcoin blocks and send them to us
    let _task_handle = tokio::spawn(async move {
        while let Some(Ok(block_hash)) = block_hash_stream.next().await {
            if sx.is_closed() {
                break;
            }

            tracing::info!("Received block hash {block_hash}");
            if let Err(_) = sx.send(block_hash).await {
                break; // Channel closed
            }
        }
    });

    // Test with multiple block generation and verification cycles for consistency
    for i in 1..=3 {
        // Generate a new block and get its hash
        let block_hashes = faucet.generate_blocks(1);
        tracing::info!("Generated block #{} with hash: {}", i, block_hashes[0]);

        // Use a timeout to avoid hanging if notification never arrives
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(received_hash)) => {
                tracing::info!("Received block hash #{}: {}", i, received_hash);

                // Verify it matches what we generated
                assert_eq!(
                    block_hashes[0], received_hash,
                    "Block hash mismatch in iteration {}",
                    i
                );
            }
            Ok(None) => return Err("Channel closed unexpectedly".into()),
            Err(_) => {
                return Err(format!("Timeout waiting for block hash notification #{}", i).into())
            }
        }
    }

    Ok(())
}

/// Ensures ZMQ endpoint is ready and accessible before proceeding
async fn ensure_zmq_ready(
    endpoint: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // Extract host and port from ZMQ endpoint
    let addr = endpoint
        .strip_prefix("tcp://")
        .ok_or_else(|| Box::<dyn std::error::Error>::from("Invalid ZMQ endpoint format"))?;

    // Try to connect with exponential backoff
    tokio::time::timeout(timeout, async {
        let mut delay = Duration::from_millis(25);
        loop {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    tracing::debug!("ZMQ not ready yet: {}", e);
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(delay * 2, Duration::from_millis(200));
                }
            }
        }
    })
    .await
    .map_err(|_| {
        Box::<dyn std::error::Error>::from("ZMQ endpoint not accessible within allotted timeout")
    })?
}
