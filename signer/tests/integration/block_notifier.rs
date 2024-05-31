use futures::StreamExt;
use signer::block_notifier::{BlockNotifier, ElectrumBlockNotifier};
use signer::config::BlockNotifierConfig;
use tracing::{error, info, warn, Level};
use tracing_subscriber;

// TODO: We need to fix docker-compose.test.yml setup so bitcoin and bitcoind use different
// RPC ports for all tests to pass. Currently, this test passes locally by
// running /devenv/local/docker-compose/up.sh to bring up bitcoin and electrs
// containers. issue: https://github.com/stacks-network/sbtc/issues/220

#[ignore]
#[tokio::test]
async fn test_electrum_block_notifier_multiple_consumers() {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Define the test configuration with shorter intervals
    let config = BlockNotifierConfig {
        server: "tcp://localhost:60401".to_string(),
        retry_interval: 1,
        max_retry_attempts: 3,
        ping_interval: 2,
        subscribe_interval: 3,
    };

    // Create the notifier with the test configuration
    let notifier = ElectrumBlockNotifier::from_config(&config).unwrap();

    // Run the notifier to get the receiver
    let receiver = notifier.run();

    // Subscribe multiple consumers to block headers
    let mut consumer1 = receiver.subscribe();
    let mut consumer2 = receiver.subscribe();

    // Initialize counters for successful receipts
    let mut success_count1 = 0;
    let mut success_count2 = 0;

    // Simulate fetching and printing a few block hashes for each consumer
    for _ in 0..5 {
        tokio::select! {
            block_hash = consumer1.next() => match block_hash {
                Some(Ok(hash)) => {
                    info!("Consumer 1 received new block hash: {:?}", hash);
                    success_count1 += 1;
                }
                Some(Err(e)) => error!("Consumer 1 received error: {:?}", e),
                None => warn!("Consumer 1 stream ended unexpectedly."),
            },
            block_hash = consumer2.next() => match block_hash {
                Some(Ok(hash)) => {
                    info!("Consumer 2 received new block hash: {:?}", hash);
                    success_count2 += 1;
                }
                Some(Err(e)) => error!("Consumer 2 received error: {:?}", e),
                None => warn!("Consumer 2 stream ended unexpectedly."),
            },
        }
    }

    // Assert that at least one successful receipt was made by each consumer
    assert!(
        success_count1 > 0,
        "Consumer 1 did not receive any block hashes successfully"
    );
    assert!(
        success_count2 > 0,
        "Consumer 2 did not receive any block hashes successfully"
    );
}
