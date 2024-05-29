use futures::StreamExt;
use signer::block_notifier::{BlockNotifier, ElectrumBlockNotifier};
use tracing::{error, info, warn, Level};
use tracing_subscriber;

#[ignore]
#[tokio::test]
async fn test_electrum_block_notifier_integration() {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Create the notifier
    let notifier = ElectrumBlockNotifier::from_config().unwrap();

    // Subscribe to block headers
    let mut block_stream = notifier.subscribe();

    // Fetch and print a few block hashes to ensure it's working
    for _ in 0..5 {
        match block_stream.next().await {
            Some(Ok(block_hash)) => info!("New block hash: {:?}", block_hash),
            Some(Err(e)) => error!("Error receiving block hash: {:?}", e),
            None => {
                warn!("Stream ended unexpectedly.");
                break;
            }
        }
    }
}
