use std::time::Duration;

use rand::{distributions::Alphanumeric, Rng};

mod bitcoin_core;
mod dynamodb;
mod emily;

// Bitcoin core types.
pub use bitcoin_core::BitcoinCore;
pub use dynamodb::DynamoDb;
pub use emily::Emily;

pub const DEFAULT_BITCOIN_CORE_TAG: &str = "28";

/// Generates a unique container name with an 8-character random alphanumeric suffix.
///
/// ## Parameters
/// * `name` - Base name for the container
///
/// ## Returns
/// A string formatted as "sbtc-test-{name}-{random_suffix}"
fn container_name(name: &str) -> String {
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    format!("sbtc-test-{name}-{suffix}")
}

/// Tests TCP connectivity with repeated attempts until success or timeout
///
/// Attempts to connect to the specified host:port every 10ms until either:
/// - Connection succeeds (returns Ok)
/// - Timeout duration is exceeded (returns Err)
///
/// # Parameters
/// * `host` - Host address to connect to (IP or hostname)
/// * `port` - Port number to connect to
/// * `timeout` - Maximum duration to keep attempting connections
///
/// # Returns
/// * `Ok(())` if connection was established successfully
/// * `Err(Error)` if timeout occurred before successful connection
pub async fn wait_for_tcp_connectivity(host: &str, port: u16, timeout: Duration) {
    let endpoint = format!("{}:{}", host, port);

    tokio::time::timeout(timeout, async {
        loop {
            match tokio::net::TcpStream::connect(&endpoint).await {
                Ok(_) => break,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
        }
    })
    .await
    .expect("ZMQ endpooint not accessible within allotted timeout");
}
