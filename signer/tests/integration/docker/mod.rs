use rand::{distributions::Alphanumeric, Rng};

mod bitcoin_core;

// Bitcoin core types.
pub use bitcoin_core::BitcoinCore;

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
