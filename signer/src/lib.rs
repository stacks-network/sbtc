#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

pub mod bitcoin;
pub mod block_observer;
pub mod blocklist_client;
pub mod codec;
pub mod config;
pub mod ecdsa;
pub mod error;
pub mod keys;
pub mod message;
pub mod network;
pub mod signature;
pub mod stacks;
pub mod storage;
#[cfg(feature = "testing")]
pub mod testing;
pub mod transaction_coordinator;
pub mod transaction_signer;
pub mod wsts_state_machine;

/// Package version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The maximum number of keys in the signers multi-sig wallet on Stacks.
/// There are a few practical limits on the maximum number of distinct
/// public keys:
/// 1. The maximum number of signatures allowed in a stacks transaction is
///    capped at u16::MAX, which is 65535.
/// 2. The maximum amount of data that can be sent as input into a clarity
///    contract call is capped at 1 MB. That limits the maximum number of
///    keys to ~31K.
/// 3. The signer bitmap in the clarity contract can take only 128 signers.
/// 4. The rotate-keys-wrapper public function in one of the clarity
///    contracts takes a maximum of 128 keys.
const MAX_KEYS: u16 = 128;
