#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

pub mod block_observer;
pub mod blocklist_client;
pub mod block_notifier;
pub mod codec;
pub mod config;
pub mod ecdsa;
pub mod error;
pub mod fees;
pub mod message;
pub mod network;
pub mod packaging;
pub mod storage;
#[cfg(feature = "testing")]
pub mod testing;
pub mod utxo;

/// Package version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
