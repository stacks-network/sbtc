pub mod codec;
pub mod ecdsa;
pub mod error;
pub mod message;
pub mod network;
pub mod packaging;
pub mod utxo;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
