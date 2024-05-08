pub mod codec;
pub mod ecdsa;
pub mod error;
pub mod logging;
pub mod message;
pub mod packaging;
pub mod utxo;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
