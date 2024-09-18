use std::sync::atomic::AtomicU16;

mod contracts;
mod postgres;
mod rbf;
mod transaction_signer;
mod complete_deposit;
mod utxo_construction;
mod zmq;

/// This is needed to make sure that each test has as many isolated
/// databases as it needs.
pub static DATABASE_NUM: AtomicU16 = AtomicU16::new(0);
