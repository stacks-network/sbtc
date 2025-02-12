use std::sync::atomic::AtomicU16;

mod bitcoin_client;
mod bitcoin_rpc;
mod bitcoin_validation;
mod block_observer;
mod communication;
mod complete_deposit;
mod contracts;
mod emily;
mod fees;
mod postgres;
mod rbf;
mod request_decider;
mod rotate_keys;
mod setup;
mod stacks_events_observer;
mod tls_checking;
mod transaction_coordinator;
mod transaction_signer;
mod utxo_construction;
mod withdrawal_accept;
mod zmq;
/// This is needed to make sure that each test has as many isolated
/// databases as it needs.
pub static DATABASE_NUM: AtomicU16 = AtomicU16::new(0);
