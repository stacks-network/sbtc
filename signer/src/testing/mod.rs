//! Module with testing utility functions.

#![allow(clippy::unwrap_in_result, clippy::unwrap_used, clippy::expect_used)]

pub mod api_clients;
pub mod block_observer;
pub mod btc;
pub mod context;
pub mod dummy;
pub mod message;
pub mod network;
pub mod stacks;
pub mod storage;
pub mod transaction_coordinator;
pub mod transaction_signer;
pub mod wallet;
pub mod wsts;

use bitcoin::key::TapTweak;
use bitcoin::TapSighashType;
use bitcoin::Witness;
use secp256k1::SECP256K1;

use crate::bitcoin::utxo::UnsignedTransaction;
use crate::config::Settings;

/// The path for the configuration file that we should use during testing.
pub const DEFAULT_CONFIG_PATH: Option<&str> = Some("./src/config/default");

impl Settings {
    /// Create a new `Settings` instance from the default configuration file.
    /// This is useful for testing.
    pub fn new_from_default_config() -> Result<Self, config::ConfigError> {
        Self::new(DEFAULT_CONFIG_PATH)
    }
}

/// Clears all signer-specific configuration environment variables. This is needed
/// for a number of tests which use the `Settings` struct due to the fact that
/// `cargo test` runs tests in threads, and environment variables are per-process.
///
/// If we switched to `cargo nextest` (which runs tests in separate processes),
/// this would no longer be needed.
pub fn clear_env() {
    for var in std::env::vars() {
        if var.0.starts_with("SIGNER_") {
            std::env::remove_var(var.0);
        }
    }
}

/// A helper function for correctly setting witness data
pub fn set_witness_data(unsigned: &mut UnsignedTransaction, keypair: secp256k1::Keypair) {
    let sighash_type = TapSighashType::Default;
    let sighashes = unsigned.construct_digests().unwrap();

    let signer_msg = secp256k1::Message::from(sighashes.signers);
    let tweaked = keypair.tap_tweak(SECP256K1, None);
    let signature = SECP256K1.sign_schnorr(&signer_msg, &tweaked.to_inner());
    let signature = bitcoin::taproot::Signature { signature, sighash_type };
    let signer_witness = Witness::p2tr_key_spend(&signature);

    let deposit_witness = sighashes.deposits.into_iter().map(|(deposit, sighash)| {
        let deposit_msg = secp256k1::Message::from(sighash);
        let signature = SECP256K1.sign_schnorr(&deposit_msg, &keypair);
        let signature = bitcoin::taproot::Signature { signature, sighash_type };
        deposit.construct_witness_data(signature)
    });

    let witness_data: Vec<Witness> = std::iter::once(signer_witness)
        .chain(deposit_witness)
        .collect();

    unsigned
        .tx
        .input
        .iter_mut()
        .zip(witness_data)
        .for_each(|(tx_in, witness)| {
            tx_in.witness = witness;
        });
}
