//! Helper functions for the bitcoin module
//!
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;

/// Return a transaction that is kinda like the signers' transaction,
/// but it does not service any requests, and it does not have any
/// signatures.
pub fn base_signer_transaction() -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![
            // This is the signers' previous UTXO
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            },
        ],
        output: vec![
            // This represents the signers' new UTXO.
            TxOut {
                value: Amount::ONE_BTC,
                script_pubkey: ScriptBuf::new(),
            },
            // This represents the OP_RETURN sBTC UTXO for a
            // transaction with no withdrawals.
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([0; 21]),
            },
        ],
    }
}
