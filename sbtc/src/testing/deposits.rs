//! Helper functions for creating deposit transactions
//!

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::Amount;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxOut;
use clarity::vm::types::PrincipalData;
use rand::rngs::OsRng;
use secp256k1::SecretKey;
use secp256k1::SECP256K1;
use stacks_common::types::chainstate::StacksAddress;

use crate::deposits;
use crate::deposits::DepositScriptInputs;
use crate::deposits::ReclaimScriptInputs;

/// A properly formated transaction and the corresponding deposit and
/// reclaim inputs.
pub struct TxSetup {
    /// The transaction
    pub tx: Transaction,
    /// The deposit scripts and their variable inputs
    pub deposits: Vec<DepositScriptInputs>,
    /// The reclaim scripts and their variable inputs
    pub reclaims: Vec<ReclaimScriptInputs>,
}

fn build_deposit_reclaim_outputs(
    lock_time: u32,
    max_fee: u64,
    amounts: &[u64],
    recipient: Option<StacksAddress>,
) -> (
    Vec<TxOut>,
    Vec<DepositScriptInputs>,
    Vec<ReclaimScriptInputs>,
) {
    let mut tx_outs = Vec::with_capacity(amounts.len());
    let mut deposits = Vec::with_capacity(amounts.len());
    let mut reclaims = Vec::with_capacity(amounts.len());

    for &amount in amounts {
        let secret_key = SecretKey::new(&mut OsRng);
        let actual_recipient = recipient.unwrap_or(StacksAddress::burn_address(false));
        let deposit = DepositScriptInputs {
            signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
            recipient: PrincipalData::from(actual_recipient),
            max_fee,
        };
        let reclaim = ReclaimScriptInputs::try_new(lock_time, ScriptBuf::new()).unwrap();
        let deposit_script = deposit.deposit_script();
        let reclaim_script = reclaim.reclaim_script();

        tx_outs.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: deposits::to_script_pubkey(deposit_script, reclaim_script),
        });
        deposits.push(deposit);
        reclaims.push(reclaim);
    }

    (tx_outs, deposits, reclaims)
}

/// The BTC transaction that is in this TxSetup is consistent with
/// the deposit and reclaim scripts.
pub fn tx_setup(lock_time: u32, max_fee: u64, amounts: &[u64]) -> TxSetup {
    let (tx_outs, deposits, reclaims) =
        build_deposit_reclaim_outputs(lock_time, max_fee, amounts, None);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: tx_outs,
    };
    TxSetup { tx, reclaims, deposits }
}

/// The BTC transaction that is in this TxSetup is consistent with the deposit and
/// reclaim scripts sent to a specific recipient.
pub fn tx_setup_with_recipient(
    lock_time: u32,
    max_fee: u64,
    amounts: &[u64],
    recipient: StacksAddress,
) -> TxSetup {
    let (tx_outs, deposits, reclaims) =
        build_deposit_reclaim_outputs(lock_time, max_fee, amounts, Some(recipient));
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: tx_outs,
    };
    TxSetup { tx, reclaims, deposits }
}
