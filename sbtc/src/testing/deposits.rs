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
    /// The deposit script and its variable inputs
    pub deposit: DepositScriptInputs,
    /// The reclaim script and its variable inputs
    pub reclaim: ReclaimScriptInputs,
}

/// The BTC transaction that is in this TxSetup is consistent with
/// the deposit and reclaim scripts.
pub fn tx_setup(lock_time: u32, max_fee: u64, amount: u64) -> TxSetup {
    let secret_key = SecretKey::new(&mut OsRng);

    let deposit = DepositScriptInputs {
        signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
        recipient: PrincipalData::from(StacksAddress::burn_address(false)),
        max_fee,
    };
    let reclaim = ReclaimScriptInputs::try_new(lock_time, ScriptBuf::new()).unwrap();

    let deposit_script = deposit.deposit_script();
    let reclaim_script = reclaim.reclaim_script();
    // This transaction is kinda invalid because it doesn't have any
    // inputs. But it is fine for our purposes.
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: deposits::to_script_pubkey(deposit_script, reclaim_script),
        }],
    };

    TxSetup { tx, reclaim, deposit }
}

/// The BTC transaction that is in this TxSetup is consistent with the deposit and
/// reclaim scripts sent to a specific recipient.
pub fn tx_setup_with_recipient(
    lock_time: u32,
    max_fee: u64,
    amount: u64,
    recipient: StacksAddress,
) -> TxSetup {
    let secret_key: SecretKey = SecretKey::new(&mut OsRng);

    let deposit = DepositScriptInputs {
        signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
        recipient: PrincipalData::from(recipient),
        max_fee,
    };
    let reclaim = ReclaimScriptInputs::try_new(lock_time, ScriptBuf::new()).unwrap();

    let deposit_script = deposit.deposit_script();
    let reclaim_script = reclaim.reclaim_script();
    // This transaction is kinda invalid because it doesn't have any
    // inputs. But it is fine for our purposes.
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: deposits::to_script_pubkey(deposit_script, reclaim_script),
        }],
    };

    TxSetup { tx, reclaim, deposit }
}
