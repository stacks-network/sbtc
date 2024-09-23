//! Test deposit validation against bitcoin-core

use bitcoin::absolute::LockTime;
use bitcoin::script::PushBytes;
use bitcoin::transaction::Version;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoincore_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoincore_rpc::jsonrpc::error::RpcError;
use bitcoincore_rpc::Error as BtcRpcError;
use bitcoincore_rpc::RpcApi;

use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::ReclaimScriptInputs;
use sbtc::rpc::BitcoinCoreClient;
use sbtc::testing::deposits::TxSetup;
use sbtc::testing::regtest;
use sbtc::testing::regtest::AsUtxo;
use sbtc::testing::regtest::Recipient;

/// Test the CreateDepositRequest::validate function.
///
/// We check that we can validate a transaction in the mempool using the
/// electrum and bitcoin-core clients
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn tx_validation_from_mempool() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();
    let max_fee: u64 = 15000;
    let amount_sats = 49_900_000;
    let lock_time = 150;

    let mut setup: TxSetup = sbtc::testing::deposits::tx_setup(lock_time, max_fee, amount_sats);

    let (rpc, faucet) = regtest::initialize_blockchain();
    let depositor = Recipient::new(AddressType::P2tr);

    // Start off with some initial UTXOs to work with.
    let outpoint = faucet.send_to(50_000_000, &depositor.address);
    faucet.generate_blocks(1);

    // There is only one UTXO under the depositor's name, so let's get it
    let utxos = depositor.get_utxos(rpc, None);

    setup.tx.input = vec![TxIn {
        previous_output: outpoint,
        sequence: Sequence::ZERO,
        script_sig: ScriptBuf::new(),
        witness: Witness::new(),
    }];

    let request = CreateDepositRequest {
        outpoint: OutPoint::new(setup.tx.compute_txid(), 0),
        reclaim_script: setup.reclaim.reclaim_script(),
        deposit_script: setup.deposit.deposit_script(),
    };

    regtest::p2tr_sign_transaction(&mut setup.tx, 0, &utxos, &depositor.keypair);
    rpc.send_raw_transaction(&setup.tx).unwrap();

    let parsed = request.validate(&client).await.unwrap().info;

    assert_eq!(parsed.outpoint, request.outpoint);
    assert_eq!(parsed.deposit_script, request.deposit_script);
    assert_eq!(parsed.reclaim_script, request.reclaim_script);
    assert_eq!(parsed.amount, amount_sats);
    assert_eq!(parsed.signers_public_key, setup.deposit.signers_public_key);
    assert_eq!(parsed.lock_time, lock_time as u64);
    assert_eq!(parsed.recipient, setup.deposit.recipient);
}

/// This validates that we need to reject deposit scripts that do not
/// follow the minimal push rule in their deposit scripts.
///
/// The test proceeds as follows:
/// 1. Create and submit a transaction where the lock script has a
///    non-minimal push for the deposit.
/// 2. Confirm the transaction and try spend it immediately. The
///    transaction spending the "deposit" should be rejected.
///
/// We do not attempt to create an actual P2TR deposit, but an
/// (unsupported) P2SH deposit.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn minimal_push_check() {
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

    let (rpc, faucet) = regtest::initialize_blockchain();
    let depositor = Recipient::new(AddressType::P2tr);

    // Start off with some initial UTXOs to work with.
    let _ = faucet.send_to(50_000_000, &depositor.address);
    faucet.generate_blocks(1);

    // There is only one UTXO under the depositor's name, so let's get it
    let utxos = depositor.get_utxos(rpc, None);
    let utxo = utxos.first().cloned().unwrap();
    let amount = 30_000_000;

    // 1. Create and submit a transaction where the lock script has a
    //    non-minimal push for the deposit.
    //
    // We're going to create a P2SH UTXO with a script that has a
    // non-minimal push of data. Anyone can spend this script immediately.
    let deposit_data = [0; 44];

    // This is non-standard script because it does not follow the minimal
    // push rule. We use the OP_PUSHDATA1 when we can use fewer bytes for
    // the same outcome in the script by removing the OP_PUSHDATA1 opcode
    // from the script.
    let script_pubkey = ScriptBuf::builder()
        .push_opcode(bitcoin::opcodes::all::OP_PUSHDATA1)
        .push_slice(deposit_data)
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script();

    let mut tx0 = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint(),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::new_p2sh(&script_pubkey.script_hash()),
            },
            TxOut {
                value: utxo.amount() - Amount::from_sat(amount + fee),
                script_pubkey: depositor.address.script_pubkey(),
            },
        ],
    };

    regtest::p2tr_sign_transaction(&mut tx0, 0, &[utxo], &depositor.keypair);
    rpc.send_raw_transaction(&tx0).unwrap();

    // 2. Confirm the transaction and try spend it immediately. The
    //    transaction spending the "deposit" should be rejected.
    faucet.generate_blocks(1);

    // The Builder::push_slice wants to make sure that the length of the
    // pushed data is within the limits, hence the conversion into this
    // PushBytes thing.
    let locking_script: &PushBytes = script_pubkey.as_bytes().try_into().unwrap();
    let script_sig = ScriptBuf::builder()
        .push_slice(locking_script)
        .into_script();

    let tx1 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(tx0.compute_txid(), 0),
            sequence: Sequence::ZERO,
            script_sig,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount - fee),
            script_pubkey: depositor.address.script_pubkey(),
        }],
    };
    // We just created a transaction that spends the P2SH UTXO where we
    // spend a deposit that did not adhere to the minimal push rule. When
    // bicoin-core attempts to validate the transaction it should fail.
    let expected = "non-mandatory-script-verify-flag (Data push larger than necessary)";
    match rpc.send_raw_transaction(&tx1).unwrap_err() {
        BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { code: -26, message, .. }))
            if message == expected => {}
        err => panic!("{err}"),
    };
}

/// This validates that a user can disable OP_CSV checks if we allow them
/// to submit any lock-time. It doesn't test much of the code in this
/// crate, just that bitcoin-core will treat OP_CSV like a no-op if the
/// [`sbtc::deposits::SEQUENCE_LOCKTIME_DISABLE_FLAG`] bit is set to 1 in
/// the input `lock_time`.
///
/// The test proceeds as follows:
/// 1. Create and submit a transaction where the lock script uses a
///    lock-time at least 50 blocks in the future but also disables OP_CSV.
/// 2. Confirm the transaction and spend it immediately, proving that
///    OP_CSV was disabled.
/// 3. Create and submit another transaction where the lock script uses a
///    lock-time where OP_CSV is not disabled.
/// 4. Confirm that transaction and try to spend it immediately. The
///    transaction that tries to spend the transaction from (3) should be
///    rejected.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn op_csv_disabled() {
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

    let (rpc, faucet) = regtest::initialize_blockchain();
    let depositor = Recipient::new(AddressType::P2tr);

    // Start off with some initial UTXOs to work with.
    let _ = faucet.send_to(50_000_000, &depositor.address);
    faucet.generate_blocks(1);

    // There is only one UTXO under the depositor's name, so let's get it
    let utxos = depositor.get_utxos(rpc, None);
    let utxo = utxos.first().cloned().unwrap();
    let amount = 30_000_000;

    // 1. Create and submit a transaction where the lock script uses a
    //    lock-time at least 50 blocks in the future but also disables
    //    OP_CSV.
    let lock_time = 50 | sbtc::deposits::SEQUENCE_LOCKTIME_DISABLE_FLAG;
    assert!(lock_time > 50);

    // We're going to create a P2SH UTXO with this script. Anyone can spend
    // this script immediately, since the lock-time disables OP_CSV.
    let script_pubkey = ScriptBuf::builder()
        .push_int(lock_time)
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script();

    let mut tx0 = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint(),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::new_p2sh(&script_pubkey.script_hash()),
            },
            TxOut {
                value: utxo.amount() - Amount::from_sat(amount + fee),
                script_pubkey: depositor.address.script_pubkey(),
            },
        ],
    };

    regtest::p2tr_sign_transaction(&mut tx0, 0, &[utxo], &depositor.keypair);
    rpc.send_raw_transaction(&tx0).unwrap();

    // 2. Confirm the transaction and spend it immediately, proving that
    //    OP_CSV was disabled.
    faucet.generate_blocks(1);

    // The Builder::push_slice wants to make sure that the length of the
    // pushed data is within the limits, hence the conversion into this
    // PushBytes thing.
    let locking_script: &PushBytes = script_pubkey.as_bytes().try_into().unwrap();
    let script_sig = ScriptBuf::builder()
        .push_slice(locking_script)
        .into_script();

    let tx1 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(tx0.compute_txid(), 0),
            sequence: Sequence::ZERO,
            script_sig,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount - fee),
            script_pubkey: depositor.address.script_pubkey(),
        }],
    };
    // We just created a transaction that spends the P2SH UTXO where we
    // disabled OP_CSV. When bitcoin-core attempts to validate the
    // transaction it should pass, proving OP_CSV was disabled.
    rpc.send_raw_transaction(&tx1).unwrap();
    faucet.generate_blocks(1);

    // Note that the above script_sig is equivalent to this one, which is
    // rejected as a reclaim script.
    let reclaim = ScriptBuf::builder()
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script();
    assert!(ReclaimScriptInputs::try_new(lock_time, reclaim).is_err());

    // 3. Create and submit another transaction where the lock script uses
    //    a lock-time where OP_CSV is not disabled.
    let lock_time = 50;

    let reclaim = ScriptBuf::builder()
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script();
    // The ReclaimScriptInputs::try_new function just checks that the
    // lock_time does not disable OP_CSV, is positive, and is within
    // bitcoin-core's bounds for an acceptable value.
    let script_pubkey = ReclaimScriptInputs::try_new(lock_time, reclaim)
        .unwrap()
        .reclaim_script();
    // The script_pubkey script function above is quite simple, it should
    // produce this:
    let script_pubkey2 = ScriptBuf::builder()
        .push_int(lock_time)
        .push_opcode(bitcoin::opcodes::all::OP_CSV)
        .push_opcode(bitcoin::opcodes::all::OP_DROP)
        .push_opcode(bitcoin::opcodes::OP_TRUE)
        .into_script();
    assert_eq!(script_pubkey, script_pubkey2);

    // Get all UTXOs where their amounts are greater than 10_000_000.
    let utxos = depositor.get_utxos(rpc, Some(10_000_000));
    let utxo = utxos.first().cloned().unwrap();
    let amount = 8_000_000;

    let mut tx2 = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint(),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::new_p2sh(&script_pubkey.script_hash()),
            },
            TxOut {
                value: utxo.amount() - Amount::from_sat(amount + fee),
                script_pubkey: depositor.address.script_pubkey(),
            },
        ],
    };

    regtest::p2tr_sign_transaction(&mut tx2, 0, &[utxo], &depositor.keypair);
    rpc.send_raw_transaction(&tx2).unwrap();

    // 4. Confirm that transaction and try to spend it immediately. The
    //    transaction that tries to spend the transaction from (3) should
    //    be rejected.
    faucet.generate_blocks(1);

    // Remember, Builder::push_slice wants to make sure that the length of
    // the pushed data is within the limits, so we have to do this dance.
    let locking_script: &PushBytes = script_pubkey.as_bytes().try_into().unwrap();
    let script_sig = ScriptBuf::builder()
        .push_slice(&locking_script)
        .into_script();

    let tx3 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(tx2.compute_txid(), 0),
            sequence: Sequence::ZERO,
            script_sig,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount - fee),
            script_pubkey: depositor.address.script_pubkey(),
        }],
    };

    // In bitcoin-core v25 the message is "non-mandatory-script-verify-flag
    // (Locktime requirement not satisfied)", but in bitcoin-core v27 the
    // message is "mandatory-script-verify-flag-failed (Locktime
    // requirement not satisfied)". We match on the part that is probably
    // consistent across versions.
    match rpc.send_raw_transaction(&tx3).unwrap_err() {
        BtcRpcError::JsonRpc(JsonRpcError::Rpc(RpcError { code: -26, message, .. }))
            if message.ends_with("(Locktime requirement not satisfied)") => {}
        err => panic!("{err}"),
    };
}
