//! Test deposit validation against bitcoin-core

use bitcoin::absolute::LockTime;
use bitcoin::opcodes;
use bitcoin::script::PushBytes;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::Version;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoincore_rpc::jsonrpc::error::Error as JsonRpcError;
use bitcoincore_rpc::jsonrpc::error::RpcError;
use bitcoincore_rpc::Error as BtcRpcError;
use bitcoincore_rpc::RpcApi;

use clarity::types::chainstate::StacksAddress;
use clarity::vm::types::PrincipalData;
use rand::rngs::OsRng;
use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::DepositScriptInputs;
use sbtc::deposits::ReclaimScriptInputs;
use sbtc::testing::deposits::TxSetup;
use sbtc::testing::regtest;
use sbtc::testing::regtest::AsUtxo;
use sbtc::testing::regtest::Recipient;
use secp256k1::SecretKey;
use secp256k1::SECP256K1;

/// Test the CreateDepositRequest::validate function.
///
/// We check that we can validate a transaction in the mempool using the
/// electrum and bitcoin-core clients
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn tx_validation_from_mempool() {
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

    let parsed = request.validate_tx(&setup.tx).unwrap();

    assert_eq!(parsed.outpoint, request.outpoint);
    assert_eq!(parsed.deposit_script, request.deposit_script);
    assert_eq!(parsed.reclaim_script, request.reclaim_script);
    assert_eq!(parsed.amount, amount_sats);
    assert_eq!(parsed.signers_public_key, setup.deposit.signers_public_key);
    assert_eq!(parsed.recipient, setup.deposit.recipient);

    let lock_time_height = bitcoin::relative::LockTime::from_height(lock_time as u16);
    assert_eq!(parsed.lock_time, lock_time_height);
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
        .push_int(lock_time as i64)
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
        .push_int(lock_time as i64)
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
fn reclaiming_rejected_deposits() {
    let max_fee: u64 = 15000;
    let amount_sats = 49_900_000;
    let lock_time = 5;

    let (rpc, faucet) = regtest::initialize_blockchain();
    let depositor = Recipient::new(AddressType::P2tr);

    // Start off with some initial UTXOs to work with.
    let outpoint = faucet.send_to(50_000_000, &depositor.address);
    faucet.generate_blocks(1);

    // There is only one UTXO under the depositor's name, so let's get it
    let utxos = depositor.get_utxos(rpc, None);

    let secret_key = SecretKey::new(&mut OsRng);

    let deposit = DepositScriptInputs {
        signers_public_key: secret_key.x_only_public_key(SECP256K1).0,
        recipient: PrincipalData::from(StacksAddress::burn_address(false)),
        max_fee,
    };
    let x_only_key = depositor.keypair.public_key().x_only_public_key().0;
    let reclaim_script = ScriptBuf::builder()
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(x_only_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    let reclaim = ReclaimScriptInputs::try_new(lock_time, reclaim_script).unwrap();

    let deposit_script = deposit.deposit_script();
    let reclaim_script = reclaim.reclaim_script();
    // This transaction is kinda invalid because it doesn't have any
    // inputs. But it is fine for our purposes.

    let deposit_utxo = TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: sbtc::deposits::to_script_pubkey(
            deposit_script.clone(),
            reclaim_script.clone(),
        ),
    };

    let mut deposit_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![deposit_utxo.clone()],
    };

    regtest::p2tr_sign_transaction(&mut deposit_tx, 0, &utxos, &depositor.keypair);
    rpc.send_raw_transaction(&deposit_tx).unwrap();

    faucet.generate_blocks(6);

    //
    let mut reclaim_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(5).unwrap(),
        input: vec![TxIn {
            previous_output: OutPoint::new(deposit_tx.compute_txid(), 0),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(amount_sats - 30000),
            script_pubkey: depositor.script_pubkey.clone(),
        }],
    };

    let input_utxos: Vec<TxOut> = vec![deposit_utxo];

    let prevouts = Prevouts::All(input_utxos.as_slice());
    let sighash_type = TapSighashType::Default;
    let mut sighasher = SighashCache::new(&reclaim_tx);
    // The signers' UTXO is always the first input in the transaction.
    // Moreover, the signers can only spend this UTXO using the taproot
    // key-spend path of UTXO.
    let leaf_hash = TapLeafHash::from_script(&reclaim_script, LeafVersion::TapScript);
    let reclaim_sighash = sighasher
        .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
        .unwrap();
    let msg = secp256k1::Message::from(reclaim_sighash);

    //

    let signature = SECP256K1.sign_schnorr(&msg, &depositor.keypair);
    let ver = LeafVersion::TapScript;
    // For such a simple tree, we construct it by hand.
    let leaf1 = NodeInfo::new_leaf_with_ver(deposit_script.clone(), ver);
    let leaf2 = NodeInfo::new_leaf_with_ver(reclaim_script.clone(), ver);

    // A Result::Err is returned by NodeInfo::combine if the depth of
    // our taproot tree exceeds the maximum depth of taproot trees,
    // which is 128. We have two nodes so the depth is 1 so this will
    // never panic.
    let node = NodeInfo::combine(leaf1, leaf2).expect("This tree depth greater than max of 128");
    let internal_key = *sbtc::UNSPENDABLE_TAPROOT_KEY;

    let taproot = TaprootSpendInfo::from_node_info(SECP256K1, internal_key, node);

    // TaprootSpendInfo::control_block returns None if the key given,
    // (script, version), is not in the tree. But this key is definitely
    // in the tree (see the variable leaf1 in the `construct_taproot_info`
    // function).
    let control_block = taproot
        .control_block(&(dbg!(reclaim_script.clone()), ver))
        .unwrap();

    let witness_data = [
        signature.serialize().to_vec(),
        reclaim_script.to_bytes(),
        control_block.serialize(),
    ];
    reclaim_tx.input[0].witness = Witness::from_slice(&witness_data);

    faucet.generate_blocks(6);

    rpc.send_raw_transaction(&reclaim_tx).unwrap();
    faucet.generate_blocks(1);
}
