use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use bitcoin::absolute::LockTime;
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
use bitcoin::XOnlyPublicKey;
use bitcoincore_rpc::RpcApi as _;
use bitvec::array::BitArray;
use clarity::vm::types::PrincipalData;
use fake::Fake;
use rand::distributions::Uniform;
use rand::rngs::OsRng;
use rand::Rng as _;
use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::DepositInfo;
use sbtc::deposits::DepositScriptInputs;
use sbtc::deposits::ReclaimScriptInputs;
use signer::bitcoin::utxo::DepositRequest;
use signer::bitcoin::utxo::SbtcRequests;
use signer::bitcoin::utxo::SignerBtcState;
use signer::bitcoin::utxo::SignerUtxo;
use signer::bitcoin::utxo::WithdrawalRequest;
use signer::context::SbtcLimits;
use signer::DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX;
use stacks_common::types::chainstate::StacksAddress;

use regtest::Recipient;
use sbtc::testing::regtest;
use sbtc::testing::regtest::AsUtxo;

pub static REQUEST_IDS: AtomicU64 = AtomicU64::new(0);

pub fn generate_withdrawal() -> (WithdrawalRequest, Recipient) {
    let recipient = Recipient::new(AddressType::P2tr);
    let amount = OsRng.sample(Uniform::new(200_000, 250_000));

    let req = WithdrawalRequest {
        amount,
        max_fee: amount / 2,
        script_pubkey: recipient.script_pubkey.clone().into(),
        signer_bitmap: BitArray::ZERO,
        request_id: REQUEST_IDS.fetch_add(1, Ordering::Relaxed),
        txid: fake::Faker.fake_with_rng(&mut OsRng),
        block_hash: fake::Faker.fake_with_rng(&mut OsRng),
    };

    (req, recipient)
}

pub fn make_deposit_request<U>(
    depositor: &Recipient,
    amount: u64,
    utxo: U,
    max_fee: u64,
    signers_public_key: XOnlyPublicKey,
) -> (Transaction, DepositRequest, DepositInfo)
where
    U: AsUtxo,
{
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let deposit_inputs = DepositScriptInputs {
        signers_public_key,
        max_fee,
        recipient: PrincipalData::from(StacksAddress::burn_address(false)),
    };
    let reclaim_inputs = ReclaimScriptInputs::try_new(50, ScriptBuf::new()).unwrap();

    let deposit_script = deposit_inputs.deposit_script();
    let reclaim_script = reclaim_inputs.reclaim_script();

    let mut deposit_tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(utxo.txid(), utxo.vout()),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: sbtc::deposits::to_script_pubkey(
                    deposit_script.clone(),
                    reclaim_script.clone(),
                ),
            },
            TxOut {
                value: utxo.amount() - Amount::from_sat(amount + fee),
                script_pubkey: depositor.address.script_pubkey(),
            },
        ],
    };

    regtest::p2tr_sign_transaction(&mut deposit_tx, 0, &[utxo], &depositor.keypair);

    let create_req = CreateDepositRequest {
        outpoint: OutPoint::new(deposit_tx.compute_txid(), 0),
        deposit_script,
        reclaim_script,
    };

    let dep = create_req.validate_tx(&deposit_tx, false).unwrap();

    let req = DepositRequest {
        outpoint: dep.outpoint,
        max_fee: dep.max_fee,
        signer_bitmap: BitArray::ZERO,
        amount: dep.amount,
        deposit_script: dep.deposit_script.clone(),
        reclaim_script: dep.reclaim_script.clone(),
        signers_public_key: dep.signers_public_key,
    };
    (deposit_tx, req, dep)
}

/// This test just checks that many of the methods on the Recipient struct
/// work as advertised.
#[test]
#[cfg_attr(not(feature = "integration-tests"), ignore)]
fn helper_struct_methods_work() {
    let (rpc, faucet) = regtest::initialize_blockchain();
    let signer = Recipient::new(AddressType::P2tr);

    // Newly created "recipients" do not have any UTXOs associated with
    // their address.
    let balance = signer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 0);

    // Okay now we send coins to an address from the one address that
    // coins have been mined to.
    faucet.send_to(500_000, &signer.address);
    faucet.generate_blocks(1);

    // Now the balance should be updated, and the amount sent should be
    // adjusted too.
    let balance = signer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 500_000);

    // Now let's have a third address get some coin from our signer address.
    let withdrawal_recipient = Recipient::new(AddressType::P2wpkh);

    // Again, this third address doesn't have any UTXOs associated with it.
    let balance = withdrawal_recipient.get_balance(rpc);
    assert_eq!(balance.to_sat(), 0);

    // Now we check that get_utxos do what we want
    let mut utxos = signer.get_utxos(rpc, None);
    assert_eq!(utxos.len(), 1);
    let utxo = utxos.pop().unwrap();

    assert_eq!(utxo.amount.to_sat(), 500_000);
}

/// Check that deposits, when sent with the expected format, are
/// spent using the transactions generated in the utxo module.
#[test]
#[cfg_attr(not(feature = "integration-tests"), ignore)]
fn deposits_add_to_controlled_amounts() {
    let (rpc, faucet) = regtest::initialize_blockchain();
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

    let signer = Recipient::new(AddressType::P2tr);
    let depositor = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;

    // Start off with some initial UTXOs to work with.
    faucet.send_to(100_000_000, &signer.address);
    faucet.send_to(50_000_000, &depositor.address);
    faucet.generate_blocks(1);

    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);
    assert_eq!(depositor.get_balance(rpc).to_sat(), 50_000_000);

    // Now lets make a deposit transaction and submit it
    let depositor_utxo = depositor.get_utxos(rpc, None).pop().unwrap();
    let deposit_amount = 25_000_000;
    let max_fee = deposit_amount / 2;

    let (deposit_tx, deposit_request, _) = make_deposit_request(
        &depositor,
        deposit_amount,
        depositor_utxo,
        max_fee,
        signers_public_key,
    );
    rpc.send_raw_transaction(&deposit_tx).unwrap();
    faucet.generate_blocks(1);

    // The depositor's balance should be updated now.
    let depositor_balance = depositor.get_balance(rpc);
    assert_eq!(depositor_balance.to_sat(), 50_000_000 - 25_000_000 - fee);
    // We deposited the transaction to the signer, but it's not clear to the
    // wallet tracking the signer's address that the deposit is associated
    // with the signer since it's hidden within the merkle tree.
    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);

    // Okay now we try to peg-in the deposit by making a transaction. Let's
    // start by getting the signer's sole UTXO.
    let signer_utxo = signer.get_utxos(rpc, None).pop().unwrap();

    // Now build the struct with the outstanding peg-in and peg-out requests.
    let requests = SbtcRequests {
        deposits: vec![deposit_request],
        withdrawals: Vec::new(),
        signer_state: SignerBtcState {
            utxo: SignerUtxo {
                outpoint: OutPoint::new(signer_utxo.txid, signer_utxo.vout),
                amount: signer_utxo.amount.to_sat(),
                public_key: signers_public_key,
            },
            fee_rate: 10.0,
            public_key: signers_public_key,
            last_fees: None,
            magic_bytes: [b'T', b'3'],
        },
        accept_threshold: 4,
        num_signers: 7,
        sbtc_limits: SbtcLimits::unlimited(),
        max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
    };

    // There should only be one transaction here since there is only one
    // deposit request and no withdrawal requests.
    let mut transactions = requests.construct_transactions().unwrap();
    assert_eq!(transactions.len(), 1);
    let mut unsigned = transactions.pop().unwrap();

    // Add the signature and/or other required information to the witness data.
    signer::testing::set_witness_data(&mut unsigned, signer.keypair);

    // The moment of truth, does the network accept the transaction?
    rpc.send_raw_transaction(&unsigned.tx).unwrap();
    faucet.generate_blocks(1);

    // The signer's balance should now reflect the deposit.
    let signers_balance = signer.get_balance(rpc);

    more_asserts::assert_gt!(signers_balance.to_sat(), 124_000_000);
    more_asserts::assert_lt!(signers_balance.to_sat(), 125_000_000);
}

#[test]
#[cfg_attr(not(feature = "integration-tests"), ignore)]
fn withdrawals_reduce_to_signers_amounts() {
    const FEE_RATE: f64 = 10.0;

    let (rpc, faucet) = regtest::initialize_blockchain();
    let fallback_fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let signer = Recipient::new(AddressType::P2tr);
    let signers_public_key = signer.keypair.x_only_public_key().0;

    // Start off with some initial UTXOs to work with.
    faucet.send_to(100_000_000, &signer.address);
    faucet.generate_blocks(1);

    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);

    // Now lets make a withdrawal request. This recipient shouldn't
    // have any coins to their name.
    let (withdrawal_request, recipient) = generate_withdrawal();
    assert_eq!(recipient.get_balance(rpc).to_sat(), 0);

    // Okay now we try to peg-out the withdrawal by making a transaction. Let's
    // start by getting the signer's sole UTXO.
    let signer_utxo = signer.get_utxos(rpc, None).pop().unwrap();

    // Now build the struct with the outstanding peg-in and peg-out requests.
    let requests = SbtcRequests {
        deposits: Vec::new(),
        withdrawals: vec![withdrawal_request.clone()],
        signer_state: SignerBtcState {
            utxo: SignerUtxo {
                outpoint: OutPoint::new(signer_utxo.txid, signer_utxo.vout),
                amount: signer_utxo.amount.to_sat(),
                public_key: signers_public_key,
            },
            fee_rate: FEE_RATE,
            public_key: signers_public_key,
            last_fees: None,
            magic_bytes: [b'T', b'3'],
        },
        accept_threshold: 4,
        num_signers: 7,
        sbtc_limits: SbtcLimits::unlimited(),
        max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
    };

    // There should only be one transaction here since there is only one
    // withdrawal request and no deposit requests.
    let mut transactions = requests.construct_transactions().unwrap();
    assert_eq!(transactions.len(), 1);
    let mut unsigned = transactions.pop().unwrap();

    // Add the signature and/or other required information to the witness data.
    signer::testing::set_witness_data(&mut unsigned, signer.keypair);

    // Ship it
    rpc.send_raw_transaction(&unsigned.tx).unwrap();
    faucet.generate_blocks(1);

    // The signer's balance should now reflect the withdrawal.
    // Note that the signer started with 1 BTC.
    let signers_balance = signer.get_balance(rpc).to_sat();

    assert_eq!(
        signers_balance,
        100_000_000 - withdrawal_request.amount - unsigned.tx_fee
    );

    let withdrawal_fee = unsigned.input_amounts() - unsigned.output_amounts();
    let recipient_balance = recipient.get_balance(rpc).to_sat();
    assert_eq!(recipient_balance, withdrawal_request.amount);

    // Let's check that we have the right fee rate too.
    let fee_rate = withdrawal_fee as f64 / unsigned.tx.vsize() as f64;
    more_asserts::assert_ge!(fee_rate, FEE_RATE);
    more_asserts::assert_lt!(fee_rate, FEE_RATE + 1.0);

    // Now we construct another transaction where the withdrawing
    // recipient pays to someone else.
    let another_recipient = Recipient::new(AddressType::P2wpkh);
    let another_recipient_balance = another_recipient.get_balance(rpc).to_sat();
    assert_eq!(another_recipient_balance, 0);

    // Get the UTXO that the signer sent to the withdrawing user.
    let withdrawal_utxo = recipient.get_utxos(rpc, None).pop().unwrap();
    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(withdrawal_utxo.txid, withdrawal_utxo.vout),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: another_recipient.address.script_pubkey(),
            },
            TxOut {
                value: withdrawal_utxo.amount() - Amount::from_sat(50_000 + fallback_fee),
                script_pubkey: recipient.address.script_pubkey(),
            },
        ],
    };
    regtest::p2tr_sign_transaction(&mut tx, 0, &[withdrawal_utxo], &recipient.keypair);

    // Ship it
    rpc.send_raw_transaction(&tx).unwrap();
    faucet.generate_blocks(1);

    // Let's make sure their ending balances are correct. We start with the
    // Withdrawal recipient.
    let recipient_balance = recipient.get_balance(rpc).to_sat();
    assert_eq!(
        recipient_balance,
        withdrawal_request.amount - 50_000 - fallback_fee
    );

    // And what about the person that they just sent coins to?
    let another_recipient_balance = another_recipient.get_balance(rpc).to_sat();
    assert_eq!(another_recipient_balance, 50_000);
}
