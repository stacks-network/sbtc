use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes;
use bitcoin::hashes::Hash;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::Version;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::PubkeyHash;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::TapLeafHash;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::XOnlyPublicKey;
use bitcoincore_rpc::json::ListUnspentResultEntry;
use bitcoincore_rpc::RpcApi;
use secp256k1::SECP256K1;
use signer::utxo::DepositRequest;
use signer::utxo::SbtcRequests;
use signer::utxo::SignerBtcState;
use signer::utxo::SignerUtxo;

use crate::regtest;
use regtest::Either;
use regtest::Recipient;

const SIGNER_ADDRESS_LABEL: Option<&str> = Some("signers-label");
const DEPOSITS_LABEL: Option<&str> = Some("deposits");

fn make_deposit_request(
    depositor: &Recipient,
    amount: u64,
    utxo: &ListUnspentResultEntry,
    signers_public_key: XOnlyPublicKey,
    faucet_public_key: XOnlyPublicKey,
) -> (Transaction, DepositRequest) {
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let deposit_script = ScriptBuf::builder()
        // Just some dummy data, since we don't test the parsing of the sBTC request data here.
        .push_slice([1, 2, 3, 4])
        .push_opcode(opcodes::all::OP_DROP)
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(PubkeyHash::hash(&signers_public_key.serialize()))
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();

    let redeem_script = ScriptBuf::new_op_return([0u8, 1, 2, 3]);
    let ver = LeafVersion::TapScript;
    let leaf1 = NodeInfo::new_leaf_with_ver(deposit_script.clone(), ver);
    let leaf2 = NodeInfo::new_leaf_with_ver(redeem_script.clone(), ver);

    let node = NodeInfo::combine(leaf1, leaf2).unwrap();
    let taproot = TaprootSpendInfo::from_node_info(SECP256K1, faucet_public_key, node);
    let merkle_root = taproot.merkle_root();

    let deposit_tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(utxo.txid, utxo.vout),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: ScriptBuf::new_p2tr(SECP256K1, faucet_public_key, merkle_root),
            },
            TxOut {
                value: utxo.amount - Amount::from_sat(amount + fee),
                script_pubkey: depositor.address.script_pubkey(),
            },
        ],
    };

    let (mut tx, signature) = regtest::p2tr_signature(
        deposit_tx,
        0,
        &[utxo.clone()],
        depositor.keypair,
        Either::Left(None),
    );
    tx.input[0].witness = Witness::p2tr_key_spend(&signature);

    let req = DepositRequest {
        outpoint: OutPoint::new(tx.compute_txid(), 0),
        max_fee: fee,
        signer_bitmap: Vec::new(),
        amount: 25_000_000,
        deposit_script: deposit_script.clone(),
        redeem_script: redeem_script.clone(),
        taproot_public_key: faucet_public_key,
        signers_public_key,
    };
    (tx, req)
}

/// This test just checks that many of the methods on the Recipient struct
/// work as advertised.
#[test]
#[cfg_attr(not(feature = "integration-tests"), ignore)]
fn helper_struct_methods_work() {
    let (rpc, faucet) = regtest::initialize_blockchain();
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

    let signer = Recipient::new(AddressType::P2tr);
    signer.track_address(rpc, SIGNER_ADDRESS_LABEL);

    // Newly created "recipients" do not have any UTXOs associated with
    // their address.
    let balance = signer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 0);

    // Okay now we send coins to an address from the one address that
    // coins have been mined to.
    faucet.send_to(rpc, 500_000, &signer.address);
    faucet.generate_blocks(rpc, 1);

    // Now the balance should be updated, and the amount sent should be
    // adjusted too.
    let balance = signer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 500_000);

    // Now let's have a third address get some coin from our signer address.
    let withdrawer = Recipient::new(AddressType::P2wpkh);
    withdrawer.track_address(rpc, Some("withdrawer"));

    // Again, this third address doesn't have any UTXOs associated with it.
    let balance = withdrawer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 0);

    // Now we send some coin to the withdrawer address. The signers' balance
    // will be updated accordingly. Note that the amount deducted from the
    // sender always incorporates fees. Also note that we do not need to
    // mine the block in order for the balance to be properly updated.
    signer.send_to(rpc, 200_000, &withdrawer.address);
    let balance = signer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 500_000 - 200_000 - fee);

    // The withdrawer now has the desired balance since we sent it some.
    let balance = withdrawer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 200_000);
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
    signer.track_address(&rpc, SIGNER_ADDRESS_LABEL);
    depositor.track_address(rpc, DEPOSITS_LABEL);

    // Start off with some initial UTXOs to work with.
    faucet.send_to(rpc, 100_000_000, &signer.address);
    faucet.send_to(rpc, 50_000_000, &depositor.address);
    faucet.generate_blocks(&rpc, 1);

    assert_eq!(signer.get_balance(rpc).to_sat(), 100_000_000);
    assert_eq!(depositor.get_balance(rpc).to_sat(), 50_000_000);

    // Now lets make a deposit transaction and submit it
    let depositor_utxo = depositor.get_utxos(rpc, None).pop().unwrap();
    let deposit_amount = 25_000_000;

    let (deposit_tx, deposit_request) = make_deposit_request(
        &depositor,
        deposit_amount,
        &depositor_utxo,
        signers_public_key,
        faucet.keypair.x_only_public_key().0,
    );
    rpc.send_raw_transaction(&deposit_tx).unwrap();
    faucet.generate_blocks(rpc, 1);

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
            fee_rate: 10,
            public_key: signers_public_key,
        },
        accept_threshold: 4,
        num_signers: 7,
    };

    // There should only be one transaction here since there is only one
    // deposit request and no withdrawal requests.
    let mut transactions = requests.construct_transactions().unwrap();
    assert_eq!(transactions.len(), 1);
    let unsigned = transactions.pop().unwrap();

    // Now we need to sign the transaction. For that we need the UTXOs used as
    // inputs and the script in the merkle tree.
    let signer_utxo_2 = TxOut {
        value: signer_utxo.amount,
        script_pubkey: signer_utxo.script_pub_key.clone(),
    };
    let utxos = [signer_utxo_2, deposit_tx.output[0].clone()];

    let deposit_script = requests.deposits[0].deposit_script.as_script();
    let leaf_hash = TapLeafHash::from_script(deposit_script, LeafVersion::TapScript);

    // Let's produce signatures for each of the two inputs. The first input
    // corresponds to the signer's UTXO, while the second input is from the
    // deposit transaction.
    let (tx, signature1) =
        regtest::p2tr_signature(unsigned.tx, 0, &utxos, signer.keypair, Either::Left(None));
    let (mut tx, signature2) =
        regtest::p2tr_signature(tx, 1, &utxos, signer.keypair, Either::Right(leaf_hash));

    // Add the signature and/or other required information to the witness data.
    tx.input[0].witness = Witness::p2tr_key_spend(&signature1);
    tx.input[1].witness = requests.deposits[0].construct_witness_data(signature2);

    // The moment of truth, does the network accept the transaction?
    rpc.send_raw_transaction(&tx).unwrap();
    faucet.generate_blocks(rpc, 1);

    // The signer's balance should now reflect the deposit.
    let signers_balance = signer.get_balance(rpc);

    more_asserts::assert_gt!(signers_balance.to_sat(), 124_000_000);
    more_asserts::assert_lt!(signers_balance.to_sat(), 125_000_000);
}
