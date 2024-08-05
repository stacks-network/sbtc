//! Test deposit validation against bitcoin-core

use bitcoin::AddressType;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::TxIn;
use bitcoin::Witness;
use bitcoincore_rpc::RpcApi;

use sbtc::deposits::CreateDepositRequest;
use sbtc::rpc::BitcoinClient;
use sbtc::rpc::BitcoinCoreClient;
use sbtc::rpc::ElectrumClient;
use sbtc::testing::deposits::TxSetup;
use sbtc::testing::regtest;
use sbtc::testing::regtest::Recipient;

use test_case::test_case;

/// Test the CreateDepositRequest::validate function.
///
/// We check that we can validate a transaction in the mempool using the
/// electrum and bitcoin-core clients
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case(BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap(); "bitcoin client")]
#[test_case(ElectrumClient::new("tcp://localhost:60401", None).unwrap() ; "electrum client")]
fn tx_validation_from_mempool<C: BitcoinClient>(client: C) {
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

    let parsed = request.validate(&client).unwrap().info;

    assert_eq!(parsed.outpoint, request.outpoint);
    assert_eq!(parsed.deposit_script, request.deposit_script);
    assert_eq!(parsed.reclaim_script, request.reclaim_script);
    assert_eq!(parsed.amount, amount_sats);
    assert_eq!(parsed.signers_public_key, setup.deposit.signers_public_key);
    assert_eq!(parsed.lock_time, lock_time as u64);
    assert_eq!(parsed.recipient, setup.deposit.recipient);
}
