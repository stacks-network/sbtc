//! Test the RPC clients

use bitcoin::hashes::Hash;
use bitcoin::AddressType;
use sbtc::error::Error;
use sbtc::rpc::BitcoinCoreClient;
use sbtc::testing::regtest;
use sbtc::testing::regtest::Recipient;

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn btc_client_gets_transactions() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();
    let (rpc, faucet) = regtest::initialize_blockchain();
    let signer = Recipient::new(AddressType::P2tr);

    // Newly created "recipients" do not have any UTXOs associated with
    // their address.
    let balance = signer.get_balance(rpc);
    assert_eq!(balance.to_sat(), 0);

    // Okay now we send coins to an address from the one address that
    // coins have been mined to.
    let outpoint = faucet.send_to(500_000, &signer.address);
    let vout = outpoint.vout as usize;

    let response = client.get_tx(&outpoint.txid).unwrap();
    // Let's make sure we got the right transaction
    assert_eq!(response.tx.compute_txid(), outpoint.txid);
    assert_eq!(response.tx.output[vout].value.to_sat(), 500_000);
    // The transaction has not been confirmed, so these should be None.
    assert!(response.block_hash.is_none());
    assert!(response.block_time.is_none());
    assert!(response.confirmations.is_none());
    assert!(response.in_active_chain.is_none());

    // Now let's confirm it and try again
    faucet.generate_blocks(1);

    let response = client.get_tx(&outpoint.txid).unwrap();
    // Let's make sure we got the right transaction
    assert_eq!(response.tx.compute_txid(), outpoint.txid);
    assert_eq!(response.tx.output[vout].value.to_sat(), 500_000);
    // The transaction has been confirmed, so these should be `Some(_)`.
    assert!(response.block_hash.is_some());
    assert!(response.block_time.is_some());
    assert_eq!(response.confirmations, Some(1));
    // The `in_active_chain` field is tricky, it needs more confirmations
    // before it is set. Moreover, it only gets set with the electrum
    // client. Under the hood, electrum looks up the blockhash of the given
    // txid and makes a getrawtransaction call to bitcoin-core with this
    // optional blockhash input, and bitcoin-core will only set the
    // `in_active_chain` field in the response if it has the blockhash
    // input in the request. So we stop here and just check that it is
    // still None. If this was the ElectrumClient then after one more
    // `faucet.generate_blocks(1)` call it would be set to `Some(true)`.
    assert!(response.in_active_chain.is_none());
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn btc_client_unsubmitted_tx() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();
    let _ = regtest::initialize_blockchain();
    let txid = bitcoin::Txid::all_zeros();

    match client.get_tx(&txid).unwrap_err() {
        Error::GetTransactionBitcoinCore(_, txid1) if txid1 == txid => {}
        _ => panic!("Incorrect error variants returned"),
    }
}

/// bitcoin-core will return a fee rate estimate if there are enough
/// transactions for it to do so. If this test runs last among integration
/// tests in this repo then there will be enough data for bitcoin-core to
/// estimate the fee rate, otherwise it will return an error. Since we do
/// not ensure that bitcoin-core has enough transactions to estimate fees
/// in the test, we just check that fee is positive.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn estimate_fee_rate() {
    let _ = regtest::initialize_blockchain();
    let btc_client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();
    let resp = btc_client.estimate_fee_rate(1);

    if resp.is_ok() {
        assert!(resp.unwrap().sats_per_vbyte > 0.0);
    }
}
