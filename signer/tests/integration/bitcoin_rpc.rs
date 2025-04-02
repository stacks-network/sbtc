//! Test the RPC clients

use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Txid;
use bitcoin::Witness;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc_json::Utxo;
use fake::{Fake, Faker};
use rand::rngs::OsRng;
use sbtc::testing::regtest;
use sbtc::testing::regtest::AsUtxo;
use sbtc::testing::regtest::Recipient;
use sbtc::testing::regtest::p2wpkh_sign_transaction;
use signer::bitcoin::BitcoinInteract;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::BitcoinTxId;

#[test]
fn btc_client_getstransaction() {
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

    let response = client.get_tx(&outpoint.txid).unwrap().unwrap();
    // Let's make sure we got the right transaction
    assert_eq!(response.tx.compute_txid(), outpoint.txid);
    assert_eq!(response.tx.output[vout].value.to_sat(), 500_000);
    // The transaction has not been confirmed, so these should be None.
    assert!(response.block_hash.is_none());
    assert!(response.block_time.is_none());
    assert!(response.confirmations.is_none());

    // Now let's confirm it and try again
    faucet.generate_blocks(1);

    let response = client.get_tx(&outpoint.txid).unwrap().unwrap();
    // Let's make sure we got the right transaction
    assert_eq!(response.tx.compute_txid(), outpoint.txid);
    assert_eq!(response.tx.output[vout].value.to_sat(), 500_000);
    // The transaction has been confirmed, so these should be `Some(_)`.
    assert!(response.block_hash.is_some());
    assert!(response.block_time.is_some());
    assert_eq!(response.confirmations, Some(1));
}

#[test]
fn btc_client_getblockheader() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();
    let (rpc, _) = regtest::initialize_blockchain();

    // Let's get the chain-tip
    let block_hash = rpc.get_best_block_hash().unwrap();
    let header = client.get_block_header(&block_hash).unwrap().unwrap();

    let block = rpc.get_block(&block_hash).unwrap();

    assert_eq!(header.hash, block.block_hash());
    assert_eq!(header.previous_block_hash, block.header.prev_blockhash);
    assert_eq!(header.height, block.bip34_block_height().unwrap());
    assert_eq!(header.time, block.header.time as u64);

    let random_hash = bitcoin::BlockHash::from_byte_array([13; 32]);
    assert!(client.get_block_header(&random_hash).unwrap().is_none());
}

#[test]
fn btc_client_gets_transaction_info() {
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

    let response = client.get_tx(&outpoint.txid).unwrap().unwrap();
    // Let's make sure we got the right transaction
    assert_eq!(response.tx.compute_txid(), outpoint.txid);
    assert_eq!(response.tx.output[vout].value.to_sat(), 500_000);
    // The transaction has not been confirmed, so these should be None.
    assert!(response.block_hash.is_none());
    assert!(response.block_time.is_none());
    assert!(response.confirmations.is_none());

    // Now let's confirm it and try again
    let block_hash = faucet.generate_blocks(1).pop().unwrap();

    let response = client
        .get_tx_info(&outpoint.txid, &block_hash)
        .unwrap()
        .unwrap();
    // Let's make sure we got the right transaction
    assert_eq!(response.tx.compute_txid(), outpoint.txid);
    assert_eq!(response.tx.output[vout].value.to_sat(), 500_000);
}

#[test]
fn btc_client_gets_transaction_info_missing_tx() {
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
    //
    let _ = client.get_tx(&outpoint.txid).unwrap();

    // Now let's confirm it and try again
    let block_hash = faucet.generate_blocks(1).pop().unwrap();

    let fake_block_hash: BitcoinBlockHash = Faker.fake_with_rng(&mut OsRng);

    let response = client
        .get_tx_info(&outpoint.txid, &fake_block_hash)
        .unwrap();

    assert!(response.is_none());

    let fake_txid: BitcoinTxId = Faker.fake_with_rng(&mut OsRng);

    let response = client.get_tx_info(&fake_txid, &block_hash).unwrap();

    assert!(response.is_none());
}

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

    assert!(client.get_tx(&txid).unwrap().is_none());
}

/// bitcoin-core will return a fee rate estimate if there are enough
/// transactions for it to do so. If this test runs last among integration
/// tests in this repo then there will be enough data for bitcoin-core to
/// estimate the fee rate, otherwise it will return an error. Since we do
/// not ensure that bitcoin-core has enough transactions to estimate fees
/// in the test, we just check that fee is positive.
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

#[tokio::test]
async fn get_tx_spending_prevout() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();

    let (rpc, faucet) = regtest::initialize_blockchain();
    let addr1 = Recipient::new(AddressType::P2wpkh);

    // Get some coins to spend (and our "utxo" outpoint).
    let outpoint = faucet.send_to(500_000, &addr1.address);
    // A coinbase transaction is not spendable until it has 100 confirmations.
    faucet.generate_blocks(1);

    // We should not have any transactions spending this outpoint in the mempool.
    let response = client.get_tx_spending_prevout(&outpoint).unwrap();
    assert!(response.is_empty());

    // Get a utxo to spend.
    let utxo = addr1.get_utxos(rpc, Some(1_000)).pop().unwrap();

    // Create a transaction that spends the utxo.
    let mut tx = bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: utxo.outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![
            bitcoin::TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: addr1.address.script_pubkey(),
            },
            bitcoin::TxOut {
                value: utxo.amount - Amount::from_sat(1_000) * 2,
                script_pubkey: addr1.address.script_pubkey(),
            },
        ],
    };

    // Sign and broadcast the transaction
    p2wpkh_sign_transaction(&mut tx, 0, &utxo, &addr1.keypair);
    client.broadcast_transaction(&tx).await.unwrap();

    // We should now have a transaction spending this outpoint in the mempool.
    let response = client.get_tx_spending_prevout(&outpoint).unwrap();

    assert_eq!(response.len(), 1);
    assert_eq!(response[0], tx.compute_txid());

    // Confirm the transaction and check again. It should no longer be in the
    // mempool, and so this should be empty.
    faucet.generate_blocks(1);

    let response = client.get_tx_spending_prevout(&outpoint).unwrap();

    assert!(response.is_empty());
}

#[tokio::test]
async fn get_tx_spending_prevout_nonexistent_txid() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();

    // Make a little noise on the blockchain so it's not empty.
    let (_, faucet) = regtest::initialize_blockchain();
    let addr = Recipient::new(AddressType::P2wpkh);
    faucet.send_to(500_000, &addr.address);
    faucet.generate_blocks(1);

    // Try to tx's spending a non-existent outpoint. It should return an empty
    // list.
    let result = client
        .get_tx_spending_prevout(&OutPoint::new(Txid::all_zeros(), 123))
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn get_mempool_descendants() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();

    let (rpc, faucet) = regtest::initialize_blockchain();
    let addr1 = Recipient::new(AddressType::P2wpkh);

    // Get some coins to spend (and our "utxo" outpoint).
    let outpoint = faucet.send_to(10_000, &addr1.address);
    faucet.generate_blocks(1);

    // There should be no transactions in the mempool spending this txid.
    let response = client.get_tx_spending_prevout(&outpoint).unwrap();
    assert!(response.is_empty());

    // Get a utxo to spend.
    let utxo = addr1.get_utxos(rpc, Some(10_000)).pop().unwrap();
    assert_eq!(utxo.txid, outpoint.txid);

    // Create a transaction that spends the utxo.
    let mut tx1 = bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: utxo.outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: addr1.address.script_pubkey(),
        }],
    };

    // Sign and broadcast the transaction
    p2wpkh_sign_transaction(&mut tx1, 0, &utxo, &addr1.keypair);
    client.broadcast_transaction(&tx1).await.unwrap();

    // This should be the only transaction in the mempool now, and it should not
    // have any descendants.
    let response = client.get_mempool_descendants(&tx1.compute_txid()).unwrap();

    assert_eq!(response.len(), 0);

    // Create a transaction that spends the utxo.
    let mut tx2 = bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: tx1.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(8_000),
            script_pubkey: addr1.address.script_pubkey(),
        }],
    };

    let utxo2 = Utxo {
        amount: Amount::from_sat(9_000),
        script_pub_key: addr1.address.script_pubkey(),
        txid: tx1.compute_txid(),
        vout: 0,
        height: 0,
        descriptor: "".into(),
    };

    // Sign and broadcast transaction #2.
    p2wpkh_sign_transaction(&mut tx2, 0, &utxo2, &addr1.keypair);
    client.broadcast_transaction(&tx2).await.unwrap();

    // Now there should be one transaction in the mempool which is a descendant
    // of tx1.
    let response = client.get_mempool_descendants(&tx1.compute_txid()).unwrap();

    assert_eq!(response.len(), 1);
    assert_eq!(response[0], tx2.compute_txid());

    // Create a new transaction that spends tx #2, creating a chain.
    let mut tx3 = bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: tx2.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: Amount::from_sat(7_000),
            script_pubkey: addr1.address.script_pubkey(),
        }],
    };

    let utxo3 = Utxo {
        amount: Amount::from_sat(8_000),
        script_pub_key: addr1.address.script_pubkey(),
        txid: tx2.compute_txid(),
        vout: 0,
        height: 0,
        descriptor: "".into(),
    };

    // Sign and broadcast transaction #3.
    p2wpkh_sign_transaction(&mut tx3, 0, &utxo3, &addr1.keypair);
    client.broadcast_transaction(&tx3).await.unwrap();

    // Now there should be two transactions in the mempool which are descendants
    // of tx1.
    let response = client.get_mempool_descendants(&tx1.compute_txid()).unwrap();

    assert_eq!(response.len(), 2);
    // Ordering is not guaranteed, so we just check that both tx2 and tx3 are
    // in the response.
    assert!(response.contains(&tx2.compute_txid()));
    assert!(response.contains(&tx3.compute_txid()));
}

#[tokio::test]
async fn get_tx_out_confirmed_no_mempool() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();

    let (_, faucet) = regtest::initialize_blockchain();
    let addr1 = Recipient::new(AddressType::P2wpkh);

    // Get some coins to spend (and our "utxo" outpoint).
    let outpoint = faucet.send_to(10_000, &addr1.address);
    faucet.generate_blocks(1);

    let txout = client
        .get_tx_out(&outpoint, false)
        .expect("error calling gettxout")
        .expect("no txout found");

    assert_eq!(txout.value, Amount::from_sat(10_000));
    assert_eq!(txout.confirmations, 1);
}

#[tokio::test]
async fn get_tx_out_confirmed_with_mempool() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();

    let (_, faucet) = regtest::initialize_blockchain();
    let addr1 = Recipient::new(AddressType::P2wpkh);

    // Get some coins to spend (and our "utxo" outpoint).
    let outpoint = faucet.send_to(10_000, &addr1.address);
    faucet.generate_blocks(1);

    let txout = client
        .get_tx_out(&outpoint, true)
        .expect("error calling gettxout")
        .expect("no txout found");

    assert_eq!(txout.value, Amount::from_sat(10_000));
    assert_eq!(txout.confirmations, 1);
}

#[tokio::test]
async fn get_tx_out_unconfirmed_no_mempool() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();

    let (_, faucet) = regtest::initialize_blockchain();
    let addr1 = Recipient::new(AddressType::P2wpkh);

    // Get some coins to spend (and our "utxo" outpoint).
    let outpoint = faucet.send_to(10_000, &addr1.address);

    let txout = client
        .get_tx_out(&outpoint, false)
        .expect("error calling gettxout");

    assert!(txout.is_none());
}

#[tokio::test]
async fn get_tx_out_unconfirmed_with_mempool() {
    let client = BitcoinCoreClient::new(
        "http://localhost:18443",
        regtest::BITCOIN_CORE_RPC_USERNAME.to_string(),
        regtest::BITCOIN_CORE_RPC_PASSWORD.to_string(),
    )
    .unwrap();

    let (_, faucet) = regtest::initialize_blockchain();
    let addr1 = Recipient::new(AddressType::P2wpkh);

    // Get some coins to spend (and our "utxo" outpoint).
    let outpoint = faucet.send_to(10_000, &addr1.address);

    let txout = client
        .get_tx_out(&outpoint, true)
        .expect("error calling gettxout")
        .expect("expected txout from mempool");

    assert_eq!(txout.value, Amount::from_sat(10_000));
    assert_eq!(txout.confirmations, 0); // Unconfirmed txs will have 0 confirmations
}
