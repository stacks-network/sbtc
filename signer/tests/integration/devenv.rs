//! Integration tests using both bitcoin and stack nodes.
//!
//! To run these test first run devenv:
//! ```bash
//! make devenv-up
//! ```
//! And wait for nakamoto to kick in; finally, stop the bitcoin miner.
//!
//! You also need to fund the faucet (after a while it will unlock coinbase):
//! ```bash
//! cargo run -p signer --bin demo-cli fund-btc --recipient BCRT1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KYGT080 --amount 1000000000
//! cargo run -p signer --bin demo-cli forward
//! ```

use bitcoin::OutPoint;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::XOnlyPublicKey;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitvec::array::BitArray;
use clarity::vm::ClarityName;
use clarity::vm::ContractName;
use clarity::vm::Value;
use clarity::vm::types::PrincipalData;
use fake::Fake as _;
use more_asserts::assert_ge;
use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::DepositInfo;
use sbtc::deposits::DepositScriptInputs;
use sbtc::deposits::ReclaimScriptInputs;
use sbtc::testing::regtest::AsUtxo;
use serde::Deserialize;
use serde_json::to_value;
use signer::bitcoin::utxo::DepositRequest;
use signer::error::Error;
use signer::stacks::contracts::SmartContract;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::ScriptBuf;
use bitcoin::consensus::encode::serialize_hex;
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc_json::Utxo;
use clarity::types::Address as _;
use clarity::types::chainstate::StacksAddress;
use emily_client::apis::deposit_api;
use emily_client::models::CreateDepositRequestBody;
use rand::rngs::OsRng;
use sbtc::testing::regtest;
use sbtc::testing::regtest::Recipient;
use signer::context::SbtcLimits;

use signer::block_observer::BlockObserver;
use signer::context::Context as _;
use signer::context::SignerEvent;
use signer::context::SignerSignal;
use signer::emily_client::EmilyClient;
use signer::keys::SignerScriptPubKey;
use signer::stacks::api::StacksClient;
use signer::stacks::api::StacksInteract as _;
use signer::storage::DbRead as _;
use signer::storage::model::StacksPrincipal;
use signer::testing;
use signer::testing::context::TestContext;
use signer::testing::context::*;
use signer::testing::storage::DbReadTestExt;
use url::Url;

use crate::zmq::BITCOIN_CORE_ZMQ_ENDPOINT;

const DEVENV_DEPLOYER: &str = "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS";

#[ignore = "This is an integration test that requires devenv running"]
#[test_log::test(tokio::test)]
async fn process_blocks_simple_fork() {
    let db = testing::storage::new_test_database().await;

    let stacks_client = StacksClient::new(Url::parse("http://127.0.0.1:20443").unwrap()).unwrap();

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_stacks_client(stacks_client.clone())
        .with_mocked_emily_client()
        .build();

    let (rpc, faucet) = regtest::initialize_blockchain_devenv();

    // No need for deposits here
    ctx.with_emily_client(|client| {
        client
            .expect_get_deposits()
            .returning(move || Box::pin(std::future::ready(Ok(vec![]))));

        client
            .expect_get_limits()
            .times(1..)
            .returning(|| Box::pin(async { Ok(SbtcLimits::unlimited()) }));
    })
    .await;

    let block_observer = BlockObserver {
        context: ctx.clone(),
        bitcoin_blocks: testing::btc::new_zmq_block_hash_stream(BITCOIN_CORE_ZMQ_ENDPOINT).await,
    };

    // We need to wait for the block observer to be up
    let start_flag = Arc::new(AtomicBool::new(false));
    let flag = start_flag.clone();

    let mut signal_rx = ctx.get_signal_receiver();
    let block_observer_handle = tokio::spawn(async move {
        flag.store(true, Ordering::Relaxed);
        block_observer.run().await
    });

    while !start_flag.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // At this point, the block observer is ready

    // First, let's check everything works
    faucet.send_to(1001, &faucet.address);
    let block_1a = faucet.generate_block();

    // Let's wait for the block observer signal
    let signal = signal_rx.recv();
    let Ok(SignerSignal::Event(SignerEvent::BitcoinBlockObserved)) = signal.await else {
        panic!("Not the right signal")
    };

    let (bitcoin_tip_original, _) = db.get_chain_tips().await;
    assert_eq!(block_1a, bitcoin_tip_original.block_hash.into());

    // Now we fork by invalidating the tip and creating a 2 blocks branch
    rpc.invalidate_block(&block_1a).unwrap();
    // Need also to add some other tx to ensure we get a different block hash
    faucet.send_to(1002, &faucet.address);
    let block_1b = faucet.generate_block();
    assert_ne!(block_1a, block_1b);

    let block_2b = faucet.generate_block();

    // Let's wait for the block observer signal
    let signal = signal_rx.recv();
    let Ok(SignerSignal::Event(SignerEvent::BitcoinBlockObserved)) = signal.await else {
        panic!("Not the right signal")
    };

    let (bitcoin_tip_fork, _) = db.get_chain_tips().await;
    assert_eq!(block_2b, bitcoin_tip_fork.block_hash.into());
    assert_eq!(
        bitcoin_tip_original.block_height + 1,
        bitcoin_tip_fork.block_height
    );

    let original_in_fork = db
        .in_canonical_bitcoin_blockchain(&bitcoin_tip_fork, &bitcoin_tip_original)
        .await
        .unwrap();
    assert!(!original_in_fork);

    block_observer_handle.abort();
    testing::storage::drop_db(db).await;
}

/// Same as `make_deposit_request`, but with a recipient (and no dust change)
fn make_deposit_request<U>(
    depositor: &Recipient,
    amount: u64,
    utxo: U,
    max_fee: u64,
    signers_public_key: XOnlyPublicKey,
    recipient_address: PrincipalData,
) -> (Transaction, DepositRequest, DepositInfo)
where
    U: AsUtxo,
{
    let fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let deposit_inputs = DepositScriptInputs {
        signers_public_key,
        max_fee,
        recipient: recipient_address,
    };
    let reclaim_inputs = ReclaimScriptInputs::try_new(50, ScriptBuf::new()).unwrap();

    let deposit_script = deposit_inputs.deposit_script();
    let reclaim_script = reclaim_inputs.reclaim_script();

    let mut tx_outs = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: sbtc::deposits::to_script_pubkey(
            deposit_script.clone(),
            reclaim_script.clone(),
        ),
    }];

    let change = utxo.amount() - Amount::from_sat(amount + fee);
    if change.to_sat() > 546 as u64 {
        tx_outs.push(TxOut {
            value: change,
            script_pubkey: depositor.address.script_pubkey(),
        });
    }
    let mut deposit_tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(utxo.txid(), utxo.vout()),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: tx_outs,
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

async fn create_nop_transaction<U>(sender: &Recipient, utxo: U, fee: Amount) -> Transaction
where
    U: AsUtxo,
{
    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(utxo.txid(), utxo.vout()),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: utxo.amount() - fee,
            script_pubkey: sender.address.script_pubkey(),
        }],
    };

    regtest::p2tr_sign_transaction(&mut tx, 0, &[utxo], &sender.keypair);
    tx
}

async fn get_sbtc_balance(
    stacks_client: &StacksClient,
    deployer: &StacksAddress,
    address: &PrincipalData,
) -> Result<Amount, Error> {
    let result = stacks_client
        .call_read(
            deployer,
            &ContractName::from(SmartContract::SbtcToken.contract_name()),
            &ClarityName::from("get-balance"),
            deployer,
            &[Value::Principal(address.clone())],
        )
        .await?;

    match result {
        Value::Response(response) => match *response.data {
            Value::UInt(total_supply) => Ok(Amount::from_sat(
                u64::try_from(total_supply)
                    .map_err(|_| Error::InvalidStacksResponse("invalid u64"))?,
            )),
            _ => Err(Error::InvalidStacksResponse(
                "expected a uint but got something else",
            )),
        },
        _ => Err(Error::InvalidStacksResponse(
            "expected a response but got something else",
        )),
    }
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct GenerateBlockJson {
    pub hash: bitcoin::BlockHash,
}

/// Test what happens to a minted deposit if the sweep tx forks.
/// This test relies on the integration env signers to do the actual work.
#[ignore = "This is an integration test that requires devenv running"]
#[test_log::test(tokio::test)]
async fn orphaned_deposit() {
    let stacks = StacksClient::new(Url::parse("http://127.0.0.1:20443").unwrap()).unwrap();
    let (rpc, faucet) = regtest::initialize_blockchain_devenv();
    let emily_client = EmilyClient::try_new(
        &Url::parse("http://testApiKey@127.0.0.1:3031").unwrap(),
        Duration::from_secs(1),
        None,
    )
    .unwrap();

    // Ensure there's a signers UTXO
    let deployer = StacksAddress::from_string(DEVENV_DEPLOYER).unwrap();
    let aggregate_key = stacks
        .get_current_signers_aggregate_key(&deployer)
        .await
        .unwrap()
        .expect("no signers aggregate key");
    let signers_address = Address::from_script(
        &aggregate_key.signers_script_pubkey(),
        bitcoin::Network::Regtest,
    )
    .unwrap();
    faucet.send_to(1000, &signers_address);
    faucet.generate_block();

    // Create a deposit request
    let deposit_amount = 100_000;
    let tx_fee = regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

    let depositor = Recipient::new(AddressType::P2tr);
    let recipient: StacksPrincipal = fake::Faker.fake_with_rng(&mut OsRng);
    dbg!(&recipient);

    // Send some extra to ensure `make_deposit_request` doesn't create dust change
    let depositor_fund_outpoint = faucet.send_to(deposit_amount * 2 + tx_fee, &depositor.address);
    faucet.generate_block();

    let depositor_utxo = Utxo {
        txid: depositor_fund_outpoint.txid,
        vout: depositor_fund_outpoint.vout,
        script_pub_key: depositor.address.script_pubkey(),
        descriptor: "".to_string(),
        amount: Amount::from_sat(deposit_amount * 2 + tx_fee),
        height: 0,
    };
    let max_fee = deposit_amount / 2;
    let (deposit_tx, deposit_request, _) = make_deposit_request(
        &depositor,
        deposit_amount,
        depositor_utxo.clone(),
        max_fee,
        aggregate_key.into(),
        recipient.clone().into(),
    );
    rpc.send_raw_transaction(&deposit_tx).unwrap();
    let block_deposit_tx = faucet.generate_block();

    let emily_request = CreateDepositRequestBody {
        bitcoin_tx_output_index: deposit_request.outpoint.vout,
        bitcoin_txid: deposit_request.outpoint.txid.to_string(),
        deposit_script: deposit_request.deposit_script.to_hex_string(),
        reclaim_script: deposit_request.reclaim_script.to_hex_string(),
        transaction_hex: serialize_hex(&deposit_tx),
    };

    deposit_api::create_deposit(emily_client.config(), emily_request.clone())
        .await
        .expect("cannot create emily deposit");

    // Wait for the signers to process the deposit
    tokio::time::sleep(Duration::from_secs(5)).await;
    faucet.generate_block();

    // Then wait for the signers to mint the deposit
    tokio::time::sleep(Duration::from_secs(5)).await;
    faucet.generate_block();

    // Check that the recipient did get the expected sBTC
    let balance = get_sbtc_balance(&stacks, &deployer, &recipient.clone().into())
        .await
        .unwrap();
    dbg!(&balance);
    assert_ge!(balance.to_sat(), deposit_amount - max_fee);

    // Now we fork:
    //  - we invalidate the deposit tx block via rpc
    rpc.invalidate_block(&block_deposit_tx).unwrap();

    //  - we invalidate the deposit tx by spending its vin
    let invlidating_deposit_tx = create_nop_transaction(
        &depositor,
        depositor_utxo.clone(),
        // must be more than the package (deposit tx + sweep) in mempool to be
        // accepted as RBF
        regtest::BITCOIN_CORE_FALLBACK_FEE * 100,
    )
    .await;
    let invlidating_deposit_txid = rpc.send_raw_transaction(&invlidating_deposit_tx).unwrap();

    rpc.call::<GenerateBlockJson>(
        "generateblock",
        &[
            faucet.address.to_string().into(),
            to_value(&[invlidating_deposit_txid.to_string()]).unwrap(),
        ],
    )
    .unwrap();

    // Now we wait for a bit, generating some blocks
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        faucet.generate_block();
    }

    // Check that the recipient did get the expected sBTC
    let balance = get_sbtc_balance(&stacks, &deployer, &recipient.into())
        .await
        .unwrap();
    dbg!(&balance);
    assert_eq!(balance.to_sat(), 0);
}
