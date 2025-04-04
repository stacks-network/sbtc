use std::collections::BTreeMap;
use std::collections::HashSet;
use std::io::Read as _;
use std::ops::Deref;
use std::time::Duration;

use bitcoin::hashes::Hash as _;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::clarity::vm::Value as ClarityValue;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksAddress;
use fake::Faker;
use futures::StreamExt as _;
use futures::future::join_all;
use more_asserts::assert_gt;
use more_asserts::assert_le;
use rand::seq::IteratorRandom as _;
use rand::seq::SliceRandom as _;
use signer::WITHDRAWAL_BLOCKS_EXPIRY;
use signer::bitcoin::validation::WithdrawalRequestStatus;
use signer::bitcoin::validation::WithdrawalValidationResult;
use signer::storage::model::BitcoinBlockHeight;
use signer::storage::model::DkgSharesStatus;
use signer::storage::model::SweptWithdrawalRequest;
use signer::storage::model::WithdrawalRequest;
use signer::testing::IterTestExt as _;
use time::OffsetDateTime;

use signer::bitcoin::MockBitcoinInteract;
use signer::bitcoin::validation::DepositConfirmationStatus;
use signer::config::Settings;
use signer::context::Context;
use signer::emily_client::MockEmilyInteract;
use signer::error::Error;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::network;
use signer::stacks::api::MockStacksInteract;
use signer::stacks::contracts::AcceptWithdrawalV1;
use signer::stacks::contracts::AsContractCall;
use signer::stacks::contracts::AsTxPayload as _;
use signer::stacks::contracts::CompleteDepositV1;
use signer::stacks::contracts::RejectWithdrawalV1;
use signer::stacks::contracts::ReqContext;
use signer::stacks::contracts::RotateKeysV1;
use signer::storage;
use signer::storage::DbRead;
use signer::storage::DbWrite;
use signer::storage::model;
use signer::storage::model::BitcoinBlock;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::BitcoinTxId;
use signer::storage::model::BitcoinTxSigHash;
use signer::storage::model::BitcoinWithdrawalOutput;
use signer::storage::model::CompletedDepositEvent;
use signer::storage::model::EncryptedDkgShares;
use signer::storage::model::QualifiedRequestId;
use signer::storage::model::ScriptPubKey;
use signer::storage::model::StacksBlock;
use signer::storage::model::StacksBlockHash;
use signer::storage::model::StacksTxId;
use signer::storage::model::WithdrawalAcceptEvent;
use signer::storage::model::WithdrawalRejectEvent;
use signer::storage::model::WithdrawalSigner;
use signer::storage::postgres::PgStore;
use signer::testing;
use signer::testing::dummy::SignerSetConfig;
use signer::testing::storage::model::TestData;
use signer::testing::wallet::ContractCallWrapper;

use fake::Fake;
use rand::SeedableRng;
use signer::DEPOSIT_LOCKTIME_BLOCK_BUFFER;
use signer::testing::context::*;
use test_case::test_case;
use test_log::test;

use crate::setup::SweepAmounts;
use crate::setup::TestSignerSet;
use crate::setup::TestSweepSetup;
use crate::setup::TestSweepSetup2;
use crate::setup::backfill_bitcoin_blocks;
use crate::setup::fetch_canonical_bitcoin_blockchain;

#[tokio::test]
async fn should_be_able_to_query_bitcoin_blocks() {
    let mut store = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, 7);

    let persisted_model = TestData::generate(&mut rng, &signer_set, &test_model_params);
    let not_persisted_model = TestData::generate(&mut rng, &signer_set, &test_model_params);

    // Write all blocks for the persisted model to the database
    persisted_model.write_to(&mut store).await;

    // Assert that we can query each of the persisted blocks
    for block in &persisted_model.bitcoin_blocks {
        let persisted_block = store
            .get_bitcoin_block(&block.block_hash)
            .await
            .expect("failed to execute query")
            .expect("block doesn't exist in database");

        assert_eq!(&persisted_block, block)
    }

    // Assert that we can't find any blocks that haven't been persisted
    for block in &not_persisted_model.bitcoin_blocks {
        let result = store
            .get_bitcoin_block(&block.block_hash)
            .await
            .expect("failed_to_execute_query");
        assert!(result.is_none());
    }
    signer::testing::storage::drop_db(store).await;
}

struct InitiateWithdrawalRequest {
    deployer: StacksAddress,
}

impl AsContractCall for InitiateWithdrawalRequest {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const FUNCTION_NAME: &'static str = "initiate-withdrawal-request";
    /// The stacks address that deployed the contract.
    fn deployer_address(&self) -> StacksAddress {
        self.deployer
    }
    /// The arguments to the clarity function.
    fn as_contract_args(&self) -> Vec<ClarityValue> {
        Vec::new()
    }
    async fn validate<C>(&self, _db: &C, _ctx: &ReqContext) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        Ok(())
    }
}

/// Test that the write_stacks_blocks function does what it is supposed to
/// do, which is store all stacks blocks and store the transactions that we
/// care about, which, naturally, are sBTC related transactions.
#[test_case(ContractCallWrapper(InitiateWithdrawalRequest {
    deployer: *testing::wallet::WALLET.0.address(),
}); "initiate-withdrawal")]
#[test_case(ContractCallWrapper(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap(),
    deployer: *testing::wallet::WALLET.0.address(),
    sweep_txid: BitcoinTxId::from([0; 32]),
    sweep_block_hash: BitcoinBlockHash::from([0; 32]),
    sweep_block_height: 7u64.into(),
}); "complete-deposit standard recipient")]
#[test_case(ContractCallWrapper(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y.my-contract-name").unwrap(),
    deployer: *testing::wallet::WALLET.0.address(),
    sweep_txid: BitcoinTxId::from([0; 32]),
    sweep_block_hash: BitcoinBlockHash::from([0; 32]),
    sweep_block_height: 7u64.into(),
}); "complete-deposit contract recipient")]
#[test_case(ContractCallWrapper(AcceptWithdrawalV1 {
    id: QualifiedRequestId {
	    request_id: 0,
	    txid: StacksTxId::from([0; 32]),
	    block_hash: StacksBlockHash::from([0; 32]),
    },
    outpoint: bitcoin::OutPoint::null(),
    tx_fee: 3500,
    signer_bitmap: 0,
    deployer: *testing::wallet::WALLET.0.address(),
    sweep_block_hash: BitcoinBlockHash::from([0; 32]),
    sweep_block_height: 7u64.into(),
}); "accept-withdrawal")]
#[test_case(ContractCallWrapper(RejectWithdrawalV1 {
    id: QualifiedRequestId {
	request_id: 0,
	txid: StacksTxId::from([0; 32]),
	block_hash: StacksBlockHash::from([0; 32]),
    },
    signer_bitmap: 0,
    deployer: *testing::wallet::WALLET.0.address(),
}); "reject-withdrawal")]
#[test_case(ContractCallWrapper(RotateKeysV1::new(
    &testing::wallet::WALLET.0,
    *testing::wallet::WALLET.0.address(),
    &signer::keys::PublicKey::from_slice(&[0x02; 33]).unwrap()
)); "rotate-keys")]
#[tokio::test]
async fn writing_stacks_blocks_works<T: AsContractCall>(contract: ContractCallWrapper<T>) {
    let store = testing::storage::new_test_database().await;

    let path = "tests/fixtures/tenure-blocks-0-e5fdeb1a51ba6eb297797a1c473e715c27dc81a58ba82c698f6a32eeccee9a5b.bin";
    let mut file = std::fs::File::open(path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    let bytes: &mut &[u8] = &mut buf.as_ref();
    let mut blocks = Vec::new();

    while !bytes.is_empty() {
        blocks.push(NakamotoBlock::consensus_deserialize(bytes).unwrap());
    }

    // Now we add a transaction of a type that we care about into one of
    // the blocks. The other transactions in this block are tenure changes,
    // coinbase transactions, or regular transfer transactions.
    let last_block = blocks.last_mut().unwrap();
    let mut tx = last_block.txs.last().unwrap().clone();

    tx.payload = contract.tx_payload();
    last_block.txs.push(tx);

    // Okay now to save these blocks. We check that all of these blocks are
    // saved and that the transaction that we care about is saved as well.
    let settings = Settings::new_from_default_config().unwrap();
    let txs = storage::postgres::extract_relevant_transactions(&blocks, &settings.signer.deployer);
    let headers = blocks
        .iter()
        .map(|block| StacksBlock::from_nakamoto_block(block, &[0; 32].into()))
        .collect::<Vec<_>>();
    store.write_stacks_block_headers(headers).await.unwrap();
    store.write_stacks_transactions(txs).await.unwrap();

    // First check that all blocks are saved
    let sql = "SELECT COUNT(*) FROM sbtc_signer.stacks_blocks";
    let stored_block_count = sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(store.pool())
        .await
        .unwrap();

    assert_eq!(stored_block_count, blocks.len() as i64);

    // Next we check that the one transaction that we care about, the one
    // we just created above, was saved.
    let sql = "SELECT COUNT(*) FROM sbtc_signer.stacks_transactions";
    let stored_transaction_count = sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(store.pool())
        .await
        .unwrap();

    assert_eq!(stored_transaction_count, 1);

    // We have a sanity check that there are more transactions that we
    // could have saved if we saved all transactions.
    let num_transactions = blocks.iter().map(|blk| blk.txs.len()).sum::<usize>();
    more_asserts::assert_gt!(num_transactions, 1);

    // Last let, we check that attempting to store identical blocks is an
    // idempotent operation.
    let headers = blocks
        .iter()
        .map(|block| StacksBlock::from_nakamoto_block(block, &[0; 32].into()))
        .collect::<Vec<_>>();
    store.write_stacks_block_headers(headers).await.unwrap();

    let sql = "SELECT COUNT(*) FROM sbtc_signer.stacks_blocks";
    let stored_block_count_again = sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(store.pool())
        .await
        .unwrap();

    // No more blocks were written
    assert_eq!(stored_block_count_again, blocks.len() as i64);
    assert_eq!(stored_block_count_again, stored_block_count);

    let sql = "SELECT COUNT(*) FROM sbtc_signer.stacks_transactions";
    let stored_transaction_count_again = sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(store.pool())
        .await
        .unwrap();

    // No more transactions were written
    assert_eq!(stored_transaction_count_again, 1);
    signer::testing::storage::drop_db(store).await;
}

/// Here we test that the DbRead::stacks_block_exists function works, while
/// implicitly testing the DbWrite::write_stacks_blocks function for the
/// PgStore type
#[tokio::test]
async fn checking_stacks_blocks_exists_works() {
    let store = testing::storage::new_test_database().await;

    let path = "tests/fixtures/tenure-blocks-0-e5fdeb1a51ba6eb297797a1c473e715c27dc81a58ba82c698f6a32eeccee9a5b.bin";
    let mut file = std::fs::File::open(path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    let bytes: &mut &[u8] = &mut buf.as_ref();
    let mut blocks = Vec::new();

    while !bytes.is_empty() {
        blocks.push(NakamotoBlock::consensus_deserialize(bytes).unwrap());
    }

    // Okay, this table is empty and so none of the blocks have
    // been saved yet.
    let any_exist = futures::stream::iter(blocks.iter())
        .any(|block| async { store.stacks_block_exists(block.block_id()).await.unwrap() })
        .await;
    assert!(!any_exist);

    // Okay now to save these blocks.
    let headers = blocks
        .iter()
        .map(|block| StacksBlock::from_nakamoto_block(block, &[0; 32].into()))
        .collect::<Vec<_>>();
    store.write_stacks_block_headers(headers).await.unwrap();

    // Now each of them should exist.
    let all_exist = futures::stream::iter(blocks.iter())
        .all(|block| async { store.stacks_block_exists(block.block_id()).await.unwrap() })
        .await;
    assert!(all_exist);
    signer::testing::storage::drop_db(store).await;
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending deposit requests
#[tokio::test]
async fn should_return_the_same_pending_deposit_requests_as_in_memory_store() {
    let mut pg_store = testing::storage::new_test_database().await;
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 7;
    let context_window = 9;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };
    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);

    test_data.write_to(&mut in_memory_store).await;
    test_data.write_to(&mut pg_store).await;

    let chain_tip = in_memory_store
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    assert_eq!(
        pg_store
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
        chain_tip
    );

    for signer_public_key in signer_set.iter() {
        let mut pending_deposit_requests = in_memory_store
            .get_pending_deposit_requests(&chain_tip, context_window, signer_public_key)
            .await
            .expect("failed to get pending deposit requests");

        pending_deposit_requests.sort();
        assert!(!pending_deposit_requests.is_empty());

        let mut pg_pending_deposit_requests = pg_store
            .get_pending_deposit_requests(&chain_tip, context_window, signer_public_key)
            .await
            .expect("failed to get pending deposit requests");

        pg_pending_deposit_requests.sort();

        assert_eq!(pending_deposit_requests, pg_pending_deposit_requests);
    }

    signer::testing::storage::drop_db(pg_store).await;
}

/// Test that [`DbRead::get_pending_deposit_requests`] returns deposit
/// requests that do not have a vote on them yet.
#[tokio::test]
async fn get_pending_deposit_requests_only_pending() {
    let db = testing::storage::new_test_database().await;

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    let mut rng = rand::rngs::StdRng::seed_from_u64(43);

    let amounts = SweepAmounts {
        amount: 123456,
        max_fee: 12345,
        is_deposit: true,
    };
    let signers = TestSignerSet::new(&mut rng);
    let setup = TestSweepSetup2::new_setup(signers, faucet, &[amounts]);

    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();

    // There aren't any deposit requests in the database.
    let signer_public_key = setup.signers.signer_keys()[0];
    let pending_requests = db
        .get_pending_deposit_requests(&chain_tip, 1000, &signer_public_key)
        .await
        .unwrap();

    assert!(pending_requests.is_empty());

    // Now let's store a deposit request with no votes.
    // `get_pending_deposit_requests` should return it now.
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;

    let pending_requests = db
        .get_pending_deposit_requests(&chain_tip, 1000, &signer_public_key)
        .await
        .unwrap();

    assert_eq!(pending_requests.len(), 1);

    // Okay now lets suppose we have a decision on it.
    // `get_pending_deposit_requests` should not return it now.
    setup.store_deposit_decisions(&db).await;

    let pending_requests = db
        .get_pending_deposit_requests(&chain_tip, 1000, &signer_public_key)
        .await
        .unwrap();

    assert!(pending_requests.is_empty());

    signer::testing::storage::drop_db(db).await;
}

/// Test that [`DbRead::get_pending_withdrawal_requests`] returns
/// withdrawal requests that do not have a vote on them yet.
#[tokio::test]
async fn get_pending_withdrawal_requests_only_pending() {
    let db = testing::storage::new_test_database().await;

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    let mut rng = rand::rngs::StdRng::seed_from_u64(43);

    let amounts = SweepAmounts {
        amount: 123456,
        max_fee: 12345,
        is_deposit: false,
    };
    let signers = TestSignerSet::new(&mut rng);
    let setup = TestSweepSetup2::new_setup(signers, faucet, &[amounts]);

    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();

    // There aren't any withdrawal requests in the database.
    let signer_public_key = setup.signers.signer_keys()[0];
    let pending_requests = db
        .get_pending_withdrawal_requests(&chain_tip, 1000, &signer_public_key)
        .await
        .unwrap();

    assert!(pending_requests.is_empty());

    // Now let's store a withdrawal request with no votes.
    // `get_pending_withdrawal_requests` should return it now.
    setup.store_withdrawal_requests(&db).await;

    let pending_requests = db
        .get_pending_withdrawal_requests(&chain_tip, 1000, &signer_public_key)
        .await
        .unwrap();

    assert_eq!(pending_requests.len(), 1);

    // Okay now lets suppose we have a decision on it.
    // `get_pending_withdrawal_requests` should not return it now.
    setup.store_withdrawal_decisions(&db).await;

    let pending_requests = db
        .get_pending_withdrawal_requests(&chain_tip, 1000, &signer_public_key)
        .await
        .unwrap();

    assert!(pending_requests.is_empty());

    signer::testing::storage::drop_db(db).await;
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending withdraw requests
#[tokio::test]
async fn should_return_the_same_pending_withdraw_requests_as_in_memory_store() {
    let mut pg_store = testing::storage::new_test_database().await;
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 7;
    let context_window = 7;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 1,
        num_signers_per_request: 0,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);

    test_data.write_to(&mut in_memory_store).await;
    test_data.write_to(&mut pg_store).await;

    let chain_tip = in_memory_store
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    assert_eq!(
        pg_store
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
        chain_tip
    );

    assert_eq!(
        in_memory_store
            .get_stacks_chain_tip(&chain_tip)
            .await
            .expect("failed to get stacks chain tip")
            .expect("no chain tip"),
        pg_store
            .get_stacks_chain_tip(&chain_tip)
            .await
            .expect("failed to get stacks chain tip")
            .expect("no chain tip"),
    );

    for signer_public_key in signer_set.iter() {
        let mut pending_withdraw_requests = in_memory_store
            .get_pending_withdrawal_requests(&chain_tip, context_window, signer_public_key)
            .await
            .expect("failed to get pending deposit requests");

        pending_withdraw_requests.sort();

        assert!(!pending_withdraw_requests.is_empty());

        let mut pg_pending_withdraw_requests = pg_store
            .get_pending_withdrawal_requests(&chain_tip, context_window, signer_public_key)
            .await
            .expect("failed to get pending deposit requests");

        pg_pending_withdraw_requests.sort();

        assert_eq!(pending_withdraw_requests, pg_pending_withdraw_requests);
    }

    signer::testing::storage::drop_db(pg_store).await;
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending accepted deposit requests
#[tokio::test]
async fn should_return_the_same_pending_accepted_deposit_requests_as_in_memory_store() {
    let mut pg_store = testing::storage::new_test_database().await;
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 7;
    let context_window = 9;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };
    let threshold = 4;

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);

    test_data.write_to(&mut in_memory_store).await;
    test_data.write_to(&mut pg_store).await;

    let chain_tip = in_memory_store
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    assert_eq!(
        pg_store
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
        chain_tip
    );

    let mut pending_accepted_deposit_requests = in_memory_store
        .get_pending_accepted_deposit_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending deposit requests");

    pending_accepted_deposit_requests.sort();

    assert!(!pending_accepted_deposit_requests.is_empty());

    let mut pg_pending_accepted_deposit_requests = pg_store
        .get_pending_accepted_deposit_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending deposit requests");

    pg_pending_accepted_deposit_requests.sort();

    assert_eq!(
        pending_accepted_deposit_requests,
        pg_pending_accepted_deposit_requests
    );
    signer::testing::storage::drop_db(pg_store).await;
}

/// This tests that when fetching pending accepted deposits we ignore swept ones.
#[tokio::test]
async fn should_not_return_swept_deposits_as_pending_accepted() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This query doesn't *need* bitcoind (it's just a query), we just need
    // the transaction data in the database. We use the [`TestSweepSetup`]
    // structure because it has helper functions for generating and storing
    // sweep transactions, and the [`TestSweepSetup`] structure correctly
    // sets up the database.
    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    let chain_tip = setup.sweep_block_hash.into();
    let context_window = 20;
    let threshold = 4;

    // We need to manually update the database with new bitcoin block
    // headers.
    crate::setup::backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    setup.store_stacks_genesis_block(&db).await;

    // This isn't technically required right now, but the deposit
    // transaction is supposed to be there, so future versions of our query
    // can rely on that fact.
    setup.store_deposit_tx(&db).await;

    // The request needs to be added to the database. This stores
    // `setup.deposit_request` into the database.
    setup.store_deposit_request(&db).await;

    // Store decisions to make it "accepted"
    setup.store_deposit_decisions(&db).await;

    let requests = db
        .get_pending_accepted_deposit_requests(&chain_tip, context_window, threshold)
        .await
        .unwrap();

    assert_eq!(requests.len(), 1);

    // We take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    let requests = db
        .get_pending_accepted_deposit_requests(&chain_tip, context_window, threshold)
        .await
        .unwrap();

    assert!(requests.is_empty());

    // Ensure that we only consider sweep tx in the canonical chain
    let requests = db
        .get_pending_accepted_deposit_requests(
            // this excludes the sweep tx block
            &setup.deposit_block_hash.into(),
            context_window,
            threshold,
        )
        .await
        .unwrap();

    assert_eq!(requests.len(), 1);

    signer::testing::storage::drop_db(db).await;
}

/// This test ensures that the postgres store will only return the pending accepted deposit requests
/// if they are within the reclaim bounds. If they can be reclaimed too close to the current chain tip
/// they should not appear in the accepted pending deposit requests list.
///
///
/// TODO(#751): Add a test to ensure that the locktime buffer is interpreted the same way during
/// DepositRequestReport validation and the get pending accepted deposits database accessor function.
#[tokio::test]
async fn should_return_only_accepted_pending_deposits_that_are_within_reclaim_bounds() {
    let mut pg_store = testing::storage::new_test_database().await;
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 7;
    let context_window = 9;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };
    let threshold = 4;

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let mut test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);

    // Modify the lock times of the deposit requests to be definitely okay to accept because
    // it's the largest possible lock time.
    for deposit in test_data.deposit_requests.iter_mut() {
        deposit.lock_time = u16::MAX as u32;
    }

    // Take 1 ------------------------------------------------------------------
    test_data.write_to(&mut pg_store).await;
    test_data.write_to(&mut in_memory_store).await;

    let chain_tip = in_memory_store
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    assert_eq!(
        chain_tip,
        pg_store
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip")
    );

    // First ensure that we didn't break the main pending accepted deposit requests functionality
    // since all the lock times are the maximum possible value and thus should be accepted.
    let mut pending_accepted_deposit_requests = pg_store
        .get_pending_accepted_deposit_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending deposit requests from pg store.");

    let mut in_memory_pending_accepted_deposit_requests = in_memory_store
        .get_pending_accepted_deposit_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending deposit requests from in memory store.");

    pending_accepted_deposit_requests.sort();
    in_memory_pending_accepted_deposit_requests.sort();
    assert_eq!(
        pending_accepted_deposit_requests, in_memory_pending_accepted_deposit_requests,
        "Basic pending accepted deposit requests functionality is broken."
    );

    // Every single accepted deposit request that is valid should be returned. If any of these aren't
    // returned after we modify the lock times then we know that the reclaim bounds are what kicked
    // them out.

    // Now get the height of the Bitcoin chain tip, we're going to use this to put some of the
    // accepted deposit requests outside of the reclaim bounds.
    let bitcoin_chain_tip_height = pg_store
        .get_bitcoin_block(&chain_tip)
        .await
        .expect("failed to get bitcoin block")
        .expect("no chain tip block")
        .block_height;

    // Add one to the acceptable unlock height because the chain tip is at height one less
    // than the height of the next block, which is the block for which we are assessing
    // the threshold.
    let minimum_acceptable_unlock_height =
        *bitcoin_chain_tip_height as u32 + DEPOSIT_LOCKTIME_BLOCK_BUFFER as u32 + 1;

    // Okay, mess with the test data and make sure that some of the pending accepted deposit requests
    // are outside of the reclaim bounds.
    let percent_of_original_requests_expected_to_be_in_bounds = 0.42;
    let num_deposits_in_bounds = (pending_accepted_deposit_requests.len() as f64
        * percent_of_original_requests_expected_to_be_in_bounds)
        .floor() as usize;

    // Prepare some data structures to filter the deposit requests that we're going to put out of bounds
    // and to check against later.
    pending_accepted_deposit_requests.shuffle(&mut rng);
    let mut unique_deposit_ids = pending_accepted_deposit_requests
        .into_iter()
        .map(|deposit_request| (deposit_request.txid, deposit_request.output_index));

    // Take the first several deposit requests to be in bounds and the rest to be out of bounds.
    let in_bounds_requests: HashSet<(BitcoinTxId, u32)> = unique_deposit_ids
        .by_ref()
        .take(num_deposits_in_bounds)
        .collect();
    let out_of_bounds_requests: HashSet<(BitcoinTxId, u32)> = unique_deposit_ids.collect();

    // Alter all the deposit test data to make sure that the lock times are JUST BARELY in bounds.
    let mut expected_pending_deposit_requests: Vec<model::DepositRequest> = Vec::new();
    for deposit_request in test_data.deposit_requests.iter_mut() {
        // Get the associated block so that we can get the height that the deposit
        // was included in.
        let associated_blocks = pg_store
            .get_bitcoin_blocks_with_transaction(&deposit_request.txid)
            .await
            .expect("failed to get bitcoin blocks with transaction");

        assert_eq!(
            associated_blocks.len(),
            1,
            "Deposit found in multiple Bitcoin blocks - this test is not designed to handle this."
        );

        let height_included = pg_store
            .get_bitcoin_block(associated_blocks.first().unwrap())
            .await
            .expect("Failed getting block from storage")
            .expect("Block included needs to exists")
            .block_height;

        let minimum_acceptable_unlock_time_for_this_deposit =
            minimum_acceptable_unlock_height - *height_included as u32;

        let unique_deposit_id: (BitcoinTxId, u32) =
            (deposit_request.txid, deposit_request.output_index);

        if out_of_bounds_requests.contains(&unique_deposit_id) {
            // Make the block the request can be reclaimed at one lower than the minimum.
            deposit_request.lock_time = minimum_acceptable_unlock_time_for_this_deposit - 1;
        } else if in_bounds_requests.contains(&unique_deposit_id) {
            // Make the block the request can be reclaimed at one lower than the minimum and
            // track that it's one of the expected acceptable deposits.
            deposit_request.lock_time = minimum_acceptable_unlock_time_for_this_deposit;
            expected_pending_deposit_requests.push(deposit_request.clone());
        }
    }

    // Take 2 ------------------------------------------------------------------
    // This time some of the deposit requests are outside of the reclaim bounds.
    // We should only get the ones that are within the reclaim bounds.
    signer::testing::storage::drop_db(pg_store).await;
    pg_store = testing::storage::new_test_database().await;
    in_memory_store = storage::in_memory::Store::new_shared();

    // Initialize the data.
    test_data.write_to(&mut pg_store).await;
    test_data.write_to(&mut in_memory_store).await;

    let mut pending_accepted_deposit_requests_in_memory = in_memory_store
        .get_pending_accepted_deposit_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending deposit requests");

    let mut pending_accepted_deposit_requests_pg_store = pg_store
        .get_pending_accepted_deposit_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending deposit requests");

    // Sort the deposit requests so that we can compare them.
    pending_accepted_deposit_requests_pg_store.sort();
    pending_accepted_deposit_requests_in_memory.sort();
    expected_pending_deposit_requests.sort();

    assert_eq!(
        expected_pending_deposit_requests, pending_accepted_deposit_requests_pg_store,
        "Pending accepted deposits from the PG store do not match the expected output."
    );
    assert_eq!(
        expected_pending_deposit_requests, pending_accepted_deposit_requests_in_memory,
        "Pending accepted deposits from the in memory store does not match the expected output."
    );

    signer::testing::storage::drop_db(pg_store).await;
}

/// This ensures that the postgres store and the in memory stores returns
/// equivalent results when fetching pending the last key rotation.
/// TODO(415): Make this robust to multiple key rotations.
#[tokio::test]
async fn should_return_the_same_last_key_rotation_as_in_memory_store() {
    let mut pg_store = testing::storage::new_test_database().await;
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 1,
        num_signers_per_request: 7,
        consecutive_blocks: false,
    };
    let num_signers = 7;
    let threshold = 4;
    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);

    test_data.write_to(&mut in_memory_store).await;
    test_data.write_to(&mut pg_store).await;

    let chain_tip = in_memory_store
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    let signer_info = testing::wsts::generate_signer_info(&mut rng, num_signers);

    let dummy_wsts_network = network::InMemoryNetwork::new();
    let mut testing_signer_set =
        testing::wsts::SignerSet::new(&signer_info, threshold, || dummy_wsts_network.connect());
    let dkg_txid = testing::dummy::txid(&fake::Faker, &mut rng);
    let (_, all_shares) = testing_signer_set
        .run_dkg(
            chain_tip,
            dkg_txid.into(),
            &mut rng,
            model::DkgSharesStatus::Verified,
        )
        .await;

    let shares = all_shares.first().unwrap();
    testing_signer_set
        .write_as_rotate_keys_tx(&mut in_memory_store, &chain_tip, shares, &mut rng)
        .await;

    testing_signer_set
        .write_as_rotate_keys_tx(&mut pg_store, &chain_tip, shares, &mut rng)
        .await;

    let last_key_rotation_in_memory = in_memory_store
        .get_last_key_rotation(&chain_tip)
        .await
        .expect("failed to get last key rotation from in memory store");

    let last_key_rotation_pg = pg_store
        .get_last_key_rotation(&chain_tip)
        .await
        .expect("failed to get last key rotation from postgres");

    assert!(last_key_rotation_in_memory.is_some());
    assert_eq!(
        last_key_rotation_pg.as_ref().unwrap().aggregate_key,
        last_key_rotation_in_memory.as_ref().unwrap().aggregate_key
    );
    assert_eq!(
        last_key_rotation_pg.as_ref().unwrap().signer_set,
        last_key_rotation_in_memory.as_ref().unwrap().signer_set
    );
    signer::testing::storage::drop_db(pg_store).await;
}

/// Here we test that we can store deposit request model objects. We also
/// test that if we attempt to write another deposit request then we do not
/// write it and that we do not error.
#[tokio::test]
async fn writing_deposit_requests_postgres() {
    let store = testing::storage::new_test_database().await;
    let num_rows = 15;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let deposit_requests: Vec<model::DepositRequest> =
        std::iter::repeat_with(|| fake::Faker.fake_with_rng(&mut rng))
            .take(num_rows)
            .collect();

    // Let's see if we can write these rows to the database.
    store
        .write_deposit_requests(deposit_requests.clone())
        .await
        .unwrap();
    let count =
        sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.deposit_requests"#)
            .fetch_one(store.pool())
            .await
            .unwrap();
    // Were they all written?
    assert_eq!(num_rows, count as usize);

    // Okay now lets test that we do not write duplicates.
    store
        .write_deposit_requests(deposit_requests)
        .await
        .unwrap();
    let count =
        sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.deposit_requests"#)
            .fetch_one(store.pool())
            .await
            .unwrap();

    // No new records written right?
    assert_eq!(num_rows, count as usize);
    signer::testing::storage::drop_db(store).await;
}

/// This is very similar to the above test; we test that we can store
/// transaction model objects. We also test that if we attempt to write
/// duplicate transactions then we do not write it and that we do not
/// error.
#[tokio::test]
async fn writing_transactions_postgres() {
    let store = testing::storage::new_test_database().await;
    let num_rows = 12;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let mut txs: Vec<model::Transaction> =
        std::iter::repeat_with(|| fake::Faker.fake_with_rng(&mut rng))
            .take(num_rows)
            .collect();

    let parent_hash = bitcoin::BlockHash::from_byte_array([0; 32]);
    let block_hash = bitcoin::BlockHash::from_byte_array([1; 32]);

    txs.iter_mut().for_each(|tx| {
        tx.block_hash = block_hash.to_byte_array();
    });

    let db_block = model::BitcoinBlock {
        block_hash: block_hash.into(),
        block_height: 15u64.into(),
        parent_hash: parent_hash.into(),
    };

    // We start by writing the bitcoin block because of the foreign key
    // constraint
    store.write_bitcoin_block(&db_block).await.unwrap();

    // Let's see if we can write these transactions to the database.
    store.write_bitcoin_transactions(txs.clone()).await.unwrap();
    let count =
        sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.bitcoin_transactions"#)
            .fetch_one(store.pool())
            .await
            .unwrap();
    // Were they all written?
    assert_eq!(num_rows, count as usize);

    // what about the transactions table, the same number of rows should
    // have been written there as well.
    let count = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.transactions"#)
        .fetch_one(store.pool())
        .await
        .unwrap();

    assert_eq!(num_rows, count as usize);
    // Okay now lets test that we do not write duplicates.
    store.write_bitcoin_transactions(txs).await.unwrap();
    let count =
        sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.bitcoin_transactions"#)
            .fetch_one(store.pool())
            .await
            .unwrap();

    // No new records written right?
    assert_eq!(num_rows, count as usize);

    // what about duplicates in the transactions table.
    let count = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.transactions"#)
        .fetch_one(store.pool())
        .await
        .unwrap();

    // let's see, who knows what will happen!
    assert_eq!(num_rows, count as usize);
    signer::testing::storage::drop_db(store).await;
}

/// Here we test that we can store completed deposit events.
#[tokio::test]
async fn writing_completed_deposit_requests_postgres() {
    let store = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let event: CompletedDepositEvent = fake::Faker.fake_with_rng(&mut rng);

    // Let's see if we can write these rows to the database.
    store.write_completed_deposit_event(&event).await.unwrap();
    let mut db_event = sqlx::query_as::<_, ([u8; 32], [u8; 32], i64, [u8; 32], i64)>(
        r#"
            SELECT txid
                 , block_hash
                 , amount
                 , bitcoin_txid
                 , output_index
            FROM sbtc_signer.completed_deposit_events"#,
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    // Did we only write one row
    assert_eq!(db_event.len(), 1);

    let (txid, block_id, amount, bitcoin_txid, vout) = db_event.pop().unwrap();

    assert_eq!(txid, event.txid.into_bytes());
    assert_eq!(block_id, event.block_id.into_bytes());
    assert_eq!(amount as u64, event.amount);
    assert_eq!(bitcoin_txid, event.outpoint.txid.to_byte_array());
    assert_eq!(vout as u32, event.outpoint.vout);

    signer::testing::storage::drop_db(store).await;
}

/// Here we test that we can store withdrawal-create events.
#[tokio::test]
async fn writing_withdrawal_requests_postgres() {
    let store = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let event: WithdrawalRequest = fake::Faker.fake_with_rng(&mut rng);

    // Let's see if we can write these rows to the database.
    store
        .write_withdrawal_request(&event.clone().into())
        .await
        .unwrap();

    let mut db_event =
        sqlx::query_as::<_, (i64, [u8; 32], [u8; 32], Vec<u8>, i64, i64, String, i64)>(
            r#"
            SELECT request_id
                 , txid
                 , block_hash
                 , recipient
                 , amount
                 , max_fee
                 , sender_address
                 , bitcoin_block_height
            FROM sbtc_signer.withdrawal_requests"#,
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
    // Did we only write one row
    assert_eq!(db_event.len(), 1);

    let (request_id, txid, block_hash, recipient, amount, max_fee, sender, block_height) =
        db_event.pop().unwrap();

    assert_eq!(txid, event.txid.into_bytes());
    assert_eq!(block_hash, event.block_hash.into_bytes());
    assert_eq!(request_id as u64, event.request_id);
    assert_eq!(amount as u64, event.amount);
    assert_eq!(sender, event.sender_address.to_string());
    assert_eq!(recipient, event.recipient.to_bytes());
    assert_eq!(max_fee as u64, event.max_fee);
    assert_eq!(block_height as u64, *event.bitcoin_block_height);

    signer::testing::storage::drop_db(store).await;
}

/// Here we test that we can store withdrawal-accept events.
#[tokio::test]
async fn writing_withdrawal_accept_requests_postgres() {
    let store = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let event: WithdrawalAcceptEvent = fake::Faker.fake_with_rng(&mut rng);

    // Let's see if we can write these rows to the database.
    eprintln!("{:#?}", event.clone());
    store.write_withdrawal_accept_event(&event).await.unwrap();
    let mut db_event =
        sqlx::query_as::<_, ([u8; 32], [u8; 32], i64, [u8; 16], [u8; 32], i64, i64)>(
            r#"
            SELECT txid
                 , block_hash
                 , request_id
                 , signer_bitmap
                 , bitcoin_txid
                 , output_index
                 , fee
            FROM sbtc_signer.withdrawal_accept_events"#,
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
    // Did we only write one row
    assert_eq!(db_event.len(), 1);

    let (txid, block_id, request_id, bitmap, bitcoin_txid, vout, fee) = db_event.pop().unwrap();

    assert_eq!(txid, event.txid.into_bytes());
    assert_eq!(block_id, event.block_id.into_bytes());
    assert_eq!(request_id as u64, event.request_id);
    assert_eq!(bitmap, event.signer_bitmap.into_inner());
    assert_eq!(bitcoin_txid, event.outpoint.txid.to_byte_array());
    assert_eq!(vout as u32, event.outpoint.vout);
    assert_eq!(fee as u64, event.fee);

    signer::testing::storage::drop_db(store).await;
}

/// Here we test that we can store withdrawal-reject events.
#[tokio::test]
async fn writing_withdrawal_reject_requests_postgres() {
    let store = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let event: WithdrawalRejectEvent = fake::Faker.fake_with_rng(&mut rng);

    // Let's see if we can write these rows to the database.
    store.write_withdrawal_reject_event(&event).await.unwrap();
    let mut db_event = sqlx::query_as::<_, ([u8; 32], [u8; 32], i64, [u8; 16])>(
        r#"
            SELECT txid
                 , block_hash
                 , request_id
                 , signer_bitmap
            FROM sbtc_signer.withdrawal_reject_events"#,
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    // Did we only write one row
    assert_eq!(db_event.len(), 1);

    let (txid, block_id, request_id, bitmap) = db_event.pop().unwrap();

    assert_eq!(txid, event.txid.into_bytes());
    assert_eq!(block_id, event.block_id.into_bytes());
    assert_eq!(request_id as u64, event.request_id);
    assert_eq!(bitmap, event.signer_bitmap.into_inner());

    signer::testing::storage::drop_db(store).await;
}

/// For this test we check that when we get the votes for a deposit request
/// for a specific aggregate key, that we get a vote for all public keys
/// for the specific aggregate key. This includes "implicit" votes where we
/// got no response from a particular signer but so we assume that they
/// vote to reject the transaction.
#[tokio::test]
async fn fetching_deposit_request_votes() {
    // So we have 7 signers, but we will only receive votes from 4 of them.
    // Three of the votes will be to accept and one explicit reject. The
    // others will be counted as rejections in the query.
    let store = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signer_set_config = SignerSetConfig {
        num_keys: 7,
        signatures_required: 4,
    };
    let shares = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Unverified,
        ..signer_set_config.fake_with_rng(&mut rng)
    };

    store.write_encrypted_dkg_shares(&shares).await.unwrap();

    let txid: BitcoinTxId = fake::Faker.fake_with_rng(&mut rng);
    let output_index = 2;

    let signer_decisions = [
        model::DepositSigner {
            txid,
            output_index,
            signer_pub_key: shares.signer_set_public_keys[0],
            can_accept: true,
            can_sign: true,
        },
        model::DepositSigner {
            txid,
            output_index,
            signer_pub_key: shares.signer_set_public_keys[1],
            can_accept: false,
            can_sign: true,
        },
        model::DepositSigner {
            txid,
            output_index,
            signer_pub_key: shares.signer_set_public_keys[2],
            can_accept: true,
            can_sign: true,
        },
        model::DepositSigner {
            txid,
            output_index,
            signer_pub_key: shares.signer_set_public_keys[3],
            can_accept: true,
            can_sign: true,
        },
    ];

    for decision in signer_decisions.clone() {
        // Before we can write the decision, we need to make sure that the
        // deposit request is in the database to satisfy the foreign key
        // constraint.
        let random_req: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
        let req = model::DepositRequest {
            txid,
            output_index,
            ..random_req
        };
        store.write_deposit_request(&req).await.unwrap();
        store
            .write_deposit_signer_decision(&decision)
            .await
            .unwrap();
    }

    // Okay let's test the query and get the votes.
    let votes = store
        .get_deposit_request_signer_votes(&txid, output_index, &shares.aggregate_key)
        .await
        .unwrap();

    let mut actual_signer_vote_map: BTreeMap<PublicKey, Option<bool>> = votes
        .iter()
        .map(|vote| (vote.signer_public_key, vote.is_accepted))
        .collect();

    // Let's make sure that the votes are what we expected. For the votes
    // that we've received, they should match exactly.
    for decision in signer_decisions.into_iter() {
        let actual_vote = actual_signer_vote_map
            .remove(&decision.signer_pub_key)
            .unwrap();
        assert_eq!(actual_vote, Some(decision.can_accept));
    }

    // The remaining keys, the ones were we have not received a vote,
    // should be all None.
    assert!(actual_signer_vote_map.values().all(Option::is_none));

    signer::testing::storage::drop_db(store).await;
}

#[tokio::test]
async fn fetching_deposit_signer_decisions() {
    let pg_store = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This is just a sql test, where we use the `TestData` struct to help
    // populate the database with test data. We set all the other
    // unnecessary parameters to zero.
    let num_signers = 3;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 5,
        num_stacks_blocks_per_bitcoin_block: 0,
        num_deposit_requests_per_block: 1,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: true,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);

    let mut test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data.write_to(&pg_store).await;

    let signer_pub_key = signer_set.first().unwrap();

    // We'll register each block with a 2 minute interval
    // i.e. times -> [-15, -13, -11, -9, -7]
    let mut new_time = OffsetDateTime::now_utc() - time::Duration::minutes(15);
    // Update Bitcoin blocks
    for block in test_data.bitcoin_blocks.iter() {
        let new_time_str = new_time
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        sqlx::query(
            r#"
            UPDATE sbtc_signer.bitcoin_blocks
            SET created_at = $1::timestamptz
            WHERE block_hash = $2"#,
        )
        .bind(new_time_str) // Bind as string
        .bind(block.block_hash)
        .execute(pg_store.pool())
        .await
        .unwrap();

        new_time += time::Duration::minutes(2);
    }

    // Rotate deposits to test edge case:
    // Move first deposit to be processed last (latest timestamp)
    // This tests that a deposit decision can still be returned
    // even when its associated block falls outside the context window
    test_data.deposit_requests.rotate_left(1);

    // Now we'll update the deposits decisions. Each decision will be
    // updated so that it will arrive 1 minute after its corresponding block.
    // With the exception of the first one, which will be updated to arrive last.
    // Block times:     [-15, -13, -11,  -9,  -7]
    // Decision times:       [-12, -10,  -8,  -6,  -4]
    //                         ^    ^     ^    ^    ^
    //                         |    |     |    |    first deposit (moved to last)
    //                         |    |     |    fifth deposit
    //                         |    |     forth deposit
    //                         |    third deposit
    //                         second deposit
    new_time = OffsetDateTime::now_utc() - time::Duration::minutes(12);
    for deposit in test_data.deposit_requests.iter() {
        let new_time_str = new_time
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        sqlx::query(
            r#"
            UPDATE sbtc_signer.deposit_signers
            SET created_at = $1::timestamptz
            WHERE txid = $2 AND output_index = $3 AND signer_pub_key = $4"#,
        )
        .bind(new_time_str) // Bind as string
        .bind(deposit.txid)
        .bind(i32::try_from(deposit.output_index).unwrap())
        .bind(signer_pub_key)
        .execute(pg_store.pool())
        .await
        .unwrap();

        new_time += time::Duration::minutes(2);
    }

    let chain_tip = pg_store
        .get_bitcoin_canonical_chain_tip()
        .await
        .unwrap()
        .unwrap();

    let deposit_decisions = pg_store
        .get_deposit_signer_decisions(&chain_tip, 3, signer_pub_key)
        .await
        .unwrap();

    assert_eq!(deposit_decisions.len(), 4);
    // Test data contains 5 deposit requests, we should get decisions for
    // the last 4.
    for deposit in test_data.deposit_requests[1..].iter() {
        assert!(deposit_decisions.iter().any(|decision| {
            decision.txid == deposit.txid
                && decision.output_index == deposit.output_index
                && decision.signer_pub_key == *signer_pub_key
        }));
    }

    signer::testing::storage::drop_db(pg_store).await;
}

#[tokio::test]
async fn fetching_withdrawal_signer_decisions() {
    let pg_store = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This is just a sql test, where we use the `TestData` struct to help
    // populate the database with test data. We set all the other
    // unnecessary parameters to zero.
    let num_signers = 3;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 5,
        num_stacks_blocks_per_bitcoin_block: 0,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 1,
        num_signers_per_request: num_signers,
        consecutive_blocks: true,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);

    let mut test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data.write_to(&pg_store).await;

    let signer_pub_key = signer_set.first().unwrap();

    // We'll register each block with a 2 minute interval
    // i.e. times -> [-15, -13, -11, -9, -7]
    let mut new_time = OffsetDateTime::now_utc() - time::Duration::minutes(15);
    // Update Bitcoin blocks
    for block in test_data.bitcoin_blocks.iter() {
        let new_time_str = new_time
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        sqlx::query(
            r#"
            UPDATE sbtc_signer.bitcoin_blocks
            SET created_at = $1::timestamptz
            WHERE block_hash = $2"#,
        )
        .bind(new_time_str) // Bind as string
        .bind(block.block_hash)
        .execute(pg_store.pool())
        .await
        .unwrap();

        new_time += time::Duration::minutes(2);
    }

    // Rotate withdraw to test edge case:
    // Move first withdraw to be processed last (latest timestamp)
    // This tests that a withdraw decision can still be returned
    // even when its associated block falls outside the context window
    test_data.withdraw_requests.rotate_left(1);

    // Now we'll update the withdraws decisions. Each decision will be
    // updated so that it will arrive 1 minute after its corresponding block.
    // With the exception of the first one, which will be updated to arrive last.
    // Block times:     [-15, -13, -11,  -9,  -7]
    // Decision times:       [-12, -10,  -8,  -6,  -4]
    //                         ^    ^     ^    ^    ^
    //                         |    |     |    |    first withdraw (moved to last)
    //                         |    |     |    fifth withdraw
    //                         |    |     forth withdraw
    //                         |    third withdraw
    //                         second withdraw
    new_time = OffsetDateTime::now_utc() - time::Duration::minutes(12);
    for withdrawal in test_data.withdraw_requests.iter() {
        let new_time_str = new_time
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        sqlx::query(
            r#"
            UPDATE sbtc_signer.withdrawal_signers
            SET created_at = $1::timestamptz
            WHERE request_id = $2 AND block_hash = $3 AND signer_pub_key = $4"#,
        )
        .bind(new_time_str) // Bind as string
        .bind(i64::try_from(withdrawal.request_id).unwrap())
        .bind(withdrawal.block_hash)
        .bind(signer_pub_key)
        .execute(pg_store.pool())
        .await
        .unwrap();

        new_time += time::Duration::minutes(2);
    }

    let chain_tip = pg_store
        .get_bitcoin_canonical_chain_tip()
        .await
        .unwrap()
        .unwrap();

    let withdrawal_decisions = pg_store
        .get_withdrawal_signer_decisions(&chain_tip, 3, signer_pub_key)
        .await
        .unwrap();

    assert_eq!(withdrawal_decisions.len(), 4);
    // Test data contains 5 withdrawal requests, we should get decisions for
    // the last 4.
    for withdrawal in test_data.withdraw_requests[1..].iter() {
        assert!(withdrawal_decisions.iter().any(|decision| {
            decision.block_hash == withdrawal.block_hash
                && decision.request_id == withdrawal.request_id
                && decision.txid == withdrawal.txid
                && decision.signer_pub_key == *signer_pub_key
        }));
    }

    signer::testing::storage::drop_db(pg_store).await;
}

/// For this test we check that when we get the votes for a withdrawal
/// request for a specific aggregate key, that we get a vote for all public
/// keys for the specific aggregate key. This includes "implicit" votes
/// where we got no response from a particular signer but so we assume that
/// they vote to reject the transaction.
#[tokio::test]
async fn fetching_withdrawal_request_votes() {
    // So we have 7 signers, but we will only receive votes from 4 of them.
    // Three of the votes will be to accept and one explicit reject. The
    // others will be counted as rejections in the query.
    let store = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signer_set_config = SignerSetConfig {
        num_keys: 7,
        signatures_required: 4,
    };
    let shares = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Unverified,
        ..signer_set_config.fake_with_rng(&mut rng)
    };

    store.write_encrypted_dkg_shares(&shares).await.unwrap();

    let txid: StacksTxId = fake::Faker.fake_with_rng(&mut rng);
    let block_hash: StacksBlockHash = fake::Faker.fake_with_rng(&mut rng);
    let request_id = 17;

    let signer_decisions = [
        WithdrawalSigner {
            txid,
            block_hash,
            request_id,
            signer_pub_key: shares.signer_set_public_keys[0],
            is_accepted: true,
        },
        WithdrawalSigner {
            txid,
            block_hash,
            request_id,
            signer_pub_key: shares.signer_set_public_keys[1],
            is_accepted: false,
        },
        WithdrawalSigner {
            txid,
            block_hash,
            request_id,
            signer_pub_key: shares.signer_set_public_keys[2],
            is_accepted: true,
        },
        WithdrawalSigner {
            txid,
            block_hash,
            request_id,
            signer_pub_key: shares.signer_set_public_keys[3],
            is_accepted: true,
        },
    ];

    for decision in signer_decisions.clone() {
        // Before we can write the decision, we need to make sure that the
        // withdrawal request and stacks block are in the database to
        // satisfy the foreign key constraints.
        let block = StacksBlock {
            block_hash,
            ..fake::Faker.fake_with_rng::<StacksBlock, _>(&mut rng)
        };
        let req = model::WithdrawalRequest {
            txid,
            block_hash,
            request_id,
            ..fake::Faker.fake_with_rng::<model::WithdrawalRequest, _>(&mut rng)
        };

        store.write_stacks_block(&block).await.unwrap();
        store.write_withdrawal_request(&req).await.unwrap();
        store
            .write_withdrawal_signer_decision(&decision)
            .await
            .unwrap();
    }

    let id = QualifiedRequestId { txid, block_hash, request_id };
    // Let's make sure the identifiers match, doesn't hurt too.
    assert_eq!(id, signer_decisions[0].qualified_id());

    // Okay let's test the query and get the votes.
    let votes = store
        .get_withdrawal_request_signer_votes(&id, &shares.aggregate_key)
        .await
        .unwrap();

    let mut actual_signer_vote_map: BTreeMap<PublicKey, Option<bool>> = votes
        .iter()
        .map(|vote| (vote.signer_public_key, vote.is_accepted))
        .collect();

    // Let's make sure that the votes are what we expected. For the votes
    // that we've received, they should match exactly.
    for decision in signer_decisions.into_iter() {
        let actual_vote = actual_signer_vote_map
            .remove(&decision.signer_pub_key)
            .unwrap();
        assert_eq!(actual_vote, Some(decision.is_accepted));
    }

    // The remaining keys, the ones were we have not received a vote,
    // should be all None.
    assert!(actual_signer_vote_map.values().all(Option::is_none));

    signer::testing::storage::drop_db(store).await;
}

/// For this test we check that the `block_in_canonical_bitcoin_blockchain`
/// function returns false when the input block is not in the canonical
/// bitcoin blockchain.
#[tokio::test]
async fn block_in_canonical_bitcoin_blockchain_in_other_block_chain() {
    let pg_store = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This is just a sql test, where we use the `TestData` struct to help
    // populate the database with test data. We set all the other
    // unnecessary parameters to zero.
    let num_signers = 0;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 50,
        num_stacks_blocks_per_bitcoin_block: 0,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    // Okay now we generate one blockchain and get its chain tip
    let test_data1 = TestData::generate(&mut rng, &signer_set, &test_model_params);
    // And we generate another blockchain and get its chain tip
    let test_data2 = TestData::generate(&mut rng, &signer_set, &test_model_params);

    test_data1.write_to(&pg_store).await;
    test_data2.write_to(&pg_store).await;

    let chain_tip1 = test_data1
        .bitcoin_blocks
        .iter()
        .max_by_key(|x| (x.block_height, x.block_hash))
        .unwrap();
    let chain_tip2 = test_data2
        .bitcoin_blocks
        .iter()
        .max_by_key(|x| (x.block_height, x.block_hash))
        .unwrap();

    // These shouldn't be equal
    assert_ne!(chain_tip1, chain_tip2);

    // Now for the moment of truth, these chains should have nothing to do
    // with one another.
    let is_in_chain = pg_store
        .in_canonical_bitcoin_blockchain(&chain_tip2.into(), &chain_tip1.into())
        .await
        .unwrap();
    assert!(!is_in_chain);
    let is_in_chain = pg_store
        .in_canonical_bitcoin_blockchain(&chain_tip1.into(), &chain_tip2.into())
        .await
        .unwrap();
    assert!(!is_in_chain);

    // Okay, now let's get a block that we know is in the blockchain.
    let block_ref = {
        let tmp = test_data1
            .get_bitcoin_block(&chain_tip1.parent_hash)
            .unwrap();
        test_data1.get_bitcoin_block(&tmp.parent_hash).unwrap()
    };

    let is_in_chain = pg_store
        .in_canonical_bitcoin_blockchain(&chain_tip1.into(), &block_ref.into())
        .await
        .unwrap();
    assert!(is_in_chain);

    signer::testing::storage::drop_db(pg_store).await;
}

/// For this test we check that the `get_bitcoin_tx` function returns a
/// transaction when the transaction exists in the block, and returns None
/// otherwise.
#[tokio::test]
async fn we_can_fetch_bitcoin_txs_from_db() {
    let pg_store = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This is just a sql test, where we use the `TestData` struct to help
    // populate the database with test data. We set all the other
    // unnecessary parameters to zero.
    let num_signers = 0;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 0,
        num_deposit_requests_per_block: 2,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data.write_to(&pg_store).await;

    let tx = test_data.bitcoin_transactions.choose(&mut rng).unwrap();

    // Now let's try fetching this transaction
    let btc_tx = pg_store
        .get_bitcoin_tx(&tx.txid, &tx.block_hash)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(btc_tx.compute_txid(), tx.txid.into());

    // Now let's try fetching this transaction when we know it is missing.
    let txid: BitcoinTxId = fake::Faker.fake_with_rng(&mut rng);
    let block_hash: BitcoinBlockHash = fake::Faker.fake_with_rng(&mut rng);
    // Actual block but missing txid
    let btc_tx = pg_store
        .get_bitcoin_tx(&txid, &tx.block_hash)
        .await
        .unwrap();
    assert!(btc_tx.is_none());
    // Actual txid but missing block
    let btc_tx = pg_store
        .get_bitcoin_tx(&tx.txid, &block_hash)
        .await
        .unwrap();
    assert!(btc_tx.is_none());
    // Now everything is missing
    let btc_tx = pg_store.get_bitcoin_tx(&txid, &block_hash).await.unwrap();
    assert!(btc_tx.is_none());

    signer::testing::storage::drop_db(pg_store).await;
}

/// Check that `is_signer_script_pub_key` correctly returns whether a
/// scriptPubKey value exists in the dkg_shares table.
#[tokio::test]
async fn is_signer_script_pub_key_checks_dkg_shares_for_script_pubkeys() {
    let db = testing::storage::new_test_database().await;
    let mem = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // Okay let's put a row in the dkg_shares table.
    let aggregate_key: PublicKey = fake::Faker.fake_with_rng(&mut rng);
    let script_pubkey: ScriptPubKey = aggregate_key.signers_script_pubkey().into();
    let shares = EncryptedDkgShares {
        script_pubkey: script_pubkey.clone(),
        tweaked_aggregate_key: aggregate_key.signers_tweaked_pubkey().unwrap(),
        encrypted_private_shares: Vec::new(),
        public_shares: Vec::new(),
        aggregate_key,
        signer_set_public_keys: vec![fake::Faker.fake_with_rng(&mut rng)],
        signature_share_threshold: 1,
        dkg_shares_status: Faker.fake_with_rng(&mut rng),
        started_at_bitcoin_block_hash: fake::Faker.fake_with_rng(&mut rng),
        started_at_bitcoin_block_height: (fake::Faker.fake_with_rng::<u32, _>(&mut rng) as u64)
            .into(),
    };
    db.write_encrypted_dkg_shares(&shares).await.unwrap();
    mem.write_encrypted_dkg_shares(&shares).await.unwrap();

    // Now we have a row in their with our scriptPubKey, let's make sure
    // that the query accurately reports that.
    assert!(db.is_signer_script_pub_key(&script_pubkey).await.unwrap());
    assert!(mem.is_signer_script_pub_key(&script_pubkey).await.unwrap());

    // Now we try the case where it is the script pub key is missing from
    // the database by generating a new one (well it's unlikely to be
    // there).
    let aggregate_key: PublicKey = fake::Faker.fake_with_rng(&mut rng);
    let script_pubkey: ScriptPubKey = aggregate_key.signers_script_pubkey().into();

    assert!(!db.is_signer_script_pub_key(&script_pubkey).await.unwrap());
    assert!(!mem.is_signer_script_pub_key(&script_pubkey).await.unwrap());

    signer::testing::storage::drop_db(db).await;
}

/// The [`DbRead::get_signers_script_pubkeys`] function is only supposed to
/// fetch the last 365 days worth of scriptPubKeys, but if there are no new
/// encrypted shares in the database in a year, we should still return the
/// most recent one.
#[tokio::test]
async fn get_signers_script_pubkeys_returns_non_empty_vec_old_rows() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let shares: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);

    sqlx::query(
        r#"
        INSERT INTO sbtc_signer.dkg_shares (
            aggregate_key
            , tweaked_aggregate_key
            , encrypted_private_shares
            , public_shares
            , script_pubkey
            , signer_set_public_keys
            , signature_share_threshold
            , created_at
            , dkg_shares_status
            , started_at_bitcoin_block_hash
            , started_at_bitcoin_block_height
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP - INTERVAL '366 DAYS', $8, $9, $10)
        ON CONFLICT DO NOTHING"#,
    )
    .bind(shares.aggregate_key)
    .bind(shares.tweaked_aggregate_key)
    .bind(&shares.encrypted_private_shares)
    .bind(&shares.public_shares)
    .bind(&shares.script_pubkey)
    .bind(&shares.signer_set_public_keys)
    .bind(shares.signature_share_threshold as i32)
    .bind(shares.dkg_shares_status)
    .bind(shares.started_at_bitcoin_block_hash)
    .bind(*shares.started_at_bitcoin_block_height as i64)
    .execute(db.pool())
    .await
    .unwrap();

    let keys = db.get_signers_script_pubkeys().await.unwrap();
    assert_eq!(keys.len(), 1);

    signer::testing::storage::drop_db(db).await;
}

/// The [`DbRead::get_last_encrypted_dkg_shares`] function is supposed to
/// fetch the last encrypted DKG shares stored in the database.
#[tokio::test]
async fn get_last_encrypted_dkg_shares_gets_most_recent_shares() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // We have an empty database, so we don't have any DKG shares there.
    let no_shares = db.get_latest_encrypted_dkg_shares().await.unwrap();
    assert!(no_shares.is_none());

    // Let's create some random DKG shares and store them in the database.
    // When we fetch the last one, there is only one to get, so nothing
    // surprising yet.
    let shares: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    db.write_encrypted_dkg_shares(&shares).await.unwrap();

    let stored_shares = db.get_latest_encrypted_dkg_shares().await.unwrap();
    assert_eq!(stored_shares.as_ref(), Some(&shares));

    // Now let's pretend that we somehow insert into the database some
    // shares with a timestamp that is in the past. Manually setting the
    // timestamp to be something in the past isn't possible in our current
    // codebase (and should probably never be possible), so this is just
    // for testing purposes.
    let shares0: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    db.write_encrypted_dkg_shares(&shares0).await.unwrap();

    tokio::time::sleep(Duration::from_millis(5)).await;

    let shares1: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    db.write_encrypted_dkg_shares(&shares1).await.unwrap();

    tokio::time::sleep(Duration::from_millis(5)).await;

    let shares2: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    db.write_encrypted_dkg_shares(&shares2).await.unwrap();

    // So when we try to get the last DKG shares this time, we'll get the
    // same ones as last time since they are the most recent.
    let some_shares = db.get_latest_encrypted_dkg_shares().await.unwrap();
    assert_eq!(some_shares.as_ref(), Some(&shares2));

    signer::testing::storage::drop_db(db).await;
}

/// The [`DbRead::get_latest_verified_dkg_shares`] function is supposed to
/// fetch the last encrypted DKG shares with status 'verified' from in the
/// database.
#[tokio::test]
async fn get_last_verified_dkg_shares_does_whats_advertised() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // We have an empty database, so we don't have any DKG shares there.
    let no_shares = db.get_latest_encrypted_dkg_shares().await.unwrap();
    assert!(no_shares.is_none());

    let no_shares = db.get_latest_verified_dkg_shares().await.unwrap();
    assert!(no_shares.is_none());

    // Let's create some random DKG shares and store them in the database.
    // When we fetch the last one, there is only one to get, so nothing
    // surprising yet.
    let mut shares: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    shares.dkg_shares_status = model::DkgSharesStatus::Failed;
    db.write_encrypted_dkg_shares(&shares).await.unwrap();

    let stored_shares = db.get_latest_encrypted_dkg_shares().await.unwrap();
    assert_eq!(stored_shares.as_ref(), Some(&shares));

    // But these shares are not verified so nothing still
    let no_shares = db.get_latest_verified_dkg_shares().await.unwrap();
    assert!(no_shares.is_none());

    let mut shares: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    shares.dkg_shares_status = model::DkgSharesStatus::Unverified;
    db.write_encrypted_dkg_shares(&shares).await.unwrap();

    let stored_shares = db.get_latest_encrypted_dkg_shares().await.unwrap();
    assert_eq!(stored_shares.as_ref(), Some(&shares));

    // None of these shares are verified so nothing still
    let no_shares = db.get_latest_verified_dkg_shares().await.unwrap();
    assert!(no_shares.is_none());

    let mut shares: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    shares.dkg_shares_status = model::DkgSharesStatus::Verified;
    db.write_encrypted_dkg_shares(&shares).await.unwrap();

    let stored_shares = db.get_latest_encrypted_dkg_shares().await.unwrap();
    assert_eq!(stored_shares.as_ref(), Some(&shares));

    // Finally some verified shares.
    let verified_shares = db.get_latest_verified_dkg_shares().await.unwrap();
    assert_eq!(verified_shares.as_ref(), Some(&shares));

    // Now let's add in some more verified shares to make sure that we get
    // the latest ones.
    let mut shares0: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    shares0.dkg_shares_status = model::DkgSharesStatus::Verified;
    db.write_encrypted_dkg_shares(&shares0).await.unwrap();

    tokio::time::sleep(Duration::from_millis(5)).await;

    let mut shares1: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    shares1.dkg_shares_status = model::DkgSharesStatus::Verified;
    db.write_encrypted_dkg_shares(&shares1).await.unwrap();

    tokio::time::sleep(Duration::from_millis(5)).await;

    let mut shares2: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    shares2.dkg_shares_status = model::DkgSharesStatus::Verified;
    db.write_encrypted_dkg_shares(&shares2).await.unwrap();

    // So when we try to get the last verified DKG shares this time, we'll
    // get the most recent ones.
    let some_shares = db.get_latest_verified_dkg_shares().await.unwrap();
    assert_eq!(some_shares.as_ref(), Some(&shares2));

    signer::testing::storage::drop_db(db).await;
}

/// The [`DbRead::deposit_request_exists`] function is return true we have
/// a record of the deposit request and false otherwise.
#[tokio::test]
async fn deposit_request_exists_works() {
    let db = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let deposit: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
    let exists = db
        .deposit_request_exists(&deposit.txid, deposit.output_index)
        .await
        .unwrap();
    assert!(!exists);

    db.write_deposit_request(&deposit).await.unwrap();
    let exists = db
        .deposit_request_exists(&deposit.txid, deposit.output_index)
        .await
        .unwrap();
    assert!(exists);

    signer::testing::storage::drop_db(db).await;
}

/// Check that is_known_bitcoin_block_hash correctly reports whether a
/// given block is in the database.
#[tokio::test]
async fn is_known_bitcoin_block_hash_works() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(71);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // We just wrote all of this data to the database, so they are all
    // known.
    for block in test_data.bitcoin_blocks.iter() {
        let block_hash = block.block_hash;
        assert!(db.is_known_bitcoin_block_hash(&block_hash).await.unwrap());
    }

    // It's very unlikely that this random block will be known. It's also
    // that the fixed one is known as well.
    let random_block_hash: model::BitcoinBlockHash = fake::Faker.fake_with_rng(&mut rng);
    assert!(
        !db.is_known_bitcoin_block_hash(&random_block_hash)
            .await
            .unwrap()
    );

    let random_block_hash = model::BitcoinBlockHash::from([23; 32]);
    assert!(
        !db.is_known_bitcoin_block_hash(&random_block_hash)
            .await
            .unwrap()
    );

    signer::testing::storage::drop_db(db).await;
}

/// This tests that deposit requests where there is an associated sweep
/// transaction will show up in the query results from
/// [`DbRead::get_swept_deposit_requests`].
#[tokio::test]
async fn get_swept_deposit_requests_returns_swept_deposit_requests() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This query doesn't *need* bitcoind (it's just a query), we just need
    // the transaction data in the database. We use the [`TestSweepSetup`]
    // structure because it has helper functions for generating and storing
    // sweep transactions, and the [`TestSweepSetup`] structure correctly
    // sets up the database.
    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // We need to manually update the database with new bitcoin block
    // headers.
    crate::setup::backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    setup.store_stacks_genesis_block(&db).await;

    // This isn't technically required right now, but the deposit
    // transaction is supposed to be there, so future versions of our query
    // can rely on that fact.
    setup.store_deposit_tx(&db).await;

    // The request needs to be added to the database. This stores
    // `setup.deposit_request` into the database.
    setup.store_deposit_request(&db).await;

    // We take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    let chain_tip = setup.sweep_block_hash.into();
    let context_window = 20;

    let mut requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    // There should only be one request in the database and it has a sweep
    // transaction so the length should be 1.
    assert_eq!(requests.len(), 1);

    // Its details should match that of the deposit request.
    let req = requests.pop().unwrap();

    assert_eq!(req.amount, setup.deposit_request.amount);
    assert_eq!(req.txid, setup.deposit_request.outpoint.txid.into());
    assert_eq!(req.output_index, setup.deposit_request.outpoint.vout);
    assert_eq!(req.recipient, setup.deposit_recipient.into());
    assert_eq!(req.sweep_block_hash, setup.sweep_block_hash.into());
    assert_eq!(req.sweep_block_height, setup.sweep_block_height);
    assert_eq!(req.sweep_txid, setup.sweep_tx_info.txid.into());

    signer::testing::storage::drop_db(db).await;
}

/// This tests that withdrawal requests where there is an associated sweep
/// transaction will show up in the query results from
/// [`DbRead::get_swept_withdrawal_requests`].
#[tokio::test]
async fn get_swept_withdrawal_requests_returns_swept_withdrawal_requests() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(16);

    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    let bitcoin_tip_ref = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    let bitcoin_tip = bitcoin_tip_ref.block_hash;
    let bitcoin_tip_height = bitcoin_tip_ref.block_height;

    let stacks_tip = db
        .get_stacks_chain_tip(&bitcoin_tip)
        .await
        .unwrap()
        .unwrap();

    // Prepare all data we want to insert into the database to see swept withdrawal requests in it.
    let bitcoin_block = model::BitcoinBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: bitcoin_tip_height + 1,
        parent_hash: bitcoin_tip,
    };
    let stacks_block = model::StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_tip.block_height + 1,
        parent_hash: stacks_tip.block_hash,
        bitcoin_anchor: bitcoin_block.block_hash,
    };
    let withdrawal_request = model::WithdrawalRequest {
        request_id: 1,
        txid: fake::Faker.fake_with_rng(&mut rng),
        block_hash: stacks_block.block_hash,
        recipient: fake::Faker.fake_with_rng(&mut rng),
        amount: 1_000,
        max_fee: 1_000,
        sender_address: fake::Faker.fake_with_rng(&mut rng),
        bitcoin_block_height: bitcoin_block.block_height,
    };
    let swept_output = BitcoinWithdrawalOutput {
        request_id: withdrawal_request.request_id,
        stacks_txid: withdrawal_request.txid,
        stacks_block_hash: withdrawal_request.block_hash,
        bitcoin_chain_tip: bitcoin_block.block_hash,
        ..Faker.fake_with_rng(&mut rng)
    };
    let sweep_tx_model = model::Transaction {
        tx_type: model::TransactionType::SbtcTransaction,
        txid: swept_output.bitcoin_txid.to_byte_array(),
        tx: Vec::new(),
        block_hash: bitcoin_block.block_hash.to_byte_array(),
    };
    let sweep_tx_ref = model::BitcoinTxRef {
        txid: swept_output.bitcoin_txid,
        block_hash: bitcoin_block.block_hash,
    };

    // There should no withdrawal request in the empty database
    let context_window = 20;
    let requests = db
        .get_swept_withdrawal_requests(&bitcoin_block.block_hash, context_window)
        .await
        .unwrap();
    assert!(requests.is_empty());

    // Now write all the data to the database.
    db.write_bitcoin_block(&bitcoin_block).await.unwrap();
    db.write_stacks_block(&stacks_block).await.unwrap();
    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();
    db.write_transaction(&sweep_tx_model).await.unwrap();
    db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
    db.write_bitcoin_withdrawals_outputs(&[swept_output.clone()])
        .await
        .unwrap();

    // There should only be one request in the database and it has a sweep
    // trasnaction so the length should be 1.
    let mut requests = db
        .get_swept_withdrawal_requests(&bitcoin_block.block_hash, context_window)
        .await
        .unwrap();
    assert_eq!(requests.len(), 1);

    // Its details should match that of the withdrawals request.
    let req = requests.pop().unwrap();
    let expected = SweptWithdrawalRequest {
        output_index: swept_output.output_index,
        amount: withdrawal_request.amount,
        txid: withdrawal_request.txid,
        sweep_block_hash: bitcoin_block.block_hash,
        sweep_block_height: bitcoin_block.block_height,
        sweep_txid: swept_output.bitcoin_txid,
        request_id: withdrawal_request.request_id,
        block_hash: withdrawal_request.block_hash,
        sender_address: withdrawal_request.sender_address,
        max_fee: withdrawal_request.max_fee,
        recipient: withdrawal_request.recipient,
    };
    assert_eq!(req.output_index, expected.output_index);
    assert_eq!(req.amount, expected.amount);
    assert_eq!(req.txid, expected.txid);
    assert_eq!(req.sweep_block_hash, expected.sweep_block_hash);
    assert_eq!(req.sweep_block_height, expected.sweep_block_height);
    assert_eq!(req.sweep_txid, expected.sweep_txid);
    assert_eq!(req.request_id, expected.request_id);
    assert_eq!(req.block_hash, expected.block_hash);
    assert_eq!(req.sender_address, expected.sender_address);
    assert_eq!(req.max_fee, expected.max_fee);

    signer::testing::storage::drop_db(db).await;
}

/// This tests that withdrawal requests that do not have a confirmed
/// response (sweep) bitcoin transaction are not returned from
/// [`DbRead::get_swept_withdrawal_requests`].
#[tokio::test]
async fn get_swept_withdrawal_requests_does_not_return_unswept_withdrawal_requests() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(16);

    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    let bitcoin_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let bitcoin_tip_height = db
        .get_bitcoin_block(&bitcoin_tip)
        .await
        .unwrap()
        .unwrap()
        .block_height;
    let stacks_tip = db
        .get_stacks_chain_tip(&bitcoin_tip)
        .await
        .unwrap()
        .unwrap();

    // Prepare all data we want to insert into the database to see swept withdrawal requests in it.
    let bitcoin_block = model::BitcoinBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: bitcoin_tip_height + 1,
        parent_hash: bitcoin_tip,
    };
    let stacks_block = model::StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_tip.block_height + 1,
        parent_hash: stacks_tip.block_hash,
        bitcoin_anchor: bitcoin_block.block_hash,
    };
    let withdrawal_request = model::WithdrawalRequest {
        request_id: 1,
        txid: fake::Faker.fake_with_rng(&mut rng),
        block_hash: stacks_block.block_hash,
        recipient: fake::Faker.fake_with_rng(&mut rng),
        amount: 1_000,
        max_fee: 1_000,
        sender_address: fake::Faker.fake_with_rng(&mut rng),
        bitcoin_block_height: bitcoin_block.block_height,
    };

    // Now write all the data to the database.
    db.write_bitcoin_block(&bitcoin_block).await.unwrap();
    db.write_stacks_block(&stacks_block).await.unwrap();
    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();

    // There should be no requests because db do not contain sweep transaction
    let context_window = 20;
    let requests = db
        .get_swept_withdrawal_requests(&bitcoin_block.block_hash, context_window)
        .await
        .unwrap();
    assert!(requests.is_empty());

    signer::testing::storage::drop_db(db).await;
}

/// This function tests that deposit requests that do not have a confirmed
/// response (sweep) bitcoin transaction are not returned from
/// [`DbRead::get_swept_deposit_requests`].
#[tokio::test]
async fn get_swept_deposit_requests_does_not_return_unswept_deposit_requests() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This query doesn't *need* bitcoind (it's just a query), we just need
    // the transaction data in the database. We use the [`TestSweepSetup`]
    // structure because it has helper functions for generating and storing
    // sweep transactions, and the [`TestSweepSetup`] structure correctly
    // sets up the database.
    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // We need to manually update the database with new bitcoin block
    // headers.
    crate::setup::backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // This isn't technically required right now, but the deposit
    // transaction is supposed to be there, so future versions of our query
    // can rely on that fact.
    setup.store_deposit_tx(&db).await;

    // The request needs to be added to the database. This stores
    // `setup.deposit_request` into the database.
    setup.store_deposit_request(&db).await;

    // We are supposed to store a sweep transaction, but we haven't, so the
    // deposit request is not considered swept.
    let chain_tip = setup.sweep_block_hash.into();
    let context_window = 20;

    let requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    // Womp, the request is not considered swept.
    assert!(requests.is_empty());

    signer::testing::storage::drop_db(db).await;
}

/// This function tests that [`DbRead::get_swept_deposit_requests`] function
/// does not return requests where we have already confirmed a
/// `complete-deposit` contract call transaction on the canonical Stacks
/// blockchain.
///
/// We use two sweep setups: we add confirming events to both but for one
/// of them the event is not in the canonical chain, then we push another event
/// (on the canonical chain) resulting in both being confirmed on the canonical chain.
#[tokio::test]
async fn get_swept_deposit_requests_does_not_return_deposit_requests_with_responses() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This query doesn't *need* bitcoind (it's just a query), we just need
    // the transaction data in the database. We use the [`TestSweepSetup`]
    // structure because it has helper functions for generating and storing
    // sweep transactions, and the [`TestSweepSetup`] structure correctly
    // sets up the database.
    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();
    let mut setup_fork = TestSweepSetup::new_setup(&rpc, &faucet, 2_000_000, &mut rng);
    let mut setup_canonical = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    let context_window = 20;

    // Adding a block, we will use it to store the complete deposit event later
    let chain_tip: BitcoinBlockHash = faucet.generate_blocks(1).pop().unwrap().into();

    // We need to manually update the database with new bitcoin block
    // headers.
    crate::setup::backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;

    for setup in [&mut setup_fork, &mut setup_canonical] {
        // We almost always need a stacks genesis block, so let's store it.
        setup.store_stacks_genesis_block(&db).await;
        // This isn't technically required right now, but the deposit
        // transaction is supposed to be there, so future versions of our query
        // can rely on that fact.
        setup.store_deposit_tx(&db).await;

        // We take the sweep transaction as is from the test setup and
        // store it in the database.
        setup.store_sweep_tx(&db).await;

        // The request needs to be added to the database. This stores
        // `setup.deposit_request` into the database.
        setup.store_deposit_request(&db).await;
    }

    // Setup the stacks blocks
    let stacks_tip = db.get_stacks_chain_tip(&chain_tip).await.unwrap().unwrap();

    let setup_fork_event_block = StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_tip.block_height + 1,
        parent_hash: stacks_tip.block_hash,
        // For `setup_fork`, the stacks block is not in the canonical chain
        bitcoin_anchor: fake::Faker.fake_with_rng(&mut rng),
    };
    let setup_canonical_event_block = StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_tip.block_height + 1,
        parent_hash: stacks_tip.block_hash,
        // For `setup_canonical`, the stacks block is in the canonical chain
        bitcoin_anchor: chain_tip,
    };
    db.write_stacks_block_headers(vec![
        setup_fork_event_block.clone(),
        setup_canonical_event_block.clone(),
    ])
    .await
    .unwrap();

    // First, let's check we get both deposits
    let requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    assert_eq!(requests.len(), 2);

    // Here we store some events that signals that the deposit request has been confirmed.
    // For `setup_canonical`, the event block is on the canonical chain
    let event = CompletedDepositEvent {
        txid: fake::Faker.fake_with_rng::<StacksTxId, _>(&mut rng).into(),
        block_id: setup_canonical_event_block.block_hash.into(),
        amount: setup_canonical.deposit_request.amount,
        outpoint: setup_canonical.deposit_request.outpoint,
        sweep_block_hash: setup_canonical.deposit_block_hash.into(),
        sweep_block_height: 42u64.into(),
        sweep_txid: setup_canonical.deposit_request.outpoint.txid.into(),
    };
    db.write_completed_deposit_event(&event).await.unwrap();

    // For `setup_fork`, the event block is not on the canonical chain
    let event = CompletedDepositEvent {
        txid: fake::Faker.fake_with_rng::<StacksTxId, _>(&mut rng).into(),
        block_id: setup_fork_event_block.block_hash.into(),
        amount: setup_fork.deposit_request.amount,
        outpoint: setup_fork.deposit_request.outpoint,
        sweep_block_hash: setup_fork.deposit_block_hash.into(),
        sweep_block_height: 42u64.into(),
        sweep_txid: setup_fork.deposit_request.outpoint.txid.into(),
    };
    db.write_completed_deposit_event(&event).await.unwrap();

    let requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    // The only deposit request has a confirmed complete-deposit
    // transaction on the canonical stacks blockchain.
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].amount, setup_fork.deposit_info.amount);

    // Finally, we mine again on a block in the canonical chain
    let setup_fork_event_block = StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: setup_canonical_event_block.block_height + 1,
        parent_hash: setup_canonical_event_block.block_hash,
        bitcoin_anchor: chain_tip,
    };
    db.write_stacks_block(&setup_fork_event_block)
        .await
        .unwrap();

    let event = CompletedDepositEvent {
        txid: fake::Faker.fake_with_rng::<StacksTxId, _>(&mut rng).into(),
        block_id: setup_fork_event_block.block_hash.into(),
        amount: setup_fork.deposit_request.amount,
        outpoint: setup_fork.deposit_request.outpoint,
        sweep_block_hash: setup_fork.deposit_block_hash.into(),
        sweep_block_height: 42u64.into(),
        sweep_txid: setup_fork.deposit_request.outpoint.txid.into(),
    };
    db.write_completed_deposit_event(&event).await.unwrap();

    let requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    // Now both are confirmed
    assert!(requests.is_empty());

    signer::testing::storage::drop_db(db).await;
}

/// This tests that accepted withdrawal requests will not show up in the query results from
/// [`DbRead::get_swept_withdrawal_requests`].
#[tokio::test]
async fn get_swept_withdrawal_requests_does_not_return_withdrawal_requests_with_responses() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(16);

    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    let bitcoin_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let bitcoin_tip_height = db
        .get_bitcoin_block(&bitcoin_tip)
        .await
        .unwrap()
        .unwrap()
        .block_height;
    let stacks_tip = db
        .get_stacks_chain_tip(&bitcoin_tip)
        .await
        .unwrap()
        .unwrap();

    // Prepare all data we want to insert into the database to see swept withdrawal requests in it.
    let bitcoin_block = model::BitcoinBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: bitcoin_tip_height + 1,
        parent_hash: bitcoin_tip,
    };
    let stacks_block = model::StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_tip.block_height + 1,
        parent_hash: stacks_tip.block_hash,
        bitcoin_anchor: bitcoin_block.block_hash,
    };
    let withdrawal_request = model::WithdrawalRequest {
        request_id: 1,
        txid: fake::Faker.fake_with_rng(&mut rng),
        block_hash: stacks_block.block_hash,
        recipient: fake::Faker.fake_with_rng(&mut rng),
        amount: 1_000,
        max_fee: 1_000,
        sender_address: fake::Faker.fake_with_rng(&mut rng),
        bitcoin_block_height: bitcoin_block.block_height,
    };
    let swept_output = BitcoinWithdrawalOutput {
        request_id: withdrawal_request.request_id,
        stacks_txid: withdrawal_request.txid,
        stacks_block_hash: withdrawal_request.block_hash,
        bitcoin_chain_tip: bitcoin_block.block_hash,
        ..Faker.fake_with_rng(&mut rng)
    };
    let sweep_tx_model = model::Transaction {
        tx_type: model::TransactionType::SbtcTransaction,
        txid: swept_output.bitcoin_txid.to_byte_array(),
        tx: Vec::new(),
        block_hash: bitcoin_block.block_hash.to_byte_array(),
    };
    let sweep_tx_ref = model::BitcoinTxRef {
        txid: swept_output.bitcoin_txid,
        block_hash: bitcoin_block.block_hash,
    };

    let event = WithdrawalAcceptEvent {
        request_id: withdrawal_request.request_id,
        sweep_block_hash: bitcoin_block.block_hash,
        sweep_txid: sweep_tx_ref.txid,
        block_id: stacks_block.block_hash,
        ..Faker.fake_with_rng(&mut rng)
    };

    // Now write all the data to the database.
    db.write_bitcoin_block(&bitcoin_block).await.unwrap();
    db.write_stacks_block(&stacks_block).await.unwrap();
    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();
    db.write_transaction(&sweep_tx_model).await.unwrap();
    db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
    db.write_bitcoin_withdrawals_outputs(&[swept_output.clone()])
        .await
        .unwrap();

    // Before we write corresponding withdrawal accept event query should return 1 request
    let context_window = 20;
    let requests = db
        .get_swept_withdrawal_requests(&bitcoin_block.block_hash, context_window)
        .await
        .unwrap();
    assert_eq!(requests.len(), 1);

    db.write_withdrawal_accept_event(&event).await.unwrap();

    // Since we have corresponding withdrawal accept event query should return nothing
    let requests = db
        .get_swept_withdrawal_requests(&bitcoin_block.block_hash, context_window)
        .await
        .unwrap();
    assert!(requests.is_empty());

    // It should remain accepted even if we have an unconfirmed accept event in
    // some fork
    let forked_event = WithdrawalAcceptEvent {
        request_id: withdrawal_request.request_id,
        ..Faker.fake_with_rng(&mut rng)
    };
    db.write_withdrawal_accept_event(&forked_event)
        .await
        .unwrap();

    let requests = db
        .get_swept_withdrawal_requests(&bitcoin_block.block_hash, context_window)
        .await
        .unwrap();
    assert!(requests.is_empty());

    signer::testing::storage::drop_db(db).await;
}

/// This checks that the DbRead::can_sign_deposit_tx implementation for
/// PgStore operators as it is supposed to. Specifically, it checks that it
/// returns Some(true) if the caller is part of the signing set,
/// Some(false) if it isn't and None if the deposit request record cannot
/// be found.
#[tokio::test]
async fn can_sign_deposit_tx_rejects_not_in_signer_set() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // Let's create any old aggregate key
    let aggregate_key: PublicKey = fake::Faker.fake_with_rng(&mut rng);

    // Now for a deposit request where we use the above aggregate key.
    let mut req: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
    req.signers_public_key = aggregate_key.into();
    db.write_deposit_request(&req).await.unwrap();

    // Now we need a row where the aggregate key matches the one we created
    // above. Also, lets create some signing set.
    let signer_set_public_keys = std::iter::repeat_with(|| fake::Faker.fake_with_rng(&mut rng))
        .take(3)
        .collect::<Vec<PublicKey>>();
    let mut shares: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    shares.aggregate_key = aggregate_key;
    shares.signer_set_public_keys = signer_set_public_keys;
    db.write_encrypted_dkg_shares(&shares).await.unwrap();

    // For each public key in the signing set, we will correctly say that
    // the public key can sign for it.
    for signer_public_key in shares.signer_set_public_keys.iter() {
        let can_sign = db
            .can_sign_deposit_tx(&req.txid, req.output_index, signer_public_key)
            .await
            .unwrap();

        assert_eq!(can_sign, Some(true));
    }

    // For some public key not in the signing set, we will return false,
    // indicating that we cannot sign for the deposit request.
    let not_in_signing_set: PublicKey = fake::Faker.fake_with_rng(&mut rng);
    let can_sign = db
        .can_sign_deposit_tx(&req.txid, req.output_index, &not_in_signing_set)
        .await
        .unwrap();
    assert_eq!(can_sign, Some(false));

    // And lastly, if we do not have a record of the deposit request then
    // we return None.
    let random_txid = fake::Faker.fake_with_rng(&mut rng);
    let signer_public_key = shares.signer_set_public_keys.first().unwrap();
    let can_sign = db
        .can_sign_deposit_tx(&random_txid, req.output_index, signer_public_key)
        .await
        .unwrap();
    assert_eq!(can_sign, None);

    signer::testing::storage::drop_db(db).await;
}

/// This function tests that [`DbRead::get_swept_deposit_requests`]
/// function return requests where we have already confirmed a
/// `complete-deposit` contract call transaction on the Stacks blockchain
/// but that transaction has been reorged while the sweep transaction has not.
#[tokio::test]
async fn get_swept_deposit_requests_response_tx_reorged() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This query doesn't *need* bitcoind (it's just a query), we just need
    // the transaction data in the database. We use the [`TestSweepSetup`]
    // structure because it has helper functions for generating and storing
    // sweep transactions, and the [`TestSweepSetup`] structure correctly
    // sets up the database.
    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    let context_window = 20;

    // Adding a block, we will use it to store the complete deposit event later
    let chain_tip: BitcoinBlockHash = faucet.generate_blocks(1).pop().unwrap().into();

    // We need to manually update the database with new bitcoin block
    // headers.
    crate::setup::backfill_bitcoin_blocks(&db, rpc, &chain_tip).await;
    setup.store_stacks_genesis_block(&db).await;

    // This isn't technically required right now, but the deposit
    // transaction is supposed to be there, so future versions of our query
    // can rely on that fact.
    setup.store_deposit_tx(&db).await;

    // We take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // The request needs to be added to the database. This stores
    // `setup.deposit_request` into the database.
    setup.store_deposit_request(&db).await;

    let stacks_tip = db
        .get_stacks_chain_tip(&chain_tip.into())
        .await
        .unwrap()
        .unwrap();

    // First, let's check we get the deposit
    let requests = db
        .get_swept_deposit_requests(&chain_tip.into(), context_window)
        .await
        .unwrap();
    assert_eq!(requests.len(), 1);

    // Now we push the event to a stacks block anchored to the chain tip
    let original_event_block = StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_tip.block_height + 1,
        parent_hash: stacks_tip.block_hash,
        bitcoin_anchor: chain_tip.into(),
    };
    db.write_stacks_block(&original_event_block).await.unwrap();

    let event = CompletedDepositEvent {
        txid: fake::Faker.fake_with_rng::<StacksTxId, _>(&mut rng).into(),
        block_id: original_event_block.block_hash.into(),
        amount: setup.deposit_request.amount,
        outpoint: setup.deposit_request.outpoint,
        sweep_block_hash: setup.deposit_block_hash.into(),
        sweep_block_height: 42u64.into(),
        sweep_txid: setup.deposit_request.outpoint.txid.into(),
    };
    db.write_completed_deposit_event(&event).await.unwrap();

    // The deposit should be confirmed now
    let requests = db
        .get_swept_deposit_requests(&chain_tip.into(), context_window)
        .await
        .unwrap();

    assert!(requests.is_empty());

    // Now assume we have a reorg: the new bitcoin chain is `sweep_block_hash`
    // and the complete deposit event is no longer in the canonical chain.
    // The deposit should no longer be confirmed.
    let requests = db
        .get_swept_deposit_requests(&setup.sweep_block_hash.into(), context_window)
        .await
        .unwrap();

    assert_eq!(requests.len(), 1);

    signer::testing::storage::drop_db(db).await;
}

/// This test shows an edge case that it's not handled by the query: when we
/// have a confirmed event in a stacks block that is anchored to bitcoin block
/// before the bitcoin block including the sweep tx, the query will return the
/// deposit as swept (not confirmed) when the sweep tx block is at the boundary
/// of the context window. This can happen if we have empty sortitions, fast
/// blocks or other situations causing stacks blocks to be mined anchored
/// to a previous bitcoin block, and we sweep deposits in some newer blocks.
///
/// This case is handled by the validation on the coordinator, on the signers
/// and on the smart contract so it's not an issue.
#[tokio::test]
async fn get_swept_deposit_requests_boundary() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // This query doesn't *need* bitcoind (it's just a query), we just need
    // the transaction data in the database. We use the [`TestSweepSetup`]
    // structure because it has helper functions for generating and storing
    // sweep transactions, and the [`TestSweepSetup`] structure correctly
    // sets up the database.
    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    let context_window = 10;

    // We need to manually update the database with new bitcoin block headers.
    let chain_tip = fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // We almost always need a stacks genesis block, so let's store it.
    setup.store_stacks_genesis_block(&db).await;
    // This isn't technically required right now, but the deposit
    // transaction is supposed to be there, so future versions of our query
    // can rely on that fact.
    setup.store_deposit_tx(&db).await;

    // We take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // The request needs to be added to the database. This stores
    // `setup.deposit_request` into the database.
    setup.store_deposit_request(&db).await;

    // Sanity check for the scenario
    let deposit_block = db
        .get_bitcoin_block(&setup.deposit_block_hash.into())
        .await
        .unwrap()
        .unwrap();
    let sweep_block = db
        .get_bitcoin_block(&setup.sweep_block_hash.into())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deposit_block.block_height + 1, sweep_block.block_height);

    // Setup the stacks blocks
    let stacks_tip = db.get_stacks_chain_tip(&chain_tip).await.unwrap().unwrap();

    // The event is anchored to the deposit block, that is before the sweep
    // block
    let event_block = StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_tip.block_height + 1,
        parent_hash: stacks_tip.block_hash,
        bitcoin_anchor: setup.deposit_block_hash.into(),
    };
    db.write_stacks_block(&event_block).await.unwrap();

    // First, let's check we get the deposit
    let requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    assert_eq!(requests.len(), 1);

    // Store the complete deposit event
    let event = CompletedDepositEvent {
        txid: fake::Faker.fake_with_rng::<StacksTxId, _>(&mut rng).into(),
        block_id: event_block.block_hash.into(),
        amount: setup.deposit_request.amount,
        outpoint: setup.deposit_request.outpoint,
        sweep_block_hash: setup.sweep_block_hash.into(),
        sweep_block_height: 42u64.into(),
        sweep_txid: setup.deposit_request.outpoint.txid.into(),
    };
    db.write_completed_deposit_event(&event).await.unwrap();

    // And now the request is no longer swept (and pending confirmation)
    let requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    assert!(requests.is_empty());

    // This will remain valid for a bunch of blocks; one block is already mined
    // for the sweep tx
    for _ in 1..context_window - 1 {
        faucet.generate_block();
        let chain_tip = fetch_canonical_bitcoin_blockchain(&db, rpc).await;

        let requests = db
            .get_swept_deposit_requests(&chain_tip, context_window)
            .await
            .unwrap();

        assert!(requests.is_empty());
    }

    // But once we reach the boundary of the context window, we will lose track
    // of the completed event
    faucet.generate_block();
    let chain_tip = fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    let requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    assert_eq!(requests.len(), 1);

    signer::testing::storage::drop_db(db).await;
}

/// This function tests that [`DbRead::get_swept_withdrawal_requests`]
/// function return requests where we have already confirmed a
/// `complete-withdrawal` contract call transaction on the Stacks blockchain
/// but that transaction has been reorged while the sweep transaction has not.
#[tokio::test]
async fn get_swept_withdrawal_requests_response_tx_reorged() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(16);

    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    let bitcoin_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let bitcoin_tip_height = db
        .get_bitcoin_block(&bitcoin_tip)
        .await
        .unwrap()
        .unwrap()
        .block_height;
    let stacks_tip = db
        .get_stacks_chain_tip(&bitcoin_tip)
        .await
        .unwrap()
        .unwrap();

    // Prepare all data we want to insert into the database to see swept withdrawal requests in it.
    let bitcoin_block = model::BitcoinBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: bitcoin_tip_height + 1,
        parent_hash: bitcoin_tip,
    };
    let stacks_block = model::StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_tip.block_height + 1,
        parent_hash: stacks_tip.block_hash,
        bitcoin_anchor: bitcoin_block.block_hash,
    };
    let withdrawal_request = model::WithdrawalRequest {
        request_id: 1,
        txid: fake::Faker.fake_with_rng(&mut rng),
        block_hash: stacks_block.block_hash,
        recipient: fake::Faker.fake_with_rng(&mut rng),
        amount: 1_000,
        max_fee: 1_000,
        sender_address: fake::Faker.fake_with_rng(&mut rng),
        bitcoin_block_height: bitcoin_block.block_height,
    };
    let swept_output = BitcoinWithdrawalOutput {
        request_id: withdrawal_request.request_id,
        stacks_txid: withdrawal_request.txid,
        stacks_block_hash: withdrawal_request.block_hash,
        bitcoin_chain_tip: bitcoin_block.block_hash,
        ..Faker.fake_with_rng(&mut rng)
    };
    let sweep_tx_model = model::Transaction {
        tx_type: model::TransactionType::SbtcTransaction,
        txid: swept_output.bitcoin_txid.to_byte_array(),
        tx: Vec::new(),
        block_hash: bitcoin_block.block_hash.to_byte_array(),
    };
    let sweep_tx_ref = model::BitcoinTxRef {
        txid: swept_output.bitcoin_txid,
        block_hash: bitcoin_block.block_hash,
    };

    // Now write all the data to the database.
    db.write_bitcoin_block(&bitcoin_block).await.unwrap();
    db.write_stacks_block(&stacks_block).await.unwrap();
    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();
    db.write_transaction(&sweep_tx_model).await.unwrap();
    db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
    db.write_bitcoin_withdrawals_outputs(&[swept_output.clone()])
        .await
        .unwrap();

    // Creating new bitcoin block, withdrawal accept event will happen
    // in stacks block ancored to this block
    let new_block = model::BitcoinBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: bitcoin_block.block_height + 1,
        parent_hash: bitcoin_block.block_hash,
    };

    // Now we push the event to a stacks block anchored to the chain tip
    let original_event_block = StacksBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: stacks_block.block_height + 1,
        parent_hash: stacks_block.block_hash,
        bitcoin_anchor: new_block.block_hash,
    };
    db.write_stacks_block(&original_event_block).await.unwrap();

    let event = WithdrawalAcceptEvent {
        request_id: withdrawal_request.request_id,
        block_id: original_event_block.block_hash,
        sweep_block_hash: bitcoin_block.block_hash,
        sweep_txid: sweep_tx_ref.txid,
        ..Faker.fake_with_rng(&mut rng)
    };

    db.write_bitcoin_block(&new_block).await.unwrap();

    db.write_withdrawal_accept_event(&event).await.unwrap();

    // since this withdrawal was accepted get_swept_withdrawal_requests should return nothing
    let context_window = 20;
    let requests = db
        .get_swept_withdrawal_requests(&new_block.block_hash, context_window)
        .await
        .unwrap();
    assert!(requests.is_empty());

    // Now assume we have a reorg: the new bitcoin chain tip is `bitcoin_block`
    // and the accept withdrawal event is no longer in the canonical chain.
    // The withdrawal should no longer be confirmed.
    let requests = db
        .get_swept_withdrawal_requests(&bitcoin_block.block_hash, context_window)
        .await
        .unwrap();

    assert_eq!(requests.len(), 1);

    signer::testing::storage::drop_db(db).await;
}

async fn transaction_coordinator_test_environment(
    store: PgStore,
) -> testing::transaction_coordinator::TestEnvironment<
    TestContext<
        storage::postgres::PgStore,
        WrappedMock<MockBitcoinInteract>,
        WrappedMock<MockStacksInteract>,
        WrappedMock<MockEmilyInteract>,
    >,
> {
    let test_model_parameters = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 7,
        consecutive_blocks: false,
    };

    let context = TestContext::builder()
        .with_storage(store)
        .with_mocked_clients()
        .build();

    testing::transaction_coordinator::TestEnvironment {
        context,
        context_window: 5,
        num_signers: 7,
        signing_threshold: 5,
        test_model_parameters,
    }
}

/// Tests that TxCoordinatorEventLoop::get_pending_requests processes withdrawals
#[tokio::test]
async fn should_process_withdrawals() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_processes_withdrawals()
        .await;

    testing::storage::drop_db(store).await;
}

#[tokio::test]
async fn should_get_signer_utxo_simple() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_simple()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[tokio::test]
async fn should_get_signer_utxo_fork() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_fork()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[tokio::test]
async fn should_get_signer_utxo_unspent() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_unspent()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[tokio::test]
async fn should_get_signer_utxo_donations() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_donations()
        .await;

    signer::testing::storage::drop_db(store).await;
}

/// The following tests check the [`DbRead::get_deposit_request_report`]
/// function and all follow a similar pattern. The pattern is:
/// 1. Generate a random blockchain and write it to the database.
/// 2. Generate a random deposit request and write it to the database.
///    Write the associated deposit transaction as well, sometimes this
///    transaction will be on the canonical bitcoin blockchain, sometimes
///    not.
/// 3. Maybe generate a random deposit vote for the current signer and
///    store that in the database.
/// 4. Maybe generate a sweep transaction and put that in our database.
/// 5. Check that the report comes out right depending on where the various
///    transactions are confirmed.

/// Check the expected report if the deposit request and transaction are in
/// the database, but this signers vote is missing and the transaction is
/// confirmed on the wrong blockchain.
#[tokio::test]
async fn deposit_report_with_only_deposit_request() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(20);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // Let's create a deposit request, we'll write it to the database
    // later.
    let deposit_request: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let txid = &deposit_request.txid;
    let output_index = deposit_request.output_index;
    let signer_public_key = &signer_set[0];

    // The deposit request is not in our database, so we should get None
    // here.
    let report = db
        .get_deposit_request_report(&chain_tip, txid, output_index, signer_public_key)
        .await
        .unwrap();

    assert!(report.is_none());

    // We're going to write the deposit request to the database. We also
    // write the deposit transaction to the database. For that transaction
    // we want to test what happens if it is not on the canonical bitcoin
    // transaction.
    let random_block: model::BitcoinBlock = fake::Faker.fake_with_rng(&mut rng);
    let tx = model::Transaction {
        txid: deposit_request.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::DepositRequest,
        block_hash: random_block.block_hash.into_bytes(),
    };
    let tx_ref = model::BitcoinTxRef {
        txid: deposit_request.txid,
        block_hash: random_block.block_hash,
    };

    db.write_deposit_request(&deposit_request).await.unwrap();

    // Sanity check, that if the transaction is not in our database then
    // the report comes back empty.
    let report = db
        .get_deposit_request_report(&chain_tip, txid, output_index, signer_public_key)
        .await
        .unwrap();

    assert!(report.is_none());

    db.write_bitcoin_block(&random_block).await.unwrap();
    db.write_transaction(&tx).await.unwrap();
    db.write_bitcoin_transaction(&tx_ref).await.unwrap();

    // The result shouldn't be Ok(None), since we have a deposit request,
    // but only the amount and locktime should be present, everything else
    // should be None.
    let report = db
        .get_deposit_request_report(&chain_tip, txid, output_index, signer_public_key)
        .await
        .unwrap()
        .unwrap();

    let report_lock_time = report.lock_time.to_consensus_u32();

    assert_eq!(report.amount, deposit_request.amount);
    assert_eq!(report_lock_time, deposit_request.lock_time);
    assert_eq!(report.max_fee, deposit_request.max_fee);
    assert!(report.can_accept.is_none());
    assert!(report.can_sign.is_none());
    // The transaction is not on the canonical bitcoin blockchain, so it
    // shows up as unconfirmed.
    assert_eq!(report.status, DepositConfirmationStatus::Unconfirmed);

    testing::storage::drop_db(db).await;
}

/// Check that if the deposit has been confirmed on a block that is not on
/// the canonical bitcoin blockchain then the deposit reports the status as
/// unconfirmed. We also check that if this signer has voted on the request
/// that the votes are accurately reflected in the report.
///
/// The difference between this test and
/// [`deposit_report_with_only_deposit_request`] is that we write the
/// signer decision to the database here and check that it gets reproduced
/// in the report.
#[tokio::test]
async fn deposit_report_with_deposit_request_reorged() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(21);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // Let's write the deposit request and associated transaction to our
    // database. The deposit transaction will be confirmed, but on a block
    // that is not on the canonical bitcoin blockchain.
    let deposit_request: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let txid = &deposit_request.txid;
    let output_index = deposit_request.output_index;
    let signer_public_key = &signer_set[0];

    let random_block: model::BitcoinBlock = fake::Faker.fake_with_rng(&mut rng);
    let tx = model::Transaction {
        txid: deposit_request.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::DepositRequest,
        block_hash: random_block.block_hash.into_bytes(),
    };
    let tx_ref = model::BitcoinTxRef {
        txid: deposit_request.txid,
        block_hash: random_block.block_hash,
    };

    db.write_deposit_request(&deposit_request).await.unwrap();
    db.write_bitcoin_block(&random_block).await.unwrap();
    db.write_transaction(&tx).await.unwrap();
    db.write_bitcoin_transaction(&tx_ref).await.unwrap();

    // Time to record the signers' vote.
    let mut decision: model::DepositSigner = fake::Faker.fake_with_rng(&mut rng);
    decision.output_index = deposit_request.output_index;
    decision.txid = deposit_request.txid;
    decision.signer_pub_key = *signer_public_key;

    db.write_deposit_signer_decision(&decision).await.unwrap();

    let report = db
        .get_deposit_request_report(&chain_tip, txid, output_index, signer_public_key)
        .await
        .unwrap()
        .unwrap();

    let report_lock_time = report.lock_time.to_consensus_u32();

    assert_eq!(report.amount, deposit_request.amount);
    assert_eq!(report_lock_time, deposit_request.lock_time);
    assert_eq!(report.max_fee, deposit_request.max_fee);
    assert_eq!(report.can_accept, Some(decision.can_accept));
    assert_eq!(report.can_sign, Some(decision.can_sign));
    assert_eq!(report.status, DepositConfirmationStatus::Unconfirmed);

    signer::testing::storage::drop_db(db).await;
}

/// Check that if the deposit has been included in a sweep transaction
/// then the deposit report states that the deposit has been spent in the
/// status.
#[tokio::test]
async fn deposit_report_with_deposit_request_spent() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(22);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // Let's write the deposit request and associated transaction to the
    // database. Here the deposit transaction will be confirmed on the
    // canonical bitcoin blockchain.
    let deposit_request: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let txid = &deposit_request.txid;
    let output_index = deposit_request.output_index;
    let signer_public_key = &signer_set[0];

    let tx = model::Transaction {
        txid: deposit_request.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::DepositRequest,
        block_hash: chain_tip.into_bytes(),
    };
    let tx_ref = model::BitcoinTxRef {
        txid: deposit_request.txid,
        block_hash: chain_tip,
    };

    db.write_deposit_request(&deposit_request).await.unwrap();
    db.write_transaction(&tx).await.unwrap();
    db.write_bitcoin_transaction(&tx_ref).await.unwrap();

    // Write the decision to the database
    let mut decision: model::DepositSigner = fake::Faker.fake_with_rng(&mut rng);
    decision.output_index = deposit_request.output_index;
    decision.txid = deposit_request.txid;
    decision.signer_pub_key = *signer_public_key;

    db.write_deposit_signer_decision(&decision).await.unwrap();

    // Okay now let's pretend that the deposit has been swept. For that we
    // need a row in the `bitcoin_tx_inputs` tables, and records in the `transactions`
    // and `bitcoin_transactions` tables.
    let mut swept_prevout: model::TxPrevout = fake::Faker.fake_with_rng(&mut rng);
    swept_prevout.prevout_txid = deposit_request.txid;
    swept_prevout.prevout_output_index = deposit_request.output_index;
    swept_prevout.amount = deposit_request.amount;

    let sweep_tx_model = model::Transaction {
        tx_type: model::TransactionType::SbtcTransaction,
        txid: swept_prevout.txid.to_byte_array(),
        tx: Vec::new(),
        block_hash: chain_tip.to_byte_array(),
    };
    let sweep_tx_ref = model::BitcoinTxRef {
        txid: swept_prevout.txid,
        block_hash: chain_tip,
    };
    db.write_transaction(&sweep_tx_model).await.unwrap();
    db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
    db.write_tx_prevout(&swept_prevout).await.unwrap();

    let report = db
        .get_deposit_request_report(&chain_tip, txid, output_index, signer_public_key)
        .await
        .unwrap()
        .unwrap();

    let report_lock_time = report.lock_time.to_consensus_u32();

    assert_eq!(report.amount, deposit_request.amount);
    assert_eq!(report_lock_time, deposit_request.lock_time);
    assert_eq!(report.max_fee, deposit_request.max_fee);
    assert_eq!(report.can_accept, Some(decision.can_accept));
    assert_eq!(report.can_sign, Some(decision.can_sign));
    assert_eq!(
        report.status,
        DepositConfirmationStatus::Spent(swept_prevout.txid)
    );

    signer::testing::storage::drop_db(db).await;
}

/// Check that if the deposit has been included in a sweep transaction
/// that gets reorged, then the deposit report states that the deposit is
/// confirmed and not spent.
#[tokio::test]
async fn deposit_report_with_deposit_request_swept_but_swept_reorged() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(23);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // Let's write the deposit request and associated transaction to the
    // database. Here the deposit transaction will be confirmed on the
    // canonical bitcoin blockchain.
    let deposit_request: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let chain_tip_block = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();
    let txid = &deposit_request.txid;
    let output_index = deposit_request.output_index;
    let signer_public_key = &signer_set[0];

    // We confirm it on the parent block of the chain tip because later we
    // change the chain tip and test certain conditions.
    let tx = model::Transaction {
        txid: deposit_request.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::DepositRequest,
        block_hash: chain_tip_block.parent_hash.into_bytes(),
    };
    let tx_ref = model::BitcoinTxRef {
        txid: deposit_request.txid,
        block_hash: chain_tip_block.parent_hash,
    };

    db.write_deposit_request(&deposit_request).await.unwrap();
    db.write_transaction(&tx).await.unwrap();
    db.write_bitcoin_transaction(&tx_ref).await.unwrap();

    // Write the decision to the database
    let mut decision: model::DepositSigner = fake::Faker.fake_with_rng(&mut rng);
    decision.output_index = deposit_request.output_index;
    decision.txid = deposit_request.txid;
    decision.signer_pub_key = *signer_public_key;

    db.write_deposit_signer_decision(&decision).await.unwrap();

    // Okay now let's pretend that the deposit has been swept, but the
    // sweep gets reorged. For that we need a row in the `sweep_*` tables,
    // and records in the `transactions` and `bitcoin_transactions` tables,
    // but we'll use a random block that appears at the same height as the
    // current chain tip for what confirms the sweep transaction. This way
    // it is not on the canonical bitcoin blockchain identified by the
    // chain tip.
    let mut alt_chain_tip_block: model::BitcoinBlock = chain_tip_block.clone();
    alt_chain_tip_block.block_hash = fake::Faker.fake_with_rng(&mut rng);

    let mut swept_prevout: model::TxPrevout = fake::Faker.fake_with_rng(&mut rng);
    swept_prevout.prevout_txid = deposit_request.txid;
    swept_prevout.prevout_output_index = deposit_request.output_index;
    swept_prevout.amount = deposit_request.amount;

    let sweep_tx_model = model::Transaction {
        tx_type: model::TransactionType::SbtcTransaction,
        txid: swept_prevout.txid.to_byte_array(),
        tx: Vec::new(),
        block_hash: alt_chain_tip_block.block_hash.to_byte_array(),
    };
    let sweep_tx_ref = model::BitcoinTxRef {
        txid: swept_prevout.txid,
        block_hash: alt_chain_tip_block.block_hash,
    };
    db.write_bitcoin_block(&alt_chain_tip_block).await.unwrap();
    db.write_transaction(&sweep_tx_model).await.unwrap();
    db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
    db.write_tx_prevout(&swept_prevout).await.unwrap();

    let report = db
        .get_deposit_request_report(&chain_tip, txid, output_index, signer_public_key)
        .await
        .unwrap()
        .unwrap();

    let report_lock_time = report.lock_time.to_consensus_u32();

    assert_eq!(report.amount, deposit_request.amount);
    assert_eq!(report_lock_time, deposit_request.lock_time);
    assert_eq!(report.max_fee, deposit_request.max_fee);
    assert_eq!(report.can_accept, Some(decision.can_accept));
    assert_eq!(report.can_sign, Some(decision.can_sign));

    let confirmed_height = chain_tip_block.block_height - 1;
    let confirmed_block_hash = chain_tip_block.parent_hash;
    let expected_status =
        DepositConfirmationStatus::Confirmed(confirmed_height, confirmed_block_hash);
    assert_eq!(report.status, expected_status);

    // If we use the chain tip that confirms the sweep transaction, then we
    // see that the report tells us that it is now spent.
    let alt_chain_tip = alt_chain_tip_block.block_hash;
    let report = db
        .get_deposit_request_report(&alt_chain_tip, txid, output_index, signer_public_key)
        .await
        .unwrap()
        .unwrap();

    let report_lock_time = report.lock_time.to_consensus_u32();

    assert_eq!(report.amount, deposit_request.amount);
    assert_eq!(report_lock_time, deposit_request.lock_time);
    assert_eq!(report.max_fee, deposit_request.max_fee);
    assert_eq!(report.can_accept, Some(decision.can_accept));
    assert_eq!(report.can_sign, Some(decision.can_sign));

    let expected_status = DepositConfirmationStatus::Spent(swept_prevout.txid);
    assert_eq!(report.status, expected_status);

    signer::testing::storage::drop_db(db).await;
}

/// Check when we have a deposit that has been confirmed on the canonical
/// bitcoin and hasn't been spent, that the deposit report has the
/// appropriate "Confirmed" status.
#[tokio::test]
async fn deposit_report_with_deposit_request_confirmed() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(24);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // Let's write the deposit request and associated transaction to the
    // database. The transaction will be on the canonical bitcoin
    // blockchain.
    let deposit_request: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let txid = &deposit_request.txid;
    let output_index = deposit_request.output_index;
    let signer_public_key = &signer_set[0];

    let tx = model::Transaction {
        txid: deposit_request.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::DepositRequest,
        block_hash: chain_tip.into_bytes(),
    };
    let tx_ref = model::BitcoinTxRef {
        txid: deposit_request.txid,
        block_hash: chain_tip,
    };

    db.write_deposit_request(&deposit_request).await.unwrap();
    db.write_transaction(&tx).await.unwrap();
    db.write_bitcoin_transaction(&tx_ref).await.unwrap();

    // Write this signer's vote to the database.
    let mut decision: model::DepositSigner = fake::Faker.fake_with_rng(&mut rng);
    decision.output_index = deposit_request.output_index;
    decision.txid = deposit_request.txid;
    decision.signer_pub_key = *signer_public_key;

    db.write_deposit_signer_decision(&decision).await.unwrap();

    let report = db
        .get_deposit_request_report(&chain_tip, txid, output_index, signer_public_key)
        .await
        .unwrap()
        .unwrap();

    let report_lock_time = report.lock_time.to_consensus_u32();

    // This is all happy path stuff, with fields filled in and a confirmed
    // status.
    assert_eq!(report.amount, deposit_request.amount);
    assert_eq!(report_lock_time, deposit_request.lock_time);
    assert_eq!(report.max_fee, deposit_request.max_fee);
    assert_eq!(report.can_accept, Some(decision.can_accept));
    assert_eq!(report.can_sign, Some(decision.can_sign));

    let block = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();
    let expected_status =
        DepositConfirmationStatus::Confirmed(block.block_height, block.block_hash);
    assert_eq!(report.status, expected_status);

    signer::testing::storage::drop_db(db).await;
}

/// The following tests check the [`DbRead::get_withdrawal_request_report`]
/// function and all follow a similar pattern. The pattern is:
/// 1. Generate a random blockchain and write it to the database.
/// 2. Generate a random withdrawal request and write it to the database.
///    Write the block that included the transaction that confirmed the
///    transaction as well, sometimes this transaction will be on the
///    canonical bitcoin blockchain, sometimes not.
/// 3. Maybe generate a random withdrawal vote for the current signer and
///    store that in the database.
/// 4. Maybe generate a sweep transaction and put that in our database.
/// 5. Check that the report comes out right depending on where the various
///    transactions are confirmed.

/// Check that no report is generated if the withdrawal request is not in
/// the database or if the stacks block that confirmed the transaction that
/// generated the request is not in the database.
#[tokio::test]
async fn withdrawal_report_with_no_withdrawal_request_or_no_block() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_public_keys = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let signer_public_key = &signer_public_keys[0];
    let test_data = TestData::generate(&mut rng, &signer_public_keys, &test_params);
    test_data.write_to(&db).await;

    let bitcoin_chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let stacks_chain_tip = db
        .get_stacks_chain_tip(&bitcoin_chain_tip)
        .await
        .unwrap()
        .unwrap()
        .block_hash;

    // Let's suppose we are given a withdrawal request to validate that we
    // do not know about. In this case no report should be returned.
    let qualified_id = QualifiedRequestId {
        request_id: Faker.fake_with_rng::<u32, _>(&mut rng) as u64,
        txid: Faker.fake_with_rng(&mut rng),
        block_hash: stacks_chain_tip,
    };

    let maybe_report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_chain_tip,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap();

    assert!(maybe_report.is_none());

    // Now suppose that we know about the withdrawal request but it is not
    // confirmed on a stacks block that we have a record of.
    let withdrawal_request: WithdrawalRequest = Faker.fake_with_rng(&mut rng);
    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();

    let qualified_id = withdrawal_request.qualified_id();
    let maybe_report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_chain_tip,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap();

    assert!(maybe_report.is_none());

    testing::storage::drop_db(db).await;
}

/// Check that the is_accepted field is none only if we do not have our
/// vote for the withdrawal request.
#[tokio::test]
async fn withdrawal_report_with_no_withdrawal_votes() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(4);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_public_keys = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let signer_public_key = &signer_public_keys[0];
    let test_data = TestData::generate(&mut rng, &signer_public_keys, &test_params);
    test_data.write_to(&db).await;

    let bitcoin_chain_tip_ref = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    let bitcoin_chain_tip = bitcoin_chain_tip_ref.block_hash;
    let stacks_chain_tip_block = db
        .get_stacks_chain_tip(&bitcoin_chain_tip)
        .await
        .unwrap()
        .unwrap();
    let stacks_chain_tip = stacks_chain_tip_block.block_hash;

    // Let's suppose that this withdrawal request was generated in a
    // transaction on the chain tip of the stacks blockchain, so that we
    // know that it is confirmed.
    //
    // Note that the block_height usually matters, since the queries only
    // look for sweeps in blocks with height greater than or equal to the
    // block height in the withdrawal request. In this case, there is no
    // sweep transaction in the database, so it doesn't matter.
    let withdrawal_request = WithdrawalRequest {
        block_hash: stacks_chain_tip,
        bitcoin_block_height: bitcoin_chain_tip_ref.block_height,
        ..Faker.fake_with_rng(&mut rng)
    };

    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();

    let qualified_id = withdrawal_request.qualified_id();
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_chain_tip,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    // We didn't put any votes in the database, but the withdrawal request
    // should be identified with a transaction on the blockchain identified
    // by the given chain tip, since it's actually on the chain tip.
    assert!(report.is_accepted.is_none());
    assert_eq!(report.status, WithdrawalRequestStatus::Confirmed);

    let withdrawal_decision = WithdrawalSigner {
        request_id: qualified_id.request_id,
        block_hash: qualified_id.block_hash,
        txid: qualified_id.txid,
        signer_pub_key: *signer_public_key,
        is_accepted: true,
    };
    db.write_withdrawal_signer_decision(&withdrawal_decision)
        .await
        .unwrap();

    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_chain_tip,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(report.is_accepted, Some(true));
    assert_eq!(report.status, WithdrawalRequestStatus::Confirmed);

    // Let's try one more time but with another public key (who we know has
    // not submitted a vote).
    let signer_public_key_2 = &signer_public_keys[1];
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_chain_tip,
            &qualified_id,
            signer_public_key_2,
        )
        .await
        .unwrap()
        .unwrap();

    assert!(report.is_accepted.is_none());
    assert_eq!(report.status, WithdrawalRequestStatus::Confirmed);

    testing::storage::drop_db(db).await;
}

/// Check that the report will return that the is unconfirmed if the
/// transaction that generated the request is not on stacks blockchain
/// identified by the given chain tip.
#[tokio::test]
async fn withdrawal_report_with_withdrawal_request_reorged() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(8);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_public_keys = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let signer_public_key = &signer_public_keys[0];
    let test_data = TestData::generate(&mut rng, &signer_public_keys, &test_params);
    test_data.write_to(&db).await;

    let bitcoin_chain_tip_ref = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    let bitcoin_chain_tip = bitcoin_chain_tip_ref.block_hash;
    let stacks_chain_tip_block = db
        .get_stacks_chain_tip(&bitcoin_chain_tip)
        .await
        .unwrap()
        .unwrap();

    // Okay let's put the withdrawal request in the database on the stacks
    // chain tip.
    let withdrawal_request = WithdrawalRequest {
        block_hash: stacks_chain_tip_block.block_hash,
        bitcoin_block_height: bitcoin_chain_tip_ref.block_height,
        ..Faker.fake_with_rng(&mut rng)
    };

    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();

    // Now let's generate a report where we know that the withdrawal
    // request is not on the blockchain identified by the given chain tip.
    let qualified_id = withdrawal_request.qualified_id();
    let random_stacks_chain_tip = Faker.fake_with_rng(&mut rng);
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &random_stacks_chain_tip,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(report.status, WithdrawalRequestStatus::Unconfirmed);

    // Okay, well does it say that it's confirmed if we know that it's on
    // the blockchain.
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_chain_tip_block.block_hash,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(report.status, WithdrawalRequestStatus::Confirmed);

    testing::storage::drop_db(db).await;
}

/// Check that the report correctly notes that the withdrawal request has
/// been fulfilled if there is sweep information in the database.
#[tokio::test]
async fn withdrawal_report_with_withdrawal_request_fulfilled() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(16);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_public_keys = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let signer_public_key = &signer_public_keys[0];
    let test_data = TestData::generate(&mut rng, &signer_public_keys, &test_params);
    test_data.write_to(&db).await;

    let bitcoin_chain_tip_ref = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    let bitcoin_chain_tip = bitcoin_chain_tip_ref.block_hash;
    let stacks_chain_tip_block = db
        .get_stacks_chain_tip(&bitcoin_chain_tip)
        .await
        .unwrap()
        .unwrap();

    // Note that the block_height matters here, since the queries look for
    // sweeps in blocks with height greater than or equal to the block
    // height in the withdrawal request. In this case, the sweep
    // transaction is confirmed on the chain tip of the bitcoin blockchain.
    let withdrawal_request = WithdrawalRequest {
        block_hash: stacks_chain_tip_block.block_hash,
        bitcoin_block_height: bitcoin_chain_tip_ref.block_height - 1,
        ..Faker.fake_with_rng(&mut rng)
    };
    let qualified_id = withdrawal_request.qualified_id();

    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();

    // Okay now let's pretend that the withdrawal has been swept. For that
    // we need a row in the `bitcoin_withdrawals_outputs` table, and
    // records in the `transactions` and `bitcoin_transactions` tables. We
    // place the sweep on the bitcoin chain tip.
    let swept_output = BitcoinWithdrawalOutput {
        request_id: qualified_id.request_id,
        stacks_txid: qualified_id.txid,
        stacks_block_hash: qualified_id.block_hash,
        bitcoin_chain_tip,
        ..Faker.fake_with_rng(&mut rng)
    };

    let sweep_tx_model = model::Transaction {
        tx_type: model::TransactionType::SbtcTransaction,
        txid: swept_output.bitcoin_txid.to_byte_array(),
        tx: Vec::new(),
        block_hash: bitcoin_chain_tip.to_byte_array(),
    };
    let sweep_tx_ref = model::BitcoinTxRef {
        txid: swept_output.bitcoin_txid,
        block_hash: bitcoin_chain_tip,
    };
    db.write_transaction(&sweep_tx_model).await.unwrap();
    db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
    db.write_bitcoin_withdrawals_outputs(&[swept_output])
        .await
        .unwrap();

    let bitcoin_block = db
        .get_bitcoin_block(&bitcoin_chain_tip)
        .await
        .unwrap()
        .unwrap();
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_block.block_hash,
            &stacks_chain_tip_block.block_hash,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    let expected_status = WithdrawalRequestStatus::Fulfilled(sweep_tx_ref);
    assert_eq!(report.status, expected_status);

    // Okay, now let's say that we give the parent of the block that
    // confirmed the sweep as the chain tip, so that we know that the sweep
    // is not on that blockchain. The status should just be confirmed now.
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_block.parent_hash,
            &stacks_chain_tip_block.block_hash,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(report.status, WithdrawalRequestStatus::Confirmed);

    testing::storage::drop_db(db).await;
}

/// Check that a reorg on bitcoin that affects the sweep leads to the
/// report switching the status of the withdrawal from fulfilled to just
/// confirmed.
#[tokio::test]
async fn withdrawal_report_with_withdrawal_request_swept_but_swept_reorged() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(32);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 50,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: true,
    };

    let signer_public_keys = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let signer_public_key = &signer_public_keys[0];
    let mut test_data = TestData::generate(&mut rng, &signer_public_keys, &test_params);
    let mut block_height = 0u64;
    let mut parent_hash = Faker.fake_with_rng(&mut rng);
    // Our `TestData` generator doesn't quite build us a nice Stacks
    // blockchain. So we manually make sure that we have consecutive blocks
    // here before writing them to the database. It matters because the
    // data that is generated by default is not a useful blockchain; all
    // blocks have the same height and their parents don't point to blocks
    // that exist.
    for block in test_data.stacks_blocks.iter_mut() {
        block.block_height = block_height.into();
        block.parent_hash = parent_hash;
        block_height += 1;
        parent_hash = block.block_hash;
    }
    test_data.write_to(&db).await;

    let bitcoin_chain_tip_ref = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    let stacks_block = test_data.stacks_blocks[1].clone();

    // Okay let's put the withdrawal request to some low block height on
    // the chain.
    assert_eq!(stacks_block.block_height, 1u64.into());
    let withdrawal_request = WithdrawalRequest {
        block_hash: stacks_block.block_hash,
        bitcoin_block_height: bitcoin_chain_tip_ref.block_height,
        ..Faker.fake_with_rng(&mut rng)
    };
    let qualified_id = withdrawal_request.qualified_id();

    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();

    // Okay now let's pretend that the withdrawal has been swept. For that
    // we need a row in the `bitcoin_withdrawals_outputs` table, and
    // records in the `transactions` and `bitcoin_transactions` tables. We
    // place the sweep on the bitcoin chain tip.
    let swept_output = BitcoinWithdrawalOutput {
        request_id: qualified_id.request_id,
        stacks_txid: qualified_id.txid,
        stacks_block_hash: qualified_id.block_hash,
        bitcoin_chain_tip: bitcoin_chain_tip_ref.block_hash,
        ..Faker.fake_with_rng(&mut rng)
    };

    let sweep_tx_model = model::Transaction {
        tx_type: model::TransactionType::SbtcTransaction,
        txid: swept_output.bitcoin_txid.to_byte_array(),
        tx: Vec::new(),
        block_hash: bitcoin_chain_tip_ref.block_hash.to_byte_array(),
    };
    let sweep_tx_ref = model::BitcoinTxRef {
        txid: swept_output.bitcoin_txid,
        block_hash: bitcoin_chain_tip_ref.block_hash,
    };
    db.write_transaction(&sweep_tx_model).await.unwrap();
    db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
    db.write_bitcoin_withdrawals_outputs(&[swept_output])
        .await
        .unwrap();

    // Alright, the report should say that the withdrawal request has been
    // fulfilled.
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip_ref.block_hash,
            &stacks_block.block_hash,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        report.status,
        WithdrawalRequestStatus::Fulfilled(sweep_tx_ref)
    );

    let bitcoin_chain_tip_block = db
        .get_bitcoin_block(&bitcoin_chain_tip_ref.block_hash)
        .await
        .unwrap()
        .unwrap();

    // Now let's fork the bitcoin blockchain, generating a sibling block to
    // the current chain tip and a child block, which would then be the
    // current chain tip.
    let bitcoin_block_fork0: BitcoinBlock = BitcoinBlock {
        block_height: bitcoin_chain_tip_block.block_height,
        block_hash: Faker.fake_with_rng(&mut rng),
        parent_hash: bitcoin_chain_tip_block.parent_hash,
    };

    let bitcoin_block_fork1: BitcoinBlock = BitcoinBlock {
        block_height: bitcoin_chain_tip_block.block_height + 1,
        block_hash: Faker.fake_with_rng(&mut rng),
        parent_hash: bitcoin_block_fork0.block_hash,
    };
    db.write_bitcoin_block(&bitcoin_block_fork0).await.unwrap();
    db.write_bitcoin_block(&bitcoin_block_fork1).await.unwrap();

    let bitcoin_chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();

    // Well now our sweep is confirmed on an orphan chain, so we still need
    // to sweep out the funds. We haven't changed anything on the stacks
    // side since that transaction was confirmed on a block that was
    // unaffected by the reorg.
    assert_eq!(bitcoin_chain_tip, bitcoin_block_fork1.block_hash);
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_block.block_hash,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(report.status, WithdrawalRequestStatus::Confirmed);

    testing::storage::drop_db(db).await;
}

/// Check that a reorg on bitcoin that affects the sweep and the bitcoin
/// block anchoring the stacks block confirming the transaction that
/// generated the withdrawal request leads to the report switching the
/// status of the withdrawal from fulfilled to just unconfirmed.
///
/// This situation is supposed to "never" happen but let's see what happens
/// in our code.
#[tokio::test]
async fn withdrawal_report_with_withdrawal_request_swept_but_swept_reorged2() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(64);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 50,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: true,
    };

    let signer_public_keys = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let signer_public_key = &signer_public_keys[0];
    let mut test_data = TestData::generate(&mut rng, &signer_public_keys, &test_params);
    let mut block_height = 0u64;
    let mut parent_hash = Faker.fake_with_rng(&mut rng);
    // Our `TestData` generator doesn't quite build us a nice Stacks
    // blockchain. So we manually make sure that we have consecutive blocks
    // here before writing them to the database. It matters because the
    // data that is generated by default is not a useful blockchain; all
    // blocks have the same height and their parents don't point to blocks
    // that exist.
    for block in test_data.stacks_blocks.iter_mut() {
        block.block_height = block_height.into();
        block.parent_hash = parent_hash;
        block_height += 1;
        parent_hash = block.block_hash;
    }
    test_data.write_to(&db).await;

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let bitcoin_chain_tip = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();
    let stacks_chain_tip = db
        .get_stacks_chain_tip(&bitcoin_chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();

    // Later, we are going to orphan the parent block of the bitcoin chain
    // tip.
    assert_eq!(
        stacks_chain_tip.bitcoin_anchor,
        bitcoin_chain_tip.parent_hash
    );

    let withdrawal_request = WithdrawalRequest {
        block_hash: stacks_chain_tip.block_hash,
        bitcoin_block_height: bitcoin_chain_tip.block_height,
        ..Faker.fake_with_rng(&mut rng)
    };
    let qualified_id = withdrawal_request.qualified_id();

    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();

    // Okay now let's pretend that the withdrawal has been swept. For that
    // we need a row in the `bitcoin_withdrawals_outputs` table, and
    // records in the `transactions` and `bitcoin_transactions` tables. We
    // place the sweep on the bitcoin chain tip.
    let swept_output = BitcoinWithdrawalOutput {
        request_id: qualified_id.request_id,
        stacks_txid: qualified_id.txid,
        stacks_block_hash: qualified_id.block_hash,
        bitcoin_chain_tip: bitcoin_chain_tip.block_hash,
        ..Faker.fake_with_rng(&mut rng)
    };

    let sweep_tx_model = model::Transaction {
        tx_type: model::TransactionType::SbtcTransaction,
        txid: swept_output.bitcoin_txid.to_byte_array(),
        tx: Vec::new(),
        block_hash: bitcoin_chain_tip.block_hash.to_byte_array(),
    };
    let sweep_tx_ref = model::BitcoinTxRef {
        txid: swept_output.bitcoin_txid,
        block_hash: bitcoin_chain_tip.block_hash,
    };
    db.write_transaction(&sweep_tx_model).await.unwrap();
    db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
    db.write_bitcoin_withdrawals_outputs(&[swept_output])
        .await
        .unwrap();

    // Alright, the report should say that the withdrawal request has been
    // fulfilled.
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip.block_hash,
            &stacks_chain_tip.block_hash,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        report.status,
        WithdrawalRequestStatus::Fulfilled(sweep_tx_ref)
    );

    let bitcoin_chain_tip_parent_block = db
        .get_bitcoin_block(&bitcoin_chain_tip.parent_hash)
        .await
        .unwrap()
        .unwrap();

    // Now let's fork the bitcoin blockchain, generating a sibling block to
    // the parent of the current chain tip and a grandchild block, which
    // would then be the current chain tip.
    let bitcoin_block_fork0: BitcoinBlock = BitcoinBlock {
        block_height: bitcoin_chain_tip_parent_block.block_height,
        block_hash: Faker.fake_with_rng(&mut rng),
        parent_hash: bitcoin_chain_tip_parent_block.parent_hash,
    };
    let bitcoin_block_fork1: BitcoinBlock = BitcoinBlock {
        block_height: bitcoin_chain_tip_parent_block.block_height + 1,
        block_hash: Faker.fake_with_rng(&mut rng),
        parent_hash: bitcoin_block_fork0.block_hash,
    };
    let bitcoin_block_fork2: BitcoinBlock = BitcoinBlock {
        block_height: bitcoin_chain_tip_parent_block.block_height + 2,
        block_hash: Faker.fake_with_rng(&mut rng),
        parent_hash: bitcoin_block_fork1.block_hash,
    };
    db.write_bitcoin_block(&bitcoin_block_fork0).await.unwrap();
    db.write_bitcoin_block(&bitcoin_block_fork1).await.unwrap();
    db.write_bitcoin_block(&bitcoin_block_fork2).await.unwrap();

    let bitcoin_chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let stacks_chain_tip = db
        .get_stacks_chain_tip(&bitcoin_chain_tip)
        .await
        .unwrap()
        .unwrap();

    // Well now our sweep is confirmed on an orphan chain. Moreover, the
    // transaction that generated the sweep was affected by the bitcoin
    // reorg, and so has been orphaned as well.
    assert_eq!(bitcoin_chain_tip, bitcoin_block_fork2.block_hash);
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_chain_tip.block_hash,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(report.status, WithdrawalRequestStatus::Unconfirmed);

    testing::storage::drop_db(db).await;
}

/// Check the normal happy path with a withdrawal request that has been
/// confirmed. Make sure that the values returned match what we would
/// expect given the contents of the withdrawal request.
#[tokio::test]
async fn withdrawal_report_with_withdrawal_request_confirmed() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(128);

    // We only want the blockchain to be generated
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_public_keys = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let signer_public_key = &signer_public_keys[0];
    let test_data = TestData::generate(&mut rng, &signer_public_keys, &test_params);
    test_data.write_to(&db).await;

    // Let's generate a withdrawal request and place it on our canonical
    // blockchain.
    let bitcoin_chain_tip_ref = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    let bitcoin_chain_tip = bitcoin_chain_tip_ref.block_hash;
    let stacks_chain_tip_block = db
        .get_stacks_chain_tip(&bitcoin_chain_tip)
        .await
        .unwrap()
        .unwrap();

    let withdrawal_request = WithdrawalRequest {
        block_hash: stacks_chain_tip_block.block_hash,
        bitcoin_block_height: bitcoin_chain_tip_ref.block_height - 1,
        ..Faker.fake_with_rng(&mut rng)
    };
    let qualified_id = withdrawal_request.qualified_id();

    db.write_withdrawal_request(&withdrawal_request)
        .await
        .unwrap();

    // Let's put a vote in the database. Let's assume that they voted
    // against it, just because we haven't tested false as `is_accepted`
    // yet.
    let withdrawal_decision = WithdrawalSigner {
        request_id: qualified_id.request_id,
        block_hash: qualified_id.block_hash,
        txid: qualified_id.txid,
        signer_pub_key: *signer_public_key,
        is_accepted: false,
    };
    db.write_withdrawal_signer_decision(&withdrawal_decision)
        .await
        .unwrap();

    // Okay, now lets get the report and check the contents.
    let report = db
        .get_withdrawal_request_report(
            &bitcoin_chain_tip,
            &stacks_chain_tip_block.block_hash,
            &qualified_id,
            signer_public_key,
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(report.is_accepted, Some(false));
    assert_eq!(report.status, WithdrawalRequestStatus::Confirmed);
    assert_eq!(
        report.bitcoin_block_height,
        withdrawal_request.bitcoin_block_height
    );
    assert_eq!(report.amount, withdrawal_request.amount);
    assert_eq!(report.max_fee, withdrawal_request.max_fee);
    assert_eq!(&report.recipient, withdrawal_request.recipient.deref());
    assert_eq!(report.id, withdrawal_request.qualified_id());

    testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn can_write_and_get_multiple_bitcoin_txs_sighashes() {
    let db = testing::storage::new_test_database().await;

    let sighashes: Vec<BitcoinTxSigHash> = (0..5).map(|_| fake::Faker.fake()).collect();

    db.write_bitcoin_txs_sighashes(&sighashes).await.unwrap();

    let withdrawal_outputs_futures = sighashes
        .iter()
        .map(|sighash| db.will_sign_bitcoin_tx_sighash(&sighash.sighash));

    let results = join_all(withdrawal_outputs_futures).await;

    for (output, result) in sighashes.iter().zip(results) {
        let (result, _) = result.unwrap().unwrap();
        assert_eq!(result, output.will_sign);
    }
    signer::testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn can_write_multiple_bitcoin_withdrawal_outputs() {
    let db = testing::storage::new_test_database().await;

    let outputs: Vec<BitcoinWithdrawalOutput> = (0..5).map(|_| fake::Faker.fake()).collect();

    db.write_bitcoin_withdrawals_outputs(&outputs)
        .await
        .unwrap();

    signer::testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn get_deposit_request_returns_none_for_missing_deposit() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // Create a random txid
    let txid: model::BitcoinTxId = fake::Faker.fake_with_rng(&mut rng);

    // Fetch the deposit request for the fake txid
    let fetched_deposit = db.get_deposit_request(&txid, 0).await.unwrap();

    // Assert that the fetched fee is None
    assert_eq!(fetched_deposit, None);

    signer::testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn get_deposit_request_returns_returns_inserted_deposit_request() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // Create multiple deposit requests
    let deposit_request1: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);
    let deposit_request2: model::DepositRequest = fake::Faker.fake_with_rng(&mut rng);

    // Insert the deposit requests into the database
    db.write_deposit_request(&deposit_request1).await.unwrap();
    db.write_deposit_request(&deposit_request2).await.unwrap();

    // Fetch deposit requests from the database
    let fetched_deposit1 = db
        .get_deposit_request(&deposit_request1.txid, deposit_request1.output_index)
        .await
        .unwrap();
    let fetched_deposit2 = db
        .get_deposit_request(&deposit_request2.txid, deposit_request2.output_index)
        .await
        .unwrap();

    // Assert that the fetched fees match the inserted fees
    assert_eq!(fetched_deposit1, Some(deposit_request1));
    assert_eq!(fetched_deposit2, Some(deposit_request2));

    signer::testing::storage::drop_db(db).await;
}

/// This struct is for testing different conditions when attempting to
/// retrieve the signers' UTXO.
struct ReorgDescription<const N: usize> {
    /// An array that indicates the height that includes at least one sweep
    /// transaction.
    sweep_heights: [BitcoinBlockHeight; N],
    /// This is the height where there is a reorg.
    reorg_height: BitcoinBlockHeight,
    /// This is the height of the donation. It must be less than or equal
    /// to the minimum sweep height indicated by `sweep_heights`.
    donation_height: BitcoinBlockHeight,
    /// The expected height of the UTXO returned by
    /// [`DbRead::get_signer_utxo`].
    utxo_height: Option<BitcoinBlockHeight>,
    /// When we create sweep package, this field controls how many
    /// transactions are created in the package.
    num_transactions: std::ops::Range<u8>,
}

impl<const N: usize> ReorgDescription<N> {
    fn num_blocks(&self) -> u64 {
        *self.sweep_heights.into_iter().max().unwrap_or_default()
    }
}

/// In these tests we check that [`DbRead::get_signer_utxo`] returns the
/// expected UTXO when there is a reorg. The test is set up as follows
/// 1. Populate the database with some minimal bitcoin blockchain data.
/// 2. For each block between the current block and the number-of-blocks to
///    generate, create a random number of transactions where we spend the
///    last output and create a new one.
/// 3. Note the last transaction created in each bitcoin block.
/// 4. Create a new chain starting at the height indicated by
///    `reorg_height`, making sure that it is longer than the current
///    blockchain in the database, so that it is the best chain.
/// 5. Get the signers' UTXO and check that the transaction ID matches the
///    one expected.
#[test_case(ReorgDescription {
    sweep_heights: [0u64.into(), 3u64.into(), 4u64.into(), 5u64.into()],
    reorg_height: 4u64.into(),
    donation_height: 0u64.into(),
    utxo_height: Some(4u64.into()),
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "vanilla reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [0u64.into(), 3u64.into(), 4u64.into(), 5u64.into()],
    reorg_height: 2u64.into(),
    donation_height: 0u64.into(),
    utxo_height: Some(0u64.into()),
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "near-complete-reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [0u64.into(), 6u64.into(), 10u64.into(), 12u64.into()],
    reorg_height: 7u64.into(),
    donation_height: 0u64.into(),
    utxo_height: Some(6u64.into()),
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "partial-reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [0u64.into(), 6u64.into(), 20u64.into(), 21u64.into()],
    reorg_height: 19u64.into(),
    donation_height: 0u64.into(),
    utxo_height: Some(6u64.into()),
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "long-gap-reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [3u64.into(), 4u64.into(), 5u64.into()],
    reorg_height: 2u64.into(),
    donation_height: 3u64.into(),
    utxo_height: None,
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "complete-reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [1u64.into(), 7u64.into(), 17u64.into(), 18u64.into(), 19u64.into(), 20u64.into(), 21u64.into()],
    reorg_height: 16u64.into(),
    donation_height: 0u64.into(),
    utxo_height: Some(7u64.into()),
    num_transactions: std::ops::Range { start: 25, end: 26 },
}; "busy-bridge-with-reorg")]
#[tokio::test]
async fn signer_utxo_reorg_suite<const N: usize>(desc: ReorgDescription<N>) {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    // We just need some basic data in the database. The only value that
    // matters is `num_bitcoin_blocks`, and it must be positive.
    let num_signers = 3;
    let test_params = testing::storage::model::Params {
        num_bitcoin_blocks: 1,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    // Let's generate some dummy data and write it into the database.
    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // We need some DKG shares here, since we identify the signers' UTXO by
    // the fact that the signers can sign for the UTXO.
    let dkg_shares: model::EncryptedDkgShares = fake::Faker.fake_with_rng(&mut rng);
    db.write_encrypted_dkg_shares(&dkg_shares).await.unwrap();

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let original_chain_tip_ref: model::BitcoinBlockRef = db
        .get_bitcoin_block(&chain_tip)
        .await
        .unwrap()
        .unwrap()
        .into();

    // This will store the last transaction ID for all transaction packages
    // created in a block with a sweep.
    let mut expected_sweep_txids = BTreeMap::new();

    let mut swept_output: model::TxOutput = fake::Faker.fake_with_rng(&mut rng);
    let mut chain_tip_ref = original_chain_tip_ref;
    let mut reorg_block_ref = chain_tip_ref;

    for height in 0..=desc.num_blocks() {
        // We need a UTXO to "bootstrap" the signers, so maybe we should
        // create one now.
        if height == *desc.donation_height {
            swept_output.output_type = model::TxOutputType::Donation;
            swept_output.output_index = 0;
            swept_output.amount = 0;
            swept_output.script_pubkey = dkg_shares.script_pubkey.clone();

            let sweep_tx_model = model::Transaction {
                tx_type: model::TransactionType::Donation,
                txid: swept_output.txid.to_byte_array(),
                tx: Vec::new(),
                block_hash: chain_tip_ref.block_hash.to_byte_array(),
            };
            let sweep_tx_ref = model::BitcoinTxRef {
                txid: swept_output.txid,
                block_hash: chain_tip_ref.block_hash,
            };
            db.write_transaction(&sweep_tx_model).await.unwrap();
            db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
            db.write_tx_output(&swept_output).await.unwrap();
        }

        // Maybe there is a sweep package in this bitcoin block. If so
        // let's generate a random number of transactions in a transaction
        // package.
        if desc.sweep_heights.contains(&height.into()) {
            let num_transactions = desc.num_transactions.clone().choose(&mut rng).unwrap();

            for _ in 0..num_transactions {
                let mut swept_prevout: model::TxPrevout = fake::Faker.fake_with_rng(&mut rng);
                swept_prevout.prevout_txid = swept_output.txid;
                swept_prevout.prevout_output_index = 0;
                swept_prevout.prevout_type = model::TxPrevoutType::SignersInput;

                swept_output.txid = swept_prevout.txid;
                swept_output.output_type = model::TxOutputType::SignersOutput;
                swept_output.output_index = 0;
                swept_output.script_pubkey = dkg_shares.script_pubkey.clone();

                let sweep_tx_model = model::Transaction {
                    tx_type: model::TransactionType::SbtcTransaction,
                    txid: swept_prevout.txid.to_byte_array(),
                    tx: Vec::new(),
                    block_hash: chain_tip_ref.block_hash.to_byte_array(),
                };
                let sweep_tx_ref = model::BitcoinTxRef {
                    txid: swept_prevout.txid,
                    block_hash: chain_tip_ref.block_hash,
                };
                db.write_transaction(&sweep_tx_model).await.unwrap();
                db.write_bitcoin_transaction(&sweep_tx_ref).await.unwrap();
                db.write_tx_prevout(&swept_prevout).await.unwrap();
                db.write_tx_output(&swept_output).await.unwrap();

                expected_sweep_txids.insert(height, swept_prevout.txid);
            }
        }

        // We need to note the block that we need to branch from for our reorg.
        if height == *desc.reorg_height {
            reorg_block_ref = chain_tip_ref;
        }

        // And now for the blockchain data.
        let (new_data, new_chain_tip_ref) =
            test_data.new_block(&mut rng, &signer_set, &test_params, Some(&chain_tip_ref));
        chain_tip_ref = new_chain_tip_ref;
        new_data.write_to(&db).await;
    }

    // And now for creating the reorg blocks.
    for _ in 0..=(desc.num_blocks() - *desc.reorg_height) + 1 {
        let (new_data, new_chain_tip_ref) =
            test_data.new_block(&mut rng, &signer_set, &test_params, Some(&reorg_block_ref));
        reorg_block_ref = new_chain_tip_ref;
        new_data.write_to(&db).await;
    }

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();

    // Let's make sure we get the expected signer UTXO.
    let utxo = db.get_signer_utxo(&chain_tip).await.unwrap();
    match desc.utxo_height {
        Some(height) => {
            let txid: model::BitcoinTxId = utxo.unwrap().outpoint.txid.into();
            assert_eq!(&txid, expected_sweep_txids.get(&height).unwrap());
        }
        None => {
            assert!(utxo.is_none());
        }
    };

    signer::testing::storage::drop_db(db).await;
}

fn hex_to_block_hash(hash: &str) -> [u8; 32] {
    hex::decode(hash).unwrap().as_slice().try_into().unwrap()
}

#[tokio::test]
async fn compare_in_memory_bitcoin_chain_tip() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let pg_store = testing::storage::new_test_database().await;
    let in_memory_store = storage::in_memory::Store::new_shared();

    let root: BitcoinBlock = fake::Faker.fake_with_rng(&mut rng);
    let mut blocks = vec![root.clone()];
    for block_hash in [
        "FF00000000000000000000000000000000000000000000000000000000000011",
        "11000000000000000000000000000000000000000000000000000000000000FF",
    ] {
        blocks.push(BitcoinBlock {
            block_hash: hex_to_block_hash(block_hash).into(),
            block_height: root.block_height + 1,
            parent_hash: root.block_hash,
        })
    }

    for block in &blocks {
        pg_store.write_bitcoin_block(block).await.unwrap();
        in_memory_store.write_bitcoin_block(block).await.unwrap();
    }

    assert_eq!(
        in_memory_store
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
        pg_store
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
    );

    signer::testing::storage::drop_db(pg_store).await;
}

#[tokio::test]
async fn compare_in_memory_stacks_chain_tip() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let pg_store = testing::storage::new_test_database().await;
    let in_memory_store = storage::in_memory::Store::new_shared();

    let root_anchor: BitcoinBlock = fake::Faker.fake_with_rng(&mut rng);

    pg_store.write_bitcoin_block(&root_anchor).await.unwrap();
    in_memory_store
        .write_bitcoin_block(&root_anchor)
        .await
        .unwrap();

    let root: StacksBlock = fake::Faker.fake_with_rng(&mut rng);

    let mut blocks = vec![root.clone()];
    for block_hash in [
        "FF00000000000000000000000000000000000000000000000000000000000011",
        "11000000000000000000000000000000000000000000000000000000000000FF",
    ] {
        blocks.push(StacksBlock {
            block_hash: hex_to_block_hash(block_hash).into(),
            block_height: root.block_height + 1,
            parent_hash: root.block_hash,
            bitcoin_anchor: root_anchor.block_hash,
        })
    }

    for block in &blocks {
        pg_store.write_stacks_block(block).await.unwrap();
        in_memory_store.write_stacks_block(block).await.unwrap();
    }

    assert_eq!(
        in_memory_store
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
        root_anchor.block_hash
    );
    assert_eq!(
        pg_store
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
        root_anchor.block_hash
    );

    assert_eq!(
        in_memory_store
            .get_stacks_chain_tip(&root_anchor.block_hash)
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
        pg_store
            .get_stacks_chain_tip(&root_anchor.block_hash)
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip"),
    );

    signer::testing::storage::drop_db(pg_store).await;
}

#[tokio::test]
async fn write_and_get_dkg_shares_is_pending() {
    let db = testing::storage::new_test_database().await;

    let insert = EncryptedDkgShares {
        aggregate_key: fake::Faker.fake(),
        tweaked_aggregate_key: fake::Faker.fake(),
        encrypted_private_shares: vec![],
        script_pubkey: fake::Faker.fake(),
        public_shares: vec![],
        signer_set_public_keys: vec![],
        signature_share_threshold: 1,
        dkg_shares_status: DkgSharesStatus::Unverified,
        ..fake::Faker.fake()
    };

    db.write_encrypted_dkg_shares(&insert).await.unwrap();

    let select = db
        .get_encrypted_dkg_shares(insert.aggregate_key)
        .await
        .expect("database error")
        .expect("no shares found");

    assert_eq!(insert, select);

    signer::testing::storage::drop_db(db).await;
}

#[test(tokio::test)]
async fn verify_dkg_shares_succeeds() {
    let db = testing::storage::new_test_database().await;

    // We start with a pending entry.
    let insert = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Unverified,
        ..Faker.fake()
    };

    // Write the dkg_shares entry.
    db.write_encrypted_dkg_shares(&insert).await.unwrap();

    // Now to verify the shares.
    let result = db.verify_dkg_shares(insert.aggregate_key).await.unwrap();
    assert!(result, "verify failed, when it should succeed");

    // Get the dkg_shares entry.
    let select = db
        .get_encrypted_dkg_shares(insert.aggregate_key)
        .await
        .expect("database error")
        .expect("no shares found");

    // Assert that the status is now verified and that the block hash and height
    // are correct, and that the rest of the fields remain the same.
    let compare = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Verified,
        ..insert.clone()
    };
    assert_eq!(select, compare);

    signer::testing::storage::drop_db(db).await;
}

#[tokio::test]
async fn revoke_dkg_shares_succeeds() {
    let db = testing::storage::new_test_database().await;

    // We start with a pending entry.
    let insert = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Unverified,
        ..Faker.fake()
    };

    // Write the dkg_shares entry.
    db.write_encrypted_dkg_shares(&insert).await.unwrap();

    // Now try to fail the keys.
    let result = db.revoke_dkg_shares(insert.aggregate_key).await.unwrap();
    assert!(result, "revoke failed, when it should succeed");

    // Get the dkg_shares entry we just inserted.
    let select = db
        .get_encrypted_dkg_shares(insert.aggregate_key)
        .await
        .expect("database error")
        .expect("no shares found");

    // Assert that the status is now revoked and that the rest of the fields
    // remain the same.
    let compare = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Failed,
        ..insert.clone()
    };
    assert_eq!(select, compare);

    signer::testing::storage::drop_db(db).await;
}

/// This test checks that DKG shares verification status follows a one-way state transition:
///
/// 1. Unverified -> Verified: Once shares are verified, they cannot be revoked
/// 2. Unverified -> Failed: Once shares are marked as failed, they cannot be verified
///
/// The test verifies both transition paths:
/// - Unverified -> Verified -> (attempt revoke, stays Verified)
/// - Unverified -> Failed -> (attempt verify, stays Failed)
#[tokio::test]
async fn verification_status_one_way_street() {
    let db = testing::storage::new_test_database().await;

    // We start with a pending entry.
    let insert = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Unverified,
        ..Faker.fake()
    };

    // Write the dkg_shares entry.
    db.write_encrypted_dkg_shares(&insert).await.unwrap();

    // Now try to verify.
    let result = db.verify_dkg_shares(insert.aggregate_key).await.unwrap();
    assert!(result, "verify failed, when it should succeed");

    let select1 = db
        .get_encrypted_dkg_shares(insert.aggregate_key)
        .await
        .expect("database error")
        .expect("no shares found");

    assert_eq!(select1.dkg_shares_status, DkgSharesStatus::Verified);

    // Now try to revoke. This shouldn't have any effect because we have
    // verified the shares already.
    let result = db.revoke_dkg_shares(insert.aggregate_key).await.unwrap();
    assert!(!result, "revoking succeeded, when it should fail");

    // Get the dkg_shares entry we just inserted.
    let select2 = db
        .get_encrypted_dkg_shares(insert.aggregate_key)
        .await
        .expect("database error")
        .expect("no shares found");

    let compare = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Verified,
        ..insert
    };

    assert_eq!(select1, select2);
    assert_eq!(select1, compare);

    // We start with a pending entry.
    let insert = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Unverified,
        ..Faker.fake()
    };

    // Write the dkg_shares entry.
    db.write_encrypted_dkg_shares(&insert).await.unwrap();

    // Now try to revoke.
    let result = db.revoke_dkg_shares(insert.aggregate_key).await.unwrap();
    assert!(result, "revoke failed, when it should succeed");

    let select1 = db
        .get_encrypted_dkg_shares(insert.aggregate_key)
        .await
        .expect("database error")
        .expect("no shares found");

    assert_eq!(select1.dkg_shares_status, DkgSharesStatus::Failed);

    // Now try to verify them. This should be a no-op, since the keys have
    // already been marked as failed.
    let result = db.verify_dkg_shares(insert.aggregate_key).await.unwrap();
    assert!(!result, "verify succeeded, when it should fail");

    // Get the dkg_shares entry we just inserted.
    let select2 = db
        .get_encrypted_dkg_shares(insert.aggregate_key)
        .await
        .expect("database error")
        .expect("no shares found");

    let compare = EncryptedDkgShares {
        dkg_shares_status: DkgSharesStatus::Failed,
        ..insert
    };

    assert_eq!(select1, select2);
    assert_eq!(select1, compare);

    signer::testing::storage::drop_db(db).await;
}

/// Tests that get_pending_rejected_withdrawal_requests correctly return expired
/// requests in case there are no events affecting them.
#[test_log::test(tokio::test)]
async fn pending_rejected_withdrawal_no_events() {
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 10;
    let context_window = 1000;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 50,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: num_signers,
        consecutive_blocks: false,
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);

    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);

    test_data.write_to(&mut db).await;

    let mut bitcoin_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    let chain_depth = bitcoin_chain_tip.block_height - test_data.bitcoin_blocks[0].block_height;

    // Append some blocks to ensure we have expired requests; we expire the
    // requests in the first 5 canonical blocks, while keeping the others valid.
    for _ in chain_depth..WITHDRAWAL_BLOCKS_EXPIRY + 5 {
        let new_block = BitcoinBlock {
            block_hash: fake::Faker.fake_with_rng(&mut rng),
            block_height: bitcoin_chain_tip.block_height + 1,
            parent_hash: bitcoin_chain_tip.block_hash,
        };
        db.write_bitcoin_block(&new_block).await.unwrap();

        bitcoin_chain_tip = new_block.into();
    }

    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&bitcoin_chain_tip, context_window)
        .await
        .expect("failed to get pending rejected withdrawals");
    assert!(!pending_rejected.is_empty());

    let stacks_chain_tip = db
        .get_stacks_chain_tip(&bitcoin_chain_tip.block_hash)
        .await
        .expect("failed to get stacks chain tip")
        .expect("no chain tip");

    let mut non_expired = 0;
    for withdrawal in test_data.withdraw_requests {
        if withdrawal.bitcoin_block_height == test_data.bitcoin_blocks[0].block_height {
            // The stacks blocks in the first bitcoin block have an hallucinated
            // anchor, so they are in the canonical chain but have no link to
            // bitcoin chain, making things weird.
            continue;
        }

        let stacks_block = db
            .get_stacks_block(&withdrawal.block_hash)
            .await
            .unwrap()
            .unwrap();

        let in_canonical_stacks = db
            .in_canonical_stacks_blockchain(
                &stacks_chain_tip.block_hash,
                &stacks_block.block_hash,
                stacks_block.block_height,
            )
            .await
            .unwrap();

        if !in_canonical_stacks {
            assert!(!pending_rejected.contains(&withdrawal));
            continue;
        }

        let confirmations = bitcoin_chain_tip.block_height - withdrawal.bitcoin_block_height;
        assert_eq!(
            pending_rejected.contains(&withdrawal),
            confirmations > WITHDRAWAL_BLOCKS_EXPIRY.into()
        );
        non_expired += 1;
    }
    // Sanity check we are testing both cases
    assert_gt!(non_expired, 0);

    signer::testing::storage::drop_db(db).await;
}

/// Test that pending_rejected_withdrawal correctly returns in case of expired
/// requests.
#[test_log::test(tokio::test)]
async fn pending_rejected_withdrawal_expiration() {
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 10;

    // Let's start with a fork-less chain
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: true,
    };
    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data.write_to(&mut db).await;

    // Add a withdrawal request not yet confirmed nor expired
    let request_confirmations = 1;
    let request_bitcoin_block = test_data
        .bitcoin_blocks
        .get(test_data.bitcoin_blocks.len() - request_confirmations - 1)
        .unwrap();
    let request_stacks_block = test_data
        .stacks_blocks
        .iter()
        .find(|block| block.bitcoin_anchor == request_bitcoin_block.block_hash)
        .unwrap();

    let request = WithdrawalRequest {
        block_hash: request_stacks_block.block_hash,
        bitcoin_block_height: request_bitcoin_block.block_height,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_withdrawal_request(&request).await.unwrap();

    // Append new blocks up to WITHDRAWAL_BLOCKS_EXPIRY, checking that the
    // request is not considered expired
    for _ in request_confirmations..WITHDRAWAL_BLOCKS_EXPIRY as usize {
        let bitcoin_chain_tip = db
            .get_bitcoin_canonical_chain_tip_ref()
            .await
            .expect("failed to get canonical chain tip")
            .expect("no chain tip");

        let new_block = BitcoinBlock {
            block_hash: fake::Faker.fake_with_rng(&mut rng),
            block_height: bitcoin_chain_tip.block_height + 1,
            parent_hash: bitcoin_chain_tip.block_hash,
        };
        db.write_bitcoin_block(&new_block).await.unwrap();

        assert_le!(
            new_block.block_height - request.bitcoin_block_height,
            WITHDRAWAL_BLOCKS_EXPIRY.into()
        );

        // Check that now we do get it as rejected
        let pending_rejected = db
            .get_pending_rejected_withdrawal_requests(&new_block.into(), 1000)
            .await
            .expect("failed to get pending rejected withdrawals");

        assert!(pending_rejected.is_empty());
    }

    // Append one last block, reaching WITHDRAWAL_BLOCKS_EXPIRY
    let bitcoin_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    let new_block = BitcoinBlock {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        block_height: bitcoin_chain_tip.block_height + 1,
        parent_hash: bitcoin_chain_tip.block_hash,
    };
    db.write_bitcoin_block(&new_block).await.unwrap();

    assert_gt!(
        new_block.block_height - request.bitcoin_block_height,
        WITHDRAWAL_BLOCKS_EXPIRY.into()
    );

    // Check that now we do get it as rejected
    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&new_block.into(), 1000)
        .await
        .expect("failed to get pending rejected withdrawals");

    assert_eq!(&pending_rejected.single(), &request);

    signer::testing::storage::drop_db(db).await;
}

/// Check that pending_rejected_withdrawal correctly skips rejected requests
/// that already have a confirmed rejection event.
#[test_log::test(tokio::test)]
async fn pending_rejected_withdrawal_rejected_already_rejected() {
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 10;

    // Let's start with a fork-less chain
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 30,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: true,
    };
    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data.write_to(&mut db).await;

    // Add a withdrawal request already expired
    let request_confirmations = WITHDRAWAL_BLOCKS_EXPIRY as usize + 1;
    let request_bitcoin_block = test_data
        .bitcoin_blocks
        .get(test_data.bitcoin_blocks.len() - request_confirmations - 1)
        .unwrap();
    let request_stacks_block = test_data
        .stacks_blocks
        .iter()
        .find(|block| block.bitcoin_anchor == request_bitcoin_block.block_hash)
        .unwrap();

    let request = WithdrawalRequest {
        block_hash: request_stacks_block.block_hash,
        bitcoin_block_height: request_bitcoin_block.block_height,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_withdrawal_request(&request).await.unwrap();

    // First, check that the request is pending rejected
    let bitcoin_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&bitcoin_chain_tip, 1000)
        .await
        .expect("failed to get pending rejected withdrawals");

    assert_eq!(&pending_rejected.single(), &request);

    // Now, let's add a rejection event in a fork first
    // As fork base, let's pick stacks tip - 2
    let mut fork_base = db
        .get_stacks_chain_tip(&bitcoin_chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..2 {
        fork_base = db
            .get_stacks_block(&fork_base.parent_hash)
            .await
            .unwrap()
            .unwrap();
    }

    // Create the forked block that will contain the reject event
    let forked_stacks_block = StacksBlock {
        parent_hash: fork_base.block_hash,
        block_height: fork_base.block_height + 1,
        bitcoin_anchor: fork_base.bitcoin_anchor,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_stacks_block(&forked_stacks_block).await.unwrap();

    let stacks_chain_tip = db
        .get_stacks_chain_tip(&bitcoin_chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(
        db.in_canonical_stacks_blockchain(
            &stacks_chain_tip.block_hash,
            &fork_base.block_hash,
            fork_base.block_height
        )
        .await
        .unwrap()
    );
    assert!(
        !db.in_canonical_stacks_blockchain(
            &stacks_chain_tip.block_hash,
            &forked_stacks_block.block_hash,
            forked_stacks_block.block_height
        )
        .await
        .unwrap()
    );

    let event = WithdrawalRejectEvent {
        request_id: request.request_id,
        block_id: forked_stacks_block.block_hash,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_withdrawal_reject_event(&event).await.unwrap();

    // With a forked rejection event, the request is still pending rejected
    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&bitcoin_chain_tip, 1000)
        .await
        .expect("failed to get pending rejected withdrawals");

    assert_eq!(&pending_rejected.single(), &request);

    // Now let's add a confirmed rejection event to fork base, so it's in the
    // canonical chain.
    let event = WithdrawalRejectEvent {
        request_id: request.request_id,
        block_id: fork_base.block_hash,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_withdrawal_reject_event(&event).await.unwrap();

    // With a confirmed rejection event, we should no longer get the request
    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&bitcoin_chain_tip, 1000)
        .await
        .expect("failed to get pending rejected withdrawals");

    assert!(pending_rejected.is_empty());

    signer::testing::storage::drop_db(db).await;
}

/// Check that pending_rejected_withdrawal correctly skips expired requests
/// that have a confirmed withdrawal output.
#[test_log::test(tokio::test)]
async fn pending_rejected_withdrawal_already_accepted() {
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 10;

    // Let's start with a fork-less chain
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 30,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: true,
    };
    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data.write_to(&mut db).await;

    // Add a withdrawal request already expired
    let request_confirmations = WITHDRAWAL_BLOCKS_EXPIRY as usize + 1;
    let request_bitcoin_block = test_data
        .bitcoin_blocks
        .get(test_data.bitcoin_blocks.len() - request_confirmations - 1)
        .unwrap();
    let request_stacks_block = test_data
        .stacks_blocks
        .iter()
        .find(|block| block.bitcoin_anchor == request_bitcoin_block.block_hash)
        .unwrap();

    let request = WithdrawalRequest {
        block_hash: request_stacks_block.block_hash,
        bitcoin_block_height: request_bitcoin_block.block_height,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_withdrawal_request(&request).await.unwrap();

    // First, check that the request is pending rejected
    let bitcoin_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&bitcoin_chain_tip, 1000)
        .await
        .expect("failed to get pending rejected withdrawals");

    assert_eq!(&pending_rejected.single(), &request);

    // Now, let's add a withdrawal output in a fork (tip - 2)
    let mut fork_base = db
        .get_bitcoin_block(&bitcoin_chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..2 {
        fork_base = db
            .get_bitcoin_block(&fork_base.parent_hash)
            .await
            .unwrap()
            .unwrap();
    }

    // Create the forked block that will contain the withdrawal output
    let forked_block = BitcoinBlock {
        parent_hash: fork_base.block_hash,
        block_height: fork_base.block_height + 1,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_bitcoin_block(&forked_block).await.unwrap();

    let forked_withdrawal_output = BitcoinWithdrawalOutput {
        request_id: request.request_id,
        stacks_block_hash: request.block_hash,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_bitcoin_withdrawals_outputs(&[forked_withdrawal_output.clone()])
        .await
        .unwrap();
    db.write_transaction(&model::Transaction {
        txid: forked_withdrawal_output.bitcoin_txid.into_bytes(),
        tx: vec![],
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: forked_block.block_hash.into_bytes(),
    })
    .await
    .unwrap();
    db.write_bitcoin_transaction(&model::BitcoinTxRef {
        txid: forked_withdrawal_output.bitcoin_txid,
        block_hash: forked_block.block_hash,
    })
    .await
    .unwrap();

    let bitcoin_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    assert!(
        db.in_canonical_bitcoin_blockchain(&bitcoin_chain_tip, &fork_base.clone().into())
            .await
            .unwrap()
    );
    assert!(
        !db.in_canonical_bitcoin_blockchain(&bitcoin_chain_tip, &forked_block.into())
            .await
            .unwrap()
    );

    // With a forked withdrawal output, the request is still pending rejected
    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&bitcoin_chain_tip, 1000)
        .await
        .expect("failed to get pending rejected withdrawals");
    assert_eq!(&pending_rejected.single(), &request);

    // Now let's add a withdrawal output in the canonical chain
    let canonical_withdrawal_output = BitcoinWithdrawalOutput {
        request_id: request.request_id,
        stacks_block_hash: request.block_hash,
        ..fake::Faker.fake_with_rng(&mut rng)
    };
    db.write_bitcoin_withdrawals_outputs(&[canonical_withdrawal_output.clone()])
        .await
        .unwrap();

    // The output is not confirmed yet, so it shouldn't affect the request
    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&bitcoin_chain_tip, 1000)
        .await
        .expect("failed to get pending rejected withdrawals");
    assert_eq!(&pending_rejected.single(), &request);

    // Confirming it (putting the output txid in a confirmed block)
    db.write_transaction(&model::Transaction {
        txid: canonical_withdrawal_output.bitcoin_txid.into_bytes(),
        tx: vec![],
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: fork_base.block_hash.into_bytes(),
    })
    .await
    .unwrap();
    db.write_bitcoin_transaction(&model::BitcoinTxRef {
        txid: canonical_withdrawal_output.bitcoin_txid,
        block_hash: fork_base.block_hash,
    })
    .await
    .unwrap();

    // With a confirmed withdrawal output, we should no longer get the request
    let pending_rejected = db
        .get_pending_rejected_withdrawal_requests(&bitcoin_chain_tip, 1000)
        .await
        .expect("failed to get pending rejected withdrawals");
    assert!(pending_rejected.is_empty());

    signer::testing::storage::drop_db(db).await;
}

/// Check that is_withdrawal_inflight correctly picks up withdrawal
/// requests that have rows associated with sweep transactions that have
/// been proposed by the coordinator.
#[tokio::test]
async fn is_withdrawal_inflight_catches_withdrawals_with_rows_in_table() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    let signers = TestSignerSet::new(&mut rng);
    let setup = TestSweepSetup2::new_setup(signers, faucet, &[]);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();

    // This is needed for the part of the query that fetches the signers'
    // UTXO.
    setup.store_dkg_shares(&db).await;

    // This donation is currently the signers' UTXO, which is needed in the
    // `is_withdrawal_inflight` implementation.
    setup.store_donation(&db).await;

    let id = QualifiedRequestId {
        request_id: 234,
        block_hash: Faker.fake_with_rng(&mut rng),
        txid: Faker.fake_with_rng(&mut rng),
    };

    assert!(!db.is_withdrawal_inflight(&id, &chain_tip).await.unwrap());

    let bitcoin_txid: model::BitcoinTxId = Faker.fake_with_rng(&mut rng);
    let output = BitcoinWithdrawalOutput {
        request_id: id.request_id,
        stacks_txid: id.txid,
        stacks_block_hash: id.block_hash,
        bitcoin_chain_tip: chain_tip,
        bitcoin_txid,
        is_valid_tx: true,
        validation_result: WithdrawalValidationResult::Ok,
        output_index: 2,
    };
    db.write_bitcoin_withdrawals_outputs(&[output])
        .await
        .unwrap();

    assert!(!db.is_withdrawal_inflight(&id, &chain_tip).await.unwrap());

    let sighash = BitcoinTxSigHash {
        txid: bitcoin_txid,
        prevout_type: model::TxPrevoutType::SignersInput,
        prevout_txid: setup.donation.txid.into(),
        prevout_output_index: setup.donation.vout,
        validation_result: signer::bitcoin::validation::InputValidationResult::Ok,
        aggregate_key: setup.signers.aggregate_key().into(),
        is_valid_tx: false,
        will_sign: false,
        chain_tip,
        sighash: bitcoin::TapSighash::from_byte_array([88; 32]).into(),
    };
    db.write_bitcoin_txs_sighashes(&[sighash]).await.unwrap();

    assert!(db.is_withdrawal_inflight(&id, &chain_tip).await.unwrap());

    signer::testing::storage::drop_db(db).await;
}

/// Check that is_withdrawal_inflight correctly picks up withdrawal
/// requests that are fulfilled further down the chain of sweep
/// transactions that have been proposed by a coordinator.
#[tokio::test]
async fn is_withdrawal_inflight_catches_withdrawals_in_package() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);
    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    // We use TestSweepSetup2 to help set up the signers' UTXO, which needs
    // to be available for this test.
    let signers = TestSignerSet::new(&mut rng);
    let setup = TestSweepSetup2::new_setup(signers, faucet, &[]);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;
    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();

    // This is needed for the part of the query that fetches the signers'
    // UTXO.
    setup.store_dkg_shares(&db).await;
    // This donation is currently the signers' UTXO, which is needed in the
    // `is_withdrawal_inflight` implementation.
    setup.store_donation(&db).await;

    let id = QualifiedRequestId {
        request_id: 234,
        block_hash: Faker.fake_with_rng(&mut rng),
        txid: Faker.fake_with_rng(&mut rng),
    };

    assert!(!db.is_withdrawal_inflight(&id, &chain_tip).await.unwrap());

    let bitcoin_txid1: model::BitcoinTxId = Faker.fake_with_rng(&mut rng);
    let bitcoin_txid2: model::BitcoinTxId = Faker.fake_with_rng(&mut rng);
    let bitcoin_txid3: model::BitcoinTxId = Faker.fake_with_rng(&mut rng);

    let output = BitcoinWithdrawalOutput {
        request_id: id.request_id,
        stacks_txid: id.txid,
        stacks_block_hash: id.block_hash,
        bitcoin_chain_tip: chain_tip,
        bitcoin_txid: bitcoin_txid3,
        is_valid_tx: true,
        validation_result: WithdrawalValidationResult::Ok,
        output_index: 2,
    };
    db.write_bitcoin_withdrawals_outputs(&[output])
        .await
        .unwrap();

    // This is the first input of the third transaction in the chain. We
    // write it first to show that the transactions need to be chained in
    // order for the query to pick up the above output.
    let sighash3 = BitcoinTxSigHash {
        txid: bitcoin_txid3,
        prevout_type: model::TxPrevoutType::SignersInput,
        prevout_txid: bitcoin_txid2,
        prevout_output_index: 0,
        validation_result: signer::bitcoin::validation::InputValidationResult::Ok,
        aggregate_key: setup.signers.aggregate_key().into(),
        is_valid_tx: false,
        will_sign: false,
        chain_tip,
        sighash: bitcoin::TapSighash::from_byte_array([66; 32]).into(),
    };
    db.write_bitcoin_txs_sighashes(&[sighash3]).await.unwrap();

    assert!(!db.is_withdrawal_inflight(&id, &chain_tip).await.unwrap());

    let sighash2 = BitcoinTxSigHash {
        txid: bitcoin_txid2,
        prevout_type: model::TxPrevoutType::SignersInput,
        prevout_txid: bitcoin_txid1,
        prevout_output_index: 0,
        validation_result: signer::bitcoin::validation::InputValidationResult::Ok,
        aggregate_key: setup.signers.aggregate_key().into(),
        is_valid_tx: false,
        will_sign: false,
        chain_tip,
        sighash: bitcoin::TapSighash::from_byte_array([77; 32]).into(),
    };
    db.write_bitcoin_txs_sighashes(&[sighash2]).await.unwrap();

    assert!(!db.is_withdrawal_inflight(&id, &chain_tip).await.unwrap());

    // Okay now we add in the first input of the first transaction in the
    // chain. The query should be able to find our output now.
    let sighash1 = BitcoinTxSigHash {
        txid: bitcoin_txid1,
        prevout_type: model::TxPrevoutType::SignersInput,
        prevout_txid: setup.donation.txid.into(),
        prevout_output_index: setup.donation.vout,
        validation_result: signer::bitcoin::validation::InputValidationResult::Ok,
        aggregate_key: setup.signers.aggregate_key().into(),
        is_valid_tx: false,
        will_sign: false,
        chain_tip,
        sighash: bitcoin::TapSighash::from_byte_array([88; 32]).into(),
    };
    db.write_bitcoin_txs_sighashes(&[sighash1]).await.unwrap();

    assert!(db.is_withdrawal_inflight(&id, &chain_tip).await.unwrap());

    signer::testing::storage::drop_db(db).await;
}

/// Check that is_withdrawal_active correctly returns false for unknown
/// withdrawal requests.
#[tokio::test]
async fn is_withdrawal_active_unknown_withdrawal() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);

    let chain_tip = Faker.fake_with_rng(&mut rng);
    let qualified_id: QualifiedRequestId = Faker.fake_with_rng(&mut rng);
    let active = db
        .is_withdrawal_active(&qualified_id, &chain_tip, 1)
        .await
        .unwrap();
    assert!(!active);

    signer::testing::storage::drop_db(db).await;
}

/// Check that is_withdrawal_active correctly returns true when there is a
/// sweep fulfilling a withdrawal request that might be in the mempool.
#[tokio::test]
async fn is_withdrawal_active_for_considered_withdrawal() {
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(4);

    let chain_tip: model::BitcoinBlock = Faker.fake_with_rng(&mut rng);
    let qualified_id: QualifiedRequestId = Faker.fake_with_rng(&mut rng);

    let output = BitcoinWithdrawalOutput {
        request_id: qualified_id.request_id,
        stacks_txid: qualified_id.txid,
        stacks_block_hash: qualified_id.block_hash,
        bitcoin_chain_tip: chain_tip.block_hash,
        is_valid_tx: true,
        validation_result: WithdrawalValidationResult::Ok,
        output_index: 2,
        bitcoin_txid: Faker.fake_with_rng(&mut rng),
    };
    db.write_bitcoin_withdrawals_outputs(&[output])
        .await
        .unwrap();

    db.write_bitcoin_block(&chain_tip).await.unwrap();

    let chain_tip_ref = chain_tip.into();

    let active = db
        .is_withdrawal_active(&qualified_id, &chain_tip_ref, 1)
        .await
        .unwrap();
    assert!(active);

    signer::testing::storage::drop_db(db).await;
}

/// Check that the query in `compute_withdrawn_total` returns the total
/// amount of withdrawal amounts in the window.
#[tokio::test]
async fn compute_withdrawn_total_gets_all_amounts_in_chain() {
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(4);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 30,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: true,
    };
    // The number of signers does not matter
    let num_signers = 1;
    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data.write_to(&mut db).await;

    let context_window = 10;
    let bitcoin_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    let current_total = db
        .compute_withdrawn_total(&bitcoin_chain_tip.block_hash, context_window)
        .await
        .unwrap();
    assert_eq!(current_total, 0);

    let mut block = db
        .get_bitcoin_block(&bitcoin_chain_tip.block_hash)
        .await
        .unwrap()
        .unwrap();
    let amount = 123_456;

    // Let's add a bunch of withdrawal outputs into our blockchain. Later
    // we will make sure that the query fetches only the ones that it is
    // supposed to.
    for _ in 0..context_window {
        let output = model::TxOutput {
            amount,
            output_type: model::TxOutputType::Withdrawal,
            ..Faker.fake_with_rng(&mut rng)
        };

        let tx = model::Transaction {
            txid: output.txid.into_bytes(),
            tx: Vec::new(),
            tx_type: model::TransactionType::SbtcTransaction,
            block_hash: block.block_hash.into_bytes(),
        };
        db.write_bitcoin_transactions(vec![tx]).await.unwrap();
        db.write_tx_output(&output).await.unwrap();

        block = db
            .get_bitcoin_block(&block.parent_hash)
            .await
            .unwrap()
            .unwrap();
    }

    // The blockchain with a context window of zero is just the chain_tip,
    // same thing as a context window of 1.
    let current_total = db
        .compute_withdrawn_total(&bitcoin_chain_tip.block_hash, 0)
        .await
        .unwrap();

    assert_eq!(current_total, amount);

    // Now let's check that we keep getting more and more outputs as we
    // increase the context window.
    for window in 1..context_window {
        let current_total = db
            .compute_withdrawn_total(&bitcoin_chain_tip.block_hash, window)
            .await
            .unwrap();

        assert_eq!(
            current_total,
            amount * window as u64,
            "Broke at context_window {window}"
        );
    }

    signer::testing::storage::drop_db(db).await;
}

/// Check that the query in `compute_withdrawn_total` returns the total
/// amount of withdrawal amounts on the identified blockchain.
///
/// This tests that if there are conflicting blockchains, where say, both
/// chains have the same height and there are sweep transactions fulfilling
/// withdrawals confirmed on both of them, then the the query will only
/// return the amounts associated with the one identified by the given
/// chain tip and context window.
#[tokio::test]
async fn compute_withdrawn_total_ignores_withdrawals_not_identified_blockchain() {
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(4);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 30,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
        consecutive_blocks: true,
    };
    // The number of signers does not matter
    let num_signers = 1;
    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data.write_to(&mut db).await;

    let context_window = 10;
    let bitcoin_chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();
    let current_total = db
        .compute_withdrawn_total(&bitcoin_chain_tip.block_hash, context_window)
        .await
        .unwrap();
    assert_eq!(current_total, 0);

    // Let's add one withdrawal output into the chain tip of our blockchain
    // and another output on a block at the same height that is not on our
    // blockchain.
    let amount1 = 123_456;
    let output1 = model::TxOutput {
        amount: amount1,
        output_type: model::TxOutputType::Withdrawal,
        ..Faker.fake_with_rng(&mut rng)
    };

    let tx = model::Transaction {
        txid: output1.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: bitcoin_chain_tip.block_hash.into_bytes(),
    };
    db.write_bitcoin_transactions(vec![tx]).await.unwrap();
    db.write_tx_output(&output1).await.unwrap();

    // Okay, and another output on another blockchain
    let amount2 = 789_101;
    let another_block = model::BitcoinBlock {
        block_height: bitcoin_chain_tip.block_height,
        ..Faker.fake_with_rng(&mut rng)
    };

    let output2 = model::TxOutput {
        amount: amount2,
        output_type: model::TxOutputType::Withdrawal,
        ..Faker.fake_with_rng(&mut rng)
    };

    let tx = model::Transaction {
        txid: output2.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: another_block.block_hash.into_bytes(),
    };
    db.write_bitcoin_block(&another_block).await.unwrap();
    db.write_bitcoin_transactions(vec![tx]).await.unwrap();
    db.write_tx_output(&output2).await.unwrap();

    // The blockchain with a context window of zero is just the chain_tip,
    // same thing as a context window of 1. So this checks the "regular"
    // chain tip.
    let current_total = db
        .compute_withdrawn_total(&bitcoin_chain_tip.block_hash, 0)
        .await
        .unwrap();

    assert_eq!(current_total, amount1);

    // Let's check for the withdrawal output on that other blockchain.
    let current_total = db
        .compute_withdrawn_total(&another_block.block_hash, 0)
        .await
        .unwrap();

    assert_eq!(current_total, amount2);

    // The blockchain with a context window of 5 should return the same
    // thing as a context window of zero or 1. Just an additional sanity
    // check.
    let current_total = db
        .compute_withdrawn_total(&bitcoin_chain_tip.block_hash, 5)
        .await
        .unwrap();

    assert_eq!(current_total, amount1);

    let current_total = db
        .compute_withdrawn_total(&another_block.block_hash, 5)
        .await
        .unwrap();

    assert_eq!(current_total, amount2);

    // Sanity check that the test isn't totally busted. It still might be
    // regular busted for some other reason though.
    assert_ne!(amount1, amount2);

    signer::testing::storage::drop_db(db).await;
}

/// Module containing a test suite and helpers specific to
/// `DbRead::get_pending_accepted_withdrawal_requests`.
mod get_pending_accepted_withdrawal_requests {
    use signer::{
        bitcoin::validation::WithdrawalValidationResult,
        testing::storage::{self, DbReadTestExt as _, DbWriteTestExt as _},
    };

    use super::*;

    /// Creates [`WithdrawalSigner`]s for each vote in the provided slice and
    /// stores them in the database. The signer public key is randomized.
    async fn store_votes(db: &PgStore, request: &WithdrawalRequest, votes: &[bool]) {
        for vote in votes {
            let signer = model::WithdrawalSigner {
                request_id: request.request_id,
                block_hash: request.block_hash,
                txid: request.txid,
                signer_pub_key: Faker.fake(),
                is_accepted: *vote,
            };
            db.write_withdrawal_signer_decision(&signer)
                .await
                .expect("failed to write signer decision");
        }
    }

    /// Creates and stores a withdrawal request, confirmed in the specified
    /// bitcoin & stacks blocks.
    ///
    /// If votes are provided, signer vote entries are created and stored as
    /// well (with the same number of votes as the length of the `votes` slice).
    /// The votes are stored under random signer public keys.
    async fn store_withdrawal_request(
        db: &PgStore,
        request_id: u64,
        bitcoin_block: &BitcoinBlock,
        stacks_block: &StacksBlock,
        votes: &[bool],
    ) -> WithdrawalRequest {
        let withdrawal_request = WithdrawalRequest {
            request_id,
            block_hash: stacks_block.block_hash,
            bitcoin_block_height: bitcoin_block.block_height,
            ..Faker.fake()
        };

        db.write_withdrawal_request(&withdrawal_request)
            .await
            .expect("failed to write withdrawal request");

        store_votes(db, &withdrawal_request, votes).await;

        withdrawal_request
    }

    /// Creates a withdrawal rejection event in the database at the specified
    /// stacks block.
    async fn reject_withdrawal_request(
        db: &PgStore,
        request: &WithdrawalRequest,
        stacks_block: &StacksBlock,
    ) {
        db.write_withdrawal_reject_event(&WithdrawalRejectEvent {
            request_id: request.request_id,
            block_id: stacks_block.block_hash,
            ..Faker.fake()
        })
        .await
        .expect("failed to write withdrawal reject event");
    }

    /// Creates a sweep transaction that includes the specified withdrawal
    /// request. The sweep transaction is written to the database in the
    /// provided bitcoin block and the transaction ID is returned.
    async fn sweep_withdrawal_request(
        db: &PgStore,
        request: &WithdrawalRequest,
        at_bitcoin_block: &BitcoinBlockHash,
    ) -> BitcoinTxId {
        // Simulate a sweep transaction on the canonical chain which will
        // include the withdrawal request.
        let transaction = model::Transaction {
            txid: Faker.fake(),
            block_hash: at_bitcoin_block.into_bytes(),
            tx_type: model::TransactionType::SbtcTransaction,
            tx: Vec::new(),
        };
        let bitcoin_sweep_tx = model::BitcoinTxRef {
            txid: transaction.txid.into(),
            block_hash: *at_bitcoin_block,
        };
        db.write_transaction(&transaction)
            .await
            .expect("failed to write transaction");
        db.write_bitcoin_transaction(&bitcoin_sweep_tx)
            .await
            .expect("failed to write bitcoin transaction");

        // Write a fully validated withdrawal output for the request.
        db.write_bitcoin_withdrawals_outputs(&[model::BitcoinWithdrawalOutput {
            bitcoin_txid: bitcoin_sweep_tx.txid,
            bitcoin_chain_tip: *at_bitcoin_block,
            is_valid_tx: true,
            stacks_txid: request.txid,
            stacks_block_hash: request.block_hash,
            request_id: request.request_id,
            validation_result: WithdrawalValidationResult::Ok,
            output_index: 2,
        }])
        .await
        .expect("failed to write bitcoin withdrawal output");

        transaction.txid.into()
    }

    /// Asserts that when there are no withdrawal requests, we return an empty
    /// list (just to make sure we don't error anywhere).
    #[test_log::test(tokio::test)]
    async fn returns_empty_list_when_no_requests() {
        let db = signer::testing::storage::new_test_database().await;

        let requests = db
            .get_pending_accepted_withdrawal_requests(
                &Faker.fake(),
                &Faker.fake(),
                1_000u64.into(),
                0,
            )
            .await
            .expect("failed to query db");
        assert!(requests.is_empty());

        signer::testing::storage::drop_db(db).await;
    }

    /// Asserts that requests which are confirmed in stacks blocks whose anchor
    /// block is, while in the canonical bitcoin chain, too old to be considered
    /// accepted and are not returned.
    ///
    /// The signature threshold/min height we are testing is _inclusive_.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    /// Height:      0           1           2
    ///          ┌────────┐  ┌────────┐  ┌────────┐
    /// Bitcoin: │   B1   ├──►   B2   ├──►   B3   │ The request is confirmed (✔)
    ///          └─▲──────┘  └─▲──────┘  └─▲──────┘ in S2 and we test different
    ///          ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐ min heights.
    /// Stacks:  │   S1   ├──►   S2 ✔ ├──►   S3   │
    ///          └────────┘  └────────┘  └────────┘
    /// ```
    #[tokio::test]
    async fn expired_requests_not_returned() {
        let db = signer::testing::storage::new_test_database().await;
        let signature_threshold = 2;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        let bitcoin_2 = bitcoin_1.new_child();
        let bitcoin_3 = bitcoin_2.new_child();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);
        let stacks_2 = stacks_1.new_child().anchored_to(&bitcoin_2);
        let stacks_3 = stacks_2.new_child().anchored_to(&bitcoin_3);

        // Write our bitcoin + stacks blocks.
        db.write_blocks(
            [&bitcoin_1, &bitcoin_2, &bitcoin_2, &bitcoin_3],
            [&stacks_1, &stacks_2, &stacks_2, &stacks_3],
        )
        .await;

        // Get our chain tips.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;

        // Assert that the chain tips are what we expect.
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_3.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_3.block_hash);

        // Store a withdrawal request, confirmed in B2/S2.
        store_withdrawal_request(&db, 1, &bitcoin_2, &stacks_2, &[true, true]).await;

        // NOTE: The bitcoin block heights are 0-indexed, so these have a height
        // of `1`.
        assert_eq!(bitcoin_2.block_height, 1u64.into());
        assert_eq!(stacks_2.block_height, 1u64.into());

        // Min bitcoin height = 0, we should get the request.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                0u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 1, "min height: 0");

        // Min bitcoin height = 1, we should get the request.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                1u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 1, "min height: 1");

        // Min bitcoin height = 2, the request should NOT be returned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                2u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert!(requests.is_empty(), "min height: 2");

        storage::drop_db(db).await;
    }

    /// Asserts that requests with a confirmed rejection event are not returned.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐
    /// Bitcoin: │   B1   │
    ///          └─▲──────┘  We both confirm (✔) and reject (✖) the
    ///          ┌─┴──────┐  request in S1.
    /// Stacks:  │  S1 ✔✖ │
    ///          └────────┘
    /// ```
    #[tokio::test]
    async fn request_with_confirmed_rejection_not_returned() {
        let db = signer::testing::storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_block = BitcoinBlock::new_genesis();
        // Stacks blocks:
        let stacks_block = StacksBlock::new_genesis().anchored_to(&bitcoin_block);

        // Write our blocks.
        db.write_blocks([&bitcoin_block], [&stacks_block]).await;

        // Store a withdrawal request.
        let request =
            store_withdrawal_request(&db, 1, &bitcoin_block, &stacks_block, &[true, true]).await;

        // We should get the request as pending accepted.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                &bitcoin_block.block_hash,
                &stacks_block.block_hash,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 1);

        // Now reject the request.
        reject_withdrawal_request(&db, &request, &stacks_block).await;

        // It should no longer be returned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                &bitcoin_block.block_hash,
                &stacks_block.block_hash,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert!(requests.is_empty());

        storage::drop_db(db).await;
    }

    /// Asserts that a withdrawal request is returned when it has been confirmed
    /// and has a rejection event, but the rejection event has been orphaned.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐  ┌────────┐  ┌────────┐
    /// Bitcoin: │   B1   ├──►  B2a   ├──►  B3a   │
    ///          └─▲──┬───┘  └─▲──────┘  └─▲──────┘
    ///            ┊  │      ┌─┊──────┐    ┊  The request is confirmed (✔) in S1
    ///            ┊  └──────► ┊ B2b  │    ┊  and rejected (✖) in S2b, but its
    ///            ┊         └─┊────▲─┘    ┊  anchor later gets orphaned by B3a.
    ///            ┊           ┊    ┊      ┊  
    ///          ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐
    /// Stacks:  │   S1 ✔ ├──►  S2a   ├──►  S3a   │
    ///          └────┬───┘  └────────┘  └────────┘
    ///               │      ┌──────┴─┐
    ///               └─────>│  S2b ✖ │
    ///                      └────────┘
    /// ```
    #[tokio::test]
    async fn request_with_orphaned_rejection_is_returned() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        let bitcoin_2a = bitcoin_1.new_child();
        let bitcoin_2b = bitcoin_1.new_child();
        let bitcoin_3a = bitcoin_2a.new_child();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);
        let stacks_2a = stacks_1.new_child().anchored_to(&bitcoin_2a);
        let stacks_2b = stacks_1.new_child().anchored_to(&bitcoin_2b);
        let stacks_3a = stacks_2a.new_child().anchored_to(&bitcoin_3a);

        // Write our bitcoin + stacks blocks.
        db.write_blocks(
            [&bitcoin_1, &bitcoin_2a, &bitcoin_2b, &bitcoin_3a],
            [&stacks_1, &stacks_2a, &stacks_2b, &stacks_3a],
        )
        .await;

        // Get our chain tips.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;

        // Assert that the chain tips are what we expect.
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_3a.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_3a.block_hash);

        // Store a withdrawal request, confirmed in B1/S1.
        let request = store_withdrawal_request(&db, 1, &bitcoin_1, &stacks_1, &[true, true]).await;

        // Reject the withdrawal request in B2b/S2b.
        reject_withdrawal_request(&db, &request, &stacks_2b).await;

        // The request should be returned as the rejection has been orphaned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 1);

        storage::drop_db(db).await;
    }

    /// Asserts that a withdrawal request is not returned when it has been
    /// confirmed and has both confirmed and orphaned rejection events. This
    /// test is to ensure that an orphaned rejection event does not
    /// "accidentally" override a confirmed rejection event.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐  ┌────────┐  ┌────────┐
    /// Bitcoin: │   B1   ├──►  B2a   ├──►  B3a   │
    ///          └─▲──┬───┘  └─▲──────┘  └─▲──────┘
    ///            ┊  │      ┌─┊──────┐    ┊  The request is confirmed (✔) in S1
    ///            ┊  └──────► ┊ B2b  │    ┊  and rejected (✖) in both S2a and S2b.
    ///            ┊         └─┊────▲─┘    ┊  B2b is orphaned by B3a, but B2a is
    ///            ┊           ┊    ┊      ┊  still confirming the rejection.
    ///          ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐
    /// Stacks:  │   S1 ✔ ├──►  S2a ✖ ├──►  S3a   │
    ///          └────┬───┘  └────────┘  └────────┘
    ///               │      ┌──────┴─┐
    ///               └─────>│  S2b ✖ │
    ///                      └────────┘
    /// ```
    #[tokio::test]
    async fn request_with_both_confirmed_and_orphaned_rejection_not_returned() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        let bitcoin_2a = bitcoin_1.new_child();
        let bitcoin_2b = bitcoin_1.new_child();
        let bitcoin_3a = bitcoin_2a.new_child();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);
        let stacks_2a = stacks_1.new_child().anchored_to(&bitcoin_2a);
        let stacks_2b = stacks_1.new_child().anchored_to(&bitcoin_2b);
        let stacks_3a = stacks_2a.new_child().anchored_to(&bitcoin_3a);

        // Write our bitcoin + stacks blocks.
        db.write_blocks(
            [&bitcoin_1, &bitcoin_2a, &bitcoin_2b, &bitcoin_3a],
            [&stacks_1, &stacks_2a, &stacks_2b, &stacks_3a],
        )
        .await;

        // Get our chain tips.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;

        // Assert that the chain tips are what we expect.
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_3a.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_3a.block_hash);

        // Store a withdrawal request, confirmed in B1/S1.
        let request = store_withdrawal_request(&db, 1, &bitcoin_1, &stacks_1, &[true, true]).await;

        // We should get the request as pending accepted.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 1);

        // Reject the withdrawal request in B2a/S2a (canonical).
        reject_withdrawal_request(&db, &request, &stacks_2a).await;
        // Reject the withdrawal request in B2b/S2b (orphaned).
        reject_withdrawal_request(&db, &request, &stacks_2b).await;

        // The request should not be returned as there is a confirmed rejection
        // on the canonical chain.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert!(requests.is_empty());

        storage::drop_db(db).await;
    }

    /// Asserts that we only return requests that have been accepted by the
    /// required number of signers. This test creates one valid withdrawal
    /// request with no votes.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐
    /// Bitcoin: │   B1 ◆ │
    ///          └─▲──────┘  We both confirm (✔) and sweep (◆) the
    ///          ┌─┴──────┐  request in B1.
    /// Stacks:  │   S1 ✔ │
    ///          └────────┘
    /// ```
    #[tokio::test]
    async fn returns_empty_list_when_no_accepted_requests() {
        let db = signer::testing::storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_block = BitcoinBlock::new_genesis();
        // Stacks blocks:
        let stacks_block = StacksBlock::new_genesis().anchored_to(&bitcoin_block);

        // Write our blocks.
        db.write_blocks([&bitcoin_block], [&stacks_block]).await;

        // Store a withdrawal request.
        store_withdrawal_request(&db, 1, &bitcoin_block, &stacks_block, &[]).await;

        // Ensure that the request is considered "pending".
        let requests = db
            .get_pending_withdrawal_requests(&bitcoin_block.block_hash, 1_000, &Faker.fake())
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 1);

        // But it should not be "pending accepted".
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                &bitcoin_block.block_hash,
                &stacks_block.block_hash,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert!(requests.is_empty());

        signer::testing::storage::drop_db(db).await;
    }

    /// Asserts that we only return requests that have been accepted by the
    /// required number of signers. This test uses an accept threshold of `2`.
    /// We create two withdrawal requests, one with two yes votes and one with
    /// one yes vote and one no vote and ensure that only the request with two
    /// yes votes is returned.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐
    /// Bitcoin: │   B1 ◆ │
    ///          └─▲──────┘  We both confirm (✔) and sweep (◆) the
    ///          ┌─┴──────┐  request in B1.
    /// Stacks:  │   S1 ✔ │
    ///          └────────┘
    /// ```
    #[tokio::test]
    async fn returns_only_withdrawals_accepted_by_threshold_signers() {
        let db = signer::testing::storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_block = BitcoinBlock::new_genesis();
        // Stacks blocks:
        let stacks_block = StacksBlock::new_genesis().anchored_to(&bitcoin_block);

        // Write our blocks.
        db.write_blocks([&bitcoin_block], [&stacks_block]).await;

        // Setup withdrawal request 1: no votes
        store_withdrawal_request(&db, 1, &bitcoin_block, &stacks_block, &[]).await;
        // Setup withdrawal request 2: two yes votes
        let withdrawal_request_2 =
            store_withdrawal_request(&db, 2, &bitcoin_block, &stacks_block, &[true, true]).await;
        // Setup withdrawal request 3: one yes vote, one no vote
        store_withdrawal_request(&db, 3, &bitcoin_block, &stacks_block, &[true, false]).await;

        // Get the pending accepted withdrawal requests. We should only
        // get withdrawal_request2.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                &bitcoin_block.block_hash,
                &stacks_block.block_hash,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        assert_eq!(requests.single(), withdrawal_request_2);

        storage::drop_db(db).await;
    }

    /// Asserts that we only return withdrawal requests that have been confirmed
    /// in a stacks block which is anchored to a bitcoin block in the canonical
    /// bitcoin blockchain.
    ///
    /// We achieve this by creating three withdrawal requests, one of which is
    /// confirmed in a stacks block which is anchored to a bitcoin block which
    /// is orphaned. We then ensure that only the requests confirmed in the
    /// canonical chain are returned.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐  ┌────────┐  ┌────────┐
    /// Bitcoin: │   B1   ├──►  B2a   ├──►  B3a   │
    ///          └─▲──┬───┘  └─▲──────┘  └─▲──────┘
    ///            ┊  │      ┌─┊──────┐    ┊  We create requests in each
    ///            ┊  └──────► ┊B2b   │    ┊  stacks block, however B2b (and
    ///            ┊         └─┊────▲─┘    ┊  thus S2b) will be orphaned by
    ///            ┊           ┊    ┊      ┊  B3a+S3a.
    ///          ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐
    /// Stacks:  │   S1 ✔ ├──►  S2a ✔ ├──►  S3a ✔ │
    ///          └────┬───┘  └────────┘  └────────┘
    ///               │      ┌──────┴─┐  The requests are each confirmed (✔) in
    ///               └─────>│  S2b ✔ │  their respective block.
    ///                      └────────┘
    /// ```
    #[tokio::test]
    async fn returns_only_requests_on_canonical_chains() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        let bitcoin_2a = bitcoin_1.new_child();
        let bitcoin_2b = bitcoin_1.new_child();
        let bitcoin_3a = bitcoin_2a.new_child();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);
        let stacks_2a = stacks_1.new_child().anchored_to(&bitcoin_2a);
        let stacks_2b = stacks_1.new_child().anchored_to(&bitcoin_2b);
        let stacks_3a = stacks_2a.new_child().anchored_to(&bitcoin_3a);

        // Write our bitcoin + stacks blocks.
        db.write_blocks(
            [&bitcoin_1, &bitcoin_2a, &bitcoin_2b, &bitcoin_3a],
            [&stacks_1, &stacks_2a, &stacks_2b, &stacks_3a],
        )
        .await;

        // Get our chain tips.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;

        // Assert that the chain tips are what we expect.
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_3a.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_3a.block_hash);

        // Give all requests enough 'yes' votes.
        let votes = [true, true];

        // Setup withdrawal request 1 (canonical: block 1)
        let request_1 = store_withdrawal_request(&db, 1, &bitcoin_1, &stacks_1, &votes).await;
        // Setup withdrawal request 2a (canonical: block 2a)
        let request_2a = store_withdrawal_request(&db, 2, &bitcoin_2a, &stacks_2a, &votes).await;
        // Setup withdrawal request 2b (orphaned fork: block 2b)
        store_withdrawal_request(&db, 3, &bitcoin_2b, &stacks_2b, &votes).await;
        // Setup withdrawal request 3a (canonical: block 3a)
        let request_3a = store_withdrawal_request(&db, 4, &bitcoin_3a, &stacks_3a, &votes).await;

        // Get the pending accepted withdrawal requests. We should only
        // get requests on the canonical chains.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        // We expect to receive requests `1`, `2a`, and `3a`. `2b` should be
        // orphaned.
        assert_eq!(requests.len(), 3);
        // We assert them in reverse order since we use `pop()` to remove them.
        assert_eq!(requests, [request_1, request_2a, request_3a]);

        storage::drop_db(db).await;
    }

    /// Asserts that requests which have been swept on the canonical chain are
    /// not returned by the query.
    ///
    /// We achieve this by creating a withdrawal request and then simulating a
    /// sweep transaction on the canonical chain which includes the request and
    /// then ensuring that the request is not returned by the query.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐
    /// Bitcoin: │   B1 ◆ │
    ///          └─▲──────┘  We both confirm (✔) and sweep (◆) the
    ///          ┌─┴──────┐  request in S1.
    /// Stacks:  │   S1 ✔ │
    ///          └────────┘
    /// ```
    #[tokio::test]
    async fn requests_swept_on_canonical_chain_are_not_returned() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_block_1 = BitcoinBlock::new_genesis();
        // Stacks blocks:
        let stacks_block_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_block_1);

        // Write our blocks to the database.
        db.write_blocks([&bitcoin_block_1], [&stacks_block_1]).await;

        // Create and store a withdrawal request confirmed in block 1 (both
        // bitcoin and stacks) and give it enough 'yes' votes.
        let request_1 =
            store_withdrawal_request(&db, 1, &bitcoin_block_1, &stacks_block_1, &[true, true])
                .await;

        // The request hasn't been swept yet, so it should be returned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                &bitcoin_block_1.block_hash,
                &stacks_block_1.block_hash,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 1);

        // Simulate a sweep transaction on the canonical chain which will
        // include the withdrawal request.
        sweep_withdrawal_request(&db, &request_1, &bitcoin_block_1.block_hash).await;

        // The request should be considered swept now, so we should get empty
        // results here.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                &bitcoin_block_1.block_hash,
                &stacks_block_1.block_hash,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 0);

        storage::drop_db(db).await;
    }

    /// Asserts that requests which have been swept in orphaned bitcoin blocks
    /// are returned by the query.
    ///
    /// We achieve this by creating a withdrawal request, simulating the
    /// request being serviced by a sweep transaction in an orphaned bitcoin
    /// block and then ensuring that the request is returned by the query.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐  ┌────────┐  ┌────────┐
    /// Bitcoin: │   B1   ├──►  B2a   ├──►  B3a   │
    ///          └─▲──┬───┘  └────────┘  └────────┘
    ///            ┊  │      ┌────────┐  We sweep (◆) the request in B2b,
    ///            ┊  └──────►  B2b ◆ │  which is orphaned by B3a.
    ///            ┊         └────────┘
    ///          ┌─┴──────┐
    /// Stacks:  │   S1 ✔ │  The request is confirmed (✔) in S1.
    ///          └────────┘
    /// ```
    #[tokio::test]
    async fn returns_request_swept_in_orphaned_bitcoin_block() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        let bitcoin_2a = bitcoin_1.new_child();
        let bitcoin_2b = bitcoin_1.new_child();
        let bitcoin_3a = bitcoin_2a.new_child();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);

        // Write the blocks to the database.
        db.write_blocks(
            [&bitcoin_1, &bitcoin_2a, &bitcoin_2b, &bitcoin_3a],
            [&stacks_1],
        )
        .await;

        // Get our chain tips and assert they're what we expect.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_3a.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_1.block_hash);

        // Create and store a withdrawal request confirmed in block 1 (both
        // bitcoin and stacks).
        let request = store_withdrawal_request(&db, 1, &bitcoin_1, &stacks_1, &[true, true]).await;

        // The request confirmed in the canonical chain and not swept, so we
        // should get it back here.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 1);

        // Sweep the request on the orphaned chain (block 2b).
        sweep_withdrawal_request(&db, &request, &bitcoin_2b.block_hash).await;

        // The request confirmed in the canonical chain and swept in an
        // orphaned bitcoin block, so we should get it back here.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.single(), request);

        storage::drop_db(db).await;
    }

    /// Asserts that a single request is not returned if it is swept in any
    /// canonical bitcoin block, despite also being swept in orphaned block(s).
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────┐  ┌────────┐  ┌────────┐
    /// Bitcoin: │   B1   ├──►  B2a ◆ ├──►  B3a   │
    ///          └─▲──┬───┘  └─▲──────┘  └─▲──────┘
    ///            ┊  │      ┌─┊──────┐    ┊  We sweep (◆) the request in
    ///            ┊  └──────► ┊B2b ◆ │    ┊  both B2a and B2b, but B2b is
    ///            ┊         └─┊────▲─┘    ┊  orphaned by B3a.
    ///            ┊           ┊    ┊      ┊
    ///          ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐
    /// Stacks:  │   S1 ✔ ├──►  S2a   ├──►  S3a   │
    ///          └────┬───┘  └────────┘  └────────┘
    ///               │      ┌──────┴─┐
    ///               └──────►  S2b   │  We confirm (✔) the request in S1.
    ///                      └────────┘
    /// ```
    #[tokio::test]
    async fn does_not_return_request_swept_in_both_canonical_and_orphaned_blocks() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        let bitcoin_2a = bitcoin_1.new_child();
        let bitcoin_2b = bitcoin_1.new_child();
        let bitcoin_3a = bitcoin_2a.new_child();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);
        let stacks_2a = stacks_1.new_child().anchored_to(&bitcoin_2a);
        let stacks_2b = stacks_1.new_child().anchored_to(&bitcoin_2b);
        let stacks_3a = stacks_2a.new_child().anchored_to(&bitcoin_3a);

        // Write the blocks to the database.
        db.write_blocks(
            [&bitcoin_1, &bitcoin_2a, &bitcoin_2b, &bitcoin_3a],
            [&stacks_1, &stacks_2a, &stacks_2b, &stacks_3a],
        )
        .await;

        // Get our chain tips and assert they're what we expect.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_3a.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_3a.block_hash);

        // Create and store a withdrawal request confirmed in block 1 (both
        // bitcoin and stacks).
        let request = store_withdrawal_request(&db, 1, &bitcoin_1, &stacks_1, &[true, true]).await;

        // Sweep the request on the canonical chain (B2a).
        sweep_withdrawal_request(&db, &request, &bitcoin_2a.block_hash).await;
        // Sweep the request on the orphaned chain (B2b).
        sweep_withdrawal_request(&db, &request, &bitcoin_2b.block_hash).await;

        // The request is both confirmed (B1) and swept (B2a) in the canonical
        // bitcoin chain. It is also swept in an orphaned block (B2b). The query
        // should not return the request as it is considered swept due to B2a.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.len(), 0);

        storage::drop_db(db).await;
    }

    /// Asserts that, for two requests with the same `request_id` confirmed in
    /// both a canonical and orphaned stacks block, that only the request
    /// confirmed in the canonical stacks block is returned. Both stacks blocks
    /// are anchored to the same bitcoin block in the canonical bitcoin chain.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///          ┌────────────────────────────────┐
    /// Bitcoin: │                B1              │
    ///          └─▲───────────▲────▲──────▲──────┘
    ///            ┊           ┊    ┊      ┊
    ///          ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐
    /// Stacks:  │   S1   ├──►  S2a ✔ ├──►  S3a   │
    ///          └────┬───┘  └────────┘  └────────┘
    ///               │      ┌──────┴─┐  We confirm (✔) a withdrawal request in
    ///               └──────►  S2b ✔ │  both S2a and S2b with the same id.
    ///                      └────────┘
    /// ```
    #[tokio::test]
    async fn requests_with_same_id_in_different_stacks_forks() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;
        let min_block_height = 0u64;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);
        let stacks_2a = stacks_1.new_child();
        let stacks_2b = stacks_1.new_child();
        let stacks_3a = stacks_2a.new_child();

        // Write our blocks.
        db.write_blocks(
            [&bitcoin_1],
            [&stacks_1, &stacks_2a, &stacks_2b, &stacks_3a],
        )
        .await;

        // Get our chain tips and assert they're what we expect.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_1.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_3a.block_hash);

        // Create withdrawal requests in both stacks forks using the same `request_id`.
        let expected =
            store_withdrawal_request(&db, 1, &bitcoin_1, &stacks_2a, &[true, true]).await;
        store_withdrawal_request(&db, 1, &bitcoin_1, &stacks_2b, &[true, true]).await;

        // Get the pending requests. The requests are both in blocks anchored to
        // the same canonical bitcoin block, but in different stacks forks. Only
        // the request in the canonical chain should be returned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                min_block_height.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");
        assert_eq!(requests.single(), expected);

        storage::drop_db(db).await;
    }

    /// In this test, the request is confirmed in S2, but the request's
    /// specified bitcoin block height is `2`. We use the request's specified
    /// bitcoin height as the actual block height. In this case, the
    /// confirmation block height (1) is lower than the specified bitcoin block
    /// height (2).
    ///
    /// The query will fetch the blockchains to a height of `min - 1`, so we
    /// would expect the following results based on the minimum height:
    ///
    /// - `0`: confirmation and block height above the minimum, request
    ///        returned.
    /// - `1`: confirmation at minimum, block height above minimum, request
    ///        returned..
    /// - `2`: confirmation at minimum - 1, block height at minimum. Given that
    ///        the blockchains will fetch to a height of `1` in this case, we
    ///        expect the request to be returned.
    /// - `3`: confirmation and block height below the minimum, nothing
    ///        returned.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    /// Height:       0           1           2          3
    ///          ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐  
    /// Bitcoin: │   B1   ├──►   B2   ├──►   B3   ├──►   B4   │  We create a withdrawal
    ///          └─▲──────┘  └─▲──────┘  └─▲──────┘  └─▲──────┘  request which is confirmed
    ///          ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐  in S2, but we set its
    /// Stacks:  │   S1   ├──►   S2 ✔ ├──►   S3 ⚠️ ├──►   S4   │  bitcoin height to 3.  
    ///          └────────┘  └────────┘  └────────┘  └────────┘  
    /// ```
    #[tokio::test]
    async fn test_confirmed_anchor_block_lower_than_block_height() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        let bitcoin_2 = bitcoin_1.new_child();
        let bitcoin_3 = bitcoin_2.new_child();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);
        let stacks_2 = stacks_1.new_child().anchored_to(&bitcoin_2);
        let stacks_3 = stacks_2.new_child().anchored_to(&bitcoin_3);

        // Write the blocks to the database.
        db.write_blocks(
            [&bitcoin_1, &bitcoin_2, &bitcoin_3],
            [&stacks_1, &stacks_2, &stacks_3],
        )
        .await;

        // Get our chain tips and assert they're what we expect.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_3.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_3.block_hash);

        // Create a withdrawal request that has a bitcoin block height of `2`,
        // but is actually confirmed in S2 (which has a height of `1`).
        let request = WithdrawalRequest {
            request_id: 1,
            block_hash: stacks_2.block_hash, // Anchored to B2 with height of 1.
            bitcoin_block_height: 2u64.into(),
            ..Faker.fake()
        };

        // Store the request in the database and give it enough votes.
        db.write_withdrawal_request(&request)
            .await
            .expect("failed to store request");
        store_votes(&db, &request, &[true, true]).await;

        // Min bitcoin height of `0`: both confirmation and block height above
        // the minimum; the request should be returned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                0u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        assert_eq!(requests.len(), 1);

        // Min bitcoin height of `1`: confirmation at minimum, block height
        // above minimum; the request should be returned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                1u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        assert_eq!(requests.len(), 1);

        // Min bitcoin height of `2`; confirmation at minimum - 1, block height
        // at minimum; the request should be returned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                2u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        assert_eq!(requests.len(), 1);

        // Min bitcoin height of `3`; both confirmation and block height below
        // the minimum; the request should NOT be returned.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                3u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        assert_eq!(requests.len(), 0);
    }

    /// In this test, the request is confirmed in S2, but the request's
    /// specified bitcoin block height is `0`. We use the request's specified
    /// bitcoin height as the actual block height. In this case, the
    /// confirmation block height (1) is higher than the specified bitcoin block
    /// height (0), so we would expect all fetches where the min bitcoin height
    /// is greater than 0 to not return the request, however a min height of `0`
    /// should as both the request height and confirmation block height meet the
    /// criteria.
    ///
    /// This test creates blockchains with the following structure:
    ///
    /// ```text
    ///
    /// Height:       0           1           2     
    ///          ┌────────┐  ┌────────┐  ┌────────┐
    /// Bitcoin: │   B1   ├──►   B2   ├──►   B3   │  We create a withdrawal
    ///          └─▲──────┘  └─▲──────┘  └─▲──────┘  request which is confirmed
    ///          ┌─┴──────┐  ┌─┴──────┐  ┌─┴──────┐  (✔) in S2, but we set its
    /// Stacks:  │   S1 ⚠️ ├──►   S2 ✔ ├──►   S3   │  bitcoin height (⚠️) to 0.
    ///          └────────┘  └────────┘  └────────┘
    /// ```
    #[tokio::test]
    async fn test_confirmed_anchor_block_higher_than_block_height() {
        let db = storage::new_test_database().await;

        let signature_threshold = 2;

        // Bitcoin blocks:
        let bitcoin_1 = BitcoinBlock::new_genesis();
        let bitcoin_2 = bitcoin_1.new_child();
        let bitcoin_3 = bitcoin_2.new_child();
        // Stacks blocks:
        let stacks_1 = StacksBlock::new_genesis().anchored_to(&bitcoin_1);
        let stacks_2 = stacks_1.new_child().anchored_to(&bitcoin_2);
        let stacks_3 = stacks_2.new_child().anchored_to(&bitcoin_3);

        // Write the blocks to the database.
        db.write_blocks(
            [&bitcoin_1, &bitcoin_2, &bitcoin_3],
            [&stacks_1, &stacks_2, &stacks_3],
        )
        .await;

        // Get our chain tips and assert they're what we expect.
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;
        assert_eq!(bitcoin_chain_tip.as_ref(), &bitcoin_3.block_hash);
        assert_eq!(&stacks_chain_tip, &stacks_3.block_hash);

        // Create a withdrawal request that has a bitcoin block height of `0`,
        // but is actually confirmed in S2 (which has a height of `1`).
        let request = WithdrawalRequest {
            request_id: 1,
            block_hash: stacks_2.block_hash, // Anchored to B2 with height of 1.
            bitcoin_block_height: 0u64.into(),
            ..Faker.fake()
        };

        // Store the request in the database and give it enough votes.
        db.write_withdrawal_request(&request)
            .await
            .expect("failed to store request");
        store_votes(&db, &request, &[true, true]).await;

        // Min height is 0, so we should get the request.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                0u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        assert_eq!(requests.len(), 1);

        // Min height is 1, which is above the request height, so we should not
        // get the request.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                1u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        assert_eq!(requests.len(), 0);

        // Min height is 2, which is above the request height, so we should not
        // get the request.
        let requests = db
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip.as_ref(),
                &stacks_chain_tip,
                2u64.into(),
                signature_threshold,
            )
            .await
            .expect("failed to query db");

        assert_eq!(requests.len(), 0);
    }
}
