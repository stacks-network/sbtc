use std::collections::BTreeMap;
use std::collections::HashSet;
use std::io::Read;
use std::time::Duration;

use bitcoin::hashes::Hash as _;
use bitvec::array::BitArray;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::Value as ClarityValue;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksAddress;
use futures::future::join_all;
use futures::StreamExt;
use rand::seq::IteratorRandom;
use rand::seq::SliceRandom;

use signer::bitcoin::validation::DepositConfirmationStatus;
use signer::bitcoin::MockBitcoinInteract;
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
use signer::storage::model;
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
use signer::storage::model::WithdrawalCreateEvent;
use signer::storage::model::WithdrawalRejectEvent;
use signer::storage::model::WithdrawalSigner;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead;
use signer::storage::DbWrite;
use signer::testing;
use signer::testing::dummy::SignerSetConfig;
use signer::testing::storage::model::TestData;
use signer::testing::wallet::ContractCallWrapper;

use fake::Fake;
use rand::SeedableRng;
use signer::testing::context::*;
use signer::DEPOSIT_LOCKTIME_BLOCK_BUFFER;
use test_case::test_case;
use test_log::test;

use crate::setup::backfill_bitcoin_blocks;
use crate::setup::DepositAmounts;
use crate::setup::TestSignerSet;
use crate::setup::TestSweepSetup;
use crate::setup::TestSweepSetup2;

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
    sweep_block_height: 7,
}); "complete-deposit standard recipient")]
#[test_case(ContractCallWrapper(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y.my-contract-name").unwrap(),
    deployer: *testing::wallet::WALLET.0.address(),
    sweep_txid: BitcoinTxId::from([0; 32]),
    sweep_block_hash: BitcoinBlockHash::from([0; 32]),
    sweep_block_height: 7,
}); "complete-deposit contract recipient")]
#[test_case(ContractCallWrapper(AcceptWithdrawalV1 {
    request_id: 0,
    outpoint: bitcoin::OutPoint::null(),
    tx_fee: 3500,
    signer_bitmap: BitArray::ZERO,
    deployer: *testing::wallet::WALLET.0.address(),
    sweep_block_hash: BitcoinBlockHash::from([0; 32]),
    sweep_block_height: 7,
}); "accept-withdrawal")]
#[test_case(ContractCallWrapper(RejectWithdrawalV1 {
    request_id: 0,
    signer_bitmap: BitArray::ZERO,
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_pending_deposit_requests_only_pending() {
    let db = testing::storage::new_test_database().await;

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    let mut rng = rand::rngs::StdRng::seed_from_u64(43);

    let amounts = DepositAmounts { amount: 123456, max_fee: 12345 };
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_pending_withdrawal_requests_only_pending() {
    let db = testing::storage::new_test_database().await;

    let (rpc, faucet) = sbtc::testing::regtest::initialize_blockchain();

    let mut rng = rand::rngs::StdRng::seed_from_u64(43);

    let amounts = DepositAmounts { amount: 123456, max_fee: 12345 };
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
    setup.store_withdrawal_request(&db).await;

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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending accepted withdraw requests
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_return_the_same_pending_accepted_withdraw_requests_as_in_memory_store() {
    let mut pg_store = testing::storage::new_test_database().await;
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 15;
    let context_window = 5;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 1,
        // The signers in these tests vote to reject the request with 50%
        // probability, so the number of signers needs to be a bit above
        // the threshold in order for the test to succeed with accepted
        // requests.
        num_signers_per_request: num_signers,
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

    let mut pending_accepted_withdraw_requests = in_memory_store
        .get_pending_accepted_withdrawal_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending_accepted deposit requests");

    pending_accepted_withdraw_requests.sort();

    assert!(!pending_accepted_withdraw_requests.is_empty());

    let mut pg_pending_accepted_withdraw_requests = pg_store
        .get_pending_accepted_withdrawal_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending_accepted deposit requests");

    pg_pending_accepted_withdraw_requests.sort();

    assert_eq!(
        pending_accepted_withdraw_requests,
        pg_pending_accepted_withdraw_requests
    );
    signer::testing::storage::drop_db(pg_store).await;
}

/// This tests that when fetching pending accepted deposits we ingore swept ones.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
        bitcoin_chain_tip_height as u32 + DEPOSIT_LOCKTIME_BLOCK_BUFFER as u32 + 1;

    // Okay, mess with the test data and make sure that some of the pending accepted deposit requests
    // are outside of the reclaim bounds.
    let percent_of_original_requests_expected_to_be_in_bounds = 0.42;
    let num_deposits_in_bounds = (pending_accepted_deposit_requests.len() as f64
        * percent_of_original_requests_expected_to_be_in_bounds)
        .floor() as usize;

    // Prepare some datastructures to filter the deposit requests that we're going to put out of bounds
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
            minimum_acceptable_unlock_height - height_included as u32;

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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
        .run_dkg(chain_tip, dkg_txid, &mut rng)
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
        block_height: 15,
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn writing_withdrawal_create_requests_postgres() {
    let store = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let event: WithdrawalCreateEvent = fake::Faker.fake_with_rng(&mut rng);

    // Let's see if we can write these rows to the database.
    store
        .write_withdrawal_create_event(&event.clone().into())
        .await
        .unwrap();
    let mut db_event =
        sqlx::query_as::<_, ([u8; 32], [u8; 32], i64, i64, String, Vec<u8>, i64, i64)>(
            r#"
            SELECT txid
                 , block_hash
                 , request_id
                 , amount
                 , sender
                 , recipient
                 , max_fee
                 , block_height
            FROM sbtc_signer.withdrawal_create_events"#,
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
    // Did we only write one row
    assert_eq!(db_event.len(), 1);

    let (txid, block_id, request_id, amount, sender, recipient, max_fee, block_height) =
        db_event.pop().unwrap();

    assert_eq!(txid, event.txid.into_bytes());
    assert_eq!(block_id, event.block_id.into_bytes());
    assert_eq!(request_id as u64, event.request_id);
    assert_eq!(amount as u64, event.amount);
    assert_eq!(sender, event.sender.to_string());
    assert_eq!(recipient, event.recipient.to_bytes());
    assert_eq!(max_fee as u64, event.max_fee);
    assert_eq!(block_height as u64, event.block_height);

    signer::testing::storage::drop_db(store).await;
}

/// Here we test that we can store withdrawal-accept events.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn writing_withdrawal_accept_requests_postgres() {
    let store = testing::storage::new_test_database().await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let event: WithdrawalAcceptEvent = fake::Faker.fake_with_rng(&mut rng);

    // Let's see if we can write these rows to the database.
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
    let shares: EncryptedDkgShares = signer_set_config.fake_with_rng(&mut rng);

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

/// For this test we check that when we get the votes for a withdrawal
/// request for a specific aggregate key, that we get a vote for all public
/// keys for the specific aggregate key. This includes "implicit" votes
/// where we got no response from a particular signer but so we assume that
/// they vote to reject the transaction.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
    let shares: EncryptedDkgShares = signer_set_config.fake_with_rng(&mut rng);

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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP - INTERVAL '366 DAYS')
        ON CONFLICT DO NOTHING"#,
    )
    .bind(shares.aggregate_key)
    .bind(shares.tweaked_aggregate_key)
    .bind(&shares.encrypted_private_shares)
    .bind(&shares.public_shares)
    .bind(&shares.script_pubkey)
    .bind(&shares.signer_set_public_keys)
    .bind(shares.signature_share_threshold as i32)
    .execute(db.pool())
    .await
    .unwrap();

    let keys = db.get_signers_script_pubkeys().await.unwrap();
    assert_eq!(keys.len(), 1);

    signer::testing::storage::drop_db(db).await;
}

/// The [`DbRead::get_last_encrypted_dkg_shares`] function is supposed to
/// fetch the last encrypted DKG shares stored in the database.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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

/// The [`DbRead::deposit_request_exists`] function is return true we have
/// a record of the deposit request and false otherwise.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
    assert!(!db
        .is_known_bitcoin_block_hash(&random_block_hash)
        .await
        .unwrap());

    let random_block_hash = model::BitcoinBlockHash::from([23; 32]);
    assert!(!db
        .is_known_bitcoin_block_hash(&random_block_hash)
        .await
        .unwrap());

    signer::testing::storage::drop_db(db).await;
}

/// This tests that deposit requests where there is an associated sweep
/// transaction will show up in the query results from
/// [`DbRead::get_swept_deposit_requests`].
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
    // trasnaction so the length should be 1.
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

/// This function tests that deposit requests that do not have a confirmed
/// response (sweep) bitcoin transaction are not returned from
/// [`DbRead::get_swept_deposit_requests`].
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
        sweep_block_height: 42,
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
        sweep_block_height: 42,
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
        sweep_block_height: 42,
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

/// This checks that the DbRead::can_sign_deposit_tx implementation for
/// PgStore operators as it is supposed to. Specifically, it checks that it
/// returns Some(true) if the caller is part of the signing set,
/// Some(false) if it isn't and None if the deposit request record cannot
/// be found.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
        sweep_block_height: 42,
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test(tokio::test)]
/// Tests that TxCoordinatorEventLoop::get_pending_requests ignores withdrawals
async fn should_ignore_withdrawals() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_ignore_withdrawals()
        .await;

    testing::storage::drop_db(store).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_get_signer_utxo_simple() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_simple()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_get_signer_utxo_fork() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_fork()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_get_signer_utxo_unspent() {
    let store = testing::storage::new_test_database().await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_unspent()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // Let's write the deposit request and associated trasnaction to the
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
    };

    let signer_set = testing::wsts::generate_signer_set_public_keys(&mut rng, num_signers);
    let test_data = TestData::generate(&mut rng, &signer_set, &test_params);
    test_data.write_to(&db).await;

    // Let's write the deposit request and associated trasnaction to the
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn can_write_multiple_bitcoin_withdrawal_outputs() {
    let db = testing::storage::new_test_database().await;

    let outputs: Vec<BitcoinWithdrawalOutput> = (0..5).map(|_| fake::Faker.fake()).collect();

    db.write_bitcoin_withdrawals_outputs(&outputs)
        .await
        .unwrap();

    signer::testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
    sweep_heights: [u64; N],
    /// This is the height where there is a reorg.
    reorg_height: u64,
    /// This is the height of the donation. It must be less than or equal
    /// to the minimum sweep height indicated by `sweep_heights`.
    donation_height: u64,
    /// The expected height of the UTXO returned by
    /// [`DbRead::get_signer_utxo`].
    utxo_height: Option<u64>,
    /// When we create sweep package, this field controls how many
    /// transactions are created in the package.
    num_transactions: std::ops::Range<u8>,
}

impl<const N: usize> ReorgDescription<N> {
    fn num_blocks(&self) -> u64 {
        self.sweep_heights.into_iter().max().unwrap_or_default()
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
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case(ReorgDescription {
    sweep_heights: [0, 3, 4, 5],
    reorg_height: 4,
    donation_height: 0,
    utxo_height: Some(4),
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "vanilla reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [0, 3, 4, 5],
    reorg_height: 2,
    donation_height: 0,
    utxo_height: Some(0),
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "near-complete-reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [0, 6, 10, 12],
    reorg_height: 7,
    donation_height: 0,
    utxo_height: Some(6),
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "partial-reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [0, 6, 20, 21],
    reorg_height: 19,
    donation_height: 0,
    utxo_height: Some(6),
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "long-gap-reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [3, 4, 5],
    reorg_height: 2,
    donation_height: 3,
    utxo_height: None,
    num_transactions: std::ops::Range { start: 1, end: 2 },
}; "complete-reorg")]
#[test_case(ReorgDescription {
    sweep_heights: [1, 7, 17, 18, 19, 20, 21],
    reorg_height: 16,
    donation_height: 0,
    utxo_height: Some(7),
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
        if height == desc.donation_height {
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
        if desc.sweep_heights.contains(&height) {
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
        if height == desc.reorg_height {
            reorg_block_ref = chain_tip_ref;
        }

        // And now for the blockchain data.
        let (new_data, new_chain_tip_ref) =
            test_data.new_block(&mut rng, &signer_set, &test_params, Some(&chain_tip_ref));
        chain_tip_ref = new_chain_tip_ref;
        new_data.write_to(&db).await;
    }

    // And now for creating the reorg blocks.
    for _ in 0..=(desc.num_blocks() - desc.reorg_height) + 1 {
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
