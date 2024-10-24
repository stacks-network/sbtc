use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bitcoin::hashes::Hash as _;
use bitvec::array::BitArray;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::Value as ClarityValue;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksAddress;
use futures::StreamExt;
use rand::seq::SliceRandom;

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
use signer::stacks::events::CompletedDepositEvent;
use signer::stacks::events::WithdrawalAcceptEvent;
use signer::stacks::events::WithdrawalCreateEvent;
use signer::stacks::events::WithdrawalRejectEvent;
use signer::storage;
use signer::storage::model;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::BitcoinTxId;
use signer::storage::model::EncryptedDkgShares;
use signer::storage::model::QualifiedRequestId;
use signer::storage::model::ScriptPubKey;
use signer::storage::model::StacksBlock;
use signer::storage::model::StacksBlockHash;
use signer::storage::model::StacksTxId;
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
use test_case::test_case;

use crate::setup::TestSweepSetup;
use crate::DATABASE_NUM;

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_be_able_to_query_bitcoin_blocks() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let mut store = testing::storage::new_test_database(db_num, true).await;
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
)); "rotate-keys")]
#[tokio::test]
async fn writing_stacks_blocks_works<T: AsContractCall>(contract: ContractCallWrapper<T>) {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

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
        .map(model::StacksBlock::try_from)
        .collect::<Result<_, _>>()
        .unwrap();
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
        .map(model::StacksBlock::try_from)
        .collect::<Result<_, _>>()
        .unwrap();
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

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
        .map(model::StacksBlock::try_from)
        .collect::<Result<_, _>>()
        .unwrap();
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let mut pg_store = testing::storage::new_test_database(db_num, true).await;
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

    let mut pending_deposit_requests = in_memory_store
        .get_pending_deposit_requests(&chain_tip, context_window)
        .await
        .expect("failed to get pending deposit requests");

    pending_deposit_requests.sort();

    let mut pg_pending_deposit_requests = pg_store
        .get_pending_deposit_requests(&chain_tip, context_window)
        .await
        .expect("failed to get pending deposit requests");

    pg_pending_deposit_requests.sort();

    assert_eq!(pending_deposit_requests, pg_pending_deposit_requests);
    signer::testing::storage::drop_db(pg_store).await;
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending withdraw requests
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_return_the_same_pending_withdraw_requests_as_in_memory_store() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let mut pg_store = testing::storage::new_test_database(db_num, true).await;
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 7;
    let context_window = 3;
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

    let mut pending_withdraw_requests = in_memory_store
        .get_pending_withdrawal_requests(&chain_tip, context_window)
        .await
        .expect("failed to get pending deposit requests");

    pending_withdraw_requests.sort();

    let mut pg_pending_withdraw_requests = pg_store
        .get_pending_withdrawal_requests(&chain_tip, context_window)
        .await
        .expect("failed to get pending deposit requests");

    pg_pending_withdraw_requests.sort();

    assert_eq!(pending_withdraw_requests, pg_pending_withdraw_requests);
    signer::testing::storage::drop_db(pg_store).await;
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending accepted deposit requests
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_return_the_same_pending_accepted_deposit_requests_as_in_memory_store() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let mut pg_store = testing::storage::new_test_database(db_num, true).await;
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let mut pg_store = testing::storage::new_test_database(db_num, true).await;
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let num_signers = 15;
    let context_window = 3;
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

/// This ensures that the postgres store and the in memory stores returns
/// equivalent results when fetching pending the last key rotation.
/// TODO(415): Make this robust to multiple key rotations.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_return_the_same_last_key_rotation_as_in_memory_store() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let mut pg_store = testing::storage::new_test_database(db_num, true).await;
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;
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
        confirms: Vec::new(),
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

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

    assert_eq!(txid, event.txid.0);
    assert_eq!(block_id, event.block_id.0);
    assert_eq!(amount as u64, event.amount);
    assert_eq!(bitcoin_txid, event.outpoint.txid.to_byte_array());
    assert_eq!(vout as u32, event.outpoint.vout);

    signer::testing::storage::drop_db(store).await;
}

/// Here we test that we can store withdrawal-create events.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn writing_withdrawal_create_requests_postgres() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let event: WithdrawalCreateEvent = fake::Faker.fake_with_rng(&mut rng);

    // Let's see if we can write these rows to the database.
    store.write_withdrawal_create_event(&event).await.unwrap();
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

    assert_eq!(txid, event.txid.0);
    assert_eq!(block_id, event.block_id.0);
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

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

    assert_eq!(txid, event.txid.0);
    assert_eq!(block_id, event.block_id.0);
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

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

    assert_eq!(txid, event.txid.0);
    assert_eq!(block_id, event.block_id.0);
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

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
            is_accepted: true,
            can_sign: true,
        },
        model::DepositSigner {
            txid,
            output_index,
            signer_pub_key: shares.signer_set_public_keys[1],
            is_accepted: false,
            can_sign: true,
        },
        model::DepositSigner {
            txid,
            output_index,
            signer_pub_key: shares.signer_set_public_keys[2],
            is_accepted: true,
            can_sign: true,
        },
        model::DepositSigner {
            txid,
            output_index,
            signer_pub_key: shares.signer_set_public_keys[3],
            is_accepted: true,
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
        assert_eq!(actual_vote, Some(decision.is_accepted));
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let pg_store = testing::storage::new_test_database(db_num, true).await;
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let pg_store = testing::storage::new_test_database(db_num, true).await;
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;

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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;

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

/// This tests that deposit requests where there is an associated sweep
/// transaction will show up in the query results from
/// [`DbRead::get_swept_deposit_requests`].
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_swept_deposit_requests_returns_swept_deposit_requests() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
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

    // We take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Lastly, the request needs to be added to the database. This stores
    // `setup.deposit_request` into the database.
    setup.store_deposit_request(&db).await;

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
    assert_eq!(req.sweep_tx, setup.sweep_tx_info.tx.into());

    signer::testing::storage::drop_db(db).await;
}

/// This function tests that deposit requests that do not have a confirmed
/// response bitcoin transaction are not returned from
/// [`DbRead::get_swept_deposit_requests`].
///
/// We need to update the query before we can activate this test. Right now
/// we do not associate deposit transactions with their sweep transaction,
/// so the query is very dumb. We should fix this once
/// https://github.com/stacks-network/sbtc/issues/585 gets completed.
#[ignore = "Underlying query has not been completed"]
#[tokio::test]
async fn get_swept_deposit_requests_does_not_return_unswept_deposit_requests() {
    let db_num = testing::storage::DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
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

/// This function tests that [`DbRead::get_swept_deposit_requests`]
/// function does not return requests where we have already confirmed a
/// `complete-deposit` contract call transaction on the canonical Stacks
/// blockchain.
///
/// Right now the query in [`DbRead::get_swept_deposit_requests`] does not
/// satisfy that criteria, because it does not check that the
/// `complete-deposit` contract call is on the Stacks blockchain that is
/// associated with the canonical bitcoin blockchain.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_swept_deposit_requests_does_not_return_deposit_requests_with_responses() {
    let db_num = testing::storage::DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
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

    // We take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // The request needs to be added to the database. This stores
    // `setup.deposit_request` into the database.
    setup.store_deposit_request(&db).await;

    // Here we store an event that signals that the deposit request has been confirmed.
    let event = CompletedDepositEvent {
        txid: fake::Faker.fake_with_rng::<StacksTxId, _>(&mut rng).into(),
        block_id: fake::Faker
            .fake_with_rng::<StacksBlockHash, _>(&mut rng)
            .into(),
        amount: setup.deposit_request.amount,
        outpoint: setup.deposit_request.outpoint,
    };

    db.write_completed_deposit_event(&event).await.unwrap();

    let chain_tip = setup.sweep_block_hash.into();
    let context_window = 20;

    let requests = db
        .get_swept_deposit_requests(&chain_tip, context_window)
        .await
        .unwrap();

    // The only deposit request has a confirmed complete-deposit
    // transaction on the canonical stacks blockchain.
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
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
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
}

/// This function tests that [`DbRead::get_swept_deposit_requests`]
/// function return requests where we have already confirmed a
/// `complete-deposit` contract call transaction on the Stacks blockchain
/// but that transaction has been reorged while the sweep transaction has not.
#[ignore = "Query does not check for transactions on canonical Stacks blockchain"]
#[tokio::test]
async fn get_swept_deposit_requests_response_tx_reorged() {}

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
#[tokio::test]
async fn should_get_signer_utxo_simple() {
    let db_num = testing::storage::DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_simple()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_get_signer_utxo_fork() {
    let db_num = testing::storage::DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_fork()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_get_signer_utxo_unspent() {
    let db_num = testing::storage::DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_unspent()
        .await;

    signer::testing::storage::drop_db(store).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_get_signer_utxo_donations() {
    let db_num = testing::storage::DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let store = testing::storage::new_test_database(db_num, true).await;

    transaction_coordinator_test_environment(store.clone())
        .await
        .assert_get_signer_utxo_donations()
        .await;

    signer::testing::storage::drop_db(store).await;
}
