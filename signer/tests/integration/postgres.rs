use std::io::Read;

use bitcoin::hashes::Hash as _;
use bitvec::array::BitArray;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::Value;
use blockstack_lib::codec::StacksMessageCodec;
use blockstack_lib::types::chainstate::StacksAddress;
use futures::StreamExt;

use signer::error::Error;
use signer::network;
use signer::stacks::contracts::AcceptWithdrawalV1;
use signer::stacks::contracts::AsContractCall;
use signer::stacks::contracts::AsTxPayload as _;
use signer::stacks::contracts::CompleteDepositV1;
use signer::stacks::contracts::RejectWithdrawalV1;
use signer::stacks::contracts::RotateKeysV1;
use signer::storage;
use signer::storage::model;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead;
use signer::storage::DbWrite;
use signer::testing;
use signer::testing::wallet::ContractCallWrapper;

use fake::Fake;
use rand::SeedableRng;
use test_case::test_case;

const DATABASE_URL: &str = "postgres://user:password@localhost:5432/signer";

/// It's better to create a new pool for each test since there is some
/// weird bug in sqlx. The issue that can crop up with pool reuse is
/// basically a PoolTimeOut error. This is a known issue:
/// https://github.com/launchbadge/sqlx/issues/2567
fn get_connection_pool() -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_lazy(DATABASE_URL)
        .unwrap()
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn should_be_able_to_query_bitcoin_blocks(pool: sqlx::PgPool) {
    let mut store = storage::postgres::PgStore::from(pool);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
    };

    let persisted_model = testing::storage::model::TestData::generate(&mut rng, &test_model_params);
    let not_persisted_model =
        testing::storage::model::TestData::generate(&mut rng, &test_model_params);

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
}

struct InitiateWithdrawalRequest;

impl AsContractCall for InitiateWithdrawalRequest {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const FUNCTION_NAME: &'static str = "initiate-withdrawal-request";
    /// The stacks address that deployed the contract.
    fn deployer_address(&self) -> StacksAddress {
        StacksAddress::burn_address(false)
    }
    /// The arguments to the clarity function.
    fn as_contract_args(&self) -> Vec<Value> {
        Vec::new()
    }
    async fn validate<S>(&self, _: &S) -> Result<bool, Error>
    where
        S: DbRead + Send + Sync,
        Error: From<<S as DbRead>::Error>,
    {
        Ok(true)
    }
}

/// Test that the write_stacks_blocks function does what it is supposed to
/// do, which is store all stacks blocks and store the transactions that we
/// care about, which, naturally, are sBTC related transactions.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test_case(ContractCallWrapper(InitiateWithdrawalRequest); "initiate-withdrawal")]
#[test_case(ContractCallWrapper(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap(),
    deployer: testing::wallet::WALLET.0.address(),
}); "complete-deposit standard recipient")]
#[test_case(ContractCallWrapper(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y.my-contract-name").unwrap(),
    deployer: testing::wallet::WALLET.0.address(),
}); "complete-deposit contract recipient")]
#[test_case(ContractCallWrapper(AcceptWithdrawalV1 {
    request_id: 0,
    outpoint: bitcoin::OutPoint::null(),
    tx_fee: 3500,
    signer_bitmap: BitArray::ZERO,
    deployer: testing::wallet::WALLET.0.address(),
}); "accept-withdrawal")]
#[test_case(ContractCallWrapper(RejectWithdrawalV1 {
    request_id: 0,
    signer_bitmap: BitArray::ZERO,
    deployer: testing::wallet::WALLET.0.address(),
}); "reject-withdrawal")]
#[test_case(ContractCallWrapper(RotateKeysV1::new(
    &testing::wallet::WALLET.0,
    testing::wallet::WALLET.0.address(),
    testing::wallet::WALLET.2,
)); "rotate-keys")]
#[tokio::test]
async fn writing_stacks_blocks_works<T: AsContractCall>(contract: ContractCallWrapper<T>) {
    let default_pool = get_connection_pool();
    let pool = crate::transaction_signer::new_database(&default_pool).await;
    let store = PgStore::from(pool.clone());

    let path = "tests/fixtures/tenure-blocks-0-1ed91e0720129bda5072540ee7283dd5345d0f6de0cf5b982c6de3943b6e3291.bin";
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
    let txs = storage::postgres::extract_relevant_transactions(&blocks);
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
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(stored_block_count, blocks.len() as i64);

    // Next we check that the one transaction that we care about, the one
    // we just created above, was saved.
    let sql = "SELECT COUNT(*) FROM sbtc_signer.stacks_transactions";
    let stored_transaction_count = sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(&pool)
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
        .fetch_one(&pool)
        .await
        .unwrap();

    // No more blocks were written
    assert_eq!(stored_block_count_again, blocks.len() as i64);
    assert_eq!(stored_block_count_again, stored_block_count);

    let sql = "SELECT COUNT(*) FROM sbtc_signer.stacks_transactions";
    let stored_transaction_count_again = sqlx::query_scalar::<_, i64>(sql)
        .fetch_one(&pool)
        .await
        .unwrap();

    // No more transactions were written
    assert_eq!(stored_transaction_count_again, 1);
}

/// Here we test that the DbRead::stacks_block_exists function works, while
/// implicitly testing the DbWrite::write_stacks_blocks function for the
/// PgStore type
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn checking_stacks_blocks_exists_works(pool: sqlx::PgPool) {
    let store = storage::postgres::PgStore::from(pool);

    let path = "tests/fixtures/tenure-blocks-0-1ed91e0720129bda5072540ee7283dd5345d0f6de0cf5b982c6de3943b6e3291.bin";
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
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending deposit requests
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn should_return_the_same_pending_deposit_requests_as_in_memory_store(pool: sqlx::PgPool) {
    let mut pg_store = storage::postgres::PgStore::from(pool);
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let context_window = 9;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
    };
    let test_data = testing::storage::model::TestData::generate(&mut rng, &test_model_params);

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

    let mut pending_depoist_requests = in_memory_store
        .get_pending_deposit_requests(&chain_tip, context_window)
        .await
        .expect("failed to get pending deposit requests");

    pending_depoist_requests.sort();

    let mut pg_pending_deposit_requests = pg_store
        .get_pending_deposit_requests(&chain_tip, context_window)
        .await
        .expect("failed to get pending deposit requests");

    pg_pending_deposit_requests.sort();

    assert_eq!(pending_depoist_requests, pg_pending_deposit_requests);
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending withdraw requests
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn should_return_the_same_pending_withdraw_requests_as_in_memory_store(pool: sqlx::PgPool) {
    let mut pg_store = storage::postgres::PgStore::from(pool);
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let context_window = 3;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 1,
        num_signers_per_request: 0,
    };
    let test_data = testing::storage::model::TestData::generate(&mut rng, &test_model_params);

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
        .get_pending_withdraw_requests(&chain_tip, context_window)
        .await
        .expect("failed to get pending deposit requests");

    pending_withdraw_requests.sort();

    let mut pg_pending_withdraw_requests = pg_store
        .get_pending_withdraw_requests(&chain_tip, context_window)
        .await
        .expect("failed to get pending deposit requests");

    pg_pending_withdraw_requests.sort();

    assert_eq!(pending_withdraw_requests, pg_pending_withdraw_requests);
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending accepted deposit requests
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn should_return_the_same_pending_accepted_deposit_requests_as_in_memory_store(
    pool: sqlx::PgPool,
) {
    let mut pg_store = storage::postgres::PgStore::from(pool);
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let context_window = 9;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 7,
    };
    let threshold = 4;
    let test_data = testing::storage::model::TestData::generate(&mut rng, &test_model_params);

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
}

/// This ensures that the postgres store and the in memory stores returns equivalent results
/// when fetching pending accepted withdraw requests
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn should_return_the_same_pending_accepted_withdraw_requests_as_in_memory_store(
    pool: sqlx::PgPool,
) {
    let mut pg_store = storage::postgres::PgStore::from(pool);
    let mut in_memory_store = storage::in_memory::Store::new_shared();

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

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
        num_signers_per_request: 15,
    };
    let threshold = 4;
    let test_data = testing::storage::model::TestData::generate(&mut rng, &test_model_params);

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
        .get_pending_accepted_withdraw_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending_accepted deposit requests");

    pending_accepted_withdraw_requests.sort();

    assert!(!pending_accepted_withdraw_requests.is_empty());

    let mut pg_pending_accepted_withdraw_requests = pg_store
        .get_pending_accepted_withdraw_requests(&chain_tip, context_window, threshold)
        .await
        .expect("failed to get pending_accepted deposit requests");

    pg_pending_accepted_withdraw_requests.sort();

    assert_eq!(
        pending_accepted_withdraw_requests,
        pg_pending_accepted_withdraw_requests
    );
}

/// This ensures that the postgres store and the in memory stores returns
/// equivalent results when fetching pending the last key rotation.
/// TODO(415): Make this robust to multiple key rotations.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn should_return_the_same_last_key_rotation_as_in_memory_store(pool: sqlx::PgPool) {
    let mut pg_store = storage::postgres::PgStore::from(pool);
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
    let test_data = testing::storage::model::TestData::generate(&mut rng, &test_model_params);

    test_data.write_to(&mut in_memory_store).await;
    test_data.write_to(&mut pg_store).await;

    let chain_tip = in_memory_store
        .get_bitcoin_canonical_chain_tip()
        .await
        .expect("failed to get canonical chain tip")
        .expect("no chain tip");

    let signer_info = testing::wsts::generate_signer_info(&mut rng, num_signers);

    let dummy_wsts_network = network::in_memory::Network::new();
    let mut testing_signer_set =
        testing::wsts::SignerSet::new(&signer_info, threshold, || dummy_wsts_network.connect());
    let dkg_txid = testing::dummy::txid(&fake::Faker, &mut rng);
    let bitcoin_chain_tip = bitcoin::BlockHash::from_byte_array(
        chain_tip.clone().try_into().expect("conversion failed"),
    );
    let (aggregate_key, _) = testing_signer_set
        .run_dkg(bitcoin_chain_tip, dkg_txid, &mut rng)
        .await;

    testing_signer_set
        .write_as_rotate_keys_tx(&mut in_memory_store, &chain_tip, aggregate_key, &mut rng)
        .await;

    testing_signer_set
        .write_as_rotate_keys_tx(&mut pg_store, &chain_tip, aggregate_key, &mut rng)
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
}

/// Here we test that we can store deposit request model objects. We also
/// test that if we attempt to write another deposit request then we do not
/// write it and that we do not error.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn writing_deposit_requests_postgres(pool: sqlx::PgPool) {
    let num_rows = 15;
    let store = storage::postgres::PgStore::from(pool.clone());
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
            .fetch_one(&pool)
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
            .fetch_one(&pool)
            .await
            .unwrap();

    // No new records written right?
    assert_eq!(num_rows, count as usize);
}

/// This is very similar to the above test; we test that we can store
/// transaction model objects. We also test that if we attempt to write
/// duplicate transactions then we do not write it and that we do not
/// error.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn writing_transactions_postgres(pool: sqlx::PgPool) {
    let num_rows = 12;
    let store = storage::postgres::PgStore::from(pool.clone());
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let mut txs: Vec<model::Transaction> =
        std::iter::repeat_with(|| fake::Faker.fake_with_rng(&mut rng))
            .take(num_rows)
            .collect();

    let parent_hash = bitcoin::BlockHash::from_byte_array([0; 32]);
    let block_hash = bitcoin::BlockHash::from_byte_array([1; 32]);

    txs.iter_mut().for_each(|tx| {
        tx.block_hash = block_hash.to_byte_array().to_vec();
    });

    let db_block = model::BitcoinBlock {
        block_hash: block_hash.to_byte_array().to_vec(),
        block_height: 15,
        parent_hash: parent_hash.to_byte_array().to_vec(),
        confirms: Vec::new(),
    };

    // We start by writing the bitcoin block because of the foreign key
    // constrait
    store.write_bitcoin_block(&db_block).await.unwrap();

    // Let's see if we can write these transactions to the database.
    store.write_bitcoin_transactions(txs.clone()).await.unwrap();
    let count =
        sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.bitcoin_transactions"#)
            .fetch_one(&pool)
            .await
            .unwrap();
    // Were they all written?
    assert_eq!(num_rows, count as usize);

    // what about the transactions table, the same number of rows should
    // have been written there as well.
    let count = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.transactions"#)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(num_rows, count as usize);
    // Okay now lets test that we do not write duplicates.
    store.write_bitcoin_transactions(txs).await.unwrap();
    let count =
        sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.bitcoin_transactions"#)
            .fetch_one(&pool)
            .await
            .unwrap();

    // No new records written right?
    assert_eq!(num_rows, count as usize);

    // what about duplicates in the transactions table.
    let count = sqlx::query_scalar::<_, i64>(r#"SELECT COUNT(*) FROM sbtc_signer.transactions"#)
        .fetch_one(&pool)
        .await
        .unwrap();

    // let's see, who knows what will happen!
    assert_eq!(num_rows, count as usize);
}
