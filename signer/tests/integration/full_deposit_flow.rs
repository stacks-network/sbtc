use std::sync::atomic::Ordering;

use blockstack_lib::types::chainstate::StacksAddress;
use rand::rngs::OsRng;
use rand::SeedableRng;

use sbtc::testing::regtest;
use signer::testing;
use signer::testing::context::*;

use fake::Fake;

use crate::setup::backfill_bitcoin_blocks;
use crate::setup::TestSweepSetup;
use crate::DATABASE_NUM;


#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_happy_path() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    // This is just setup and should be essentially the same between tests.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    setup.store_dkg_shares(&db).await;

    

    // Create a context object for reaching out to the database and bitcoin
    // core. This will create a bitcoin core client that connects to the
    // bitcoin-core at the [bitcoin].endpoints[0] endpoint from the default
    // toml config file.
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    testing::storage::drop_db(db).await;
}

