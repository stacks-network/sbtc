use signer::storage::{DbRead, DbWrite};

use signer::storage::postgres::*;
use signer::testing;

use rand::SeedableRng;

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[sqlx::test]
async fn should_be_able_to_query_bitcoin_blocks(pool: sqlx::PgPool) {
    let store = PgStore::from(pool);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        chain_type: testing::storage::model::ChainType::Chaotic,
    };

    let persisted_model = testing::storage::model::TestData::generate(&mut rng, &test_model_params);
    let not_persisted_model =
        testing::storage::model::TestData::generate(&mut rng, &test_model_params);

    // Write all blocks for the persisted model to the database
    for block in &persisted_model.bitcoin_blocks {
        store
            .write_bitcoin_block(block)
            .await
            .expect("failed to write bitcoin block");
    }

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
