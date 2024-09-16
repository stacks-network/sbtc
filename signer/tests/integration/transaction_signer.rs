use std::sync::atomic::Ordering;

use signer::storage::postgres::PgStore;
use signer::testing;

use futures::StreamExt;
use testing::transaction_signer::TestEnvironment;

use crate::DATABASE_NUM;

async fn test_environment(
    mut signer_connections: Vec<PgStore>,
    signing_threshold: u32,
) -> TestEnvironment<impl FnMut() -> PgStore> {
    let context_window = 3;

    let test_model_parameters = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
    };

    testing::transaction_signer::TestEnvironment {
        num_signers: signer_connections.len(),
        storage_constructor: move || signer_connections.pop().unwrap(),
        context_window,
        signing_threshold,
        test_model_parameters,
    }
}

async fn create_signer_databases(num_signers: usize) -> Vec<PgStore> {
    let get_next_num = || DATABASE_NUM.fetch_add(1, Ordering::SeqCst);

    futures::stream::repeat_with(get_next_num)
        .then(|i| signer::testing::storage::new_test_database(i, true))
        .take(num_signers)
        .collect()
        .await
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_for_pending_deposit_requests() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_store_decisions_for_pending_deposit_requests()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_for_pending_withdraw_requests() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_store_decisions_for_pending_withdraw_requests()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_received_from_other_signers() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_store_decisions_received_from_other_signers()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_respond_to_bitcoin_transaction_sign_request() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_respond_to_bitcoin_transaction_sign_requests()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_be_able_to_participate_in_signing_round() {
    let num_signers = 3;
    let signing_threshold = 2;

    let signer_connections = create_signer_databases(num_signers).await;
    // We need to clone the connections so that we can drop the associated
    // databases later.
    let cloned_connections = signer_connections.clone();

    test_environment(signer_connections, signing_threshold)
        .await
        .assert_should_be_able_to_participate_in_signing_round()
        .await;

    // Now drop all of the databases that we just created.
    let _: Vec<_> = futures::stream::iter(cloned_connections)
        .then(signer::testing::storage::drop_db)
        .collect()
        .await;
}
