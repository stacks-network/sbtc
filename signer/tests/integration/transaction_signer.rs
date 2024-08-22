use std::sync::atomic::Ordering;

use signer::storage::postgres::PgStore;
use signer::testing;

use futures::StreamExt;
use testing::transaction_signer::TestEnvironment;

use crate::DATABASE_NUM;

async fn test_environment() -> TestEnvironment<impl FnMut() -> PgStore> {
    let num_signers = 3;
    let signing_threshold = 2;
    let context_window = 3;

    let get_next_num = || DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let mut connections: Vec<PgStore> = futures::stream::repeat_with(get_next_num)
        .then(signer::testing::storage::new_test_database)
        .collect()
        .await;

    let test_model_parameters = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
        num_signers_per_request: 0,
    };

    testing::transaction_signer::TestEnvironment {
        storage_constructor: move || connections.pop().unwrap(),
        context_window,
        num_signers: num_signers as usize,
        signing_threshold,
        test_model_parameters,
    }
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_for_pending_deposit_requests() {
    test_environment()
        .await
        .assert_should_store_decisions_for_pending_deposit_requests()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_for_pending_withdraw_requests() {
    test_environment()
        .await
        .assert_should_store_decisions_for_pending_withdraw_requests()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_store_decisions_received_from_other_signers() {
    test_environment()
        .await
        .assert_should_store_decisions_received_from_other_signers()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_respond_to_bitcoin_transaction_sign_request() {
    test_environment()
        .await
        .assert_should_respond_to_bitcoin_transaction_sign_requests()
        .await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn should_be_able_to_participate_in_signing_round() {
    test_environment()
        .await
        .assert_should_be_able_to_participate_in_signing_round()
        .await;
}
