//! Integration tests for the database accessors

use emily_handler::{
    context::EmilyContext,
    database::{accessors, entries::deposit::DepositEntryKey},
};

use crate::util::{self, TestClient};

/// Test environment.
struct TestEnvironment {
    client: TestClient,
    context: EmilyContext,
}

/// Setup accessor test.
async fn setup_accessor_test() -> TestEnvironment {
    // Get client and wipe the API.
    let client = TestClient::new();
    client.setup_test().await;
    // Setup context.
    let context = util::test_context().await;
    // Return test environment.
    TestEnvironment { client, context }
}

/// Get all deposits for each transaction using a page size large enough to get all entries.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_update() {
    // Setup test environment.
    let TestEnvironment { client, context } = setup_accessor_test().await;
    // Make a bunch of chainstates.

    let fork_id = 0;
    for height in 0..10 {
        client
            .create_chainstate(&util::test_chainstate(height, fork_id))
            .await;
    }
    // Make a new deposit.
    let create_deposit_request = util::test_create_deposit_request(5, 0);
    let deposit = client.create_deposit(&create_deposit_request).await;
    // Get the corresponding deposit entry.
    let deposit_entry = accessors::get_deposit_entry(
        &context,
        &DepositEntryKey {
            bitcoin_txid: deposit.bitcoin_txid.clone(),
            bitcoin_tx_output_index: deposit.bitcoin_tx_output_index,
        },
    )
    .await
    .expect("Get deposit entry for newly created deposit should work.");
    // Assert.
    assert_eq!(
        deposit_entry.key.bitcoin_txid,
        create_deposit_request.bitcoin_txid
    );
    assert_eq!(
        deposit_entry.key.bitcoin_tx_output_index,
        create_deposit_request.bitcoin_tx_output_index
    );
}
