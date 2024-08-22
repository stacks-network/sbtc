//! Integration tests for the database accessors

use emily_handler::{
    api::models::{
        common::Status,
        deposit::{
            requests::{DepositUpdate, UpdateDepositsRequestBody},
            DepositInfo,
        },
    },
    context::EmilyContext,
    database::{
        accessors,
        entries::{chainstate::ApiStateEntry, deposit::DepositEntryKey},
    },
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

/// Get all deposits for each transaction using a page size large enough to get all entries.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn test_chaintip_update() {
    // Setup test environment.
    let TestEnvironment { client, context } = setup_accessor_test().await;

    // Make a bunch of chainstates.
    let fork_id = 0;
    for height in 0..10 {
        client
            .create_chainstate(&util::test_chainstate(height, fork_id))
            .await;
    }

    let api_state: ApiStateEntry = accessors::get_api_state(&context)
        .await
        .expect("Should succeed");
    assert_eq!(api_state.version, 10);
}

/// Tests getting all deposits that were modified after a given height.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_deposits_modified_after_height() {
    // Arrange.
    let TestEnvironment { client, context } = setup_accessor_test().await;
    let offset = 11232142;
    let total_created = 10;
    let status = Status::Failed;

    // Create a bunch of deposits.
    for i in 0..total_created {
        // Make a deposit.
        let deposit = client
            .create_deposit(&util::test_create_deposit_request(i, 1))
            .await;
        // Get the key for the deposit.
        let key = util::entry_key_from_deposit(&deposit);
        // Make the request.
        let single_update = UpdateDepositsRequestBody {
            deposits: vec![DepositUpdate {
                // Original fields.
                bitcoin_txid: key.bitcoin_txid.clone(),
                bitcoin_tx_output_index: key.bitcoin_tx_output_index,
                // New updated height.
                last_update_height: offset + i,
                last_update_block_hash: "dummy_hash".to_string(),
                status: status.clone(),
                status_message: "dummy_message".to_string(),
                fulfillment: None,
            }],
        };
        client.update_deposits(&single_update).await;
    }
    let number_to_get = 4;
    let minimum_height = offset + total_created - number_to_get;

    // Act.
    let deposit_infos: Vec<DepositInfo> =
        accessors::get_all_deposit_entries_modified_after_height_with_status(
            &context,
            &status,
            minimum_height,
            None,
        )
        .await
        .expect("Query succeeds")
        .into_iter()
        .map(|entry| -> DepositInfo { entry.into() })
        .collect();

    // Assert.
    assert_eq!(deposit_infos.len(), number_to_get as usize);
    for deposit_info in deposit_infos {
        // Assert that all deposits have an acceptable height.
        assert!(deposit_info.last_update_height >= minimum_height);
    }
}
