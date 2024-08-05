use emily_handler::api::models::{
    common::Status,
    withdrawal::{
        requests::CreateWithdrawalRequestBody,
        responses::{GetWithdrawalResponse, GetWithdrawalsResponse},
        Withdrawal, WithdrawalInfo,
    },
};
use serde_json::json;
use std::sync::LazyLock;
use tokio;

use crate::util::{self, constants::EMILY_WITHDRAWAL_ENDPOINT, TestClient};

// TODO(392): Use test setup functions to wipe the database before performing these
// tests instead of relying on circumstantial test execution order.

/// Contains the data about a withdrawal that will be used for testing. There are
/// more fields in a withdrawal than listed here; this represents the data that we
/// expect to be common accross the tests.
struct TestWithdrawalData {
    pub request_id: u64,
    pub recipient: String,
    pub stacks_block_hash: String,
}

/// Test data for withdrawals.
static TEST_WITHDRAWAL_DATA: LazyLock<Vec<TestWithdrawalData>> = LazyLock::new(|| {
    vec![
        TestWithdrawalData {
            request_id: 1,
            recipient: "test_recipient_1".to_string(),
            stacks_block_hash: "test_stacks_block_hash_1".to_string(),
        },
        TestWithdrawalData {
            request_id: 5,
            recipient: "test_recipient_5".to_string(),
            stacks_block_hash: "test_stacks_block_hash_5".to_string(),
        },
        TestWithdrawalData {
            request_id: 213842,
            recipient: "test_recipient_213842".to_string(),
            stacks_block_hash: "test_stacks_block_hash_213842".to_string(),
        },
    ]
});

/// Setup function that wipes the database and populates it with the necessary
/// withdrawal data.
async fn setup_deposit_integration_test() -> TestClient {
    let client = TestClient::new();
    client.setup_test().await;
    for test_withdrawal_data in TEST_WITHDRAWAL_DATA.iter() {
        // Arrange.
        let TestWithdrawalData {
            request_id,
            recipient,
            stacks_block_hash,
        } = test_withdrawal_data;
        let request: CreateWithdrawalRequestBody = serde_json::from_value(json!({
          "requestId": request_id,
          "stacksBlockHash": stacks_block_hash,
          "recipient": recipient,
          "amount": 0,
          "parameters": {
             "maxFee": 0
          }
        }))
        .expect("Failed to deserialize create withdrawal request body in test setup");
        let response = client.create_withdrawal(&request).await;
        util::assert_eq_pretty(
            response,
            just_created_withdrawal(request_id, recipient, stacks_block_hash),
        );
    }
    client
}

/// Creates the withdrawal that one would expect to receive from the API
/// after it was JUST created. Note that this will need to be changed when
/// the API becomes more complicated and correct; many of the default values
/// will need to be non-default once there's a full implementation that retrieves
/// values from the script.
fn just_created_withdrawal(
    request_id: &u64,
    recipient: &String,
    stacks_block_hash: &String,
) -> Withdrawal {
    Withdrawal {
        request_id: *request_id,
        recipient: recipient.clone(),
        last_update_block_hash: stacks_block_hash.clone(),
        stacks_block_hash: stacks_block_hash.clone(),
        status_message: "Just received withdrawal".to_string(),
        status: Status::Pending,
        ..Default::default()
    }
}

/// Make a bunch of withdrawals that will be used by the rest of the following tests.
/// This test suite, and the rest of the tests, assume that the database is empty
/// when this test suite starts up.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn create_withdrawals() {
    // The setup function runs what was origninally the create tests by creating the
    // resources and then assessing what was created.
    let client = setup_deposit_integration_test().await;
    client.teardown().await;
}

/// Get every withdrawal one at a time.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_withdrawal() {
    let client = setup_deposit_integration_test().await;
    for test_withdrawal_data in TEST_WITHDRAWAL_DATA.iter() {
        // Arrange.
        let TestWithdrawalData {
            request_id,
            recipient,
            stacks_block_hash,
        } = test_withdrawal_data;

        // Act.
        let response = client
            .inner
            .get(format!("{EMILY_WITHDRAWAL_ENDPOINT}/{request_id}"))
            .send()
            .await
            .expect("Request should succeed");

        // Assert.
        let actual: GetWithdrawalResponse = response
            .json()
            .await
            .expect("Failed to parse JSON response");

        let expected = just_created_withdrawal(request_id, recipient, stacks_block_hash);

        util::assert_eq_pretty(actual, expected);
    }
    client.teardown().await;
}

/// Get withdrawals from the paginated endpoit `ENDPOINT/withdrawal` searching
/// for all `pending` withdrawals. This test uses a small page size so that the
/// "nextToken" and repeated queries are required to get all the withdrawals in
/// the table.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_withdrawals() {
    // Arrange.
    let client = setup_deposit_integration_test().await;
    let page_size: i32 = 1;

    let mut aggregate_withdrawals: Vec<WithdrawalInfo> = vec![];

    // Act 1.
    let mut response: GetWithdrawalsResponse = client
        .inner
        .get(EMILY_WITHDRAWAL_ENDPOINT)
        .query(&[
            ("pageSize", page_size.to_string()),
            ("status", "pending".to_string()),
        ])
        .send()
        .await
        .expect("Request should succeed")
        .json()
        .await
        .expect("Failed to parse JSON response");

    // Ensure that the number of items returned is at most the same as the page size.
    assert!(response.withdrawals.len() <= page_size as usize);
    aggregate_withdrawals.append(response.withdrawals.as_mut());

    // Act 2.
    while let Some(next_token) = response.next_token.clone() {
        response = client
            .inner
            .get(EMILY_WITHDRAWAL_ENDPOINT)
            .query(&[
                ("pageSize", page_size.to_string()),
                ("status", "pending".to_string()),
                ("nextToken", next_token),
            ])
            .send()
            .await
            .expect("Request should succeed")
            .json()
            .await
            .expect("Failed to parse JSON response");
        // Ensure that the number of items returned is the same as the requested page size.
        assert!(response.withdrawals.len() <= page_size as usize);
        aggregate_withdrawals.append(response.withdrawals.as_mut());
    }

    // Assert.
    let mut expected_withdrawal_infos: Vec<WithdrawalInfo> = TEST_WITHDRAWAL_DATA
        .iter()
        .map(|test_withdrawal_data| {
            // Extract testing data.
            let TestWithdrawalData {
                request_id,
                recipient,
                stacks_block_hash,
            } = test_withdrawal_data;
            // Make withdrawal.
            just_created_withdrawal(request_id, recipient, stacks_block_hash)
        })
        .map(|withdrawal| withdrawal.into())
        .collect();
    aggregate_withdrawals.sort();
    expected_withdrawal_infos.sort();
    assert_eq!(aggregate_withdrawals, expected_withdrawal_infos);
    client.teardown().await;
}
