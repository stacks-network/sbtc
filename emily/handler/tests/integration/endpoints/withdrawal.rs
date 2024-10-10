use emily_handler::{
    api::models::{
        common::{Fulfillment, Status},
        withdrawal::{
            requests::{
                CreateWithdrawalRequestBody, UpdateWithdrawalsRequestBody, WithdrawalUpdate,
            },
            responses::GetWithdrawalsResponse,
            Withdrawal, WithdrawalInfo,
        },
    },
    context::EmilyContext,
    database::{
        accessors,
        entries::{withdrawal::WithdrawalEvent, StatusEntry},
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
async fn setup_withdrawal_integration_test() -> TestClient {
    let client = TestClient::new();
    client.setup_test().await;
    let stacks_block_height: u64 = 0;
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
          "stacksBlockHeight": stacks_block_height,
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
    let client = setup_withdrawal_integration_test().await;
    client.teardown().await;
}

/// Get every withdrawal one at a time.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_withdrawal() {
    let client = setup_withdrawal_integration_test().await;
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
        let actual: Withdrawal = response
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
    let client = setup_withdrawal_integration_test().await;
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

/// Update deposits test.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn update_withdrawal() {
    // Arrange.
    let client = setup_withdrawal_integration_test().await;

    // Get a random deposit info and its identifying fields.
    let withdrawal_ids: Vec<u64> = client
        .get_all_withdrawals()
        .await
        .into_iter()
        .map(|withdrawal_info| withdrawal_info.request_id)
        .collect();

    let request_id_1 = withdrawal_ids.get(0).unwrap().clone();
    let request_id_2 = withdrawal_ids.get(1).unwrap().clone();

    // Get the full deposit.
    let _original_deposit = client.get_withdrawal(&request_id_1).await;

    // Make some parameters.
    let updated_hash = "UPDATED_HASH".to_string();
    let updated_height: u64 = 12345;
    let updated_status: Status = Status::Confirmed;
    let updated_message: String = "UPDATED_MESSAGE".to_string();
    let fulfillment: Fulfillment = Fulfillment {
        bitcoin_txid: "FULFILLMENT_BITCOIN_TXID".to_string(),
        bitcoin_tx_index: 10,
        stacks_txid: "FULFILLMENT_STACKS_TXID".to_string(),
        bitcoin_block_hash: "FULFILLMENT_HASH".to_string(),
        bitcoin_block_height: 10,
        btc_fee: 12,
    };

    // Create and make the request.
    let update_requests = UpdateWithdrawalsRequestBody {
        withdrawals: vec![
            WithdrawalUpdate {
                // Original fields.
                request_id: request_id_1,
                // New updated height.
                last_update_height: updated_height,
                last_update_block_hash: updated_hash.clone(),
                status: updated_status.clone(),
                status_message: updated_message.clone(),
                fulfillment: Some(fulfillment.clone()),
            },
            WithdrawalUpdate {
                // Original fields.
                request_id: request_id_2,
                // New updated height.
                last_update_height: updated_height,
                last_update_block_hash: updated_hash.clone(),
                status: updated_status.clone(),
                status_message: updated_message.clone(),
                fulfillment: Some(fulfillment.clone()),
            },
        ],
    };
    let response = client.update_withdrawals(&update_requests).await;
    assert_eq!(
        response.withdrawals.len(),
        update_requests.withdrawals.len()
    );

    let updated_withdrawal = response.withdrawals.get(0).unwrap().clone();
    assert_eq!(updated_withdrawal.last_update_height, updated_height);
    assert_eq!(updated_withdrawal.last_update_block_hash, updated_hash);
    assert_eq!(updated_withdrawal.status, updated_status);
    assert_eq!(updated_withdrawal.status_message, updated_message);
    assert_eq!(updated_withdrawal.fulfillment, Some(fulfillment.clone()));

    let updated_withdrawal = response.withdrawals.get(1).unwrap().clone();
    assert_eq!(updated_withdrawal.last_update_height, updated_height);
    assert_eq!(updated_withdrawal.last_update_block_hash, updated_hash);
    assert_eq!(updated_withdrawal.status, updated_status);
    assert_eq!(updated_withdrawal.status_message, updated_message);
    assert_eq!(updated_withdrawal.fulfillment, Some(fulfillment.clone()));

    // Update the parameters.
    let updated_status: Status = Status::Reprocessing;
    // Make the request.
    let update_requests = UpdateWithdrawalsRequestBody {
        withdrawals: vec![WithdrawalUpdate {
            // Original fields.
            request_id: request_id_1,
            // New updated height.
            last_update_height: updated_height + 1,
            last_update_block_hash: updated_hash.clone(),
            status: updated_status.clone(),
            status_message: updated_message.clone(),
            fulfillment: None,
        }],
    };
    let response = client.update_withdrawals(&update_requests).await;
    assert_eq!(
        response.withdrawals.len(),
        update_requests.withdrawals.len()
    );

    let updated_withdrawal = response.withdrawals.first().unwrap().clone();
    assert_eq!(updated_withdrawal.last_update_height, updated_height + 1);
    assert_eq!(updated_withdrawal.last_update_block_hash, updated_hash);
    assert_eq!(updated_withdrawal.status, updated_status);
    assert_eq!(updated_withdrawal.status_message, updated_message);
    assert_eq!(updated_withdrawal.fulfillment, None);

    // Now try getting the raw internal entry and ensure that the history is good.
    let context: EmilyContext = EmilyContext::local_instance("http://localhost:8000")
        .await
        .expect("Making emily context must succeed in integration test.");
    let withdrawal_entry = accessors::get_withdrawal_entry(&context, &request_id_1)
        .await
        .expect("Getting withdrawal entry in test must succeed.");

    // The history of the withdrawal should be tracked correctly.
    let history: Vec<WithdrawalEvent> = vec![
        WithdrawalEvent {
            status: StatusEntry::Pending,
            message: "Just received withdrawal".to_string(),
            stacks_block_height: 0,
            stacks_block_hash: "test_stacks_block_hash_1".to_string(),
        },
        WithdrawalEvent {
            status: StatusEntry::Confirmed(fulfillment.clone()),
            message: updated_message.clone(),
            stacks_block_height: updated_height,
            stacks_block_hash: updated_hash.clone(),
        },
        WithdrawalEvent {
            status: StatusEntry::Reprocessing,
            message: updated_message.clone(),
            stacks_block_height: updated_height + 1,
            stacks_block_hash: updated_hash.clone(),
        },
    ];
    assert_eq!(withdrawal_entry.history, history);

    // Assert.
    client.teardown().await;
}
