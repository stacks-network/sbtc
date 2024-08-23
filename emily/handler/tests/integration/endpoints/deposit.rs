use crate::util::{self, constants::EMILY_DEPOSIT_ENDPOINT, TestClient};
use emily_handler::{
    api::models::{
        chainstate::Chainstate,
        common::{Fulfillment, Status},
        deposit::{
            requests::{CreateDepositRequestBody, DepositUpdate, UpdateDepositsRequestBody},
            responses::{GetDepositsForTransactionResponse, GetDepositsResponse},
            Deposit, DepositInfo, DepositParameters,
        },
    },
    context::EmilyContext,
    database::{
        accessors,
        entries::{
            deposit::{DepositEntryKey, DepositEvent},
            StatusEntry,
        },
    },
};
use serde_json::json;
use std::sync::LazyLock;
use tokio;

const TEST_BLOCK_HEIGHT: u64 = 123;

/// Contains data about a deposit transaction used for testing so that
/// all the tests have a common understanding of the deposits in the
/// system. Deposit transactions can have multiple deposits within them;
/// The `number_of_outputs` field is the number of deposits on this individual
/// transaction.
#[derive(Clone)]
struct TestDepositTransactionData {
    pub bitcoin_txid: String,
    pub number_of_outputs: u32,
}

/// Test data for deposits.
static TEST_DEPOSIT_DATA: LazyLock<Vec<TestDepositTransactionData>> = LazyLock::new(|| {
    vec![
        TestDepositTransactionData {
            bitcoin_txid: "example_txid_1".to_string(),
            number_of_outputs: 4,
        },
        TestDepositTransactionData {
            bitcoin_txid: "example_txid_2".to_string(),
            number_of_outputs: 1,
        },
        TestDepositTransactionData {
            bitcoin_txid: "example_txid_3".to_string(),
            number_of_outputs: 8,
        },
    ]
});

/// Data about a single deposit.
struct TestDepositData {
    pub bitcoin_txid: String,
    pub bitcoin_tx_output_index: u32,
}

/// Setup function that wipes the database and populates it with the necessary
/// deposit data.
async fn setup_deposit_integration_test() -> TestClient {
    let client = TestClient::new();
    client.setup_test().await;
    // Setup first chainstate.
    client
        .create_chainstate(&Chainstate {
            stacks_block_height: TEST_BLOCK_HEIGHT,
            stacks_block_hash: "DUMMY_HASH".to_string(),
        })
        .await;
    // Make test deposits.
    for test_deposit in all_test_deposit_data() {
        let bitcoin_txid: String = test_deposit.bitcoin_txid;
        let bitcoin_tx_output_index: u32 = test_deposit.bitcoin_tx_output_index;
        let request: CreateDepositRequestBody = serde_json::from_value(json!({
            "bitcoinTxid": bitcoin_txid.clone(),
            "bitcoinTxOutputIndex": bitcoin_tx_output_index,
            "reclaim": "example_reclaim_script",
            "deposit": "example_deposit_script",
        }))
        .expect("Failed to deserialize create deposit request body in test setup");
        let response = client.create_deposit(&request).await;
        util::assert_eq_pretty(
            response,
            just_created_deposit(bitcoin_txid, bitcoin_tx_output_index),
        );
    }
    client
}

/// Creates a list of test deposit datas based on `TEST_DEPOSIT_DATA`.
fn all_test_deposit_data() -> impl Iterator<Item = TestDepositData> {
    TEST_DEPOSIT_DATA
        .iter()
        .map(|test_deposit_transaction_data| {
            (0..test_deposit_transaction_data.number_of_outputs).map(
                move |bitcoin_tx_output_index| TestDepositData {
                    bitcoin_txid: test_deposit_transaction_data.bitcoin_txid.clone(),
                    bitcoin_tx_output_index,
                },
            )
        })
        .flatten()
}

/// Makes a deposit as though it were just created with the given
/// bitcoin txid and bitcoin tx output index. Note that this will
/// need to be changed as the creation function becomes more
/// complex and correct.
fn just_created_deposit(bitcoin_txid: String, bitcoin_tx_output_index: u32) -> Deposit {
    Deposit {
        bitcoin_txid,
        bitcoin_tx_output_index,
        last_update_block_hash: "DUMMY_HASH".to_string(),
        last_update_height: TEST_BLOCK_HEIGHT,
        status_message: "Just received deposit".to_string(),
        parameters: DepositParameters {
            reclaim_script: "example_reclaim_script".to_string(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Test that the creation works.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn create_deposits() {
    // The setup function runs what was origninally the create tests by creating the
    // resources and then assessing what was created.
    let client = setup_deposit_integration_test().await;
    client.teardown().await;
}

/// Get every deposit from the previous test one at a time.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_deposit() {
    let client = setup_deposit_integration_test().await;
    for test_deposit in all_test_deposit_data() {
        // Arrange.
        let bitcoin_txid: String = test_deposit.bitcoin_txid.clone();
        let bitcoin_tx_output_index: u32 = test_deposit.bitcoin_tx_output_index;

        // Act.
        let response = client
            .inner
            .get(format!(
                "{EMILY_DEPOSIT_ENDPOINT}/{bitcoin_txid}/{bitcoin_tx_output_index}"
            ))
            .send()
            .await
            .expect("Request should succeed");

        // Assert.
        let actual: Deposit = response
            .json()
            .await
            .expect("Failed to parse JSON response");

        let expected = just_created_deposit(bitcoin_txid, bitcoin_tx_output_index);

        util::assert_eq_pretty(actual, expected);
    }
    client.teardown().await;
}

/// Get all deposits for each transaction using a page size large enough to get all entries.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_deposits_for_transaction() {
    let client = setup_deposit_integration_test().await;
    for test_deposit_transaction_data in TEST_DEPOSIT_DATA.iter() {
        // Arrange.
        let number_of_outputs = test_deposit_transaction_data.number_of_outputs;
        let bitcoin_txid = test_deposit_transaction_data.bitcoin_txid.clone();

        // Act.
        let response = client
            .inner
            .get(format!("{EMILY_DEPOSIT_ENDPOINT}/{bitcoin_txid}"))
            .query(&[
                // Query for one more than expected so that the call
                // doesn't return a `next_token`.
                ("pageSize", number_of_outputs + 1),
            ])
            .send()
            .await
            .expect("Request should succeed");

        // Assert.
        let actual: GetDepositsForTransactionResponse = response
            .json()
            .await
            .expect("Failed to parse JSON response");

        assert_eq!(actual.deposits.len(), number_of_outputs as usize);
        assert_eq!(actual.next_token, None);
    }
    client.teardown().await;
}

/// Get deposits for transaction using a small page size that will require multiple calls
/// to the paginated endpoint to get all the deposits.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_deposits_for_transaction_with_small_page_size() {
    let client = setup_deposit_integration_test().await;
    for test_deposit_transaction_data in TEST_DEPOSIT_DATA.iter() {
        // Arrange.
        let mut aggregate_deposits: Vec<Deposit> = vec![];
        let number_of_outputs = test_deposit_transaction_data.number_of_outputs;
        let bitcoin_txid = test_deposit_transaction_data.bitcoin_txid.clone();
        let page_size: i32 = 2;
        let uri: String = format!("{EMILY_DEPOSIT_ENDPOINT}/{bitcoin_txid}");

        // Act.
        let mut response: GetDepositsForTransactionResponse = client
            .inner
            .get(&uri)
            .query(&[("pageSize", page_size.to_string())])
            .send()
            .await
            .expect("Request should succeed")
            .json()
            .await
            .expect("Failed to parse JSON response");
        // Ensure that the number of items returned is at most the same as the page size.
        assert!(response.deposits.len() <= page_size as usize);
        aggregate_deposits.append(response.deposits.as_mut());

        while let Some(next_token) = response.next_token.clone() {
            // Act.
            response = client
                .inner
                .get(&uri)
                .query(&[
                    ("pageSize", page_size.to_string()),
                    ("nextToken", next_token),
                ])
                .send()
                .await
                .expect("Request should succeed")
                .json()
                .await
                .expect("Failed to parse JSON response");
            // Ensure that the number of items returned is the same as the requested page size.
            assert!(response.deposits.len() <= page_size as usize);
            aggregate_deposits.append(response.deposits.as_mut());
        }

        // Make the expected deposits.
        let mut expected_deposits: Vec<Deposit> = (0..number_of_outputs)
            .map(|bitcoin_tx_output_index| {
                just_created_deposit(bitcoin_txid.clone(), bitcoin_tx_output_index)
            })
            .collect();

        aggregate_deposits.sort();
        expected_deposits.sort();
        assert_eq!(aggregate_deposits, expected_deposits);
    }
    client.teardown().await;
}

/// Get pending deposits by searching for all deposits that have a `pending` status
/// and using a small enough page size that will require multiple calls to the paginated
/// endpoing to get all the pending deposits present.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_pending_deposits() {
    // Arrange.
    let client = setup_deposit_integration_test().await;
    let page_size: i32 = 2;

    let mut aggregate_deposits: Vec<DepositInfo> = vec![];

    // Act 1.
    let mut response: GetDepositsResponse = client
        .inner
        .get(EMILY_DEPOSIT_ENDPOINT)
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
    assert!(response.deposits.len() <= page_size as usize);
    aggregate_deposits.append(response.deposits.as_mut());

    // Act 2.
    while let Some(next_token) = response.next_token.clone() {
        response = client
            .inner
            .get(EMILY_DEPOSIT_ENDPOINT)
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
        assert!(response.deposits.len() <= page_size as usize);
        aggregate_deposits.append(response.deposits.as_mut());
    }

    // Assert.
    let mut expected_deposit_infos: Vec<DepositInfo> = all_test_deposit_data()
        .map(|test_deposit_data| {
            just_created_deposit(
                test_deposit_data.bitcoin_txid,
                test_deposit_data.bitcoin_tx_output_index,
            )
        })
        .map(|deposit| deposit.into())
        .collect();

    aggregate_deposits.sort();
    expected_deposit_infos.sort();
    assert_eq!(aggregate_deposits, expected_deposit_infos);
    client.teardown().await;
}

/// Get failed deposits. Because there are no failed deposits in the set of test data
/// this should always be empty.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_failed_deposits() {
    // Arrange.
    let client = setup_deposit_integration_test().await;

    // Act.
    let response: GetDepositsResponse = client
        .inner
        .get(EMILY_DEPOSIT_ENDPOINT)
        .query(&[("status", "failed".to_string())])
        .send()
        .await
        .expect("Request should succeed")
        .json()
        .await
        .expect("Failed to parse JSON response");

    // Assert.
    assert_eq!(response.deposits.len(), 0);
    client.teardown().await;
}

/// Update deposits test.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn update_deposit() {
    // Arrange.
    let client = setup_deposit_integration_test().await;

    // Get a random deposit info and its identifying fields.
    let deposit_keys: Vec<DepositEntryKey> = client
        .get_all_deposits()
        .await
        .into_iter()
        .map(|deposit_info| DepositEntryKey {
            bitcoin_tx_output_index: deposit_info.bitcoin_tx_output_index,
            bitcoin_txid: deposit_info.bitcoin_txid,
        })
        .collect();

    let key1 = deposit_keys.get(0).unwrap().clone();
    let key2 = deposit_keys.get(1).unwrap().clone();

    let bitcoin_txid = key1.bitcoin_txid.clone();
    let bitcoin_tx_output_index = key1.bitcoin_tx_output_index;

    // Get the full deposit.
    let _original_deposit = client
        .get_deposit(&bitcoin_txid, bitcoin_tx_output_index)
        .await;

    // Make some parameters.
    let updated_hash = "UPDATED_HASH".to_string();
    let updated_height: u64 = 12345;
    let updated_status: Status = Status::Accepted;
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
    let update_requests = UpdateDepositsRequestBody {
        deposits: vec![
            DepositUpdate {
                // Original fields.
                bitcoin_txid: key1.bitcoin_txid.clone(),
                bitcoin_tx_output_index: key1.bitcoin_tx_output_index,
                // New updated height.
                last_update_height: updated_height,
                last_update_block_hash: updated_hash.clone(),
                status: updated_status.clone(),
                status_message: updated_message.clone(),
                fulfillment: Some(fulfillment.clone()),
            },
            DepositUpdate {
                // Original fields.
                bitcoin_txid: key2.bitcoin_txid.clone(),
                bitcoin_tx_output_index: key2.bitcoin_tx_output_index,
                // New updated height.
                last_update_height: updated_height,
                last_update_block_hash: updated_hash.clone(),
                status: updated_status.clone(),
                status_message: updated_message.clone(),
                fulfillment: Some(fulfillment.clone()),
            },
        ],
    };
    let response = client.update_deposits(&update_requests).await;
    assert_eq!(response.deposits.len(), update_requests.deposits.len());

    let updated_deposit = response.deposits.get(0).unwrap().clone();
    assert_eq!(updated_deposit.last_update_height, updated_height);
    assert_eq!(updated_deposit.last_update_block_hash, updated_hash);
    assert_eq!(updated_deposit.status, updated_status);
    assert_eq!(updated_deposit.status_message, updated_message);
    assert_eq!(updated_deposit.fulfillment, Some(fulfillment.clone()));

    let updated_deposit = response.deposits.get(1).unwrap().clone();
    assert_eq!(updated_deposit.last_update_height, updated_height);
    assert_eq!(updated_deposit.last_update_block_hash, updated_hash);
    assert_eq!(updated_deposit.status, updated_status);
    assert_eq!(updated_deposit.status_message, updated_message);
    assert_eq!(updated_deposit.fulfillment, Some(fulfillment.clone()));

    // Update the parameters.
    let updated_status: Status = Status::Reprocessing;
    // Make the request.
    let update_requests = UpdateDepositsRequestBody {
        deposits: vec![DepositUpdate {
            // Original fields.
            bitcoin_txid: bitcoin_txid,
            bitcoin_tx_output_index: bitcoin_tx_output_index,
            // New updated height.
            last_update_height: updated_height + 1,
            last_update_block_hash: updated_hash.clone(),
            status: updated_status.clone(),
            status_message: updated_message.clone(),
            fulfillment: None,
        }],
    };
    let response = client.update_deposits(&update_requests).await;
    assert_eq!(response.deposits.len(), update_requests.deposits.len());

    let updated_deposit = response.deposits.first().unwrap().clone();
    assert_eq!(updated_deposit.last_update_height, updated_height + 1);
    assert_eq!(updated_deposit.last_update_block_hash, updated_hash);
    assert_eq!(updated_deposit.status, updated_status);
    assert_eq!(updated_deposit.status_message, updated_message);
    assert_eq!(updated_deposit.fulfillment, None);

    // Now try getting the raw internal entry.
    let context: EmilyContext = EmilyContext::local_test_instance()
        .await
        .expect("Making emily context must succeed in integration test.");
    let deposit_entry = accessors::get_deposit_entry(
        &context,
        &DepositEntryKey {
            bitcoin_txid: updated_deposit.bitcoin_txid.clone(),
            bitcoin_tx_output_index: updated_deposit.bitcoin_tx_output_index,
        },
    )
    .await
    .expect("Getting deposit entry in test must succeed.");

    // The history of the deposit should be tracked correctly.
    let history: Vec<DepositEvent> = vec![
        DepositEvent {
            status: StatusEntry::Pending,
            message: "Just received deposit".to_string(),
            stacks_block_height: TEST_BLOCK_HEIGHT,
            stacks_block_hash: "DUMMY_HASH".to_string(),
        },
        DepositEvent {
            status: StatusEntry::Accepted(fulfillment.clone()),
            message: updated_message.clone(),
            stacks_block_height: updated_height,
            stacks_block_hash: updated_hash.clone(),
        },
        DepositEvent {
            status: StatusEntry::Reprocessing,
            message: updated_message.clone(),
            stacks_block_height: updated_height + 1,
            stacks_block_hash: updated_hash.clone(),
        },
    ];
    assert_eq!(deposit_entry.history, history);

    // Assert.
    client.teardown().await;
}
