use crate::util::{self, constants::EMILY_DEPOSIT_ENDPOINT};
use emily_handler::api::models::deposit::{
    responses::{GetDepositsForTransactionResponse, GetDepositsResponse},
    Deposit, DepositInfo, DepositParameters,
};
use reqwest::Client;
use serde_json::json;
use serial_test::serial;
use std::sync::LazyLock;
use tokio;

use emily_handler::api::models::deposit::responses::{CreateDepositResponse, GetDepositResponse};

// TODO(392): Use test setup functions to wipe the database before performing these
// tests instead of relying on circumstantial test execution order.

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
        status_message: "Just received deposit".to_string(),
        parameters: DepositParameters {
            reclaim_script: "example_reclaim_script".to_string(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Create all the deposits one at a time that are required for the rest of the
/// tests. Note that this test suite assumes the database is empty when the integration
/// tests start and this test should populate the table in its entirety.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
#[serial]
async fn create_deposits() {
    let client = Client::new();
    for test_deposit in all_test_deposit_data() {
        // Arrange.
        let bitcoin_txid: String = test_deposit.bitcoin_txid;
        let bitcoin_tx_output_index: u32 = test_deposit.bitcoin_tx_output_index;

        // Act.
        let response = client
            .post(EMILY_DEPOSIT_ENDPOINT)
            .json(&json!({
                "bitcoinTxid": bitcoin_txid.clone(),
                "bitcoinTxOutputIndex": bitcoin_tx_output_index,
                "reclaim": "example_reclaim_script",
                "deposit": "example_deposit_script",
            }))
            .send()
            .await
            .expect("Request should succeed");

        // Assert.
        let actual: CreateDepositResponse = response
            .json()
            .await
            .expect("Failed to parse JSON response");

        let expected = just_created_deposit(bitcoin_txid, bitcoin_tx_output_index);

        util::assert_eq_pretty(actual, expected);
    }
}

/// Get every deposit from the previous test one at a time.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
#[serial]
async fn get_deposit() {
    let client = Client::new();
    for test_deposit in all_test_deposit_data() {
        // Arrange.
        let bitcoin_txid: String = test_deposit.bitcoin_txid.clone();
        let bitcoin_tx_output_index: u32 = test_deposit.bitcoin_tx_output_index;

        // Act.
        let response = client
            .get(format!(
                "{EMILY_DEPOSIT_ENDPOINT}/{bitcoin_txid}/{bitcoin_tx_output_index}"
            ))
            .send()
            .await
            .expect("Request should succeed");

        // Assert.
        let actual: GetDepositResponse = response
            .json()
            .await
            .expect("Failed to parse JSON response");

        let expected = just_created_deposit(bitcoin_txid, bitcoin_tx_output_index);

        util::assert_eq_pretty(actual, expected);
    }
}

/// Get all deposits for each transaction using a page size large enough to get all entries.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
#[serial]
async fn get_deposits_for_transaction() {
    let client = Client::new();

    for test_deposit_transaction_data in TEST_DEPOSIT_DATA.iter() {
        // Arrange.
        let number_of_outputs = test_deposit_transaction_data.number_of_outputs;
        let bitcoin_txid = test_deposit_transaction_data.bitcoin_txid.clone();

        // Act.
        let response = client
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
}

/// Get deposits for transaction using a small page size that will require multiple calls
/// to the paginated endpoint to get all the deposits.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
#[serial]
async fn get_deposits_for_transaction_with_small_page_size() {
    let client = Client::new();

    for test_deposit_transaction_data in TEST_DEPOSIT_DATA.iter() {
        // Arrange.
        let mut aggregate_deposits: Vec<Deposit> = vec![];
        let number_of_outputs = test_deposit_transaction_data.number_of_outputs;
        let bitcoin_txid = test_deposit_transaction_data.bitcoin_txid.clone();
        let page_size: i32 = 2;
        let uri: String = format!("{EMILY_DEPOSIT_ENDPOINT}/{bitcoin_txid}");

        // Act.
        let mut response: GetDepositsForTransactionResponse = client
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
}

/// Get pending deposits by searching for all deposits that have a `pending` status
/// and using a small enough page size that will require multiple calls to the paginated
/// endpoing to get all the pending deposits present.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
#[serial]
async fn get_pending_deposits() {
    // Arrange.
    let client = Client::new();
    let page_size: i32 = 2;

    let mut aggregate_deposits: Vec<DepositInfo> = vec![];

    // Act 1.
    let mut response: GetDepositsResponse = client
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
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
#[serial]
async fn get_failed_deposits() {
    // Arrange.
    let client = Client::new();

    // Act.
    let response: GetDepositsResponse = client
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
}
