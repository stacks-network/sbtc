use std::cmp::Ordering;

use emily_client::models::{Fulfillment, Status, UpdateDepositsRequestBody};
use emily_client::{
    apis::{self, configuration::Configuration},
    models::{CreateDepositRequestBody, Deposit, DepositInfo, DepositParameters, DepositUpdate},
};

use crate::common::{clean_setup, StandardError};

const RECIPIENT: &'static str = "";
const BLOCK_HASH: &'static str = "";
const BLOCK_HEIGHT: i64 = 0;
const INITIAL_DEPOSIT_STATUS_MESSAGE: &'static str = "Just received deposit";

/// An arbitrary fully ordered partial cmp comparator for DepositInfos.
/// This is useful for sorting vectors of deposit infos so that vectors with
/// the same elements will be considered equal in a test assert.
fn arbitrary_deposit_info_partial_cmp(a: &DepositInfo, b: &DepositInfo) -> Ordering {
    let a_str: String = format!("{}-{}", a.bitcoin_txid, a.bitcoin_tx_output_index);
    let b_str: String = format!("{}-{}", b.bitcoin_txid, b.bitcoin_tx_output_index);
    b_str
        .partial_cmp(&a_str)
        .expect("Failed to compare two strings that should be comparable")
}

/// An arbitrary fully ordered partial cmp comparator for Deposits.
/// This is useful for sorting vectors of deposits so that vectors with
/// the same elements will be considered equal in a test assert.
fn arbitrary_deposit_partial_cmp(a: &Deposit, b: &Deposit) -> Ordering {
    let a_str: String = format!("{}-{}", a.bitcoin_txid, a.bitcoin_tx_output_index);
    let b_str: String = format!("{}-{}", b.bitcoin_txid, b.bitcoin_tx_output_index);
    b_str
        .partial_cmp(&a_str)
        .expect("Failed to compare two strings that should be comparable")
}

/// Makes a bunch of deposits.
async fn batch_create_deposits(
    configuration: &Configuration,
    create_requests: Vec<CreateDepositRequestBody>,
) -> Vec<Deposit> {
    let mut created_deposits: Vec<Deposit> = Vec::with_capacity(create_requests.len());
    for request in create_requests {
        created_deposits.push(
            apis::deposit_api::create_deposit(&configuration, request)
                .await
                .expect("Received an error after making a valid create deposit request api call."),
        );
    }
    created_deposits
}

// Tests.
// ------

#[tokio::test]
async fn create_and_get_deposit_happy_path() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let bitcoin_txid: &str = "bitcoin_txid";
    let bitcoin_tx_output_index = 12;
    let deposit_script: &str = "deposit_script";
    let reclaim_script: &str = "reclaim_script";

    let request = CreateDepositRequestBody {
        bitcoin_tx_output_index,
        bitcoin_txid: bitcoin_txid.into(),
        deposit: deposit_script.into(),
        reclaim: reclaim_script.into(),
    };

    let expected_deposit = Deposit {
        amount: 0,
        bitcoin_tx_output_index,
        bitcoin_txid: bitcoin_txid.into(),
        fulfillment: None,
        last_update_block_hash: BLOCK_HASH.into(),
        last_update_height: BLOCK_HEIGHT,
        parameters: Box::new(DepositParameters {
            lock_time: 0,
            max_fee: 0,
            reclaim_script: reclaim_script.into(),
        }),
        recipient: RECIPIENT.into(),
        status: emily_client::models::Status::Pending,
        status_message: INITIAL_DEPOSIT_STATUS_MESSAGE.into(),
    };

    // Act.
    // ----

    let created_deposit = apis::deposit_api::create_deposit(&configuration, request)
        .await
        .expect("Received an error after making a valid create deposit request api call.");

    let bitcoin_tx_output_index_string = bitcoin_tx_output_index.to_string();
    let gotten_deposit = apis::deposit_api::get_deposit(
        &configuration,
        bitcoin_txid,
        &bitcoin_tx_output_index_string,
    )
    .await
    .expect("Received an error after making a valid get deposit request api call.");

    // Assert.
    // -------
    assert_eq!(expected_deposit, created_deposit);
    assert_eq!(expected_deposit, gotten_deposit);
}

#[tokio::test]
async fn wipe_databases_test() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let bitcoin_txid: &str = "bitcoin_txid";
    let bitcoin_tx_output_index = 12;
    let deposit_script: &str = "deposit_script";
    let reclaim_script: &str = "reclaim_script";

    let request = CreateDepositRequestBody {
        bitcoin_tx_output_index,
        bitcoin_txid: bitcoin_txid.into(),
        deposit: deposit_script.into(),
        reclaim: reclaim_script.into(),
    };

    // Act.
    // ----
    apis::deposit_api::create_deposit(&configuration, request)
        .await
        .expect("Received an error after making a valid create deposit request api call.");

    apis::testing_api::wipe_databases(&configuration)
        .await
        .expect("Received an error after making a valid wipe api call.");

    let bitcoin_tx_output_index_string = bitcoin_tx_output_index.to_string();
    let attempted_get: StandardError = apis::deposit_api::get_deposit(
        &configuration,
        bitcoin_txid,
        &bitcoin_tx_output_index_string,
    )
    .await
    .expect_err("Received a successful response attempting to access a nonpresent deposit.")
    .into();

    // Assert.
    // -------
    assert_eq!(attempted_get.status_code, 404);
}

#[tokio::test]
async fn get_deposits_for_transaction() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let bitcoin_txid: &str = "bitcoin_txid";
    let bitcoin_tx_output_indices = vec![1, 3, 2, 4]; // unordered.
    let deposit_script: &str = "deposit_script";
    let reclaim_script: &str = "reclaim_script";

    let mut create_requests: Vec<CreateDepositRequestBody> = Vec::new();
    let mut expected_deposits: Vec<Deposit> = Vec::new();

    for bitcoin_tx_output_index in bitcoin_tx_output_indices {
        let request = CreateDepositRequestBody {
            bitcoin_tx_output_index,
            bitcoin_txid: bitcoin_txid.into(),
            deposit: deposit_script.into(),
            reclaim: reclaim_script.into(),
        };
        create_requests.push(request);

        let expected_deposit = Deposit {
            amount: 0,
            bitcoin_tx_output_index,
            bitcoin_txid: bitcoin_txid.into(),
            fulfillment: None,
            last_update_block_hash: BLOCK_HASH.into(),
            last_update_height: BLOCK_HEIGHT,
            parameters: Box::new(DepositParameters {
                lock_time: 0,
                max_fee: 0,
                reclaim_script: reclaim_script.into(),
            }),
            recipient: RECIPIENT.into(),
            status: emily_client::models::Status::Pending,
            status_message: INITIAL_DEPOSIT_STATUS_MESSAGE.into(),
        };
        expected_deposits.push(expected_deposit);
    }

    // Act.
    // ----
    batch_create_deposits(&configuration, create_requests).await;

    let gotten_deposits =
        apis::deposit_api::get_deposits_for_transaction(&configuration, bitcoin_txid, None, None)
            .await
            .expect(
                "Received an error after making a valid get deposits for transaction api call.",
            );
    // Assert.
    // -------

    // Expect the deposits to be sorted by output index.
    // TODO(TBD): Reverse this order of deposits for this specific api call.
    expected_deposits.sort_by(|a, b| {
        b.bitcoin_tx_output_index
            .partial_cmp(&a.bitcoin_tx_output_index)
            .expect("Failed to order the expected deposits")
    });
    assert_eq!(expected_deposits, gotten_deposits.deposits);
}

#[tokio::test]
async fn get_deposits() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let bitcoin_txids: Vec<&str> = vec!["bitcoin_txid_1", "bitcoin_txid_2"];
    let bitcoin_tx_output_indices = vec![1, 3, 2, 4]; // unordered.
    let deposit_script: &str = "deposit_script";
    let reclaim_script: &str = "reclaim_script";

    let mut create_requests: Vec<CreateDepositRequestBody> = Vec::new();
    let mut expected_deposit_infos: Vec<DepositInfo> = Vec::new();

    for bitcoin_txid in bitcoin_txids {
        for &bitcoin_tx_output_index in bitcoin_tx_output_indices.iter() {
            let request = CreateDepositRequestBody {
                bitcoin_tx_output_index,
                bitcoin_txid: bitcoin_txid.into(),
                deposit: deposit_script.into(),
                reclaim: reclaim_script.into(),
            };
            create_requests.push(request);

            let expected_deposit_info = DepositInfo {
                amount: 0,
                bitcoin_tx_output_index,
                bitcoin_txid: bitcoin_txid.into(),
                last_update_block_hash: BLOCK_HASH.into(),
                last_update_height: BLOCK_HEIGHT,
                recipient: RECIPIENT.into(),
                status: emily_client::models::Status::Pending,
            };
            expected_deposit_infos.push(expected_deposit_info);
        }
    }

    let chunksize: i32 = 2;
    // If the number of elements is an exact multiple of the chunk size the "final"
    // query will still have a next token, and the next query will now have a next
    // token and will return no additional data.
    let expected_chunks = expected_deposit_infos.len() as i32 / chunksize + 1;

    // Act.
    // ----
    batch_create_deposits(&configuration, create_requests).await;

    let status = emily_client::models::Status::Pending;
    let mut next_token: Option<Option<String>> = None;
    let mut gotten_deposit_info_chunks: Vec<Vec<DepositInfo>> = Vec::new();
    loop {
        let response = apis::deposit_api::get_deposits(
            &configuration,
            status,
            next_token.as_ref().and_then(|o| o.as_deref()),
            Some(chunksize),
        )
        .await
        .expect("Received an error after making a valid get deposits api call.");
        gotten_deposit_info_chunks.push(response.deposits);
        // If there's no next token then break.
        next_token = response.next_token;
        if !next_token.as_ref().is_some_and(|inner| inner.is_some()) {
            break;
        }
    }

    // Assert.
    // -------
    assert_eq!(expected_chunks, gotten_deposit_info_chunks.len() as i32);
    let max_chunk_size = gotten_deposit_info_chunks
        .iter()
        .map(|chunk| chunk.len())
        .max()
        .unwrap();
    assert!(chunksize >= max_chunk_size as i32);

    let mut gotten_deposit_infos = gotten_deposit_info_chunks
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    expected_deposit_infos.sort_by(arbitrary_deposit_info_partial_cmp);
    gotten_deposit_infos.sort_by(arbitrary_deposit_info_partial_cmp);
    assert_eq!(expected_deposit_infos, gotten_deposit_infos);
}

#[tokio::test]
async fn update_deposits() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let bitcoin_txids: Vec<&str> = vec!["bitcoin_txid_1", "bitcoin_txid_2"];
    let bitcoin_tx_output_indices = vec![1, 2];
    let deposit_script: &str = "deposit_script";
    let reclaim_script: &str = "reclaim_script";

    let update_status_message: &str = "test_status_message";
    let update_block_hash: &str = "update_block_hash";
    let update_block_height: i64 = 34;
    let update_status: Status = Status::Accepted;

    let update_fulfillment: Fulfillment = Fulfillment {
        bitcoin_block_hash: "bitcoin_block_hash".to_string(),
        bitcoin_block_height: 23,
        bitcoin_tx_index: 45,
        bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
        btc_fee: 2314,
        stacks_txid: "test_fulfillment_stacks_txid".to_string(),
    };

    let num_deposits = bitcoin_tx_output_indices.len() * bitcoin_txids.len();
    let mut create_requests: Vec<CreateDepositRequestBody> = Vec::with_capacity(num_deposits);
    let mut deposit_updates: Vec<DepositUpdate> = Vec::with_capacity(num_deposits);
    let mut expected_deposits: Vec<Deposit> = Vec::with_capacity(num_deposits);
    for bitcoin_txid in bitcoin_txids {
        for &bitcoin_tx_output_index in bitcoin_tx_output_indices.iter() {
            let create_request = CreateDepositRequestBody {
                bitcoin_tx_output_index,
                bitcoin_txid: bitcoin_txid.into(),
                deposit: deposit_script.into(),
                reclaim: reclaim_script.into(),
            };
            create_requests.push(create_request);

            let deposit_update = DepositUpdate {
                bitcoin_tx_output_index: bitcoin_tx_output_index,
                bitcoin_txid: bitcoin_txid.into(),
                fulfillment: Some(Some(Box::new(update_fulfillment.clone()))),
                last_update_block_hash: update_block_hash.into(),
                last_update_height: update_block_height.clone(),
                status: update_status.clone(),
                status_message: update_status_message.into(),
            };
            deposit_updates.push(deposit_update);

            let expected_deposit = Deposit {
                amount: 0,
                bitcoin_tx_output_index,
                bitcoin_txid: bitcoin_txid.into(),
                fulfillment: Some(Some(Box::new(update_fulfillment.clone()))),
                last_update_block_hash: update_block_hash.into(),
                last_update_height: update_block_height.clone(),
                parameters: Box::new(DepositParameters {
                    lock_time: 0,
                    max_fee: 0,
                    reclaim_script: reclaim_script.into(),
                }),
                recipient: RECIPIENT.into(),
                status: update_status.clone(),
                status_message: update_status_message.into(),
            };
            expected_deposits.push(expected_deposit);
        }
    }

    // Create the deposits here.
    let update_request = UpdateDepositsRequestBody { deposits: deposit_updates };

    // Act.
    // ----
    batch_create_deposits(&configuration, create_requests).await;
    let update_deposits_response =
        apis::deposit_api::update_deposits(&configuration, update_request)
            .await
            .expect("Received an error after making a valid update deposits api call.");

    // Assert.
    // -------
    let mut updated_deposits = update_deposits_response.deposits;
    updated_deposits.sort_by(arbitrary_deposit_partial_cmp);
    expected_deposits.sort_by(arbitrary_deposit_partial_cmp);
    assert_eq!(expected_deposits, updated_deposits);
}
