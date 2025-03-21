use std::cmp::Ordering;
use std::collections::HashMap;

use test_case::test_case;

use testing_emily_client::apis::chainstate_api::set_chainstate;
use testing_emily_client::apis::configuration::{ApiKey, Configuration};
use testing_emily_client::apis::{self, ResponseContent};
use testing_emily_client::models::{
    Chainstate, CreateWithdrawalRequestBody, Fulfillment, Status, UpdateWithdrawalsRequestBody,
    Withdrawal, WithdrawalInfo, WithdrawalParameters, WithdrawalUpdate,
};

use crate::common::clean_setup;

const RECIPIENT: &'static str = "TEST_RECIPIENT";
const SENDER: &'static str = "TEST_SENDER";
const BLOCK_HASH: &'static str = "TEST_BLOCK_HASH";
const BLOCK_HEIGHT: u64 = 0;
const INITIAL_WITHDRAWAL_STATUS_MESSAGE: &'static str = "Just received withdrawal";

/// An arbitrary fully ordered partial cmp comparator for WithdrawalInfos.
/// This is useful for sorting vectors of withdrawal infos so that vectors with
/// the same elements will be considered equal in a test assert.
fn arbitrary_withdrawal_info_partial_cmp(a: &WithdrawalInfo, b: &WithdrawalInfo) -> Ordering {
    let a_str: String = format!("{}-{}", a.stacks_block_hash, a.request_id);
    let b_str: String = format!("{}-{}", b.stacks_block_hash, b.request_id);
    b_str
        .partial_cmp(&a_str)
        .expect("Failed to compare two strings that should be comparable")
}

/// An arbitrary fully ordered partial cmp comparator for Withdrawals.
/// This is useful for sorting vectors of withdrawal so that vectors with
/// the same elements will be considered equal in a test assert.
fn arbitrary_withdrawal_partial_cmp(a: &Withdrawal, b: &Withdrawal) -> Ordering {
    let a_str: String = format!("{}-{}", a.stacks_block_hash, a.request_id);
    let b_str: String = format!("{}-{}", b.stacks_block_hash, b.request_id);
    b_str
        .partial_cmp(&a_str)
        .expect("Failed to compare two strings that should be comparable")
}

/// Makes a bunch of withdrawals.
async fn batch_create_withdrawals(
    configuration: &Configuration,
    create_requests: Vec<CreateWithdrawalRequestBody>,
) -> Vec<Withdrawal> {
    let mut created: Vec<Withdrawal> = Vec::with_capacity(create_requests.len());
    for request in create_requests {
        created.push(
            apis::withdrawal_api::create_withdrawal(&configuration, request)
                .await
                .expect(
                    "Received an error after making a valid create withdrawal request api call.",
                ),
        );
    }
    created
}

#[tokio::test]
async fn create_and_get_withdrawal_happy_path() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };
    let request_id = 1;

    let request = CreateWithdrawalRequestBody {
        amount,
        parameters: Box::new(parameters.clone()),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id,
        stacks_block_hash: BLOCK_HASH.into(),
        stacks_block_height: BLOCK_HEIGHT,
    };

    let expected = Withdrawal {
        amount,
        fulfillment: None,
        last_update_block_hash: BLOCK_HASH.into(),
        last_update_height: BLOCK_HEIGHT,
        parameters: Box::new(parameters.clone()),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id,
        stacks_block_hash: BLOCK_HASH.into(),
        stacks_block_height: BLOCK_HEIGHT,
        status: Status::Pending,
        status_message: INITIAL_WITHDRAWAL_STATUS_MESSAGE.into(),
    };

    // Act.
    // ----
    let created = apis::withdrawal_api::create_withdrawal(&configuration, request)
        .await
        .expect("Received an error after making a valid create withdrawal request api call.");

    let gotten = apis::withdrawal_api::get_withdrawal(&configuration, request_id)
        .await
        .expect("Received an error after making a valid get withdrawal request api call.");

    // Assert.
    // -------
    assert_eq!(expected, created);
    assert_eq!(expected, gotten);
}

#[tokio::test]
async fn get_withdrawals() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let withdrawal_request_ids = vec![1, 2, 3, 4, 5, 6];
    let mut create_requests: Vec<CreateWithdrawalRequestBody> = Vec::new();
    let mut expected_withdrawal_infos: Vec<WithdrawalInfo> = Vec::new();

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    for request_id in withdrawal_request_ids {
        let request = CreateWithdrawalRequestBody {
            amount,
            parameters: Box::new(parameters.clone()),
            recipient: RECIPIENT.into(),
            sender: SENDER.into(),
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
        };
        create_requests.push(request);

        let expected_withdrawal_info = WithdrawalInfo {
            amount,
            last_update_block_hash: BLOCK_HASH.into(),
            last_update_height: BLOCK_HEIGHT,
            recipient: RECIPIENT.into(),
            sender: SENDER.into(),
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
            status: Status::Pending,
        };
        expected_withdrawal_infos.push(expected_withdrawal_info);
    }

    let chunksize = 2;
    // If the number of elements is an exact multiple of the chunk size the "final"
    // query will still have a next token, and the next query will now have a next
    // token and will return no additional data.
    let expected_chunks = expected_withdrawal_infos.len() / chunksize + 1;

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    let status = testing_emily_client::models::Status::Pending;
    let mut next_token: Option<String> = None;
    let mut gotten_withdrawal_info_chunks: Vec<Vec<WithdrawalInfo>> = Vec::new();
    loop {
        let response = apis::withdrawal_api::get_withdrawals(
            &configuration,
            status,
            next_token.as_deref(),
            Some(chunksize as u32),
        )
        .await
        .expect("Received an error after making a valid get withdrawal api call.");
        gotten_withdrawal_info_chunks.push(response.withdrawals);
        // If there's no next token then break.
        next_token = match response.next_token.flatten() {
            Some(token) => Some(token),
            None => break,
        };
    }

    // Assert.
    // -------
    assert_eq!(expected_chunks, gotten_withdrawal_info_chunks.len());
    let max_chunk_size = gotten_withdrawal_info_chunks
        .iter()
        .map(|chunk| chunk.len())
        .max()
        .unwrap();
    assert!(chunksize >= max_chunk_size);

    let mut gotten_withdrawal_infos = gotten_withdrawal_info_chunks
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    expected_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
    gotten_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
    assert_eq!(expected_withdrawal_infos, gotten_withdrawal_infos);
}

#[tokio::test]
async fn get_withdrawals_by_recipient() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let recipients = vec!["recipient_1", "recipient_2", "recipient_3"];
    let withdrawals_per_recipient = 5;
    let mut create_requests: Vec<CreateWithdrawalRequestBody> = Vec::new();
    let mut expected_recipient_data: HashMap<String, Vec<WithdrawalInfo>> = HashMap::new();

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    let mut request_id = 1;
    for recipient in recipients {
        let mut expected_withdrawal_infos: Vec<WithdrawalInfo> = Vec::new();
        for _ in 1..=withdrawals_per_recipient {
            let request = CreateWithdrawalRequestBody {
                amount,
                parameters: Box::new(parameters.clone()),
                recipient: recipient.into(),
                sender: SENDER.into(),
                request_id,
                stacks_block_hash: BLOCK_HASH.into(),
                stacks_block_height: BLOCK_HEIGHT,
            };
            create_requests.push(request);

            let expected_withdrawal_info = WithdrawalInfo {
                amount,
                last_update_block_hash: BLOCK_HASH.into(),
                last_update_height: BLOCK_HEIGHT,
                recipient: recipient.into(),
                sender: SENDER.into(),
                request_id,
                stacks_block_hash: BLOCK_HASH.into(),
                stacks_block_height: BLOCK_HEIGHT,
                status: Status::Pending,
            };
            request_id += 1;
            expected_withdrawal_infos.push(expected_withdrawal_info);
        }
        // Add the recipient data to the recipient data hashmap that stores what
        // we expect to see from the recipient.
        expected_recipient_data.insert(recipient.to_string(), expected_withdrawal_infos.clone());
    }

    let chunksize = 2;

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    let mut actual_recipient_data: HashMap<String, Vec<WithdrawalInfo>> = HashMap::new();
    for recipient in expected_recipient_data.keys() {
        let mut gotten_withdrawal_info_chunks: Vec<Vec<WithdrawalInfo>> = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let response = apis::withdrawal_api::get_withdrawals_for_recipient(
                &configuration,
                recipient,
                next_token.as_deref(),
                Some(chunksize as u32),
            )
            .await
            .expect("Received an error after making a valid get withdrawal api call.");
            gotten_withdrawal_info_chunks.push(response.withdrawals);
            // If there's no next token then break.
            next_token = match response.next_token.flatten() {
                Some(token) => Some(token),
                None => break,
            };
        }
        // Store the actual data received from the api.
        actual_recipient_data.insert(
            recipient.clone(),
            gotten_withdrawal_info_chunks
                .into_iter()
                .flatten()
                .collect(),
        );
    }

    // Assert.
    // -------
    for recipient in expected_recipient_data.keys() {
        let mut expected_withdrawal_infos = expected_recipient_data.get(recipient).unwrap().clone();
        expected_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
        let mut actual_withdrawal_infos = actual_recipient_data.get(recipient).unwrap().clone();
        actual_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
        // Assert that the expected and actual withdrawal infos are the same.
        assert_eq!(expected_withdrawal_infos, actual_withdrawal_infos);
    }
}

#[tokio::test]
async fn get_withdrawals_by_sender() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let senders = vec![
        "SN1Z0WW5SMN4J99A1G1725PAB8H24CWNA7Z8H7214.my-contract",
        "SN1Z0WW5SMN4J99A1G1725PAB8H24CWNA7Z8H7214",
    ];
    let withdrawals_per_sender = 5;
    let mut create_requests: Vec<CreateWithdrawalRequestBody> = Vec::new();
    let mut expected_sender_data: HashMap<String, Vec<WithdrawalInfo>> = HashMap::new();

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    let mut request_id = 1;
    for sender in senders {
        let mut expected_withdrawal_infos: Vec<WithdrawalInfo> = Vec::new();
        for _ in 1..=withdrawals_per_sender {
            let request = CreateWithdrawalRequestBody {
                amount,
                parameters: Box::new(parameters.clone()),
                recipient: RECIPIENT.into(),
                sender: sender.into(),
                request_id,
                stacks_block_hash: BLOCK_HASH.into(),
                stacks_block_height: BLOCK_HEIGHT,
            };
            create_requests.push(request);

            let expected_withdrawal_info = WithdrawalInfo {
                amount,
                last_update_block_hash: BLOCK_HASH.into(),
                last_update_height: BLOCK_HEIGHT,
                recipient: RECIPIENT.into(),
                sender: sender.into(),
                request_id,
                stacks_block_hash: BLOCK_HASH.into(),
                stacks_block_height: BLOCK_HEIGHT,
                status: Status::Pending,
            };
            request_id += 1;
            expected_withdrawal_infos.push(expected_withdrawal_info);
        }
        // Add the sender data to the sender data hashmap that stores what
        // we expect to see from the sender.
        expected_sender_data.insert(sender.to_string(), expected_withdrawal_infos.clone());
    }

    let chunksize = 2;

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    let mut actual_sender_data: HashMap<String, Vec<WithdrawalInfo>> = HashMap::new();
    for sender in expected_sender_data.keys() {
        let mut gotten_withdrawal_info_chunks: Vec<Vec<WithdrawalInfo>> = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let response = apis::withdrawal_api::get_withdrawals_for_sender(
                &configuration,
                sender,
                next_token.as_deref(),
                Some(chunksize as u32),
            )
            .await
            .expect("Received an error after making a valid get withdrawal api call.");
            gotten_withdrawal_info_chunks.push(response.withdrawals);
            // If there's no next token then break.
            next_token = match response.next_token.flatten() {
                Some(token) => Some(token),
                None => break,
            };
        }
        // Store the actual data received from the api.
        actual_sender_data.insert(
            sender.clone(),
            gotten_withdrawal_info_chunks
                .into_iter()
                .flatten()
                .collect(),
        );
    }

    // Assert.
    // -------
    for recipient in expected_sender_data.keys() {
        let mut expected_withdrawal_infos = expected_sender_data.get(recipient).unwrap().clone();
        expected_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
        let mut actual_withdrawal_infos = actual_sender_data.get(recipient).unwrap().clone();
        actual_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
        // Assert that the expected and actual deposit infos are the same.
        assert_eq!(expected_withdrawal_infos, actual_withdrawal_infos);
    }
}

#[tokio::test]
async fn update_withdrawals() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let withdrawal_request_ids = vec![1, 2, 3, 4, 5, 7, 9, 111];

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    let update_status_message: &str = "test_status_message";
    let update_chainstate = Chainstate {
        stacks_block_hash: "update_block_hash".to_string(),
        stacks_block_height: 42,
    };
    let update_status: Status = Status::Confirmed;

    let update_fulfillment: Fulfillment = Fulfillment {
        bitcoin_block_hash: "bitcoin_block_hash".to_string(),
        bitcoin_block_height: 23,
        bitcoin_tx_index: 45,
        bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
        btc_fee: 2314,
        stacks_txid: "test_fulfillment_stacks_txid".to_string(),
    };

    let mut create_requests: Vec<CreateWithdrawalRequestBody> =
        Vec::with_capacity(withdrawal_request_ids.len());
    let mut withdrawal_updates: Vec<WithdrawalUpdate> =
        Vec::with_capacity(withdrawal_request_ids.len());
    let mut expected_withdrawals: Vec<Withdrawal> =
        Vec::with_capacity(withdrawal_request_ids.len());
    for request_id in withdrawal_request_ids {
        let request = CreateWithdrawalRequestBody {
            amount,
            parameters: Box::new(parameters.clone()),
            recipient: RECIPIENT.into(),
            sender: SENDER.into(),
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
        };
        create_requests.push(request);

        let withdrawal_update = WithdrawalUpdate {
            request_id,
            fulfillment: Some(Some(Box::new(update_fulfillment.clone()))),
            status: update_status.clone(),
            status_message: update_status_message.into(),
        };
        withdrawal_updates.push(withdrawal_update);

        let expected = Withdrawal {
            amount,
            fulfillment: Some(Some(Box::new(update_fulfillment.clone()))),
            last_update_block_hash: update_chainstate.stacks_block_hash.clone(),
            last_update_height: update_chainstate.stacks_block_height,
            parameters: Box::new(parameters.clone()),
            recipient: RECIPIENT.into(),
            sender: SENDER.into(),
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
            status: update_status.clone(),
            status_message: update_status_message.into(),
        };
        expected_withdrawals.push(expected);
    }

    let update_request = UpdateWithdrawalsRequestBody {
        withdrawals: withdrawal_updates,
    };

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    // Not strictly necessary, but we do it to make sure that the updates
    // are connected with the current chainstate.
    set_chainstate(&configuration, update_chainstate.clone())
        .await
        .expect("Received an error after making a valid set chainstate api call.");

    let update_withdrawals_response =
        apis::withdrawal_api::update_withdrawals(&configuration, update_request)
            .await
            .expect("Received an error after making a valid update withdrawals api call.");

    // Assert.
    // -------
    let mut updated_withdrawals = update_withdrawals_response.withdrawals;
    updated_withdrawals.sort_by(arbitrary_withdrawal_partial_cmp);
    expected_withdrawals.sort_by(arbitrary_withdrawal_partial_cmp);
    assert_eq!(expected_withdrawals, updated_withdrawals);
}

#[test_case(Status::Pending, Status::Pending, "untrusted_api_key", true; "untrusted_key_pending_to_pending")]
#[test_case(Status::Pending, Status::Accepted, "untrusted_api_key", false; "untrusted_key_pending_to_accepted")]
#[test_case(Status::Pending, Status::Reprocessing, "untrusted_api_key", true; "untrusted_key_pending_to_reprocessing")]
#[test_case(Status::Pending, Status::Confirmed, "untrusted_api_key", true; "untrusted_key_pending_to_confirmed")]
#[test_case(Status::Pending, Status::Failed, "untrusted_api_key", true; "untrusted_key_pending_to_failed")]
#[test_case(Status::Accepted, Status::Pending, "untrusted_api_key", true; "untrusted_key_accepted_to_pending")]
#[test_case(Status::Failed, Status::Pending, "untrusted_api_key", true; "untrusted_key_failed_to_pending")]
#[test_case(Status::Reprocessing, Status::Pending, "untrusted_api_key", true; "untrusted_key_reprocessing_to_pending")]
#[test_case(Status::Confirmed, Status::Pending, "untrusted_api_key", true; "untrusted_key_confirmed_to_pending")]
#[test_case(Status::Accepted, Status::Accepted, "untrusted_api_key", false; "untrusted_key_accepted_to_accepted")]
#[test_case(Status::Failed, Status::Accepted, "untrusted_api_key", true; "untrusted_key_failed_to_accepted")]
#[test_case(Status::Reprocessing, Status::Accepted, "untrusted_api_key", true; "untrusted_key_reprocessing_to_accepted")]
#[test_case(Status::Confirmed, Status::Accepted, "untrusted_api_key", true; "untrusted_key_confirmed_to_accepted")]
#[test_case(Status::Pending, Status::Accepted, "testApiKey", false; "trusted_key_pending_to_accepted")]
#[test_case(Status::Pending, Status::Pending, "testApiKey", false; "trusted_key_pending_to_pending")]
#[test_case(Status::Pending, Status::Reprocessing, "testApiKey", false; "trusted_key_pending_to_reprocessing")]
#[test_case(Status::Pending, Status::Confirmed, "testApiKey", false; "trusted_key_pending_to_confirmed")]
#[test_case(Status::Pending, Status::Failed, "testApiKey", false; "trusted_key_pending_to_failed")]
#[test_case(Status::Confirmed, Status::Pending, "testApiKey", false; "trusted_key_confirmed_to_pending")]
#[tokio::test]
async fn update_withdrawals_is_forbidden(
    previous_status: Status,
    new_status: Status,
    api_key: &str,
    is_forbidden: bool,
) {
    // the testing configuration has privileged access to all endpoints.
    let testing_configuration = clean_setup().await;

    // the user configuration access depends on the api_key.
    let mut user_configuration = testing_configuration.clone();
    user_configuration.api_key = Some(ApiKey {
        prefix: None,
        key: api_key.to_string(),
    });
    // Arrange.
    // --------
    let request_id = 1;

    let chainstate = Chainstate {
        stacks_block_hash: "test_block_hash".to_string(),
        stacks_block_height: 1,
    };

    set_chainstate(&testing_configuration, chainstate.clone())
        .await
        .expect("Received an error after making a valid set chainstate api call.");

    // Setup test withdrawal transaction.
    let request = CreateWithdrawalRequestBody {
        amount: 10000,
        parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
        recipient: RECIPIENT.into(),
        sender: SENDER.into(),
        request_id,
        stacks_block_hash: chainstate.stacks_block_hash.clone(),
        stacks_block_height: chainstate.stacks_block_height,
    };

    // Create the withdrawal with the privileged configuration.
    apis::withdrawal_api::create_withdrawal(&testing_configuration, request.clone())
        .await
        .expect("Received an error after making a valid create withdrawal request api call.");

    // Update the withdrawal status with the privileged configuration.
    if previous_status != Status::Pending {
        let mut fulfillment: Option<Option<Box<Fulfillment>>> = None;

        if previous_status == Status::Confirmed {
            fulfillment = Some(Some(Box::new(Fulfillment {
                bitcoin_block_hash: "bitcoin_block_hash".to_string(),
                bitcoin_block_height: 23,
                bitcoin_tx_index: 45,
                bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
                btc_fee: 2314,
                stacks_txid: "test_fulfillment_stacks_txid".to_string(),
            })));
        }

        apis::withdrawal_api::update_withdrawals(
            &testing_configuration,
            UpdateWithdrawalsRequestBody {
                withdrawals: vec![WithdrawalUpdate {
                    request_id,
                    fulfillment,
                    status: previous_status,
                    status_message: "foo".into(),
                }],
            },
        )
        .await
        .expect("Received an error after making a valid update withdrawal api call.");
    }

    let mut fulfillment: Option<Option<Box<Fulfillment>>> = None;

    if new_status == Status::Confirmed {
        fulfillment = Some(Some(Box::new(Fulfillment {
            bitcoin_block_hash: "bitcoin_block_hash".to_string(),
            bitcoin_block_height: 23,
            bitcoin_tx_index: 45,
            bitcoin_txid: "test_fulfillment_bitcoin_txid".to_string(),
            btc_fee: 2314,
            stacks_txid: "test_fulfillment_stacks_txid".to_string(),
        })));
    }

    let response = apis::withdrawal_api::update_withdrawals(
        &user_configuration,
        UpdateWithdrawalsRequestBody {
            withdrawals: vec![WithdrawalUpdate {
                request_id,
                fulfillment,
                status: new_status,
                status_message: "foo".into(),
            }],
        },
    )
    .await;

    if is_forbidden {
        assert!(response.is_err());
        match response.unwrap_err() {
            testing_emily_client::apis::Error::ResponseError(ResponseContent {
                status, ..
            }) => {
                assert_eq!(status, 403);
            }
            e => panic!("Expected a 403 error, got {e}"),
        }

        let response = apis::withdrawal_api::get_withdrawal(&user_configuration, request_id)
            .await
            .expect("Received an error after making a valid get withdrawal api call.");
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.status, previous_status);
    } else {
        assert!(response.is_ok());
        let response = response.unwrap();
        let withdrawal = response
            .withdrawals
            .first()
            .expect("No withdrawal in response");
        assert_eq!(withdrawal.request_id, request_id);
        assert_eq!(withdrawal.status, new_status);
    }
}
