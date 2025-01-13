use std::cmp::Ordering;

use crate::common::clean_setup;
use testing_emily_client::apis;
use testing_emily_client::apis::configuration::Configuration;
use testing_emily_client::models::{
    CreateWithdrawalRequestBody, Fulfillment, Status, UpdateWithdrawalsRequestBody, Withdrawal,
    WithdrawalInfo, WithdrawalParameters, WithdrawalUpdate,
};

const RECIPIENT: &'static str = "";
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
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
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
            status: Status::Pending,
        };
        expected_withdrawal_infos.push(expected_withdrawal_info);
    }

    let chunksize: u16 = 2;
    // If the number of elements is an exact multiple of the chunk size the "final"
    // query will still have a next token, and the next query will now have a next
    // token and will return no additional data.
    let expected_chunks = expected_withdrawal_infos.len() as u16 / chunksize + 1;

    // Act.
    // ----
    batch_create_withdrawals(&configuration, create_requests).await;

    let status = testing_emily_client::models::Status::Pending;
    let mut next_token: Option<Option<String>> = None;
    let mut gotten_withdrawal_info_chunks: Vec<Vec<WithdrawalInfo>> = Vec::new();
    loop {
        let response = apis::withdrawal_api::get_withdrawals(
            &configuration,
            status,
            next_token.as_ref().and_then(|o| o.as_deref()),
            Some(chunksize as i32),
        )
        .await
        .expect("Received an error after making a valid get withdrawal api call.");
        gotten_withdrawal_info_chunks.push(response.withdrawals);
        // If there's no next token then break.
        next_token = response.next_token;
        if !next_token.as_ref().is_some_and(|inner| inner.is_some()) {
            break;
        }
    }

    // Assert.
    // -------
    assert_eq!(expected_chunks, gotten_withdrawal_info_chunks.len() as u16);
    let max_chunk_size = gotten_withdrawal_info_chunks
        .iter()
        .map(|chunk| chunk.len())
        .max()
        .unwrap();
    assert!(chunksize >= max_chunk_size as u16);

    let mut gotten_withdrawal_infos = gotten_withdrawal_info_chunks
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    expected_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
    gotten_withdrawal_infos.sort_by(arbitrary_withdrawal_info_partial_cmp);
    assert_eq!(expected_withdrawal_infos, gotten_withdrawal_infos);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn update_withdrawals() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let withdrawal_request_ids = vec![1, 2, 3, 4, 5, 7, 9, 111];

    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    let update_status_message: &str = "test_status_message";
    let update_block_hash: &str = "update_block_hash";
    let update_block_height: u64 = 34;
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
            request_id,
            stacks_block_hash: BLOCK_HASH.into(),
            stacks_block_height: BLOCK_HEIGHT,
        };
        create_requests.push(request);

        let withdrawal_update = WithdrawalUpdate {
            request_id,
            fulfillment: Some(Some(Box::new(update_fulfillment.clone()))),
            last_update_block_hash: update_block_hash.into(),
            last_update_height: update_block_height.clone(),
            status: update_status.clone(),
            status_message: update_status_message.into(),
        };
        withdrawal_updates.push(withdrawal_update);

        let expected = Withdrawal {
            amount,
            fulfillment: Some(Some(Box::new(update_fulfillment.clone()))),
            last_update_block_hash: update_block_hash.into(),
            last_update_height: update_block_height.clone(),
            parameters: Box::new(parameters.clone()),
            recipient: RECIPIENT.into(),
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

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn update_withdrawals_updates_chainstate() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let request_id = 123;
    let amount = 0;
    let parameters = WithdrawalParameters { max_fee: 123 };

    let create_request = CreateWithdrawalRequestBody {
        amount,
        parameters: Box::new(parameters.clone()),
        recipient: RECIPIENT.into(),
        request_id,
        stacks_block_hash: BLOCK_HASH.into(),
        stacks_block_height: BLOCK_HEIGHT,
    };

    // It's okay to say it's accepted over and over.
    let update_status: Status = Status::Accepted;
    let update_status_message: &str = "test_status_message";

    let min_height: i64 = 20;
    let max_height: i64 = 30;
    let range = min_height..max_height;

    let mut withdrawal_updates = Vec::new();
    for update_block_height in range.clone() {
        let withdrawal_update = WithdrawalUpdate {
            request_id,
            fulfillment: None,
            last_update_block_hash: format!("hash_{}", update_block_height),
            last_update_height: update_block_height as u64,
            status: update_status.clone(),
            status_message: update_status_message.into(),
        };
        withdrawal_updates.push(withdrawal_update);
    }

    // Order the updates pecularily so that they are not in order.
    withdrawal_updates.sort_by_key(|update| {
        (update.last_update_height as i64 - (min_height + (max_height - min_height) / 2)).abs()
    });

    let expected_last_update_height_at_output_index: Vec<(usize, u64)> = withdrawal_updates
        .iter()
        .enumerate()
        .map(|(index, update)| (index, update.last_update_height))
        .collect();

    let update_request = UpdateWithdrawalsRequestBody {
        withdrawals: withdrawal_updates,
    };

    // Act.
    // ----

    // Create a withdrawal.
    apis::withdrawal_api::create_withdrawal(&configuration, create_request)
        .await
        .expect("Received an error after making a valid create withdrawal request api call.");

    // Send it a bunch of updates.
    let update_withdrawals_response =
        apis::withdrawal_api::update_withdrawals(&configuration, update_request)
            .await
            .expect("Received an error after making a valid update withdrawals api call.");

    for height in range {
        let chainstate =
            apis::chainstate_api::get_chainstate_at_height(&configuration, height as u64)
                .await
                .expect(
                    "Received an error after making a valid get chainstate at height api call.",
                );
        assert_eq!(chainstate.stacks_block_height, height as u64);
        assert_eq!(chainstate.stacks_block_hash, format!("hash_{}", height));
    }

    for (index, last_update_height) in expected_last_update_height_at_output_index {
        assert_eq!(
            update_withdrawals_response.withdrawals[index].last_update_height,
            last_update_height
        );
    }
}
