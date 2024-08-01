//! Testing utilities.
//! TODO(283, TBD): Use openapi generated client instead of bespoke methods.

use std::collections::HashMap;

use emily_handler::api::models::{
    chainstate::Chainstate,
    common::Status,
    deposit::{
        requests::CreateDepositRequestBody,
        responses::{CreateDepositResponse, GetDepositsResponse},
        DepositInfo,
    },
    withdrawal::{
        requests::CreateWithdrawalRequestBody,
        responses::{CreateWithdrawalResponse, GetWithdrawalsResponse},
        WithdrawalInfo,
    },
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Test constants module.
pub mod constants;

use constants::{
    ALL_STATUSES, EMILY_CHAINSTATE_ENDPOINT, EMILY_DEPOSIT_ENDPOINT, EMILY_WITHDRAWAL_ENDPOINT,
};

pub fn assert_eq_pretty<T>(actual: T, expected: T)
where
    T: Serialize + std::fmt::Debug + Eq,
{
    // Assert both objects equal with a prettier output string.
    assert_eq!(
        actual,
        expected,
        "Actual:\n{}\nExpected:\n{}",
        serde_json::to_string_pretty(&actual).unwrap(),
        serde_json::to_string_pretty(&expected).unwrap()
    );
}

// Create
// -----------------------------------------------------------------------------

/// Create deposit.
pub async fn create_deposit(
    client: &Client,
    request: CreateDepositRequestBody,
) -> CreateDepositResponse {
    create_xyz(client, EMILY_DEPOSIT_ENDPOINT, request).await
}

/// Create withdrawal.
pub async fn create_withdrawal(
    client: &Client,
    request: CreateWithdrawalRequestBody,
) -> CreateWithdrawalResponse {
    create_xyz(client, EMILY_WITHDRAWAL_ENDPOINT, request).await
}

/// Create chainstate.
pub async fn create_chainstate(client: &Client, request: Chainstate) -> Chainstate {
    create_xyz::<Chainstate, Chainstate>(client, EMILY_CHAINSTATE_ENDPOINT, request).await
}

/// Generic create function.
async fn create_xyz<T, R>(client: &Client, endpoint: &str, request: T) -> R
where
    T: Serialize,
    R: for<'de> Deserialize<'de>,
{
    client
        .post(endpoint)
        .json(&request)
        .send()
        .await
        .expect(&format!(
            "Failed to perform create Emily API call: [{endpoint}]"
        ))
        .json()
        .await
        .expect(&format!(
            "Failed to deserialize response from create Emily API call: [{endpoint}]"
        ))
}

// Get Many
// -----------------------------------------------------------------------------

/// Get all withdrawals.
pub async fn get_all_withdrawals(client: &Client) -> Vec<WithdrawalInfo> {
    let mut all_withdrawals: Vec<WithdrawalInfo> = Vec::new();
    for status in ALL_STATUSES {
        all_withdrawals.extend(
            get_all_withdrawals_with_status(client, status.clone())
                .await
                .into_iter(),
        );
    }
    all_withdrawals
}

/// Gets all withdrawals with a specified status.
pub async fn get_all_withdrawals_with_status(
    client: &Client,
    status: Status,
) -> Vec<WithdrawalInfo> {
    // Get all withdrawals with the given status.
    get_all_xyz_with_status::<GetWithdrawalsResponse, WithdrawalInfo>(
        client,
        EMILY_WITHDRAWAL_ENDPOINT,
        base_query_from_status(status),
        |response: &GetWithdrawalsResponse| response.next_token.clone(),
        |response: &GetWithdrawalsResponse| response.withdrawals.clone(),
    )
    .await
}

/// Get all deposits.
pub async fn get_all_deposits(client: &Client) -> Vec<DepositInfo> {
    let mut all_deposits: Vec<DepositInfo> = Vec::new();
    for status in ALL_STATUSES {
        all_deposits.extend(
            get_all_deposits_with_status(client, status.clone())
                .await
                .into_iter(),
        );
    }
    all_deposits
}

/// Gets all deposits with a specified status.
pub async fn get_all_deposits_with_status(client: &Client, status: Status) -> Vec<DepositInfo> {
    // Get all deposits with the given status.
    get_all_xyz_with_status::<GetDepositsResponse, DepositInfo>(
        client,
        EMILY_DEPOSIT_ENDPOINT,
        base_query_from_status(status),
        |response: &GetDepositsResponse| response.next_token.clone(),
        |response: &GetDepositsResponse| response.deposits.clone(),
    )
    .await
}

/// Creates a base query from a provided status.
fn base_query_from_status(status: Status) -> HashMap<String, String> {
    let mut base_query: HashMap<String, String> = HashMap::new();
    base_query.insert(
        "status".to_string(),
        serde_json::to_string(&status).expect("status param failed serialization."),
    );
    base_query
}

/// Generic get all function that will get all of the items from a specific API query
/// with a given status.
async fn get_all_xyz_with_status<R, I>(
    client: &Client,
    endpoint: &str,
    base_query: HashMap<String, String>,
    extract_token: fn(&R) -> Option<String>,
    extract_items: fn(&R) -> Vec<I>,
) -> Vec<I>
where
    R: for<'de> Deserialize<'de>,
{
    // Aggregate list to get accumulate items.
    let mut all_items: Vec<I> = Vec::new();
    // Make initial query.
    let mut response = client
        .get(endpoint)
        .query(&base_query.clone().into_iter().collect::<Vec<_>>())
        .send()
        .await
        .expect(&format!(
            "Failed to perform get many Emily API call: [{endpoint}]"
        ))
        .json()
        .await
        .expect(&format!(
            "Failed to deserialize response from get many Emily API call: [{endpoint}]"
        ));
    // Add items from latest response to accumulator list.
    all_items.extend(extract_items(&response).into_iter());
    // Loop until the `next_token` is null.
    while let Some(next_token) = extract_token(&response) {
        // Add next token to the query.
        let mut query = base_query.clone();
        query.insert("nextToken".to_string(), next_token.clone());
        response = client
            .get(endpoint)
            .query(&query.into_iter().collect::<Vec<_>>())
            .send()
            .await
            .expect(&format!(
                "Failed to perform get many Emily API call: [{endpoint}]"
            ))
            .json()
            .await
            .expect(&format!(
                "Failed to deserialize response from get many Emily API call: [{endpoint}]"
            ));
        // Add items from latest response to accumulator list.
        all_items.extend(extract_items(&response).into_iter());
    }
    all_items
}
