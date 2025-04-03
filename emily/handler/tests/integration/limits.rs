use std::collections::HashMap;

use test_case::test_case;

use testing_emily_client::apis;
use testing_emily_client::models;
use testing_emily_client::models::AccountLimits;
use testing_emily_client::models::Chainstate;
use testing_emily_client::models::Limits;
use testing_emily_client::models::{CreateWithdrawalRequestBody, WithdrawalParameters};

use crate::common::StandardError;
use crate::common::{batch_set_chainstates, clean_setup, new_test_chainstate};

#[tokio::test]
async fn empty_default_is_as_expected() {
    let configuration = clean_setup().await;

    let expected_empty_default = models::Limits {
        available_to_withdraw: Some(None),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(None),
        rolling_withdrawal_blocks: Some(None),
        rolling_withdrawal_cap: Some(None),
        account_caps: HashMap::new(),
    };

    let limits = apis::limits_api::get_limits(&configuration)
        .await
        .expect("Failed to get limits during empty default test.");

    assert_eq!(limits, expected_empty_default);
}

#[tokio::test]
async fn adding_and_then_updating_single_accout_limit_works() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let limits_to_set = vec![
        (
            "test_account",
            AccountLimits {
                peg_cap: Some(Some(100)),
                per_deposit_minimum: Some(Some(100)),
                per_deposit_cap: Some(Some(100)),
                per_withdrawal_cap: Some(Some(100)),
                rolling_withdrawal_blocks: Some(Some(100)),
                rolling_withdrawal_cap: Some(Some(100)),
            },
        ),
        (
            "test_account_2",
            AccountLimits {
                peg_cap: Some(Some(1200)),
                per_deposit_minimum: Some(Some(1200)),
                per_deposit_cap: Some(Some(1200)),
                per_withdrawal_cap: Some(Some(1200)),
                rolling_withdrawal_blocks: Some(Some(1200)),
                rolling_withdrawal_cap: Some(Some(1200)),
            },
        ),
        (
            "test_account_2",
            AccountLimits {
                peg_cap: Some(Some(100)),
                per_deposit_minimum: Some(Some(200)),
                per_deposit_cap: Some(Some(300)),
                per_withdrawal_cap: Some(Some(500)),
                rolling_withdrawal_blocks: Some(Some(600)),
                rolling_withdrawal_cap: Some(Some(700)),
            },
        ),
        (
            "test_account_2",
            AccountLimits {
                peg_cap: Some(Some(200)),
                per_deposit_minimum: Some(Some(200)),
                per_deposit_cap: Some(Some(200)),
                per_withdrawal_cap: Some(Some(200)),
                rolling_withdrawal_blocks: Some(Some(200)),
                rolling_withdrawal_cap: Some(Some(200)),
            },
        ),
        (
            "test_account",
            AccountLimits {
                peg_cap: Some(Some(300)),
                per_deposit_minimum: Some(Some(300)),
                per_deposit_cap: Some(Some(300)),
                per_withdrawal_cap: Some(Some(300)),
                rolling_withdrawal_blocks: Some(Some(300)),
                rolling_withdrawal_cap: Some(Some(300)),
            },
        ),
    ];

    // Set the expected account caps at the end to be the most recently
    // applied limits.
    let expected_account_caps: HashMap<String, AccountLimits> = vec![
        (
            "test_account_2",
            AccountLimits {
                peg_cap: Some(Some(200)),
                per_deposit_minimum: Some(Some(200)),
                per_deposit_cap: Some(Some(200)),
                per_withdrawal_cap: Some(Some(200)),
                rolling_withdrawal_blocks: Some(Some(200)),
                rolling_withdrawal_cap: Some(Some(200)),
            },
        ),
        (
            "test_account",
            AccountLimits {
                peg_cap: Some(Some(300)),
                per_deposit_minimum: Some(Some(300)),
                per_deposit_cap: Some(Some(300)),
                per_withdrawal_cap: Some(Some(300)),
                rolling_withdrawal_blocks: Some(Some(300)),
                rolling_withdrawal_cap: Some(Some(300)),
            },
        ),
    ]
    .iter()
    .map(|(account_name, limits)| (account_name.to_string(), limits.clone()))
    .collect();

    // The global limits should show the latest account caps.
    let expected_limits = Limits {
        available_to_withdraw: Some(None),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(None),
        rolling_withdrawal_blocks: Some(None),
        rolling_withdrawal_cap: Some(None),
        account_caps: expected_account_caps.clone(),
    };

    // Act.
    // ----
    for (account_name, limit_to_set) in limits_to_set {
        apis::limits_api::set_limits_for_account(
            &configuration,
            account_name,
            limit_to_set.clone(),
        )
        .await
        .expect("Failed to set limit for an account during test.");
    }

    // Get the account limits for each account that we expect to have a value for
    // individually to check the `get_limits_for_account` api.
    let mut individually_retrieved_account_caps: HashMap<String, AccountLimits> = HashMap::new();
    for (account_name, _) in expected_account_caps.clone() {
        individually_retrieved_account_caps.insert(
            account_name.clone(),
            apis::limits_api::get_limits_for_account(&configuration, &account_name)
                .await
                .expect("Failed to get limit for a specific account during test."),
        );
    }

    // Get the global limits.
    let global_limits = apis::limits_api::get_limits(&configuration)
        .await
        .expect("Failed to get limits during test.");

    // Assert.
    // -------
    assert_eq!(individually_retrieved_account_caps, expected_account_caps);
    assert_eq!(global_limits, expected_limits);
}

#[tokio::test]
async fn test_updating_account_limits_via_global_limit_works() {
    let configuration = clean_setup().await;

    // Arrange.
    // --------
    let account_limits_to_set_individually = vec![
        (
            "test_account_1",
            AccountLimits {
                peg_cap: Some(Some(100)),
                per_deposit_minimum: Some(Some(100)),
                per_deposit_cap: Some(Some(100)),
                per_withdrawal_cap: Some(Some(100)),
                rolling_withdrawal_blocks: Some(Some(100)),
                rolling_withdrawal_cap: Some(Some(100)),
            },
        ),
        (
            "test_account_2",
            AccountLimits {
                peg_cap: Some(Some(150)),
                per_deposit_minimum: Some(Some(150)),
                per_deposit_cap: Some(Some(150)),
                per_withdrawal_cap: Some(Some(150)),
                rolling_withdrawal_blocks: Some(Some(150)),
                rolling_withdrawal_cap: Some(Some(150)),
            },
        ),
        (
            "test_account_4",
            AccountLimits {
                peg_cap: Some(Some(150)),
                per_deposit_minimum: Some(Some(150)),
                per_deposit_cap: Some(Some(150)),
                per_withdrawal_cap: Some(Some(150)),
                rolling_withdrawal_blocks: Some(Some(150)),
                rolling_withdrawal_cap: Some(Some(150)),
            },
        ),
    ];

    // Set the expected account caps at the end to be the most recently
    // applied limits.
    let account_limits_to_set_globally: HashMap<String, AccountLimits> = vec![
        (
            "test_account_2",
            AccountLimits {
                peg_cap: Some(Some(200)),
                per_deposit_minimum: Some(Some(200)),
                per_deposit_cap: Some(Some(200)),
                per_withdrawal_cap: Some(Some(200)),
                rolling_withdrawal_blocks: Some(Some(200)),
                rolling_withdrawal_cap: Some(Some(200)),
            },
        ),
        (
            "test_account_3",
            AccountLimits {
                peg_cap: Some(Some(300)),
                per_deposit_minimum: Some(Some(300)),
                per_deposit_cap: Some(Some(300)),
                per_withdrawal_cap: Some(Some(300)),
                rolling_withdrawal_blocks: Some(Some(300)),
                rolling_withdrawal_cap: Some(Some(300)),
            },
        ),
        // Set all the values to none so this account should no longer show up
        // in any lists.
        (
            "test_account_4",
            AccountLimits {
                peg_cap: Some(None),
                per_deposit_minimum: Some(None),
                per_deposit_cap: Some(None),
                per_withdrawal_cap: Some(None),
                rolling_withdrawal_blocks: Some(None),
                rolling_withdrawal_cap: Some(None),
            },
        ),
    ]
    .iter()
    .map(|(account_name, limits)| (account_name.to_string(), limits.clone()))
    .collect();
    let global_limits_to_set = Limits {
        available_to_withdraw: Some(None),
        peg_cap: Some(Some(123)),
        per_deposit_minimum: Some(Some(654)),
        per_deposit_cap: Some(Some(456)),
        per_withdrawal_cap: Some(Some(789)),
        rolling_withdrawal_blocks: Some(Some(101)),
        rolling_withdrawal_cap: Some(Some(112)),
        account_caps: account_limits_to_set_globally.clone(),
    };

    // Set the expected account caps at the end to be the most recently
    // applied limits.
    let expected_global_account_limits: HashMap<String, AccountLimits> = vec![
        (
            "test_account_1",
            AccountLimits {
                peg_cap: Some(Some(100)),
                per_deposit_minimum: Some(Some(100)),
                per_deposit_cap: Some(Some(100)),
                per_withdrawal_cap: Some(Some(100)),
                rolling_withdrawal_blocks: Some(Some(100)),
                rolling_withdrawal_cap: Some(Some(100)),
            },
        ),
        (
            "test_account_2",
            AccountLimits {
                peg_cap: Some(Some(200)),
                per_deposit_minimum: Some(Some(200)),
                per_deposit_cap: Some(Some(200)),
                per_withdrawal_cap: Some(Some(200)),
                rolling_withdrawal_blocks: Some(Some(200)),
                rolling_withdrawal_cap: Some(Some(200)),
            },
        ),
        (
            "test_account_3",
            AccountLimits {
                peg_cap: Some(Some(300)),
                per_deposit_minimum: Some(Some(300)),
                per_deposit_cap: Some(Some(300)),
                per_withdrawal_cap: Some(Some(300)),
                rolling_withdrawal_blocks: Some(Some(300)),
                rolling_withdrawal_cap: Some(Some(300)),
            },
        ),
    ]
    .iter()
    .map(|(account_name, limits)| (account_name.to_string(), limits.clone()))
    .collect();
    let expected_global_limits = Limits {
        available_to_withdraw: Some(Some(112)),
        peg_cap: Some(Some(123)),
        per_deposit_minimum: Some(Some(654)),
        per_deposit_cap: Some(Some(456)),
        per_withdrawal_cap: Some(Some(789)),
        rolling_withdrawal_blocks: Some(Some(101)),
        rolling_withdrawal_cap: Some(Some(112)),
        account_caps: expected_global_account_limits.clone(),
    };

    let chainstates: Vec<Chainstate> = (0..103)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;

    // Act.
    // ----
    for (account_name, limit_to_set) in account_limits_to_set_individually {
        apis::limits_api::set_limits_for_account(
            &configuration,
            account_name,
            limit_to_set.clone(),
        )
        .await
        .expect("Failed to set limit for an account during test.");
    }
    let global_limits_returned_on_set =
        apis::limits_api::set_limits(&configuration, global_limits_to_set.clone())
            .await
            .expect("Failed to set global limits during test.");

    // Get the account limits for each account that we expect to have a value for
    // individually to check the `get_limits_for_account` api.
    let mut individually_retrieved_account_caps: HashMap<String, AccountLimits> = HashMap::new();
    for (account_name, _) in expected_global_account_limits.clone() {
        individually_retrieved_account_caps.insert(
            account_name.clone(),
            apis::limits_api::get_limits_for_account(&configuration, &account_name)
                .await
                .expect("Failed to get limit for a specific account during test."),
        );
    }

    // Get the global limits.
    let global_limits = apis::limits_api::get_limits(&configuration)
        .await
        .expect("Failed to get limits during test.");

    // Assert.
    // -------
    assert_eq!(
        individually_retrieved_account_caps,
        expected_global_account_limits
    );
    assert_eq!(global_limits_returned_on_set, expected_global_limits);
    assert_eq!(global_limits, expected_global_limits);
}

#[test_case(Some(100), None)]
#[test_case(None, Some(100))]
#[tokio::test]
async fn test_incomplete_rolling_withdrawal_limit_config_returns_error(
    rolling_withdrawal_blocks: Option<u64>,
    rolling_withdrawal_cap: Option<u64>,
) {
    let configuration = clean_setup().await;

    // Arrange.
    let limits = Limits {
        available_to_withdraw: Some(None),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(None),
        rolling_withdrawal_blocks: Some(rolling_withdrawal_blocks),
        rolling_withdrawal_cap: Some(rolling_withdrawal_cap),
        account_caps: HashMap::new(),
    };

    // Act.
    let result: StandardError = apis::limits_api::set_limits(&configuration, limits.clone())
    .await
    .expect_err("Expected an error to be returned when setting incomplete withdrawal limit configuration.")
    .into();

    // Assert.
    assert_eq!(result.status_code, 400);
}

#[test_case(Some(100), Some(100))]
#[test_case(None, None)]
#[tokio::test]
async fn test_complete_rolling_withdrawal_limit_config_works(
    rolling_withdrawal_blocks: Option<u64>,
    rolling_withdrawal_cap: Option<u64>,
) {
    let configuration = clean_setup().await;

    let limits = Limits {
        available_to_withdraw: Some(rolling_withdrawal_cap),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(None),
        rolling_withdrawal_blocks: Some(rolling_withdrawal_blocks),
        rolling_withdrawal_cap: Some(rolling_withdrawal_cap),
        account_caps: HashMap::new(),
    };
    if let Some(window_size) = rolling_withdrawal_blocks {
        // Set some chainstates to make set_limits work
        let chainstates: Vec<Chainstate> = (0..window_size + 2)
            .map(|height| new_test_chainstate(height, height, 0))
            .collect();
        let _ = batch_set_chainstates(&configuration, chainstates).await;
    }

    let result = apis::limits_api::set_limits(&configuration, limits.clone()).await;
    assert!(result.is_ok());

    let global_limits = apis::limits_api::get_limits(&configuration).await;
    assert!(global_limits.is_ok());
    assert_eq!(global_limits.unwrap(), limits);
}

// Tests correctness of available_to_withdraw calculation in case, where there is no chainstate
// on height (tip - window size).
#[tokio::test]
async fn test_available_to_withdraw_no_chainstate_in_db_at_target_height() {
    let configuration = clean_setup().await;

    // Set limits
    let limits = Limits {
        available_to_withdraw: Some(None),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(None),
        rolling_withdrawal_blocks: Some(Some(100)),
        rolling_withdrawal_cap: Some(Some(10_000)),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..110)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;

    let result = apis::limits_api::set_limits(&configuration, limits.clone()).await;
    assert!(result.is_ok());

    // Create chainstates
    let min_height = 1000;
    let max_height = 1010;
    let expected_chainstates: Vec<Chainstate> = (min_height..max_height + 1)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, expected_chainstates.clone()).await;

    // Create withdrawal
    // Setup test withdrawal transaction.
    let request = CreateWithdrawalRequestBody {
        amount: 1000,
        parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
        recipient: "test_recepient".into(),
        sender: "test_sender".into(),
        request_id: 1,
        stacks_block_hash: "test_hash".into(),
        stacks_block_height: 1005,
        txid: "test_txid".into(),
    };

    apis::withdrawal_api::create_withdrawal(&configuration, request.clone())
        .await
        .expect("Received an error after making a valid create withdrawal request api call.");

    // Get limits and perform assertions
    let limits = apis::limits_api::get_limits(&configuration).await;

    assert!(limits.is_ok());
    assert_eq!(limits.unwrap().available_to_withdraw, Some(Some(9000)));
}

#[tokio::test]
async fn test_available_to_withdraw_success() {
    let configuration = clean_setup().await;

    // Set limits
    let limits = Limits {
        available_to_withdraw: Some(None),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(None),
        rolling_withdrawal_blocks: Some(Some(10)),
        rolling_withdrawal_cap: Some(Some(10_000)),
        account_caps: HashMap::new(),
    };
    // Set some chainstates to make set_limits work
    let chainstates: Vec<Chainstate> = (0..12)
        .map(|height| new_test_chainstate(height, height, 0))
        .collect();
    let _ = batch_set_chainstates(&configuration, chainstates).await;
    let result = apis::limits_api::set_limits(&configuration, limits.clone()).await;
    assert!(result.is_ok());

    // Create chainstates
    let min_bitcoin_height = 1_000_000;
    let max_bitcoin_height = 1_000_020;
    let stacks_block_per_bitcoin_block = 5;
    let mut stacks_height = 2_000_000;
    let mut chainstates: Vec<_> = Default::default();

    for bitcoin_height in min_bitcoin_height..max_bitcoin_height {
        for _ in 0..stacks_block_per_bitcoin_block {
            let chainstate = new_test_chainstate(bitcoin_height, stacks_height, 0);
            chainstates.push(chainstate);
            stacks_height += 1;
        }
    }

    let _ = batch_set_chainstates(&configuration, chainstates).await;

    // Create withdrawals

    // bitcoin heights in window: [1_000_010;1_000_019] (both sides including)
    // stacks heights in window: [2_000_050;2_000_099] (both sides including)

    // Here we put different amount to withdrawals that should be included in window and to ones that shouldn't.
    // Thus, if total sum is correct, then only correct withdrawals was counted
    for (stacks_height, amount) in [
        (2_000_050, 1000),
        (2_000_049, 999),
        (2_000_099, 1000),
        (2_000_070, 1000),
    ] {
        let request = CreateWithdrawalRequestBody {
            amount,
            parameters: Box::new(WithdrawalParameters { max_fee: 100 }),
            recipient: "test_recepient".into(),
            sender: "test_sender".into(),
            request_id: stacks_height,
            stacks_block_hash: "test_hash".into(),
            stacks_block_height: stacks_height,
            txid: "test_txid".into(),
        };

        apis::withdrawal_api::create_withdrawal(&configuration, request.clone())
            .await
            .expect("Received an error after making a valid create withdrawal request api call.");
    }

    // Get limits and perform assertions
    let limits = apis::limits_api::get_limits(&configuration)
        .await
        .expect("failed to get limits during a valid api call");
    assert_eq!(limits.available_to_withdraw, Some(Some(7000)))
}
