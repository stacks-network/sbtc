use std::collections::HashMap;

use test_case::test_case;

use testing_emily_client::apis;
use testing_emily_client::models;
use testing_emily_client::models::AccountLimits;
use testing_emily_client::models::Limits;

use crate::common::clean_setup;
use crate::common::StandardError;

#[tokio::test]
async fn empty_default_is_as_expected() {
    let configuration = clean_setup().await;

    let expected_empty_default = models::Limits {
        available_to_withdraw: Some(Some(u64::MAX)),
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
        available_to_withdraw: Some(Some(u64::MAX)),
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
        available_to_withdraw: Some(Some(1000)),
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
        available_to_withdraw: Some(None),
        peg_cap: Some(Some(123)),
        per_deposit_minimum: Some(Some(654)),
        per_deposit_cap: Some(Some(456)),
        per_withdrawal_cap: Some(Some(789)),
        rolling_withdrawal_blocks: Some(Some(101)),
        rolling_withdrawal_cap: Some(Some(112)),
        account_caps: expected_global_account_limits.clone(),
    };

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

    // Unlike other fields, available_to_withdraw cannot be set directly, instead it is calculated based on
    // other settings and state of Emily.
    // If any of rolling_withdrawal_blocks or rolling_withdrawal_cap are none, we treat it as "no withdrawal cap set",
    // and return limit equal to u64::MAX.
    // If both of them are Some, in this test available_to_withdraw will be calculated as Some, because there are no data in
    // Emily db and it is impossible to calculate such value.
    let available_to_withdraw =
        if rolling_withdrawal_blocks.is_some() && rolling_withdrawal_cap.is_some() {
            None
        } else {
            Some(u64::MAX)
        };

    let limits = Limits {
        available_to_withdraw: Some(available_to_withdraw),
        peg_cap: Some(None),
        per_deposit_minimum: Some(None),
        per_deposit_cap: Some(None),
        per_withdrawal_cap: Some(None),
        rolling_withdrawal_blocks: Some(rolling_withdrawal_blocks),
        rolling_withdrawal_cap: Some(rolling_withdrawal_cap),
        account_caps: HashMap::new(),
    };

    let result = apis::limits_api::set_limits(&configuration, limits.clone()).await;
    assert_eq!(result.is_ok(), true);

    let global_limits = apis::limits_api::get_limits(&configuration).await;
    assert_eq!(global_limits.is_ok(), true);
    assert_eq!(global_limits.unwrap(), limits);
}
