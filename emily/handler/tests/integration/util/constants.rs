//! Test constants.

use emily_handler::api::models::{common::Status, withdrawal::WithdrawalParameters};

pub const EMILY_ENDPOINT: &'static str = "http://localhost:3000";
pub const EMILY_WITHDRAWAL_ENDPOINT: &'static str = "http://localhost:3000/withdrawal";
pub const EMILY_DEPOSIT_ENDPOINT: &'static str = "http://localhost:3000/deposit";
pub const EMILY_CHAINSTATE_ENDPOINT: &'static str = "http://localhost:3000/chainstate";
pub const EMILY_TESTING_ENDPOINT: &'static str = "http://localhost:3000/testing";

pub const TEST_WITHDRAWAL_PARAMETERS: WithdrawalParameters = WithdrawalParameters { max_fee: 1234 };

pub const TEST_RECLAIM_SCRIPT: &'static str = "test-reclaim-script";
pub const TEST_DEPOSIT_SCRIPT: &'static str = "test-deposit-script";
pub const TEST_RECIPIENT: &'static str = "test-recipient";
pub const TEST_BITCOIN_TXID: &'static str = "test-bitcoin-txid";

/// Hacky exhasutive list of all statuses that we will iterate over in order to
/// get every deposit present.
pub const ALL_STATUSES: &[Status] = &[
    Status::Accepted,
    Status::Confirmed,
    Status::Failed,
    Status::Pending,
    Status::Reevaluating,
];
