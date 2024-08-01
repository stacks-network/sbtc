//! Test constants.

use emily_handler::api::models::common::Status;

pub const EMILY_ENDPOINT: &'static str = "http://localhost:3000";
pub const EMILY_WITHDRAWAL_ENDPOINT: &'static str = "http://localhost:3000/withdrawal";
pub const EMILY_DEPOSIT_ENDPOINT: &'static str = "http://localhost:3000/deposit";
pub const EMILY_CHAINSTATE_ENDPOINT: &'static str = "http://localhost:3000/chainstate";

/// Hacky exhasutive list of all statuses that we will iterate over in order to
/// get every deposit present.
pub const ALL_STATUSES: &[Status] = &[
    Status::Accepted,
    Status::Confirmed,
    Status::Failed,
    Status::Pending,
    Status::Reevaluating,
];
