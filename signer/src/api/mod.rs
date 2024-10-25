//! This module contains functions and structs for the Signer API.
//!

pub mod new_block;
pub mod status;

use emily_client::models::Chainstate;
use emily_client::models::UpdateDepositsResponse;
use emily_client::models::UpdateWithdrawalsResponse;
use emily_client::models::Withdrawal;
pub use new_block::new_block_handler;
pub use status::status_handler;

use crate::error::Error;

/// A struct with state data necessary for runtime operation.
#[derive(Debug, Clone)]
pub struct ApiState<C> {
    /// For writing to the database.
    pub ctx: C,
}

/// The name of the sbtc registry smart contract.
const SBTC_REGISTRY_CONTRACT_NAME: &str = "sbtc-registry";

enum UpdateResult {
    Deposit(Result<UpdateDepositsResponse, Error>),
    Withdrawal(Result<UpdateWithdrawalsResponse, Error>),
    CreatedWithdrawal(Vec<Result<Withdrawal, Error>>),
    Chainstate(Result<Chainstate, Error>),
}
