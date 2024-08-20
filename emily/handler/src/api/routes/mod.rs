//! Route definitiions for the Emily API.

use crate::context::EmilyContext;

use super::handlers;
use warp::Filter;

/// Chainstate routes.
mod chainstate;
/// Deposit routes.
mod deposit;
/// Health routes.
mod health;
/// Testing routes.
#[cfg(feature = "testing")]
mod testing;
/// Withdrawal routes.
mod withdrawal;

/// This function sets up the Warp filters for handling all requests.
#[cfg(feature = "testing")]
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    health::routes()
        .or(chainstate::routes(context.clone()))
        .or(deposit::routes(context.clone()))
        .or(withdrawal::routes(context.clone()))
        .or(testing::routes(context))
        // Convert reply to tuple to that more routes can be added to the returned filter.
        .map(|reply| (reply,))
}

/// This function sets the Warp filters for handling all requests.
#[cfg(not(feature = "testing"))]
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    health::routes()
        .or(chainstate::routes(context.clone()))
        .or(deposit::routes(context.clone()))
        .or(withdrawal::routes(context))
        // Convert reply to tuple to that more routes can be added to the returned filter.
        .map(|reply| (reply,))
}
