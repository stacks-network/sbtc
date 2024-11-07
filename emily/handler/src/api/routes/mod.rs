//! Route definitiions for the Emily API.

use crate::context::EmilyContext;

use super::handlers;
use warp::Filter;
use tracing::debug;

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

    warp::path::param::<String>()
        .and(health::routes()
            .or(chainstate::routes(context.clone()))
            .or(deposit::routes(context.clone()))
            .or(withdrawal::routes(context.clone()))
            .or(testing::routes(context))
            .or(not_found_route())
            // Convert reply to tuple to that more routes can be added to the returned filter.
            .map(|reply| (reply,))
        )
        .map(|path_prefix, reply| {
            debug!("Path prefix: {}", path_prefix);
            (reply,)
        })
}

/// This function sets the Warp filters for handling all requests.
#[cfg(not(feature = "testing"))]
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path::param::<String>()
        .and(health::routes()
            .or(chainstate::routes(context.clone()))
            .or(deposit::routes(context.clone()))
            .or(withdrawal::routes(context))
            .or(not_found_route())
            // Convert reply to tuple to that more routes can be added to the returned filter.
            .map(|reply| (reply,))
        ).map(|path_prefix, reply| {
            debug!("Path prefix: {}", path_prefix);
            (reply,)
        })
}

/// Handler for 404 errors.
fn not_found_route() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::get())
        .and(warp::path::full())
        .and(warp::path::peek())
        .map(|full_path, peek_path| {
            warp::reply::with_status(
            format!("Not Found. Full: {:?} | Peek: {:?}", full_path, peek_path),
            warp::http::StatusCode::NOT_FOUND,
            )
        })
}
