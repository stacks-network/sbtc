//! Route definitions for the Emily API.

use crate::context::EmilyContext;

use super::handlers;
use tracing::debug;
use warp::Filter;

/// Chainstate routes.
mod chainstate;
/// Deposit routes.
mod deposit;
/// Health routes.
mod health;
/// Limit routes.
mod limits;
/// NewBlock routes.
mod new_block;
/// Testing routes.
#[cfg(feature = "testing")]
mod testing;
/// Withdrawal routes.
mod withdrawal;

// Filter that will print the response to the logs if set to debug.
fn log_response<T>(reply: T) -> (impl warp::Reply,)
where
    T: warp::Reply,
{
    let as_response = reply.into_response();
    tracing::debug!(
        event = ?"response",
        status = ?as_response.status().as_u16(),
        body = ?format!("{:?}", as_response.body()),
        headers = ?format!("{:?}", as_response.headers()),
    );
    (as_response,)
}

/// This function sets up the Warp filters for handling all requests.
#[cfg(feature = "testing")]
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // `.boxed()` erases the deeply nested filter type from multiple `.or()` calls,
    // making the return type manageable and preventing compilation errors and runtime stack overflows.
    health::routes(context.clone())
        .or(new_block::routes(context.clone()))
        .boxed()
        .or(chainstate::routes(context.clone()))
        .boxed()
        .or(deposit::routes(context.clone()))
        .boxed()
        .or(withdrawal::routes(context.clone()))
        .boxed()
        .or(limits::routes(context.clone()))
        .boxed()
        .or(testing::routes(context))
        .boxed()
        .or(verbose_not_found_route())
        .boxed()
        // Convert reply to tuple to that more routes can be added to the returned filter.
        .map(|reply| (reply,))
        .map(log_response)
}

/// This function sets the Warp filters for handling all requests.
#[cfg(not(feature = "testing"))]
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    health::routes(context.clone())
        .or(new_block::routes(context.clone()))
        .boxed()
        .or(chainstate::routes(context.clone()))
        .boxed()
        .or(deposit::routes(context.clone()))
        .boxed()
        .or(withdrawal::routes(context.clone()))
        .boxed()
        .or(limits::routes(context))
        .boxed()
        // Convert reply to tuple to that more routes can be added to the returned filter.
        .map(|reply| (reply,))
        .map(log_response)
}

/// This function sets up the routes expecting the AWS stage to be passed in as the very
/// first segment of the path. AWS does this by default, and it's not something we can
/// change.
pub fn routes_with_stage_prefix(
    context: EmilyContext,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    // Get the AWS Stage name and then ignore it, but print it in the logs if
    // we're in debug mode.
    warp::path::param::<String>()
        .and(routes(context))
        .map(|stage, reply| {
            debug!("AWS stage: {}", stage);
            (reply,)
        })
}

/// A verbose route that will return a 404 with the full path and peeked path.
///
/// This is useful if you called the API and it doesn't recognize the call that was made internally,
/// but APIGateway let it through.
#[cfg(feature = "testing")]
fn verbose_not_found_route(
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::get())
        .and(warp::path::full())
        .and(warp::path::peek())
        .map(|full_path, peek_path| {
            warp::reply::with_status(
                format!(
                    "Endpoint not found. Full: {:?} | Peek: {:?}",
                    full_path, peek_path
                ),
                warp::http::StatusCode::NOT_FOUND,
            )
        })
}
