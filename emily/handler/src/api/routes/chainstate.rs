//! Route definitions for the chainstate endpoint.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Chainstate routes.
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_chainstate_at_height(context.clone())
        .or(set_chainstate(context.clone()))
        .or(update_chainstate(context))
}

/// Get chainstate at height endpoint.
fn get_chainstate_at_height(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("chainstate" / u64))
        .and(warp::get())
        .then(handlers::chainstate::get_chainstate_at_height)
}

/// Set chainstate endpoint.
fn set_chainstate(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("chainstate"))
        .and(warp::post())
        .and(warp::body::json())
        .then(handlers::chainstate::set_chainstate)
}

/// Update chainstate endpoint.
fn update_chainstate(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("chainstate"))
        .and(warp::put())
        .and(warp::body::json())
        .then(handlers::chainstate::update_chainstate)
}

// TODO(TBD): Add route unit tests.
