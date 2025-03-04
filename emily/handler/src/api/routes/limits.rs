//! Route definitions for the limits endpoint.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Limits routes.
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_limits(context.clone())
        .or(set_limits(context.clone()))
        .boxed()
        .or(set_limits_for_account(context.clone()))
        .boxed()
        .or(get_limits_for_account(context))
        .boxed()
}

/// Get limits endpoint.
fn get_limits(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("limits"))
        .and(warp::get())
        .then(handlers::limits::get_limits)
}

/// Set limits endpoint.
fn set_limits(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("limits"))
        .and(warp::post())
        .and(warp::body::json())
        .then(handlers::limits::set_limits)
}

/// Endpoint to set the limits for a specific account.
fn set_limits_for_account(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("limits" / String))
        .and(warp::post())
        .and(warp::body::json())
        .then(handlers::limits::set_limits_for_account)
}

/// Endpoint to get the limits for a specific account.
fn get_limits_for_account(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("limits" / String))
        .and(warp::get())
        .then(handlers::limits::get_limits_for_account)
}
