//! Route definitions for the chainstate endpoint.

use warp::Filter;

use super::handlers;
use crate::context::EmilyContext;

/// Chainstate routes.
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    register_signer(context.clone())
        .or(get_signer(context.clone()))
}

/// Register a specific signer.
fn register_signer(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("signer"))
        .and(warp::post())
        .and(warp::body::json())
        .then(handlers::signer::register_signer)
}

/// Get chainstate at height endpoint.
fn get_signer(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("signer" / String))
        .and(warp::get())
        .then(handlers::signer::get_signer)
}
