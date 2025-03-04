//! Route definitions for the new_block endpoint.

use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// New block routes.
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    new_block(context.clone())
}

/// New block endpoint.
fn new_block(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("new_block"))
        .and(warp::post())
        .and(warp::body::json())
        .then(handlers::new_block::new_block)
}
