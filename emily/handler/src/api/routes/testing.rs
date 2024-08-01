//! Route definitions for the deposit endpoint.
use warp::Filter;


use crate::context::EmilyContext;

use super::handlers;

/// Debug routes
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    wipe_databases(context.clone())
}

/// Wipe databases
fn wipe_databases(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!(
            "testing" / "wipe"
        ))
        .and(warp::post())
        .then(handlers::testing::wipe_databases)
}
