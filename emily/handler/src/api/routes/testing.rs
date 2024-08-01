//! Route definitions for the testing endpoint.
use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Testing routes
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    wipe_databases(context)
}

/// Wipe databases
fn wipe_databases(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("testing" / "wipe"))
        .and(warp::post())
        .then(handlers::testing::wipe_databases)
}
