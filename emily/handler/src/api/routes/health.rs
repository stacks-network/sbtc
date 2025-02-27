//! Route definitions for the health endpoint.

use crate::context::EmilyContext;

use super::handlers;
use warp::Filter;

/// Health routes.
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_health(context)
}

/// Get health endpoint.
fn get_health(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("health")
        .map(move || context.clone())
        .and(warp::get())
        .then(handlers::health::get_health)
}

// TODO(387): Add route unit tests.
