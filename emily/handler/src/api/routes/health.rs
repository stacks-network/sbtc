//! Route definitions for the health endpoint.

use super::handlers;
use warp::Filter;

/// Health routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_health()
}

/// Get health endpoint.
fn get_health() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("health")
        .and(warp::get())
        .then(handlers::health::get_health)
}

// TODO(387): Add route unit tests.
