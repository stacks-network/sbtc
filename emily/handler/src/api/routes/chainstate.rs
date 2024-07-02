//! Route definitions for the chainstate endpoint.

use warp::Filter;

use super::handlers;

/// Chainstate routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_chainstate()
        .or(set_chainstate())
        .or(update_chainstate())
}

/// Get chainstate endpoint.
fn get_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate" / u64)
        .and(warp::get())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::chainstate::get_chainstate)
}

/// Set chainstate endpoint.
fn set_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate")
        .and(warp::post())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::chainstate::set_chainstate)
}

/// Update chainstate endpoint.
fn update_chainstate() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("chainstate")
        .and(warp::put())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::chainstate::update_chainstate)
}
