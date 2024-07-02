//! Route definitions for the withdrawal endpoint.
use warp::Filter;

use super::handlers;

/// Withdrawal routes.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_withdrawal()
        .or(get_withdrawals())
        .or(create_withdrawal())
        .or(update_withdrawals())
}

/// Get withdrawal endpoint.
fn get_withdrawal() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal" / u64)
        .and(warp::get())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::withdrawal::get_withdrawal)
}

/// Get withdrawals endpoint.
fn get_withdrawals() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::get())
        .and(warp::query())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::withdrawal::get_withdrawals)
}

/// Create withdrawal endpoint.
fn create_withdrawal() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::post())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::withdrawal::create_withdrawal)
}

/// Update withdrawals endpoint.
fn update_withdrawals() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("withdrawal")
        .and(warp::put())
        .and(warp::body::json())
        // Only get full path because the handler is unimplemented.
        .and(warp::path::full())
        .map(handlers::withdrawal::update_withdrawals)
}
