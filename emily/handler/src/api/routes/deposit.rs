//! Route definitions for the deposit endpoint.
use warp::Filter;

use crate::context::EmilyContext;

use super::handlers;

/// Deposit routes.
pub fn routes(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    get_deposit(context.clone())
        .or(get_deposits_for_transaction(context.clone()))
        .or(get_deposits(context.clone()))
        .or(get_deposits_for_recipient(context.clone()))
        .or(create_deposit(context.clone()))
        .or(update_deposits(context))
}

/// Get deposit endpoint.
fn get_deposit(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("deposit" / String / u32))
        .and(warp::get())
        .then(handlers::deposit::get_deposit)
}

/// Get deposits for transaction endpoint.
fn get_deposits_for_transaction(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("deposit" / String))
        .and(warp::get())
        .and(warp::query())
        .then(handlers::deposit::get_deposits_for_transaction)
}

/// Get deposits endpoint.
fn get_deposits(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("deposit"))
        .and(warp::get())
        .and(warp::query())
        .then(handlers::deposit::get_deposits)
}

/// Get deposits endpoint.
fn get_deposits_for_recipient(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("deposit" / "recipient" / String))
        .and(warp::get())
        .and(warp::query())
        .then(handlers::deposit::get_deposits_for_recipient)
}

/// Create deposit endpoint.
fn create_deposit(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("deposit"))
        .and(warp::post())
        .and(warp::body::json())
        .then(handlers::deposit::create_deposit)
}

/// Update deposits endpoint.
fn update_deposits(
    context: EmilyContext,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::any()
        .map(move || context.clone())
        .and(warp::path!("deposit"))
        .and(warp::put())
        .and(warp::header::<String>("x-api-key"))
        .and(warp::body::json())
        .then(handlers::deposit::update_deposits)
}

// TODO(387): Add route unit tests.
