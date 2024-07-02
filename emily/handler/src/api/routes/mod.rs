//! Route definitiions for the Emily API.

use super::handlers;
use warp::Filter;

/// Deposit routes.
pub mod deposit;
/// Health routes.
pub mod health;

/// This function sets up the Warp filters for handling all requests.
pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // TODO(273):  Remove the "local" prefix once we figure out why all local
    // testing calls seem to forcibly start with `local`.
    warp::path("local")
        .and(health::routes()
            .or(deposit::routes()))
}
