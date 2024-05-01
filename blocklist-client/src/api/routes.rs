use super::handlers;
use crate::config::Settings;
use std::convert::Infallible;
use warp::Filter;

pub fn routes(
    settings: &Settings,
) -> impl Filter<Extract = impl warp::Reply, Error = Infallible> + Clone {
    let config = settings.risk_analysis.clone();

    warp::path("screen")
        .and(warp::path::param::<String>())
        .and(warp::get())
        .and(warp::any().map(move || config.clone()))
        .and_then(handlers::check_address_handler)
        .recover(handlers::handle_rejection)
}
