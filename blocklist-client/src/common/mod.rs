use serde::Serialize;
use std::fmt;
use warp::reject::Reject;

#[derive(Debug)]
pub enum Error {
    AddressNotFound,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub(crate) message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Reject for Error {}
