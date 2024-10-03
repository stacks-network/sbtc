//! Testing helpers for api clients

use url::Url;

use crate::bitcoin::MockBitcoinInteract;
use crate::config::Settings;
use crate::error::Error;
use crate::stacks::api::MockStacksInteract;

impl TryFrom<&[Url]> for MockBitcoinInteract {
    type Error = Error;

    fn try_from(_: &[Url]) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

impl TryFrom<&Settings> for MockStacksInteract {
    type Error = Error;

    fn try_from(_: &Settings) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}
