//! Testing helpers for api clients

use url::Url;

use crate::bitcoin::MockBitcoinInteract;
use crate::error::Error;

impl TryFrom<&[Url]> for MockBitcoinInteract {
    type Error = Error;

    fn try_from(_: &[Url]) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}
