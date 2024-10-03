//! Emily API client module

use emily_client::apis::configuration::Configuration as EmilyApiConfig;
use emily_client::apis::deposit_api;
use emily_client::apis::Error as EmilyError;
use sbtc::deposits::CreateDepositRequest;
use url::Url;

use crate::error::Error;
use crate::util::ApiFallbackClient;

/// Emily client error variants.
#[derive(Debug, thiserror::Error)]
pub enum EmilyClientError {
    /// Scheme must be HTTP or HTTPS
    #[error("invalid URL scheme: {0}")]
    InvalidUrlScheme(String),

    /// Host is required
    #[error("invalid URL: host is required: {0}")]
    InvalidUrlHostRequired(String),

    /// An error occurred while getting deposits
    #[error("error getting deposits: {0}")]
    GetDeposits(EmilyError<deposit_api::GetDepositsError>),
}

/// Trait describing the interactions with Emily API.
#[cfg_attr(any(test, feature = "testing"), mockall::automock())]
pub trait EmilyInteract: Sync + Send {
    /// Get pending deposits from Emily.
    fn get_deposits(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> + Send;
}

/// Emily API client.
pub struct EmilyClient {
    config: EmilyApiConfig,
}

impl TryFrom<&Url> for EmilyClient {
    type Error = Error;

    /// Attempt to create an Emily client from a URL. Note that for the Signer,
    /// this should already have been validated by the configuration, but we do
    /// the checks here anyway to keep them close to the implementation.
    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        // Must be HTTP or HTTPS
        if !["http", "https"].contains(&url.scheme()) {
            return Err(EmilyClientError::InvalidUrlScheme(url.to_string()).into());
        }

        // Host cannot be empty
        if url.host_str().is_none() {
            return Err(EmilyClientError::InvalidUrlHostRequired(url.to_string()).into());
        }

        let mut config = EmilyApiConfig::new();
        config.base_path = url.to_string();

        Ok(Self { config })
    }
}

impl EmilyInteract for EmilyClient {
    async fn get_deposits(&self) -> Result<Vec<CreateDepositRequest>, Error> {
        // just to kill the unused warning for now (Self.config)
        let _ = &self.config;

        // TODO: We need to be able to build `CreateDepositRequests` from the `DepositInfo` response.
        // However, we don't have all of the information we need yet from Emily to do that.
        // For now, we'll just return an empty vector.
        Ok(vec![])

        // let _resp = deposit_api::get_deposits(
        //         &self.config,
        //         Status::Pending,
        //         None,
        //         None
        //     )
        //     .await
        //     .map_err(EmilyClientError::GetDeposits)?;
    }
}

impl EmilyInteract for ApiFallbackClient<EmilyClient> {
    fn get_deposits(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> {
        self.exec(|client, _| client.get_deposits())
    }
}

impl TryFrom<&[Url]> for ApiFallbackClient<EmilyClient> {
    type Error = Error;

    fn try_from(urls: &[Url]) -> Result<Self, Self::Error> {
        let clients = urls
            .iter()
            .map(EmilyClient::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(clients).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_url() {
        let url = Url::parse("http://localhost:8080").unwrap();
        let client = EmilyClient::try_from(&url).unwrap();
        assert_eq!(client.config.base_path, "http://localhost:8080/");
    }
}
