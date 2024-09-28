//! Emily API client module

use emily_client::apis::deposit_api;
use emily_client::apis::configuration::Configuration as EmilyApiConfig;
use emily_client::apis::Error as EmilyError;
use sbtc::deposits::CreateDepositRequest;
use url::Url;

use crate::error::Error;
use crate::util::ApiFallbackClient;

/// Emily client error variants.
#[derive(Debug, thiserror::Error)]
pub enum EmilyClientError {
    /// Host is required
    #[error("invalid URL: host is required")]
    HostIsRequired(String),

    /// An error occurred while getting deposits
    #[error("error getting deposits: {0}")]
    GetDeposits(EmilyError<deposit_api::GetDepositsError>)
}

/// Trait describing the interactions with Emily API.
pub trait EmilyInteract {
    /// Get pending deposits from Emily.
    fn get_deposits(&self) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>>;
}

/// Emily API client.
pub struct EmilyClient {
    config: EmilyApiConfig,
}

impl TryFrom<&Url> for EmilyClient {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        let host = url.host_str()
            .ok_or_else(|| EmilyClientError::HostIsRequired(url.to_string()))?;

        let mut config = EmilyApiConfig::default();
        config.base_path = format!("{}://{}/{}", url.scheme(), host, url.path());
        config.basic_auth = Some((url.username().to_string(), url.password().map(String::from)));

        Ok(Self {
            config
        })
    }
}

impl EmilyInteract for EmilyClient {
    async fn get_deposits(&self) -> Result<Vec<CreateDepositRequest>, Error> {
        let _ = &self.config; // just to kill the unused warning for now
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
    fn get_deposits(&self) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> {
        self.exec(|client| client.get_deposits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_url() {
        let url = Url::parse("http://localhost:8080").unwrap();
        let client = EmilyClient::try_from(&url).unwrap();
        assert_eq!(client.config.base_path, "http://localhost:8080/");
    }
}