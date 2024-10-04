//! Emily API client module

use std::str::FromStr;

use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use emily_client::apis::configuration::Configuration as EmilyApiConfig;
use emily_client::apis::deposit_api;
use emily_client::apis::Error as EmilyError;
use emily_client::models::DepositUpdate;
use emily_client::models::Fulfillment;
use emily_client::models::Status;
use emily_client::models::UpdateDepositsRequestBody;
use emily_client::models::UpdateDepositsResponse;
use sbtc::deposits::CreateDepositRequest;
use url::Url;

use crate::bitcoin::utxo::RequestRef;
use crate::bitcoin::utxo::UnsignedTransaction;
use crate::error::Error;
use crate::storage::model::BitcoinBlockRef;
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

    /// An error occurred while updating deposits
    #[error("error updating deposits: {0}")]
    UpdateDeposits(EmilyError<deposit_api::UpdateDepositsError>),
}

/// Trait describing the interactions with Emily API.
#[cfg_attr(any(test, feature = "testing"), mockall::automock())]
pub trait EmilyInteract: Sync + Send {
    /// Get pending deposits from Emily.
    fn get_deposits(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> + Send;

    /// Update deposits.
    fn update_broadcasted_deposits<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        bitcoin_chain_tip: &'a BitcoinBlockRef,
    ) -> impl std::future::Future<Output = Result<UpdateDepositsResponse, Error>> + Send;
}

/// Emily API client.
#[derive(Clone)]
pub struct EmilyClient {
    config: EmilyApiConfig,
}

#[cfg(any(test, feature = "testing"))]
impl EmilyClient {
    /// Get the client config
    pub fn config(&self) -> &EmilyApiConfig {
        &self.config
    }
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
        // Url::parse defaults `path` to `/` even if the parsed url was without the trailing `/`
        // causing the api calls to have two leading slashes in the path (getting a 404)
        config.base_path = url.to_string().trim_end_matches("/").to_string();

        Ok(Self { config })
    }
}

impl EmilyInteract for EmilyClient {
    async fn get_deposits(&self) -> Result<Vec<CreateDepositRequest>, Error> {
        let resp = deposit_api::get_deposits(&self.config, Status::Pending, None, None)
            .await
            .map_err(EmilyClientError::GetDeposits)
            .map_err(Error::EmilyApi)?;

        // TODO: fetch multiple pages?
        resp.deposits
            .iter()
            .map(|deposit| {
                Ok(CreateDepositRequest {
                    outpoint: OutPoint {
                        txid: Txid::from_str(&deposit.bitcoin_txid)
                            .map_err(|_| Error::TypeConversion)?,
                        vout: deposit.bitcoin_tx_output_index,
                    },
                    reclaim_script: ScriptBuf::from_hex(&deposit.reclaim_script)
                        .map_err(|_| Error::TypeConversion)?,
                    deposit_script: ScriptBuf::from_hex(&deposit.deposit_script)
                        .map_err(|_| Error::TypeConversion)?,
                })
            })
            .collect()
    }

    async fn update_broadcasted_deposits<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        bitcoin_chain_tip: &'a BitcoinBlockRef,
    ) -> Result<UpdateDepositsResponse, Error> {
        let deposits = transaction
            .requests
            .iter()
            .filter_map(RequestRef::as_deposit);

        let mut update_request = Vec::new();
        for deposit in deposits {
            update_request.push(DepositUpdate {
                bitcoin_tx_output_index: deposit.outpoint.vout,
                bitcoin_txid: deposit.outpoint.txid.to_string(),
                last_update_block_hash: bitcoin_chain_tip.block_hash.to_string(),
                last_update_height: bitcoin_chain_tip.block_height,
                status: Status::Accepted,
                fulfillment: Some(Some(Box::new(Fulfillment {
                    bitcoin_txid: transaction.tx.compute_txid().to_string(),
                    btc_fee: transaction.tx_fee,
                    // For accepted requests we don't have a block, nor a tx index
                    bitcoin_block_hash: "".to_string(),
                    bitcoin_block_height: 0,
                    bitcoin_tx_index: 0,
                    stacks_txid: "".to_string(),
                }))),
                status_message: "".to_string(),
            });
        }

        if update_request.is_empty() {
            // Skip the call
            return Ok(UpdateDepositsResponse { deposits: vec![] });
        }

        let update_request = UpdateDepositsRequestBody { deposits: update_request };

        deposit_api::update_deposits(&self.config, update_request)
            .await
            .map_err(EmilyClientError::UpdateDeposits)
            .map_err(Error::EmilyApi)
    }
}

impl EmilyInteract for ApiFallbackClient<EmilyClient> {
    fn get_deposits(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> {
        self.exec(|client, _| client.get_deposits())
    }

    async fn update_broadcasted_deposits<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        bitcoin_chain_tip: &'a BitcoinBlockRef,
    ) -> Result<UpdateDepositsResponse, Error> {
        self.exec(|client, _| client.update_broadcasted_deposits(transaction, bitcoin_chain_tip))
            .await
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
        assert_eq!(client.config.base_path, "http://localhost:8080");
    }
}
