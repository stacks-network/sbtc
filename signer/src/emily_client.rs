//! Emily API client module

use std::str::FromStr;

use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use emily_client::apis::chainstate_api;
use emily_client::apis::configuration::ApiKey;
use emily_client::apis::configuration::Configuration as EmilyApiConfig;
use emily_client::apis::deposit_api;
use emily_client::apis::withdrawal_api;
use emily_client::apis::Error as EmilyError;
use emily_client::apis::ResponseContent;
use emily_client::models::Chainstate;
use emily_client::models::CreateWithdrawalRequestBody;
use emily_client::models::DepositUpdate;
use emily_client::models::Status;
use emily_client::models::UpdateDepositsRequestBody;
use emily_client::models::UpdateDepositsResponse;
use emily_client::models::UpdateWithdrawalsRequestBody;
use emily_client::models::UpdateWithdrawalsResponse;
use emily_client::models::Withdrawal;
use emily_client::models::WithdrawalUpdate;
use sbtc::deposits::CreateDepositRequest;
use url::Url;

use crate::bitcoin::utxo::RequestRef;
use crate::bitcoin::utxo::UnsignedTransaction;
use crate::config::EmilyClientConfig;
use crate::error::Error;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::StacksBlock;
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

    /// An error occurred while getting a deposit request
    #[error("error getting a deposit: {0}")]
    GetDeposit(EmilyError<deposit_api::GetDepositError>),

    /// An error occurred while getting deposits
    #[error("error getting deposits: {0}")]
    GetDeposits(EmilyError<deposit_api::GetDepositsError>),

    /// An error occurred while updating deposits
    #[error("error updating deposits: {0}")]
    UpdateDeposits(EmilyError<deposit_api::UpdateDepositsError>),

    /// An error occurred while creating withdrawals
    #[error("error creating withdrawals: {0}")]
    CreateWithdrawal(EmilyError<withdrawal_api::CreateWithdrawalError>),

    /// An error occurred while updating withdrawals
    #[error("error updating withdrawals: {0}")]
    UpdateWithdrawals(EmilyError<withdrawal_api::UpdateWithdrawalsError>),

    /// An error occurred while adding a chainstate entry
    #[error("error adding chainstate entry: {0}")]
    AddChainstateEntry(EmilyError<chainstate_api::SetChainstateError>),
}

/// Trait describing the interactions with Emily API.
#[cfg_attr(any(test, feature = "testing"), mockall::automock())]
pub trait EmilyInteract: Sync + Send {
    /// Get a deposit from Emily.
    fn get_deposit(
        &self,
        txid: &BitcoinTxId,
        output_index: u32,
    ) -> impl std::future::Future<Output = Result<Option<CreateDepositRequest>, Error>> + Send;

    /// Get pending deposits from Emily.
    fn get_deposits(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> + Send;

    /// Update accepted deposits after their sweep bitcoin transaction has been
    /// confirmed (but before being finalized -- the stacks transaction minting
    /// sBTC has not been confirmed yet).
    fn accept_deposits<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        stacks_chain_tip: &'a StacksBlock,
    ) -> impl std::future::Future<Output = Result<UpdateDepositsResponse, Error>> + Send;

    /// Update the status of deposits in Emily.
    fn update_deposits(
        &self,
        update_deposits: Vec<DepositUpdate>,
    ) -> impl std::future::Future<Output = Result<UpdateDepositsResponse, Error>> + Send;

    /// Create withdrawals in Emily.
    fn create_withdrawals(
        &self,
        create_withdrawals: Vec<CreateWithdrawalRequestBody>,
    ) -> impl std::future::Future<Output = Vec<Result<Withdrawal, Error>>> + Send;

    /// Update the status of withdrawals in Emily.
    fn update_withdrawals(
        &self,
        update_withdrawals: Vec<WithdrawalUpdate>,
    ) -> impl std::future::Future<Output = Result<UpdateWithdrawalsResponse, Error>> + Send;

    /// Set the chainstate in Emily. This could trigger a reorg.
    fn set_chainstate(
        &self,
        chainstate_entry: Chainstate,
    ) -> impl std::future::Future<Output = Result<Chainstate, Error>> + Send;
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

#[cfg(any(test, feature = "testing"))]
impl TryFrom<&Url> for EmilyClient {
    type Error = Error;
    /// Initialize a new Emily client from just a URL for testing scenarios.
    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        let mut url = url.clone();
        let api_key = if url.username().is_empty() {
            None
        } else {
            Some(ApiKey {
                prefix: None,
                key: url.username().to_string(),
            })
        };

        // Must be HTTP or HTTPS
        if !["http", "https"].contains(&url.scheme()) {
            return Err(EmilyClientError::InvalidUrlScheme(url.to_string()).into());
        }

        // Host cannot be empty
        if url.host_str().is_none() {
            return Err(EmilyClientError::InvalidUrlHostRequired(url.to_string()).into());
        }

        // We don't really care if this fails, the failure modes are handled by
        // the above checks. We just don't want the base_path below to contain
        // the api key.
        let _ = url.set_username("");

        let mut config = EmilyApiConfig::new();
        // Url::parse defaults `path` to `/` even if the parsed url was without the trailing `/`
        // causing the api calls to have two leading slashes in the path (getting a 404)
        config.base_path = url.to_string().trim_end_matches("/").to_string();
        config.api_key = api_key;

        Ok(Self { config })
    }
}

impl EmilyInteract for EmilyClient {
    async fn get_deposit(
        &self,
        txid: &BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<CreateDepositRequest>, Error> {
        let txid_str = txid.to_string();
        let index = output_index.to_string();

        let resp = deposit_api::get_deposit(&self.config, &txid_str, &index).await;

        let deposit = match resp {
            Ok(deposit) => deposit,
            Err(EmilyError::ResponseError(ResponseContent { status, .. }))
                if status.as_u16() == 404 =>
            {
                return Ok(None)
            }
            error => error.map_err(EmilyClientError::GetDeposit)?,
        };

        Ok(Some(CreateDepositRequest {
            outpoint: OutPoint {
                txid: Txid::from_str(&deposit.bitcoin_txid).map_err(Error::DecodeHexTxid)?,
                vout: deposit.bitcoin_tx_output_index,
            },
            reclaim_script: ScriptBuf::from_hex(&deposit.reclaim_script)
                .map_err(Error::DecodeHexScript)?,
            deposit_script: ScriptBuf::from_hex(&deposit.deposit_script)
                .map_err(Error::DecodeHexScript)?,
        }))
    }
    async fn get_deposits(&self) -> Result<Vec<CreateDepositRequest>, Error> {
        // TODO: hanlde pagination -- if the queried data is over 1MB DynamoDB will
        // paginate the results even if we pass `None` as page limit.
        let resp = deposit_api::get_deposits(&self.config, Status::Pending, None, None)
            .await
            .map_err(EmilyClientError::GetDeposits)
            .map_err(Error::EmilyApi)?;

        resp.deposits
            .iter()
            .map(|deposit| {
                Ok(CreateDepositRequest {
                    outpoint: OutPoint {
                        txid: Txid::from_str(&deposit.bitcoin_txid)
                            .map_err(Error::DecodeHexTxid)?,
                        vout: deposit.bitcoin_tx_output_index,
                    },
                    reclaim_script: ScriptBuf::from_hex(&deposit.reclaim_script)
                        .map_err(Error::DecodeHexScript)?,
                    deposit_script: ScriptBuf::from_hex(&deposit.deposit_script)
                        .map_err(Error::DecodeHexScript)?,
                })
            })
            .collect()
    }

    async fn update_deposits(
        &self,
        update_deposits: Vec<DepositUpdate>,
    ) -> Result<UpdateDepositsResponse, Error> {
        if update_deposits.is_empty() {
            return Ok(UpdateDepositsResponse { deposits: vec![] });
        }

        let update_request = UpdateDepositsRequestBody { deposits: update_deposits };
        deposit_api::update_deposits(&self.config, update_request)
            .await
            .map_err(EmilyClientError::UpdateDeposits)
            .map_err(Error::EmilyApi)
    }

    async fn accept_deposits<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        stacks_chain_tip: &'a StacksBlock,
    ) -> Result<UpdateDepositsResponse, Error> {
        let deposits = transaction
            .requests
            .iter()
            .filter_map(RequestRef::as_deposit);

        let update_request: Vec<_> = deposits
            .map(|deposit| DepositUpdate {
                bitcoin_tx_output_index: deposit.outpoint.vout,
                bitcoin_txid: deposit.outpoint.txid.to_string(),
                status: Status::Accepted,
                fulfillment: None,
                status_message: "".to_string(),
                last_update_block_hash: stacks_chain_tip.block_hash.to_string(),
                last_update_height: stacks_chain_tip.block_height,
            })
            .collect();

        self.update_deposits(update_request).await
    }

    async fn create_withdrawals(
        &self,
        create_withdrawals: Vec<CreateWithdrawalRequestBody>,
    ) -> Vec<Result<Withdrawal, Error>> {
        if create_withdrawals.is_empty() {
            return vec![];
        }

        let futures = create_withdrawals
            .into_iter()
            .map(|withdrawal| withdrawal_api::create_withdrawal(&self.config, withdrawal));

        let results = futures::future::join_all(futures).await;

        results
            .into_iter()
            .map(|result| {
                result
                    .map_err(EmilyClientError::CreateWithdrawal)
                    .map_err(Error::EmilyApi)
            })
            .collect()
    }

    async fn update_withdrawals(
        &self,
        update_withdrawals: Vec<WithdrawalUpdate>,
    ) -> Result<UpdateWithdrawalsResponse, Error> {
        if update_withdrawals.is_empty() {
            return Ok(UpdateWithdrawalsResponse { withdrawals: vec![] });
        }

        let update_request = UpdateWithdrawalsRequestBody {
            withdrawals: update_withdrawals,
        };
        withdrawal_api::update_withdrawals(&self.config, update_request)
            .await
            .map_err(EmilyClientError::UpdateWithdrawals)
            .map_err(Error::EmilyApi)
    }

    async fn set_chainstate(&self, chainstate: Chainstate) -> Result<Chainstate, Error> {
        chainstate_api::set_chainstate(&self.config, chainstate)
            .await
            .inspect_err(|error| tracing::info!(?error, "error for set_chainstate"))
            .map_err(EmilyClientError::AddChainstateEntry)
            .map_err(Error::EmilyApi)
    }
}

impl EmilyInteract for ApiFallbackClient<EmilyClient> {
    async fn get_deposit(
        &self,
        txid: &BitcoinTxId,
        output_index: u32,
    ) -> Result<Option<CreateDepositRequest>, Error> {
        self.exec(|client, _| client.get_deposit(txid, output_index))
            .await
    }

    fn get_deposits(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> {
        self.exec(|client, _| client.get_deposits())
    }

    async fn update_deposits(
        &self,
        update_deposits: Vec<DepositUpdate>,
    ) -> Result<UpdateDepositsResponse, Error> {
        self.exec(|client, _| client.update_deposits(update_deposits.clone()))
            .await
    }

    async fn accept_deposits<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        stacks_chain_tip: &'a StacksBlock,
    ) -> Result<UpdateDepositsResponse, Error> {
        self.exec(|client, _| client.accept_deposits(transaction, stacks_chain_tip))
            .await
    }

    async fn create_withdrawals(
        &self,
        create_withdrawals: Vec<CreateWithdrawalRequestBody>,
    ) -> Vec<Result<Withdrawal, Error>> {
        self.exec(|client, _| async {
            let withdrawals = client.create_withdrawals(create_withdrawals.clone()).await;
            Ok::<Vec<Result<Withdrawal, Error>>, Error>(withdrawals) // Wrap the Vec in Ok to satisfy exec's type constraints
        })
        .await
        .unwrap_or_else(|err| vec![Err(err)])
    }

    async fn update_withdrawals(
        &self,
        update_withdrawals: Vec<WithdrawalUpdate>,
    ) -> Result<UpdateWithdrawalsResponse, Error> {
        self.exec(|client, _| client.update_withdrawals(update_withdrawals.clone()))
            .await
    }

    async fn set_chainstate(&self, chainstate: Chainstate) -> Result<Chainstate, Error> {
        self.exec(|client, _| client.set_chainstate(chainstate.clone()))
            .await
    }
}

impl TryFrom<&EmilyClientConfig> for ApiFallbackClient<EmilyClient> {
    type Error = Error;

    fn try_from(config: &EmilyClientConfig) -> Result<Self, Self::Error> {
        let clients = config
            .endpoints
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
    fn try_from_url_with_key() {
        // Arrange.
        let url = Url::parse("http://test_key@localhost:8080").unwrap();
        // Act.
        let client = EmilyClient::try_from(&url).unwrap();
        // Assert.
        assert_eq!(client.config.base_path, "http://localhost:8080");
        assert_eq!(client.config.api_key.unwrap().key, "test_key");
    }

    #[test]
    fn try_from_url_without_key() {
        // Arrange.
        let url = Url::parse("http://localhost:8080").unwrap();
        // Act.
        let client = EmilyClient::try_from(&url).unwrap();
        // Assert.
        assert_eq!(client.config.base_path, "http://localhost:8080");
        assert!(client.config.api_key.is_none());
    }
}
