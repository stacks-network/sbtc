//! Emily API client module

use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use emily_client::apis::configuration::ApiKey;
use emily_client::apis::configuration::Configuration as EmilyApiConfig;
use emily_client::apis::deposit_api;
use emily_client::apis::limits_api;
use emily_client::apis::withdrawal_api;
use emily_client::apis::Error as EmilyError;
use emily_client::apis::ResponseContent;
use emily_client::models::DepositInfo;
use emily_client::models::DepositUpdate;
use emily_client::models::Status;
use emily_client::models::UpdateDepositsRequestBody;
use emily_client::models::UpdateDepositsResponse;
use emily_client::models::UpdateWithdrawalsRequestBody;
use emily_client::models::UpdateWithdrawalsResponse;
use emily_client::models::WithdrawalUpdate;
use sbtc::deposits::CreateDepositRequest;
use url::Url;

use crate::bitcoin::utxo::RequestRef;
use crate::bitcoin::utxo::UnsignedTransaction;
use crate::config::EmilyClientConfig;
use crate::context::SbtcLimits;
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

    /// An error occurred while updating withdrawals
    #[error("error updating withdrawals: {0}")]
    UpdateWithdrawals(EmilyError<withdrawal_api::UpdateWithdrawalsError>),

    /// An error occurred while getting limits
    #[error("error getting limits: {0}")]
    GetLimits(EmilyError<limits_api::GetLimitsError>),
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

    /// Get pending and accepted deposits to process from Emily.
    fn get_deposits(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> + Send;

    /// Get pending deposits with a specific status from Emily.
    fn get_deposits_with_status(
        &self,
        status: Status,
    ) -> impl std::future::Future<Output = Result<Vec<CreateDepositRequest>, Error>> + Send;

    /// Update accepted deposits after their sweep bitcoin transaction has been
    /// confirmed (but before being finalized -- the stacks transaction minting
    /// sBTC has not been confirmed yet).
    fn accept_deposits<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        stacks_chain_tip: &'a StacksBlock,
    ) -> impl std::future::Future<Output = Result<UpdateDepositsResponse, Error>> + Send;

    /// Update accepted withdrawals after their sweep bitcoin transaction has
    /// been submitted (but before being finalized -- the stacks transaction
    /// accepting the withdrawal has not been submitted yet).
    fn accept_withdrawals<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        stacks_chain_tip: &'a StacksBlock,
    ) -> impl std::future::Future<Output = Result<UpdateWithdrawalsResponse, Error>> + Send;

    /// Update the status of deposits in Emily.
    fn update_deposits(
        &self,
        update_deposits: Vec<DepositUpdate>,
    ) -> impl std::future::Future<Output = Result<UpdateDepositsResponse, Error>> + Send;

    /// Update the status of withdrawals in Emily.
    fn update_withdrawals(
        &self,
        update_withdrawals: Vec<WithdrawalUpdate>,
    ) -> impl std::future::Future<Output = Result<UpdateWithdrawalsResponse, Error>> + Send;

    /// Gets the current sBTC-cap limits from Emily.
    fn get_limits(&self) -> impl std::future::Future<Output = Result<SbtcLimits, Error>> + Send;
}

/// Emily API client.
#[derive(Clone)]
pub struct EmilyClient {
    config: EmilyApiConfig,
    pagination_timeout: Duration,
    /// Maximum items returned per page. When set, responses will be limited to this many items.
    /// Regardless of the page_size setting, responses are always capped at 1 MB total size.
    /// If None, only the 1 MB cap applies.
    page_size: Option<u32>,
}

impl EmilyClient {
    /// Get the client config
    pub fn config(&self) -> &EmilyApiConfig {
        &self.config
    }

    /// Initialize a new Emily client and validate the url.
    pub fn try_new(
        url: &Url,
        pagination_timeout: Duration,
        page_size: Option<u16>,
    ) -> Result<Self, Error> {
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

        Ok(Self {
            config,
            pagination_timeout,
            // Page size must be u16 despite autogenerated client using u32.
            // This limitation exists because Emily needs to pass the parameter
            // to DynamoDB's as a i32.
            page_size: page_size.map(|size| size as u32),
        })
    }

    fn parse_deposit(deposit: &DepositInfo) -> Result<CreateDepositRequest, Error> {
        Ok(CreateDepositRequest {
            outpoint: OutPoint {
                txid: Txid::from_str(&deposit.bitcoin_txid).map_err(Error::DecodeHexTxid)?,
                vout: deposit.bitcoin_tx_output_index,
            },
            reclaim_script: ScriptBuf::from_hex(&deposit.reclaim_script)
                .map_err(Error::DecodeHexScript)?,
            deposit_script: ScriptBuf::from_hex(&deposit.deposit_script)
                .map_err(Error::DecodeHexScript)?,
        })
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
        let pending_deposits = self.get_deposits_with_status(Status::Pending).await;
        let accepted_deposits = self.get_deposits_with_status(Status::Accepted).await;

        match (pending_deposits, accepted_deposits) {
            (Err(pending_err), Err(_accepted_err)) => {
                // If both calls fail, return the error from the first call
                Err(pending_err)
            }
            (Ok(pending), Err(accepted_err)) => {
                // If the pending call succeeds, return the pending deposits
                tracing::warn!("failed to fetch accepted deposits: {:?}", accepted_err);
                Ok(pending)
            }
            (Err(pending_err), Ok(accepted)) => {
                // If the pending call fails, return the accepted deposits
                tracing::warn!("failed to fetch pending deposits: {:?}", pending_err);
                Ok(accepted)
            }
            (Ok(mut pending), Ok(mut accepted)) => {
                // Combine the results
                pending.append(&mut accepted);
                Ok(pending)
            }
        }
    }

    async fn get_deposits_with_status(
        &self,
        status: Status,
    ) -> Result<Vec<CreateDepositRequest>, Error> {
        let mut all_deposits = Vec::new();
        let mut next_token: Option<String> = None;
        let start_time = Instant::now();
        loop {
            let resp = match deposit_api::get_deposits(
                &self.config,
                status,
                next_token.as_deref(),
                self.page_size,
            )
            .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    if all_deposits.is_empty() {
                        return Err(Error::EmilyApi(EmilyClientError::GetDeposits(e)));
                    }
                    tracing::warn!("failed to fetch page of deposits: {:?}", e);
                    break;
                }
            };
            // Convert each DepositInfo to our CreateDepositRequest
            for deposit in resp.deposits.iter() {
                match Self::parse_deposit(deposit) {
                    Ok(req) => all_deposits.push(req),
                    Err(e) => tracing::warn!(
                        "Skipping corrupted deposit (txid: {}): {:?}",
                        deposit.bitcoin_txid,
                        e
                    ),
                }
            }

            // If more pages exist, loop again; otherwise stop
            match resp.next_token.flatten() {
                Some(token) => next_token = Some(token),
                None => break,
            }

            if start_time.elapsed() > self.pagination_timeout {
                tracing::warn!(
                    "timeout fetching deposits, breaking at page {:?}, fetched {} deposits",
                    next_token,
                    all_deposits.len()
                );
                break;
            }
        }

        Ok(all_deposits)
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

    async fn accept_withdrawals<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        stacks_chain_tip: &'a StacksBlock,
    ) -> Result<UpdateWithdrawalsResponse, Error> {
        let withdrawals = transaction
            .requests
            .iter()
            .filter_map(RequestRef::as_withdrawal);

        let update_request: Vec<_> = withdrawals
            .map(|withdrawal| WithdrawalUpdate {
                request_id: withdrawal.request_id,
                fulfillment: None,
                status: Status::Accepted,
                status_message: "".to_string(),
                last_update_block_hash: stacks_chain_tip.block_hash.to_string(),
                last_update_height: stacks_chain_tip.block_height,
            })
            .collect();

        self.update_withdrawals(update_request).await
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

    async fn get_limits(&self) -> Result<SbtcLimits, Error> {
        let limits = limits_api::get_limits(&self.config)
            .await
            .map_err(EmilyClientError::GetLimits)
            .map_err(Error::EmilyApi)?;

        let total_cap = limits.peg_cap.flatten().map(Amount::from_sat);
        let per_deposit_minimum = limits.per_deposit_minimum.flatten().map(Amount::from_sat);
        let per_deposit_cap = limits.per_deposit_cap.flatten().map(Amount::from_sat);
        let per_withdrawal_cap = limits.per_withdrawal_cap.flatten().map(Amount::from_sat);
        let rolling_withdrawal_blocks = limits.rolling_withdrawal_blocks.flatten();
        let rolling_withdrawal_cap = limits
            .rolling_withdrawal_cap
            .flatten()
            .map(Amount::from_sat);

        Ok(SbtcLimits::new(
            total_cap,
            per_deposit_minimum,
            per_deposit_cap,
            per_withdrawal_cap,
            rolling_withdrawal_blocks,
            rolling_withdrawal_cap,
            None,
        ))
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

    async fn get_deposits(&self) -> Result<Vec<CreateDepositRequest>, Error> {
        self.exec(|client, _| client.get_deposits()).await
    }

    async fn get_deposits_with_status(
        &self,
        status: Status,
    ) -> Result<Vec<CreateDepositRequest>, Error> {
        self.exec(|client, _| client.get_deposits_with_status(status))
            .await
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

    async fn accept_withdrawals<'a>(
        &'a self,
        transaction: &'a UnsignedTransaction<'a>,
        stacks_chain_tip: &'a StacksBlock,
    ) -> Result<UpdateWithdrawalsResponse, Error> {
        self.exec(|client, _| client.accept_withdrawals(transaction, stacks_chain_tip))
            .await
    }

    async fn update_withdrawals(
        &self,
        update_withdrawals: Vec<WithdrawalUpdate>,
    ) -> Result<UpdateWithdrawalsResponse, Error> {
        self.exec(|client, _| client.update_withdrawals(update_withdrawals.clone()))
            .await
    }

    async fn get_limits(&self) -> Result<SbtcLimits, Error> {
        self.exec(|client, _| client.get_limits()).await
    }
}

impl TryFrom<&EmilyClientConfig> for ApiFallbackClient<EmilyClient> {
    type Error = Error;

    fn try_from(config: &EmilyClientConfig) -> Result<Self, Self::Error> {
        let clients = config
            .endpoints
            .iter()
            .map(|url| EmilyClient::try_new(url, config.pagination_timeout, None))
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
        let client = EmilyClient::try_new(&url, Duration::from_secs(1), None).unwrap();
        // Assert.
        assert_eq!(client.config.base_path, "http://localhost:8080");
        assert_eq!(client.config.api_key.unwrap().key, "test_key");
    }

    #[test]
    fn try_from_url_without_key() {
        // Arrange.
        let url = Url::parse("http://localhost:8080").unwrap();
        // Act.
        let client = EmilyClient::try_new(&url, Duration::from_secs(1), None).unwrap();
        // Assert.
        assert_eq!(client.config.base_path, "http://localhost:8080");
        assert!(client.config.api_key.is_none());
    }
}
