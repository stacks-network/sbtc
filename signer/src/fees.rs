use std::future::Future;
use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

use crate::error::Error;

const FIVE_MINUTES_SECONDS: i64 = 300;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
enum FeeSource {
    BitcoinerLive(BitcoinerLive),
    MempoolSpace(MempoolSpace),
}

impl FeeEstimator for FeeSource {
    async fn estimate_fee_rate(&self, client: &Client) -> Result<FeeEstimate, Error> {
        match self {
            Self::BitcoinerLive(btclive) => btclive.estimate_fee_rate(client).await,
            Self::MempoolSpace(mempool) => mempool.estimate_fee_rate(client).await,
        }
    }
}

/// A struct representing requests to https://bitcoiner.live
/// 
/// The docs for this API can be found at https://bitcoiner.live/doc/api
#[derive(Debug, Clone)]
struct BitcoinerLive {
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct BitcoinerLiveResponse {
    /// Unix timestamp of when the data was last refreshed
    timestamp: i64,

    estimates: BitcoinerLiveEstimates,
}

/// BitcoinLive gives fee estimates given the target confirmation time in
/// minutes. This struct represents part of their JSON response when
/// requesting fee estimates.
///
/// In the actual response, there are also estimates for 60, 120, 180 and
/// 360 minutes.
#[derive(Debug, Deserialize)]
pub struct BitcoinerLiveEstimates {
    #[serde(alias = "30")]
    pub thirty: BitcoinerLiveFeeEstimate,
}

#[derive(Debug, Deserialize)]
pub struct BitcoinerLiveFeeEstimate {
    /// estimated fee rate in satoshis per virtual-byte
    sat_per_vbyte: f64,
}

/// A struct representing requests to https://mempool.space
/// 
/// The docs for this API can be found at https://mempool.space/docs/api,
/// while the specific docs for getting recommended fees can be found at
/// https://mempool.space/docs/api/rest#get-recommended-fees
#[derive(Debug, Clone)]
struct MempoolSpace {
    base_url: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MempoolSpaceResponse {
    fastest_fee: u64,
    half_hour_fee: u64,
    hour_fee: u64,
    economy_fee: u64,
    minimum_fee: u64,
}

/// A struct representing the recommended fee, in sats per vbtye, from a
/// particular source.
pub struct FeeEstimate {
    pub sats_per_vbyte: f64,
}

pub trait FeeEstimator {
    fn estimate_fee_rate(
        &self,
        client: &Client,
    ) -> impl Future<Output = Result<FeeEstimate, Error>> + Send;
}

impl FeeEstimator for BitcoinerLive {
    /// Fetch the fee estimate from bitcoiner.live.
    ///
    /// The returned value gives a fee estimate where there is a 90%
    /// probability that the transaction will be confirmed within 30
    /// minutes.
    async fn estimate_fee_rate(&self, client: &Client) -> Result<FeeEstimate, Error> {
        let url = format!(
            "{}/api/fees/estimates/latest?confidence=0.9",
            &self.base_url
        );
        let resp: BitcoinerLiveResponse = client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await?
            .json()
            .await?;

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if now - resp.timestamp > FIVE_MINUTES_SECONDS {
            return Err(Error::OldFeeEstimate);
        }

        Ok(FeeEstimate {
            sats_per_vbyte: resp.estimates.thirty.sat_per_vbyte,
        })
    }
}

impl FeeEstimator for MempoolSpace {
    /// Fetch the fee estimate from mempool.space
    /// 
    /// The returned value is the High Priority 
    async fn estimate_fee_rate(&self, client: &Client) -> Result<FeeEstimate, Error> {
        let url = format!("{}/api/v1/fees/recommended", &self.base_url);
        let resp: MempoolSpaceResponse = client
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await?
            .json()
            .await?;

        Ok(FeeEstimate {
            sats_per_vbyte: resp.fastest_fee as f64,
        })
    }
}

pub async fn estimate_fee_rate2<T>(sources: &[T], client: &Client) -> Result<f64, Error>
where
    T: FeeEstimator,
{
    let futures_iter = sources
        .iter()
        .map(|source| async move { source.estimate_fee_rate(client).await });
    let mut responses = futures::future::join_all(futures_iter).await;

    if responses.iter().all(Result::is_err) {
        return Err(Error::OldFeeEstimate);
    }

    responses.retain(Result::is_ok);
    let num_responses = responses.len();
    let sum = responses
        .into_iter()
        .filter_map(Result::ok)
        .map(|x| x.sats_per_vbyte)
        .sum::<f64>();
    Ok(sum / num_responses as f64)
}

pub async fn estimate_fee_rate(client: &Client) -> Result<f64, Error> {
    let fee_sources: [FeeSource; 2] = [
        FeeSource::MempoolSpace(MempoolSpace {
            base_url: "https://mempool.space".to_string(),
        }),
        FeeSource::BitcoinerLive(BitcoinerLive {
            base_url: "https://bitcoiner.live".to_string(),
        }),
    ];
    estimate_fee_rate2(&fee_sources, client).await
}
