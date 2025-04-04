//! Fee rate estimation module

use std::future::Future;
use std::time::Duration;

use serde::Deserialize;

use crate::bitcoin::rpc::FeeEstimate;
use crate::error::Error;

const FIVE_MINUTES_SECONDS: i64 = 300;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Compute the current market fee rate by averaging the recommended price
/// estimates from various sources.
pub async fn estimate_fee_rate(client: &reqwest::Client) -> Result<FeeEstimate, Error> {
    let sources: [FeeSource; 2] = [
        FeeSource::MempoolSpace(MempoolSpace {
            base_url: "https://mempool.space".to_string(),
            client: client.clone(),
        }),
        FeeSource::BitcoinerLive(BitcoinerLive {
            base_url: "https://bitcoiner.live".to_string(),
            client: client.clone(),
        }),
    ];

    estimate_fee_rate_impl(&sources).await
}

/// Used to compute the average price of the fee estimates from the given
/// sources.
async fn estimate_fee_rate_impl<T>(sources: &[T]) -> Result<FeeEstimate, Error>
where
    T: EstimateFees,
{
    let futures_iter = sources
        .iter()
        .map(|source| async move { source.estimate_fee_rate().await });
    let mut responses = futures::future::join_all(futures_iter).await;

    if responses.iter().all(Result::is_err) {
        return Err(Error::NoGoodFeeEstimates);
    }

    responses.retain(Result::is_ok);
    let num_responses = responses.len();
    let sum_sats_per_vbyte = responses
        .into_iter()
        .filter_map(Result::ok)
        .map(|x| x.sats_per_vbyte)
        .sum::<f64>();

    let sats_per_vbyte = sum_sats_per_vbyte / num_responses as f64;
    Ok(FeeEstimate { sats_per_vbyte })
}

/// A struct representing requests to https://bitcoiner.live
///
/// The docs for this API can be found at https://bitcoiner.live/doc/api
#[derive(Debug, Clone)]
struct BitcoinerLive {
    base_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct BitcoinerLiveResponse {
    /// Unix timestamp of when the data was last refreshed
    timestamp: i64,
    /// The actual fee rate estimates.
    estimates: BitcoinerLiveEstimates,
}

/// BitcoinLive gives fee estimates given the target confirmation time in
/// minutes. This struct represents part of their JSON response when
/// requesting fee estimates.
///
/// In the actual response, there are also estimates for 60, 120, 180 and
/// 360 minutes.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct BitcoinerLiveEstimates {
    #[serde(alias = "30")]
    thirty: BitcoinerLiveFeeEstimate,
    #[serde(alias = "60")]
    sixty: BitcoinerLiveFeeEstimate,
}

/// A single fee estimate from bitcoiner.live
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
pub struct MempoolSpace {
    base_url: String,
    client: reqwest::Client,
}

impl MempoolSpace {
    /// Create a new MempoolSpace instance
    pub fn new(base_url: String, client: reqwest::Client) -> Self {
        Self { base_url, client }
    }
}

/// The response from mempool.space when requesting fee estimates
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MempoolSpaceResponse {
    fastest_fee: u64,
    half_hour_fee: u64,
    hour_fee: u64,
    economy_fee: u64,
    minimum_fee: u64,
}

/// Trait representing the ability to provide a fee rate estimation
pub trait EstimateFees {
    /// Estimate the current fee rate
    fn estimate_fee_rate(&self) -> impl Future<Output = Result<FeeEstimate, Error>> + Send;
}

const BITCOINER_LIVE_PATH: &str = "/api/fees/estimates/latest?confidence=0.9";

impl EstimateFees for BitcoinerLive {
    /// Fetch the fee estimate from bitcoiner.live.
    ///
    /// The returned value gives a fee estimate where there is a 90%
    /// probability that the transaction will be confirmed within 30
    /// minutes.
    async fn estimate_fee_rate(&self) -> Result<FeeEstimate, Error> {
        let url = format!("{}{BITCOINER_LIVE_PATH}", &self.base_url);
        let resp: BitcoinerLiveResponse = self
            .client
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

const MEMPOOL_SPACE_PATH: &str = "/api/v1/fees/recommended";

impl EstimateFees for MempoolSpace {
    /// Fetch the fee estimate from mempool.space
    ///
    /// The returned value is the High Priority fee rate displayed on
    /// https://mempool.space.
    async fn estimate_fee_rate(&self) -> Result<FeeEstimate, Error> {
        let url = format!("{}{MEMPOOL_SPACE_PATH}", &self.base_url);
        let resp: MempoolSpaceResponse = self
            .client
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

#[derive(Debug)]
enum FeeSource {
    BitcoinerLive(BitcoinerLive),
    MempoolSpace(MempoolSpace),
}

impl EstimateFees for FeeSource {
    async fn estimate_fee_rate(&self) -> Result<FeeEstimate, Error> {
        match self {
            Self::BitcoinerLive(btclive) => btclive.estimate_fee_rate().await,
            Self::MempoolSpace(mempool) => mempool.estimate_fee_rate().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct KnownFeeEstimator(f64);

    impl EstimateFees for KnownFeeEstimator {
        async fn estimate_fee_rate(&self) -> Result<FeeEstimate, Error> {
            Ok(FeeEstimate { sats_per_vbyte: self.0 })
        }
    }

    #[tokio::test]
    async fn average_fee_estimator_works() {
        let sources = [
            KnownFeeEstimator(1.),
            KnownFeeEstimator(3.),
            KnownFeeEstimator(5.),
            KnownFeeEstimator(7.),
            KnownFeeEstimator(9.),
        ];
        let est = estimate_fee_rate_impl(&sources).await.unwrap();

        assert_eq!(est.sats_per_vbyte, 5.);
    }

    #[tokio::test]
    async fn estimate_fee_rate_impl_happy_path() {
        let mempool_body =
            r#"{"fastestFee":13,"halfHourFee":11,"hourFee":11,"economyFee":10,"minimumFee":5}"#;
        // I've cut out some of the bodies here. There are keys for:
        // 120, 180, 360, 720, and 1440.
        // Also, I've modified the timestamp to be very far in the future.
        let bitcoiner_body = r#"{
            "timestamp": 171588751400000,
            "estimates": {
                "30": {
                    "sat_per_vbyte": 15,
                    "total": {
                        "p2wpkh": {
                            "usd": "NaN",
                            "satoshi": 2115
                        },
                        "p2sh-p2wpkh": {
                            "usd": "NaN",
                            "satoshi": 2490
                        },
                        "p2pkh": {
                            "usd": "NaN",
                            "satoshi": 3390
                        }
                    }
                },
                "60": {
                    "sat_per_vbyte": 14,
                    "total": {
                        "p2wpkh": {
                            "usd": "NaN",
                            "satoshi": 1974
                        },
                        "p2sh-p2wpkh": {
                            "usd": "NaN",
                            "satoshi": 2324
                        },
                        "p2pkh": {
                            "usd": "NaN",
                            "satoshi": 3164
                        }
                    }
                }
            }
        }"#;
        let mut mempool_server = mockito::Server::new_async().await;
        let mempool_mock = mempool_server
            .mock("GET", MEMPOOL_SPACE_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mempool_body)
            .expect(1)
            .create();

        let mut bitcoiner_server = mockito::Server::new_async().await;
        let bitcoiner_mock = bitcoiner_server
            .mock("GET", BITCOINER_LIVE_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(bitcoiner_body)
            .expect(1)
            .create();

        let client = reqwest::Client::new();

        let fee_sources: [FeeSource; 2] = [
            FeeSource::MempoolSpace(MempoolSpace {
                base_url: mempool_server.url(),
                client: client.clone(),
            }),
            FeeSource::BitcoinerLive(BitcoinerLive {
                base_url: bitcoiner_server.url(),
                client,
            }),
        ];

        let actual_estimate = estimate_fee_rate_impl(&fee_sources).await.unwrap();

        // The expected response here is (15 + 13) / 2 = 14.
        let expected_estimate = 14.0;
        assert_eq!(actual_estimate.sats_per_vbyte, expected_estimate);

        mempool_mock.assert();
        bitcoiner_mock.assert();
    }

    #[tokio::test]
    async fn estimate_fee_rate_impl_some_invalid_responses() {
        let mempool_body =
            r#"{"fastestFee":13,"halfHourFee":11,"hourFee":11,"economyFee":10,"minimumFee":5}"#;
        // Let's say we get an invalid response from bitcoiner
        let bitcoiner_body = "{}";

        let mut mempool_server = mockito::Server::new_async().await;
        let mempool_mock = mempool_server
            .mock("GET", MEMPOOL_SPACE_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mempool_body)
            .expect(1)
            .create();

        let mut bitcoiner_server = mockito::Server::new_async().await;
        let bitcoiner_mock = bitcoiner_server
            .mock("GET", BITCOINER_LIVE_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(bitcoiner_body)
            .expect(1)
            .create();

        let client = reqwest::Client::new();

        let fee_sources: [FeeSource; 2] = [
            FeeSource::MempoolSpace(MempoolSpace {
                base_url: mempool_server.url(),
                client: client.clone(),
            }),
            FeeSource::BitcoinerLive(BitcoinerLive {
                base_url: bitcoiner_server.url(),
                client,
            }),
        ];

        let actual_estimate = estimate_fee_rate_impl(&fee_sources).await.unwrap();

        // Only mempool responded, so only its response is used to compute
        // the average.
        let expected_estimate = 13.0;
        assert_eq!(actual_estimate.sats_per_vbyte, expected_estimate);

        mempool_mock.assert();
        bitcoiner_mock.assert();
    }

    #[tokio::test]
    async fn estimate_fee_rate_impl_all_invalid_responses() {
        // Let's say we get all invalid response
        let mempool_body = "{}";
        let bitcoiner_body = "{}";

        let mut mempool_server = mockito::Server::new_async().await;
        let mempool_mock = mempool_server
            .mock("GET", MEMPOOL_SPACE_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mempool_body)
            .expect(1)
            .create();

        let mut bitcoiner_server = mockito::Server::new_async().await;
        let bitcoiner_mock = bitcoiner_server
            .mock("GET", BITCOINER_LIVE_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(bitcoiner_body)
            .expect(1)
            .create();

        let client = reqwest::Client::new();

        let fee_sources: [FeeSource; 2] = [
            FeeSource::MempoolSpace(MempoolSpace {
                base_url: mempool_server.url(),
                client: client.clone(),
            }),
            FeeSource::BitcoinerLive(BitcoinerLive {
                base_url: bitcoiner_server.url(),
                client,
            }),
        ];

        let response = estimate_fee_rate_impl(&fee_sources).await;
        assert!(response.is_err());

        mempool_mock.assert();
        bitcoiner_mock.assert();
    }
}
