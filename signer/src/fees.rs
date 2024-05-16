use std::future::Future;
use std::time::Duration;

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
    async fn estimate_fee_rate(&self, client: &reqwest::Client) -> Result<FeeEstimate, Error> {
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

/// A struct representing the recommended fee, in sats per vbyte, from a
/// particular source.
#[derive(Debug)]
pub struct FeeEstimate {
    pub sats_per_vbyte: f64,
}

pub trait FeeEstimator {
    fn estimate_fee_rate(
        &self,
        client: &reqwest::Client,
    ) -> impl Future<Output = Result<FeeEstimate, Error>> + Send;
}

impl FeeEstimator for BitcoinerLive {
    /// Fetch the fee estimate from bitcoiner.live.
    ///
    /// The returned value gives a fee estimate where there is a 90%
    /// probability that the transaction will be confirmed within 30
    /// minutes.
    async fn estimate_fee_rate(&self, client: &reqwest::Client) -> Result<FeeEstimate, Error> {
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
    /// The returned value is the High Priority fee rate displayed on
    /// https://mempool.space.
    async fn estimate_fee_rate(&self, client: &reqwest::Client) -> Result<FeeEstimate, Error> {
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

/// Compute the average price of the fee estimates from the given sources.
async fn estimate_fee_rate_impl<T>(sources: &[T], client: &reqwest::Client) -> Result<f64, Error>
where
    T: FeeEstimator,
{
    let futures_iter = sources
        .iter()
        .map(|source| async move { source.estimate_fee_rate(client).await });
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

    Ok(sum_sats_per_vbyte / num_responses as f64)
}

pub async fn estimate_fee_rate(client: &reqwest::Client) -> Result<f64, Error> {
    let fee_sources: [FeeSource; 2] = [
        FeeSource::MempoolSpace(MempoolSpace {
            base_url: "https://mempool.space".to_string(),
        }),
        FeeSource::BitcoinerLive(BitcoinerLive {
            base_url: "https://bitcoiner.live".to_string(),
        }),
    ];
    estimate_fee_rate_impl(&fee_sources, client).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to setup a mock API response
    fn setup_mock(method: &str, path: &str, status: usize, body: &str) -> mockito::Mock {
        return mockito::mock(method, path)
            .with_status(status)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create();
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "integration-tests"), ignore)]
    async fn prod_estimate_fee_rate_works() {
        let client = reqwest::Client::new();

        let ans = estimate_fee_rate(&client).await.unwrap();
        more_asserts::assert_gt!(ans, 0.0);
    }

    #[tokio::test]
    async fn estimate_fee_rate_impl_happy_path() {
        let mempool_body =
            r#"{"fastestFee":13,"halfHourFee":11,"hourFee":11,"economyFee":10,"minimumFee":5}"#;
        // I've cut out some of the bodys here. There are keys for:
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
        let status = 200;

        let mempool_path = "/api/v1/fees/recommended";
        let mempool_mock = setup_mock("GET", mempool_path, status, mempool_body).expect(1);

        let bitcoiner_path = "/api/fees/estimates/latest?confidence=0.9";
        let bitcoiner_mock = setup_mock("GET", bitcoiner_path, status, bitcoiner_body).expect(1);

        let fee_sources: [FeeSource; 2] = [
            FeeSource::MempoolSpace(MempoolSpace {
                base_url: mockito::server_url(),
            }),
            FeeSource::BitcoinerLive(BitcoinerLive {
                base_url: mockito::server_url(),
            }),
        ];

        let client = reqwest::Client::new();
        let actual_estimate = estimate_fee_rate_impl(&fee_sources, &client).await.unwrap();

        // The expected response here is (15 + 13) / 2 = 14.
        let expected_estimate = 14.0;
        assert_eq!(actual_estimate, expected_estimate);

        mempool_mock.assert();
        bitcoiner_mock.assert();
    }

    #[tokio::test]
    async fn estimate_fee_rate_impl_some_invalid_responses() {
        let mempool_body =
            r#"{"fastestFee":13,"halfHourFee":11,"hourFee":11,"economyFee":10,"minimumFee":5}"#;
        // Let's say we get an invalid response from bitcoiner
        let bitcoiner_body = "{}";
        let status = 200;

        let mempool_path = "/api/v1/fees/recommended";
        let mempool_mock = setup_mock("GET", mempool_path, status, mempool_body).expect(1);

        let bitcoiner_path = "/api/fees/estimates/latest?confidence=0.9";
        let bitcoiner_mock = setup_mock("GET", bitcoiner_path, status, bitcoiner_body).expect(1);

        let fee_sources: [FeeSource; 2] = [
            FeeSource::MempoolSpace(MempoolSpace {
                base_url: mockito::server_url(),
            }),
            FeeSource::BitcoinerLive(BitcoinerLive {
                base_url: mockito::server_url(),
            }),
        ];

        let client = reqwest::Client::new();
        let actual_estimate = estimate_fee_rate_impl(&fee_sources, &client).await.unwrap();

        // Only mempool responded, so only its response is used to compute
        // the average.
        let expected_estimate = 13.0;
        assert_eq!(actual_estimate, expected_estimate);

        mempool_mock.assert();
        bitcoiner_mock.assert();
    }

    #[tokio::test]
    async fn estimate_fee_rate_impl_all_invalid_responses() {
        // Let's say we get all invalid response
        let mempool_body = "{}";
        let bitcoiner_body = "{}";
        let status = 200;

        let mempool_path = "/api/v1/fees/recommended";
        let mempool_mock = setup_mock("GET", mempool_path, status, mempool_body).expect(1);

        let bitcoiner_path = "/api/fees/estimates/latest?confidence=0.9";
        let bitcoiner_mock = setup_mock("GET", bitcoiner_path, status, bitcoiner_body).expect(1);

        let fee_sources: [FeeSource; 2] = [
            FeeSource::MempoolSpace(MempoolSpace {
                base_url: mockito::server_url(),
            }),
            FeeSource::BitcoinerLive(BitcoinerLive {
                base_url: mockito::server_url(),
            }),
        ];

        let client = reqwest::Client::new();
        let response = estimate_fee_rate_impl(&fee_sources, &client).await;
        assert!(response.is_err());

        mempool_mock.assert();
        bitcoiner_mock.assert();
    }
}
