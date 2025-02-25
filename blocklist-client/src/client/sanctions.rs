//! This module interacts with the risk API to determine the risk severity associated with a user wallet address.
//!
//! It provides functionality to:
//! - Check if given address is under sanctions
//!
//! The module includes functions to handle API requests, interpret responses, and map them to application-specific errors.

use crate::common::error::Error;
use crate::common::{BlocklistStatus, RiskAssessment, RiskSeverity};
use crate::config::RiskAnalysisConfig;
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use std::error::Error as StdError;
use tracing::debug;
const API_BASE_PATH: &str = "/api/v1/address";

/// Represents the identification information for a blockchain address.
#[derive(Debug, Deserialize)]
pub struct Identification {
    /// The Chainalysis Entity category. For sanctioned addresses, the value will be 'sanctions'.
    #[serde(rename = "category")]
    pub _category: String,
    /// The OFAC name associated with the sanctioned address.
    #[serde(rename = "name")]
    pub _name: Option<String>,
    /// The OFAC description of the sanctioned address.
    #[serde(rename = "description")]
    pub _description: Option<String>,
    /// The OFAC URL for more information about the sanctioned address.
    #[serde(rename = "url")]
    pub _url: Option<String>,
}

/// Response structure of the sanctions API
#[derive(Debug, Deserialize)]
pub struct SanctionsResponse {
    /// Array with sanctions data. If empty, the address is not blocklisted.
    pub identifications: Vec<Identification>,
}

fn risk_assessment_path(base_url: &str, address: &str) -> String {
    format!("{}{}/{}", base_url, API_BASE_PATH, address)
}

/// Check risk status associated with a registered address
async fn get_risk_assessment(
    client: &Client,
    config: &RiskAnalysisConfig,
    address: &str,
) -> Result<RiskAssessment, Error> {
    let api_url = risk_assessment_path(&config.api_url, address);
    debug!("Beginning risk assessment for address: {address}");
    let response = client
        .get(&api_url)
        .header("X-API-Key", &config.api_key)
        .header("Accept", "application/json")
        .send()
        .await?;
    let checked_response = check_api_response(response).await?;
    let resp_result = checked_response.json::<SanctionsResponse>().await;
    // Currently this client can produce only two risks: Low and Severe. If the response contains any
    // identifications (which mean address is under sanctions), the risk is Severe. Otherwise, it is Low.
    match resp_result {
        Ok(resp) => {
            if resp.identifications.is_empty() {
                Ok(RiskAssessment {
                    severity: RiskSeverity::Low,
                    reason: None,
                })
            } else {
                Ok(RiskAssessment {
                    severity: RiskSeverity::Severe,
                    reason: Some("sanctions".to_string()),
                })
            }
        }
        Err(e) if e.is_decode() => {
            // Check if the source of the error is serde_json::Error
            if let Some(serde_err) = e
                .source()
                .and_then(|cause| cause.downcast_ref::<serde_json::Error>())
            {
                match serde_err.classify() {
                    serde_json::error::Category::Data => Err(Error::InvalidApiResponse),
                    _ => Err(Error::Serialization(serde_err.to_string())),
                }
            } else {
                Err(Error::Network(e))
            }
        }
        Err(e) => Err(Error::Network(e)),
    }
}

/// Screen the provided address for blocklist status
/// Marks the address as not accepted if it is identified as high risk
pub async fn check_address(
    client: &Client,
    config: &RiskAnalysisConfig,
    address: &str,
) -> Result<BlocklistStatus, Error> {
    let RiskAssessment { severity, reason } = get_risk_assessment(client, config, address).await?;
    debug!(
        "Received risk assessment: Severity = {}, Reason = {:?}",
        severity, reason
    );
    let is_severe = severity.is_severe();
    let blocklist_status = BlocklistStatus {
        // `is_blocklisted` is set to true if risk is Severe
        is_blocklisted: is_severe,
        severity,
        // `accept` is set to false if severity is Severe
        accept: !is_severe,
        reason,
    };

    Ok(blocklist_status)
}

/// Evaluates the HTTP response from an API request and translates HTTP status codes into application-specific errors
async fn check_api_response(response: Response) -> Result<Response, Error> {
    match response.status() {
        StatusCode::OK | StatusCode::CREATED => Ok(response),
        StatusCode::BAD_REQUEST => Err(Error::HttpRequest(
            response.status(),
            "Bad request - Invalid parameters or data".to_string(),
        )),
        StatusCode::FORBIDDEN => Err(Error::Unauthorized),
        StatusCode::NOT_FOUND => Err(Error::NotFound),
        StatusCode::NOT_ACCEPTABLE => Err(Error::NotAcceptable),
        StatusCode::CONFLICT => Err(Error::Conflict),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::InternalServer),
        StatusCode::SERVICE_UNAVAILABLE => Err(Error::ServiceUnavailable),
        StatusCode::REQUEST_TIMEOUT => Err(Error::RequestTimeout),
        status => Err(Error::HttpRequest(
            status,
            "Unhandled status code".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::RiskSeverity::{Low, Severe};
    use mockito::{Server, ServerGuard};

    const TEST_ADDRESS: &str = "test_address";

    // Setup function for common client and configuration
    fn setup_client(server: &ServerGuard) -> (Client, RiskAnalysisConfig) {
        let client = Client::new();
        let config = RiskAnalysisConfig {
            api_url: server.url(),
            api_key: "dummy_api_key".to_string(),
        };
        (client, config)
    }

    #[tokio::test]
    async fn test_get_risk_assessment_high_risk() {
        let response_json = r#"{
   "identifications": [
       {
           "category": "sanctions",
           "name": "SANCTIONS: OFAC SDN Secondeye Solution 2021-04-15 1da5821544e25c636c1417ba96ade4cf6d2f9b5a",
           "description": "Pakistan-based Secondeye Solution (SES), also known as Forwarderz, is a synthetic identity document vendor that was added to the OFAC SDN list in April 2021.\n \n\n SES customers could buy fake identity documents to sign up for accounts with cryptocurrency exchanges, payment providers, banks, and more under false identities. According to the US Treasury Department, SES assisted the Internet Research Agency (IRA), the Russian troll farm that OFAC designated pursuant to E.O. 13848 in 2018 for interfering in the 2016 presidential election, in concealing its identity to evade sanctions.\n \n\n https://home.treasury.gov/news/press-releases/jy0126",
           "url": "https://home.treasury.gov/news/press-releases/jy0126"
       }
   ]
}"#;

        let mut server = Server::new_async().await;
        let mock = server
            .mock(
                "GET",
                format!("{}/{}", API_BASE_PATH, TEST_ADDRESS).as_str(),
            )
            .with_status(200)
            .with_body(response_json)
            .create();

        let (client, config) = setup_client(&server);

        let result = get_risk_assessment(&client, &config, TEST_ADDRESS).await;

        mock.assert();

        assert!(matches!(
            result,
            Ok(RiskAssessment { severity: Severe, .. })
        ));
    }

    #[tokio::test]
    async fn test_get_risk_assessment_invalid_response() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock(
                "GET",
                format!("{}/{}", API_BASE_PATH, TEST_ADDRESS).as_str(),
            )
            .with_status(200)
            .with_body(r#"{"risky": "Severe"}"#)
            .create();

        let (client, config) = setup_client(&server);

        let result = get_risk_assessment(&client, &config, TEST_ADDRESS).await;

        mock.assert();

        assert!(matches!(result, Err(Error::InvalidApiResponse)));
    }

    #[tokio::test]
    async fn test_check_address_blocklisted_for_high_risk() {
        let response_json = r#"{
   "identifications": [
       {
           "category": "sanctions",
           "name": "SANCTIONS: OFAC SDN Secondeye Solution 2021-04-15 1da5821544e25c636c1417ba96ade4cf6d2f9b5a",
           "description": "Pakistan-based Secondeye Solution (SES), also known as Forwarderz, is a synthetic identity document vendor that was added to the OFAC SDN list in April 2021.\n \n\n SES customers could buy fake identity documents to sign up for accounts with cryptocurrency exchanges, payment providers, banks, and more under false identities. According to the US Treasury Department, SES assisted the Internet Research Agency (IRA), the Russian troll farm that OFAC designated pursuant to E.O. 13848 in 2018 for interfering in the 2016 presidential election, in concealing its identity to evade sanctions.\n \n\n https://home.treasury.gov/news/press-releases/jy0126",
           "url": "https://home.treasury.gov/news/press-releases/jy0126"
       }
   ]
}"#;
        let mut server = Server::new_async().await;
        let risk_mock = server
            .mock(
                "GET",
                format!("{}/{}", API_BASE_PATH, TEST_ADDRESS).as_str(),
            )
            .with_status(200)
            .with_body(response_json)
            .create();

        let (client, config) = setup_client(&server);

        let result = check_address(&client, &config, TEST_ADDRESS).await;

        risk_mock.assert();

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(status.is_blocklisted);
        assert_eq!(status.severity, Severe);
        assert_eq!(status.reason, Some("sanctions".to_string()));
        assert!(!status.accept);
    }

    #[tokio::test]
    async fn test_check_address_not_blocklisted_for_low_risk() {
        let mut server = Server::new_async().await;
        let risk_mock = server
            .mock(
                "GET",
                format!("{}/{}", API_BASE_PATH, TEST_ADDRESS).as_str(),
            )
            .with_status(200)
            .with_body(r#"{"identifications": []}"#)
            .create();

        let (client, config) = setup_client(&server);

        let result = check_address(&client, &config, TEST_ADDRESS).await;

        risk_mock.assert();

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(!status.is_blocklisted);
        assert_eq!(status.severity, Low);
        assert!(status.reason.is_none());
        assert!(status.accept);
    }

    #[tokio::test]
    async fn test_check_address_registration_fails() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", API_BASE_PATH)
            .with_status(400)
            .with_body(r#"{"message": "Invalid address"}"#)
            .create();

        let (client, config) = setup_client(&server);

        let result = check_address(&client, &config, TEST_ADDRESS).await;

        assert!(matches!(
            result,
            Err(Error::HttpRequest(StatusCode::NOT_IMPLEMENTED, _))
        ));
    }

    #[tokio::test]
    async fn test_check_address_risk_assessment_fails() {
        let mut server = Server::new_async().await;
        let risk_mock = server
            .mock(
                "GET",
                format!("{}/{}", API_BASE_PATH, TEST_ADDRESS).as_str(),
            )
            .with_status(500)
            .with_body("{}")
            .create();

        let (client, config) = setup_client(&server);

        let result = check_address(&client, &config, TEST_ADDRESS).await;

        risk_mock.assert();

        assert!(matches!(result, Err(Error::InternalServer)));
    }
}
