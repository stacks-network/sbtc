use crate::config::RiskAnalysisConfig;
use reqwest::Client;
use serde_json::Value;

/// Screen the provided address for blocklist status
pub async fn check_address(
    client: Client,
    config: &RiskAnalysisConfig,
    address: &str,
) -> Result<Value, reqwest::Error> {
    let api_url = format!("{}/screen/{}", config.api_url, address);

    let response = client
        .get(&api_url)
        .header("Token", config.api_key.to_string())
        .send()
        .await?;

    response.json::<Value>().await
}
