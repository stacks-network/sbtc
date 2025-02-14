use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn check_tls_support() {
    let resp = reqwest::Client::new()
        .get("https://google.com")
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await
        .unwrap();

    resp.error_for_status().unwrap();
}
