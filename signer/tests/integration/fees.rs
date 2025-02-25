//! Tests for the fees module.

use signer::bitcoin::fees::{estimate_fee_rate, EstimateFees, MempoolSpace};

#[ignore = "This uses external sources and is not currently used in the codebase"]
#[tokio::test]
async fn prod_estimate_fee_rate_works() {
    let client = reqwest::Client::new();

    let ans = estimate_fee_rate(&client).await.unwrap();
    more_asserts::assert_gt!(ans.sats_per_vbyte, 0.0);

    // It's not obvious from the docs that mempool.space returns a fee
    // rate in sats per vbyte, so this is to help manually validate
    // that.
    let mempool = MempoolSpace::new("https://mempool.space".to_string(), client.clone());

    let ans = mempool.estimate_fee_rate().await.unwrap();
    more_asserts::assert_gt!(ans.sats_per_vbyte, 0.0);
}
