use crate::constants::EMILY_ENDPOINT;
use emily_handler::api::models::{chainstate::Chainstate, deposit::{requests::CreateDepositRequestBody, responses::GetDepositResponse}};
// use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
// use serde_json::json;
use tokio;

/// Get every chainstate from the previous test one at a time.
#[cfg_attr(not(feature = "complex-integration-tests"), ignore)]
#[tokio::test]
async fn simple_reorg() {
    let client = Client::new();

    let block_suffix: String = "fork_1".to_string();
    for height in 0..12 {
        let chainstate = test_chainstate(height, &block_suffix);
        let _ = create_chainstate(&client, chainstate);
    }
    let created_chainstate = get_chainstate_at_height(&client, 3).await;
    println!("{:?}", serde_json::to_string(&created_chainstate).unwrap());
    // assert_eq!(chainstate, to_create);
}

async fn create_chainstate(
    client: &Client,
    chainstate: Chainstate,
) -> Chainstate {
    client
        .post(format!("{EMILY_ENDPOINT}/chainstate"))
        .json(&chainstate)
        .send()
        .await
        .expect("Request should succeed")
        .json()
        .await
        .expect("Creating chain link failed.")
}

async fn get_chainstate_at_height(
    client: &Client,
    height: u64,
) -> Chainstate {
    with_actual_json(client
        .get(format!("{EMILY_ENDPOINT}/chainstate/{height}"))
        .send()
        .await
        .expect("Request should succeed")
        .json()
        .await
        .expect("Expected SOME output from get chainstate")
    )
}

async fn create_deposit(
    client: &Client,
    create_deposit_request: CreateDepositRequestBody,
) -> GetDepositResponse {
    client
        .post(format!("{EMILY_ENDPOINT}/deposit/"))
        .json(&create_deposit_request)
        .send()
        .await
        .expect("Request should succeed")
        .json()
        .await
        .expect("Creating deposit failed.")
}

async fn get_deposit(
    client: &Client,
    txid: String,
    output_index: u32,
) -> GetDepositResponse {
    client
        .get(format!("{EMILY_ENDPOINT}/deposit/{txid}/{output_index}"))
        .send()
        .await
        .expect("Request should succeed")
        .json()
        .await
        .expect("Getting deposit failed.")
}

/// Makes a test chainstate that indicates both its height and hash.
fn test_chainstate(height: u64, block_hash_suffix: &String) -> Chainstate {
    Chainstate {
        stacks_block_height: height,
        stacks_block_hash: format!("BLOCK_HASH_AT_{height}_{block_hash_suffix}"),
    }
}

fn with_actual_json<T>(value: serde_json::Value) -> T
where
    T: for <'de> Deserialize<'de>
{
    // Convert the string to the value we'd like.
    let stringified_value = serde_json::to_string_pretty(&value)
        .expect("failed to serialize a json value");
    match serde_json::from_value(value) {
        Ok(t) => t,
        Err(_) => {
            panic!("Failed to deserialize: {}", stringified_value)
        }
    }
}
