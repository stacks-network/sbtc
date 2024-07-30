use super::EMILY_ENDPOINT;
use crate::endpoints::util;
use emily_handler::api::models::chainstate::Chainstate;
use reqwest::Client;
use serde_json::json;
use serial_test::serial;
use std::sync::LazyLock;
use tokio;

/// Test data for chainstate tests.
static TEST_CHAINSTATE_DATA: LazyLock<Vec<Chainstate>> = LazyLock::new(|| {
    vec![
        Chainstate {
            stacks_block_height: 1,
            stacks_block_hash: "test_hash_1".to_string(),
        },
        Chainstate {
            stacks_block_height: 2,
            stacks_block_hash: "test_hash_2".to_string(),
        },
        Chainstate {
            stacks_block_height: 5,
            stacks_block_hash: "test_hash_5".to_string(),
        },
    ]
});

/// Initialize the chainstate table with a bunch of chainstates.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
#[serial]
async fn create_chainstates() {
    let client = Client::new();
    for test_chainstate_data in TEST_CHAINSTATE_DATA.iter() {
        // Arrange.
        let Chainstate {
            stacks_block_height,
            stacks_block_hash,
        } = test_chainstate_data;

        // Act.
        let response = client
            .post(format!("{EMILY_ENDPOINT}/chainstate"))
            .json(&json!({
              "stacksBlockHeight": stacks_block_height,
              "stacksBlockHash": stacks_block_hash,
            }))
            .send()
            .await
            .expect("Request should succeed");

        // Assert.
        let actual: Chainstate = response.json().await.expect("msg");

        let expected = test_chainstate_data;
        util::assert_eq_pretty(&actual, expected);
    }
}

/// Get every chainstate from the previous test one at a time.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
#[serial]
async fn get_chainstate_at_height() {
    let client = Client::new();
    for test_chainstate_data in TEST_CHAINSTATE_DATA.iter() {
        // Arrange..
        let Chainstate {
            stacks_block_height,
            stacks_block_hash: _,
        } = test_chainstate_data;

        // Act.
        let response = client
            .get(format!("{EMILY_ENDPOINT}/chainstate/{stacks_block_height}"))
            .send()
            .await
            .expect("Request should succeed");

        // Assert.
        let actual: Chainstate = response
            .json()
            .await
            .expect("Failed to parse JSON response");

        let expected = test_chainstate_data;
        util::assert_eq_pretty(&actual, expected);
    }
}
