use crate::util::{self, constants::EMILY_CHAINSTATE_ENDPOINT, TestClient};
use emily_handler::api::models::chainstate::Chainstate;
use serde_json::json;
use std::sync::LazyLock;
use tokio;

// TODO(392): Use test setup functions to wipe the database before performing these
// tests instead of relying on circumstantial test execution order.

static NUM_TEST_CHAINSTATES: u32 = 10;

/// Test data for chainstate tests.
static TEST_CHAINSTATE_DATA: LazyLock<Vec<Chainstate>> = LazyLock::new(|| {
    (0..NUM_TEST_CHAINSTATES)
        .map(|height| util::test_chainstate(height as u64, 0))
        .collect()
});

/// Setup function that wipes the database and populates it with the necessary
/// chainstate data.
async fn setup_chainstate_integration_test() -> TestClient {
    let client = TestClient::new();
    client.setup_test().await;
    for test_chainstate_data in TEST_CHAINSTATE_DATA.iter() {
        // Arrange.
        let Chainstate {
            stacks_block_height,
            stacks_block_hash,
        } = test_chainstate_data;
        let request: Chainstate = serde_json::from_value(json!({
            "stacksBlockHeight": stacks_block_height,
            "stacksBlockHash": stacks_block_hash,
        }))
        .expect("Failed to deserialize create chainstate request body in test setup");
        let response = client.create_chainstate(&request).await;
        util::assert_eq_pretty(&response, test_chainstate_data);
    }
    client
}

/// Test that the creation works.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn create_chainstates() {
    // The setup function runs what was origninally the create tests by creating the
    // resources and then assessing what was created.
    let client = setup_chainstate_integration_test().await;
    client.teardown().await;
}

/// Get every chainstate from the previous test one at a time.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn get_chainstate_at_height() {
    let client = setup_chainstate_integration_test().await;
    for test_chainstate_data in TEST_CHAINSTATE_DATA.iter() {
        // Arrange..
        let Chainstate {
            stacks_block_height,
            stacks_block_hash: _,
        } = test_chainstate_data;

        // Act.
        let response = client
            .inner
            .get(format!("{EMILY_CHAINSTATE_ENDPOINT}/{stacks_block_height}"))
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
    client.teardown().await;
}
