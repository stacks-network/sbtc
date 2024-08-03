use emily_handler::api::models::{
    chainstate::Chainstate,
    deposit::requests::CreateDepositRequestBody,
    withdrawal::requests::CreateWithdrawalRequestBody,
};

use crate::util::{
    constants::{
        TEST_BITCOIN_TXID, TEST_DEPOSIT_SCRIPT, TEST_RECIPIENT, TEST_RECLAIM_SCRIPT,
        TEST_WITHDRAWAL_PARAMETERS,
    }, error::TestError, TestClient,
};

struct ReorgScenario {
    /// The total length of the chain to create.
    initial_chain_length: u64,
    /// The depth of the reorg.
    reorg_depth: u64,
}

impl ReorgScenario {
    fn validate(&self) -> Result<(), TestError> {
        if self.initial_chain_length < self.reorg_depth {
            return Err(TestError::TestConditions(
                format!(
                    "Initial chain length less than reorg depth: {} < {}",
                    self.initial_chain_length,
                    self.reorg_depth,
                )
            ))
        }
        Ok(())
    }
}

/// Tests a simple blockchain reorg.
///
/// To test a simple reorg we create a single deposit and withdrawal for a number
/// chainstates after we create them, and then we update the API to say that a number
/// of those chainstates were re-written.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
pub async fn simple_reorg() {
    // Setup client.
    simple_reorg_test_base(ReorgScenario {
        initial_chain_length: 10,
        reorg_depth: 5,
    }).await;
}

async fn simple_reorg_test_base(
    scenario: ReorgScenario
) {
    // Extract the scenario.
    scenario.validate().unwrap();
    let ReorgScenario {
        initial_chain_length,
        reorg_depth: _,
    } = scenario;

    // Setup the test client and environment.
    let client: TestClient = TestClient::new();
    client.setup_test().await;

    // Identifier for the current fork.
    let fork_id: i32 = 0;

    // Process some deposits and withdrawals.
    for stacks_block_height in 0..initial_chain_length {
        // Make stacks block hash for the current block.
        let stacks_block_hash: String =
            format!("stacks-block-{stacks_block_height}-hash-fork-{fork_id}");

        // Setup requests.
        let chainstate = Chainstate {
            stacks_block_height,
            stacks_block_hash: stacks_block_hash.clone(),
        };
        let deposit_request = CreateDepositRequestBody {
            bitcoin_txid: format!("{TEST_BITCOIN_TXID}-{stacks_block_height}"),
            bitcoin_tx_output_index: 1,
            reclaim: TEST_RECLAIM_SCRIPT.to_string(),
            deposit: TEST_DEPOSIT_SCRIPT.to_string(),
        };
        let withdrawal_request = CreateWithdrawalRequestBody {
            request_id: stacks_block_height,
            stacks_block_hash: stacks_block_hash,
            recipient: TEST_RECIPIENT.to_string(),
            amount: 1,
            parameters: TEST_WITHDRAWAL_PARAMETERS.clone(),
        };

        // Make requests to populate the database.
        client.create_chainstate(chainstate).await;
        client.create_deposit(deposit_request).await;
        client.create_withdrawal(withdrawal_request).await;
    }

    // Ensure that all right number of deposits and withdrawals were created.
    let all_deposits = client.get_all_deposits().await;
    let all_withdrawals =client.get_all_withdrawals().await;

    // Ensure that the right number of deposits and withdrawals were made.
    assert_eq!(all_deposits.len(), scenario.initial_chain_length as usize);
    assert_eq!(all_withdrawals.len(), scenario.initial_chain_length as usize);

    // Setup for the next test.
    client.reset_environment().await;
}
