use emily_handler::api::models::{
    chainstate::Chainstate, common::Status, deposit::requests::CreateDepositRequestBody,
    withdrawal::requests::CreateWithdrawalRequestBody,
};

use crate::util::{
    self,
    constants::{
        TEST_BITCOIN_TXID, TEST_DEPOSIT_SCRIPT, TEST_RECIPIENT, TEST_RECLAIM_SCRIPT,
        TEST_WITHDRAWAL_PARAMETERS,
    },
    error::TestError,
    TestClient,
};

/// Testing scenario for a blockchain reorg.
struct ReorgScenario {
    /// The total length of the chain to create.
    initial_chain_length: u64,
    /// The depth of the reorg.
    reorg_depth: u64,
    /// Whether to do a reorg.
    do_reorg: bool,
}

/// Reorg validate implementation.
impl ReorgScenario {
    /// Validate.
    fn validate(&self) -> Result<(), TestError> {
        if self.initial_chain_length < self.reorg_depth {
            return Err(TestError::TestConditions(format!(
                "Initial chain length less than reorg depth: {} < {}",
                self.initial_chain_length, self.reorg_depth,
            )));
        } else if self.reorg_depth < 1 {
            return Err(TestError::TestConditions(
                "Reorg depth mut be at least 1".to_string(),
            ));
        }
        Ok(())
    }

    /// Lowest reorganized block height.
    #[allow(dead_code)]
    fn lowest_reorganized_block_height(&self) -> u64 {
        self.initial_chain_length - self.reorg_depth
    }

    /// Creates a list of reorganized chainstates with the standard test block hash format.
    #[allow(dead_code)]
    fn reorganized_chainstates(&self, fork_id: u32) -> Vec<Chainstate> {
        ((self.lowest_reorganized_block_height())..self.initial_chain_length)
            .map(|height| util::test_chainstate(height, fork_id))
            .collect()
    }
}

/// Tests a simple blockchain setup without a reorg.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
pub async fn simple_no_reorg() {
    // Setup client.
    simple_reorg_test_base(ReorgScenario {
        initial_chain_length: 10,
        reorg_depth: 5,
        do_reorg: false,
    })
    .await;
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
        do_reorg: true,
    })
    .await;
}

/// Base reorg test.
async fn simple_reorg_test_base(scenario: ReorgScenario) {
    // Extract the scenario.
    scenario.validate().unwrap();
    let ReorgScenario {
        initial_chain_length,
        reorg_depth: _,
        do_reorg,
    } = scenario;

    // Setup the test client and environment.
    let client: TestClient = TestClient::new();
    client.setup_test().await;

    // Identifier for the current fork.
    let mut fork_id: u32 = 0;

    // Step 1: Make an initial fork.
    // -------------------------------------------------------------------------

    // Process some deposits and withdrawals.
    for stacks_block_height in 0..initial_chain_length {
        // Setup requests.
        let chainstate = util::test_chainstate(stacks_block_height, fork_id);
        let stacks_block_hash = chainstate.stacks_block_hash.clone();
        let deposit_request = CreateDepositRequestBody {
            bitcoin_txid: format!("{TEST_BITCOIN_TXID}-{stacks_block_height}"),
            bitcoin_tx_output_index: 1,
            reclaim_script: TEST_RECLAIM_SCRIPT.to_string(),
            deposit_script: TEST_DEPOSIT_SCRIPT.to_string(),
        };
        let withdrawal_request = CreateWithdrawalRequestBody {
            request_id: stacks_block_height,
            stacks_block_hash,
            stacks_block_height,
            recipient: TEST_RECIPIENT.to_string(),
            amount: 1,
            parameters: TEST_WITHDRAWAL_PARAMETERS.clone(),
        };
        // Make requests to populate the database.
        client.create_chainstate(&chainstate).await;
        client.create_deposit(&deposit_request).await;
        client.create_withdrawal(&withdrawal_request).await;
    }

    // Ensure that all right number of deposits and withdrawals were created.
    let all_deposits = client.get_all_deposits().await;
    let all_withdrawals = client.get_all_withdrawals().await;

    // Ensure that the right number of deposits and withdrawals were made.
    assert_eq!(all_deposits.len(), initial_chain_length as usize);
    assert_eq!(all_withdrawals.len(), initial_chain_length as usize);

    // Verify that the chain tip is the highest block created.
    let chain_tip: Chainstate = client.get_chaintip().await;
    assert_eq!(
        chain_tip,
        util::test_chainstate(initial_chain_length - 1, fork_id),
    );

    // Do the reorg part of the test if specified.
    if do_reorg {
        // Step 2: Create a conflicting fork.
        // -------------------------------------------------------------------------
        fork_id += 1;

        // Set a conflicting chainstate for a lower than top depth to initiate an internal reorg.
        let reorganized_chainstates = scenario.reorganized_chainstates(fork_id);
        let lowest_reorganized_block: Chainstate = reorganized_chainstates.first().unwrap().clone();
        client.update_chainstate(&lowest_reorganized_block).await;

        // Verify that the chain tip is updated to be the new reorg height.
        let chain_tip: Chainstate = client.get_chaintip().await;
        assert_eq!(chain_tip, lowest_reorganized_block);

        let all_deposits = client.get_all_deposits().await;

        assert_eq!(all_deposits.len(), initial_chain_length as usize);
        let all_reevaluating_deposits = client
            .get_all_deposits_with_status(&Status::Reprocessing)
            .await;

        assert_eq!(
            all_reevaluating_deposits.len(),
            reorganized_chainstates.len(),
        );
    }

    // Setup for the next test.
    client.reset_environment().await;
}
