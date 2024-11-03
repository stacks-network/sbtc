use std::sync::OnceLock;

use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::types::chainstate::StacksAddress;
use signer::config::Settings;
use signer::stacks::api::FeePriority;
use signer::stacks::api::StacksClient;
use signer::stacks::api::StacksInteract;
use signer::stacks::contracts::CompleteDepositV1;
use signer::stacks::contracts::ContractDeploy;
use signer::stacks::contracts::SbtcRegistryContract;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::BitcoinTxId;
use signer::testing::wallet::ContractCallWrapper;
use signer::util::ApiFallbackClient;

/// Create or return a long-lived stacks client.
fn stacks_client() -> ApiFallbackClient<StacksClient> {
    static STACKS_CLIENT: OnceLock<ApiFallbackClient<StacksClient>> = OnceLock::new();
    STACKS_CLIENT
        .get_or_init(|| {
            let settings = Settings::new_from_default_config().unwrap();
            TryFrom::try_from(&settings).unwrap()
        })
        .clone()
}

#[ignore = "This is an integration test that requires a stacks-node to work"]
#[tokio::test]
async fn estimate_tx_fees() {
    signer::logging::setup_logging("info", false);
    let client = stacks_client();

    let contract = SbtcRegistryContract;
    let payload = ContractDeploy::SbtcRegistry(contract);

    let _ = client
        .get_client()
        .get_fee_estimate(&payload)
        .await
        .unwrap();

    let contract_call = CompleteDepositV1 {
        outpoint: bitcoin::OutPoint::null(),
        amount: 123654,
        recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap(),
        deployer: StacksAddress::burn_address(false),
        sweep_txid: BitcoinTxId::from([0; 32]),
        sweep_block_hash: BitcoinBlockHash::from([0; 32]),
        sweep_block_height: 7,
    };
    let payload = ContractCallWrapper(contract_call);

    // This should work, but will likely be an estimate for a STX transfer
    // transaction.

    let fee = client
        .estimate_fees(&payload, FeePriority::Medium)
        .await
        .unwrap();
    more_asserts::assert_gt!(fee, 0);
}
