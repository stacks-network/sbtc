use std::sync::OnceLock;

use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TransactionAnchorMode;
use blockstack_lib::chainstate::stacks::TransactionAuth;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::chainstate::stacks::TransactionSmartContract;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use blockstack_lib::chainstate::stacks::TransactionVersion;
use blockstack_lib::clarity::vm::ContractName;
use blockstack_lib::core::CHAIN_ID_TESTNET;
use blockstack_lib::util_lib::strings::StacksString;

use signer::stacks::wallet::SignerStxState;

pub const DEPOSIT: &str = std::include_str!("../../../contracts/contracts/sbtc-deposit.clar");
pub const REGISTRY: &str = std::include_str!("../../../contracts/contracts/sbtc-registry.clar");
pub const TOKEN: &str = std::include_str!("../../../contracts/contracts/sbtc-token.clar");
pub const WITHDRAWAL: &str = std::include_str!("../../../contracts/contracts/sbtc-withdrawal.clar");

pub trait AsSmartContract {
    /// The name of the clarity smart contract that relates to this struct.
    const CONTRACT_NAME: &'static str;
    /// The specific function name that relates to this struct.
    const CONTRACT_BODY: &'static str;
    /// Convert this struct to a Stacks contract deployment.
    fn as_smart_contract(&self) -> TransactionSmartContract {
        TransactionSmartContract {
            name: ContractName::from(Self::CONTRACT_NAME),
            code_body: StacksString::from_str(Self::CONTRACT_BODY).unwrap(),
        }
    }
}

pub fn new_smart_contract<T>(item: T, state: &SignerStxState, tx_fee: u64) -> StacksTransaction
where
    T: AsSmartContract,
{
    let auth = state.as_unsigned_tx_auth(tx_fee);
    let spending_condition = TransactionSpendingCondition::OrderIndependentMultisig(auth);

    StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::Standard(spending_condition),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: Vec::new(),
        payload: TransactionPayload::SmartContract(item.as_smart_contract(), None),
    }
}

pub fn deploy_smart_contracts() {
    static SBTC_TOKEN_DEPLOYMENT: OnceLock<bool> = OnceLock::new();
}

#[ignore]
#[tokio::test]
async fn complete_deposit_wrapper_tx_accepted() {
    // TODO(#264): Add integration test for signing Stacks smart contracts
}

#[ignore]
#[tokio::test]
async fn accept_withdrawal_request_tx_accepted() {
    // TODO(#264): Add integration test for signing Stacks smart contracts
}

#[ignore]
#[tokio::test]
async fn reject_withdrawal_request_tx_accepted() {
    // TODO(#264): Add integration test for signing Stacks smart contracts
}
