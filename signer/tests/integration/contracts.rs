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

use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Keypair;
use signer::stacks::contracts::AsTxPayload;
use signer::stacks::wallet::sign_ecdsa;
use signer::stacks::wallet::MultisigTx;
use signer::stacks::wallet::SignerStxState;
use signer::testing::wallet;
use signer::testing::wallet::AsSmartContract;
use signer::testing::wallet::SmartContract;

pub const DEPOSIT: &str = std::include_str!("../../../contracts/contracts/sbtc-deposit.clar");
pub const REGISTRY: &str = std::include_str!("../../../contracts/contracts/sbtc-registry.clar");
pub const TOKEN: &str = std::include_str!("../../../contracts/contracts/sbtc-token.clar");
pub const WITHDRAWAL: &str = std::include_str!("../../../contracts/contracts/sbtc-withdrawal.clar");

const TX_FEE: u64 = 150000;

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

pub struct SbtcTokenContract;

impl AsSmartContract for SbtcTokenContract {
    const CONTRACT_BODY: &'static str = TOKEN;
    const CONTRACT_NAME: &'static str = "sbtc-token";
}

pub async fn deploy_smart_contract<T>(contract: T, state: &SignerStxState, keys: [Keypair; 3])
where
    T: AsTxPayload,
{
    let mut unsigned = MultisigTx::new_tx(contract, &state, TX_FEE);

    let signatures: Vec<RecoverableSignature> = keys
        .iter()
        .map(|kp| sign_ecdsa(unsigned.tx(), &kp.secret_key()))
        .collect();

    // This only fails when we are given an invalid signature.
    for signature in signatures {
        unsigned.add_signature(signature).unwrap();
    }

    let tx = unsigned.finalize_transaction();
}

pub fn deploy_smart_contracts() {
    static SBTC_TOKEN_DEPLOYMENT: OnceLock<bool> = OnceLock::new();
    let (signer_wallet, key_pairs) = wallet::generate_wallet();
    let deployer = signer_wallet.address();
    let state = SignerStxState::new(signer_wallet, 0, deployer);

    SBTC_TOKEN_DEPLOYMENT.get_or_init(|| {
        let contract = SmartContract(SbtcTokenContract);
        let mut unsigned = MultisigTx::new_tx(contract, &state, TX_FEE);

        let signatures: Vec<RecoverableSignature> = key_pairs
            .iter()
            .map(|kp| sign_ecdsa(unsigned.tx(), &kp.secret_key()))
            .collect();

        // This only fails when we are given an invalid signature.
        for signature in signatures {
            unsigned.add_signature(signature).unwrap();
        }

        let tx = unsigned.finalize_transaction();
        true
    });
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
