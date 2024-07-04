use tokio::sync::OnceCell;

use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Keypair;
use signer::config::StacksSettings;
use signer::stacks::api::StacksClient;
use signer::stacks::contracts::AsTxPayload;
use signer::stacks::wallet::sign_ecdsa;
use signer::stacks::wallet::MultisigTx;
use signer::stacks::wallet::SignerStxState;
use signer::testing::wallet;
use signer::testing::wallet::AsSmartContract;
use signer::testing::wallet::SmartContract;

const BOOTSTRAP: &str =
    std::include_str!("../../../contracts/contracts/sbtc-bootstrap-signers.clar");
const DEPOSIT: &str = std::include_str!("../../../contracts/contracts/sbtc-deposit.clar");
const REGISTRY: &str = std::include_str!("../../../contracts/contracts/sbtc-registry.clar");
const TOKEN: &str = std::include_str!("../../../contracts/contracts/sbtc-token.clar");
const WITHDRAWAL: &str = std::include_str!("../../../contracts/contracts/sbtc-withdrawal.clar");

const TX_FEE: u64 = 15000000;

pub struct SbtcTokenContract;

impl AsSmartContract for SbtcTokenContract {
    const CONTRACT_BODY: &'static str = TOKEN;
    const CONTRACT_NAME: &'static str = "sbtc-token";
}

pub struct SbtcRegistryContract;

impl AsSmartContract for SbtcRegistryContract {
    const CONTRACT_BODY: &'static str = REGISTRY;
    const CONTRACT_NAME: &'static str = "sbtc-registry";
}

pub struct SbtcDepositContract;

impl AsSmartContract for SbtcDepositContract {
    const CONTRACT_BODY: &'static str = DEPOSIT;
    const CONTRACT_NAME: &'static str = "sbtc-deposit";
}

pub struct SbtcWithdrawalContract;

impl AsSmartContract for SbtcWithdrawalContract {
    const CONTRACT_BODY: &'static str = WITHDRAWAL;
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
}

pub struct SbtcBootstrapContract;

impl AsSmartContract for SbtcBootstrapContract {
    const CONTRACT_BODY: &'static str = BOOTSTRAP;
    const CONTRACT_NAME: &'static str = "sbtc-bootstrap-signers";
}

pub struct SignerKeyState {
    pub state: SignerStxState,
    pub keys: [Keypair; 3],
}

async fn deploy_smart_contract<T>(state: &SignerKeyState, client: &StacksClient, contract: T)
where
    T: AsTxPayload,
{
    let mut unsigned = MultisigTx::new_tx(contract, &state.state, TX_FEE);

    let signatures: Vec<RecoverableSignature> = state
        .keys
        .iter()
        .map(|kp| sign_ecdsa(unsigned.tx(), &kp.secret_key()))
        .collect();

    // This only fails when we are given an invalid signature.
    for signature in signatures {
        unsigned.add_signature(signature).unwrap();
    }

    let tx = unsigned.finalize_transaction();

    dbg!(client.submit_tx(&tx).await.unwrap());
}

pub async fn deploy_smart_contracts() -> SignerKeyState {
    static SBTC_DEPLOYMENT: OnceCell<bool> = OnceCell::const_new();
    let (signer_wallet, key_pairs) = wallet::generate_wallet();
    let deployer = signer_wallet.address();
    let state = SignerKeyState {
        state: SignerStxState::new(signer_wallet, 0, deployer),
        keys: key_pairs,
    };

    let settings = StacksSettings::new_from_config().unwrap();
    let client = StacksClient::new(settings);

    SBTC_DEPLOYMENT
        .get_or_init(|| async {
            deploy_smart_contract(&state, &client, SmartContract(SbtcRegistryContract)).await;
            deploy_smart_contract(&state, &client, SmartContract(SbtcTokenContract)).await;
            deploy_smart_contract(&state, &client, SmartContract(SbtcDepositContract)).await;
            deploy_smart_contract(&state, &client, SmartContract(SbtcWithdrawalContract)).await;
            deploy_smart_contract(&state, &client, SmartContract(SbtcBootstrapContract)).await;
            true
        })
        .await;

    state
}

#[ignore]
#[tokio::test]
async fn test_deploy() {
    let _state = deploy_smart_contracts().await;
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
