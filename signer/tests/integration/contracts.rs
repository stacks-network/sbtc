use signer::stacks::api::SubmitTxResponse;
use tokio::sync::OnceCell;

use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Keypair;
use signer::config::StacksSettings;
use signer::stacks;
use signer::stacks::api::StacksClient;
use signer::stacks::wallet::MultisigTx;
use signer::stacks::wallet::SignerStxState;
use signer::testing;
use signer::testing::wallet::AsContractDeploy;
use signer::testing::wallet::ContractDeploy;

const TX_FEE: u64 = 15000000;

pub struct SbtcTokenContract;

impl AsContractDeploy for SbtcTokenContract {
    const CONTRACT_NAME: &'static str = "sbtc-token";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-token.clar");
}

pub struct SbtcRegistryContract;

impl AsContractDeploy for SbtcRegistryContract {
    const CONTRACT_NAME: &'static str = "sbtc-registry";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-registry.clar");
}

pub struct SbtcDepositContract;

impl AsContractDeploy for SbtcDepositContract {
    const CONTRACT_NAME: &'static str = "sbtc-deposit";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-deposit.clar");
}

pub struct SbtcWithdrawalContract;

impl AsContractDeploy for SbtcWithdrawalContract {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-withdrawal.clar");
}

pub struct SbtcBootstrapContract;

impl AsContractDeploy for SbtcBootstrapContract {
    const CONTRACT_NAME: &'static str = "sbtc-bootstrap-signers";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-bootstrap-signers.clar");
}

pub struct SignerKeyState {
    pub state: SignerStxState,
    pub keys: [Keypair; 3],
}

/// Deploy an sBTC smart contract to the stacks node
async fn deploy_smart_contract<T>(state: &SignerKeyState, client: &StacksClient, deploy: T)
where
    T: AsContractDeploy,
{
    let mut unsigned = MultisigTx::new_tx(ContractDeploy(deploy), &state.state, TX_FEE);

    let signatures: Vec<RecoverableSignature> = state
        .keys
        .iter()
        .map(|kp| stacks::wallet::sign_ecdsa(unsigned.tx(), &kp.secret_key()))
        .collect();

    // This only fails when we are given an invalid signature.
    for signature in signatures {
        unsigned.add_signature(signature).unwrap();
    }

    let tx = unsigned.finalize_transaction();

    match client.submit_tx(&tx).await.unwrap() {
        SubmitTxResponse::Acceptance(_) => (),
        SubmitTxResponse::Rejection(err) => panic!("{}", serde_json::to_string(&err).unwrap()),
    }
}

/// Deploy all sBTC smart contracts to the stacks node
pub async fn deploy_smart_contracts() -> SignerKeyState {
    static SBTC_DEPLOYMENT: OnceCell<bool> = OnceCell::const_new();
    let (signer_wallet, key_pairs) = testing::wallet::generate_wallet();

    let settings = StacksSettings::new_from_config().unwrap();
    let client = StacksClient::new(settings);

    let account_info = client.get_account(&signer_wallet.address()).await.unwrap();
    let state = SignerKeyState {
        state: SignerStxState::new(signer_wallet, account_info.nonce),
        keys: key_pairs,
    };

    SBTC_DEPLOYMENT
        .get_or_init(|| async {
            // The registry and token contracts need to be deployed first
            // and second respectively. The rest can be deployed in any
            // order.
            deploy_smart_contract(&state, &client, SbtcRegistryContract).await;
            deploy_smart_contract(&state, &client, SbtcTokenContract).await;
            deploy_smart_contract(&state, &client, SbtcDepositContract).await;
            deploy_smart_contract(&state, &client, SbtcWithdrawalContract).await;
            deploy_smart_contract(&state, &client, SbtcBootstrapContract).await;
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
