use std::collections::HashSet;
use std::sync::OnceLock;

use bitvec::array::BitArray;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::types::chainstate::StacksAddress;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Keypair;
use signer::stacks::api::StacksInteract;
use signer::stacks::contracts::AcceptWithdrawalV1;
use signer::stacks::contracts::AsContractCall;
use signer::stacks::contracts::ContractCall;
use signer::stacks::contracts::RejectWithdrawalV1;
use signer::stacks::contracts::RotateKeysV1;
use signer::stacks::wallet::SignerWallet;
use tokio::sync::OnceCell;

use signer::config::StacksSettings;
use signer::stacks;
use signer::stacks::api::FeePriority;
use signer::stacks::api::RejectionReason;
use signer::stacks::api::StacksClient;
use signer::stacks::api::SubmitTxResponse;
use signer::stacks::api::TxRejection;
use signer::stacks::contracts::CompleteDepositV1;
use signer::stacks::wallet::MultisigTx;
use signer::storage::in_memory::Store;
use signer::storage::postgres;
use signer::testing;
use signer::testing::wallet::AsContractDeploy;
use signer::testing::wallet::ContractDeploy;

use test_case::test_case;

const TX_FEE: u64 = 1500000;

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

fn make_signatures(tx: &StacksTransaction, keys: &[Keypair]) -> Vec<RecoverableSignature> {
    keys.iter()
        .map(|kp| signer::signature::sign_stacks_tx(tx, &kp.secret_key().into()))
        .collect()
}

pub struct SignerStxState {
    /// A multi-sig wallet for the signers.
    pub wallet: SignerWallet,
    /// These are the private keys to public keys in the above wallet.
    pub keys: [Keypair; 3],
    /// A stacks client built using the src/config/default.toml config.
    pub stacks_client: &'static StacksClient,
}

impl SignerStxState {
    /// Deploy an sBTC smart contract to the stacks node
    async fn deploy_smart_contract<T>(&self, deploy: T)
    where
        T: AsContractDeploy,
    {
        let mut unsigned = MultisigTx::new_tx(ContractDeploy(deploy), &self.wallet, TX_FEE);

        for signature in make_signatures(unsigned.tx(), &self.keys) {
            unsigned.add_signature(signature).unwrap();
        }

        let tx = unsigned.finalize_transaction();

        match self.stacks_client.submit_tx(&tx).await.unwrap() {
            SubmitTxResponse::Acceptance(_) => (),
            SubmitTxResponse::Rejection(TxRejection {
                reason: RejectionReason::ContractAlreadyExists,
                ..
            }) => (),
            SubmitTxResponse::Rejection(err) => panic!("{}", serde_json::to_string(&err).unwrap()),
        }
    }
}

/// Create or return a long-lived stacks client.
fn stacks_client() -> &'static StacksClient {
    static STACKS_CLIENT: OnceLock<StacksClient> = OnceLock::new();
    STACKS_CLIENT.get_or_init(|| {
        let settings = StacksSettings::new_from_config().unwrap();
        StacksClient::new(settings)
    })
}

/// Deploy all sBTC smart contracts to the stacks node
pub async fn deploy_smart_contracts() -> &'static SignerStxState {
    static SBTC_DEPLOYMENT: OnceCell<()> = OnceCell::const_new();
    static SIGNER_STATE: OnceCell<SignerStxState> = OnceCell::const_new();

    let (signer_wallet, key_pairs) = testing::wallet::generate_wallet();

    let client = stacks_client();

    let signer = SIGNER_STATE
        .get_or_init(|| async {
            let account_info = client.get_account(&signer_wallet.address()).await.unwrap();
            signer_wallet.set_nonce(account_info.nonce);
            SignerStxState {
                wallet: signer_wallet,
                keys: key_pairs,
                stacks_client: client,
            }
        })
        .await;

    SBTC_DEPLOYMENT
        .get_or_init(|| async {
            // The registry and token contracts need to be deployed first
            // and second respectively. The rest can be deployed in any
            // order.
            signer.deploy_smart_contract(SbtcRegistryContract).await;
            signer.deploy_smart_contract(SbtcTokenContract).await;
            signer.deploy_smart_contract(SbtcDepositContract).await;
            signer.deploy_smart_contract(SbtcWithdrawalContract).await;
            signer.deploy_smart_contract(SbtcBootstrapContract).await;
        })
        .await;

    signer
}

#[ignore]
#[test_case(ContractCall(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap(),
    deployer: testing::wallet::generate_wallet().0.address(),
}); "complete-deposit standard recipient")]
#[test_case(ContractCall(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y.my-contract-name").unwrap(),
    deployer: testing::wallet::generate_wallet().0.address(),
}); "complete-deposit contract recipient")]
#[test_case(ContractCall(AcceptWithdrawalV1 {
    request_id: 0,
    outpoint: bitcoin::OutPoint::null(),
    tx_fee: 3500,
    signer_bitmap: BitArray::ZERO,
    deployer: testing::wallet::generate_wallet().0.address(),
}); "accept-withdrawal")]
#[test_case(ContractCall(RejectWithdrawalV1 {
    request_id: 0,
    signer_bitmap: BitArray::ZERO,
    deployer: testing::wallet::generate_wallet().0.address(),
}); "reject-withdrawal")]
#[test_case(ContractCall(RotateKeysV1::new(
    &testing::wallet::generate_wallet().0,
    testing::wallet::generate_wallet().0.address(),
)); "rotate-keys")]
#[tokio::test]
async fn complete_deposit_wrapper_tx_accepted<T: AsContractCall>(contract: ContractCall<T>) {
    let signer = deploy_smart_contracts().await;
    let mut unsigned = MultisigTx::new_tx(contract, &signer.wallet, TX_FEE);

    for signature in make_signatures(unsigned.tx(), &signer.keys) {
        unsigned.add_signature(signature).unwrap();
    }
    let tx = unsigned.finalize_transaction();

    // We need to wait for the deployed contracts to be mined before we can
    // use them. Five seconds seems to be enough time for that to happen.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    match signer.stacks_client.submit_tx(&tx).await.unwrap() {
        SubmitTxResponse::Acceptance(_) => (),
        SubmitTxResponse::Rejection(err) => panic!("{}", serde_json::to_string(&err).unwrap()),
    }

    // The submitted transaction tends to linger in the mempool for quite
    // some time before being confirmed in a Nakamoto block (best guess is
    // 5-10 minutes). It's not clear why this is the case.
    if true {
        println!("{}", tx.txid());
        return;
    }

    let settings = StacksSettings::new_from_config().unwrap();
    let mut client = StacksClient::new(settings);

    // We need a block id
    let info = client.get_tenure_info().await.unwrap();
    let storage = Store::new_shared();

    let blocks = stacks::api::fetch_unknown_ancestors(&mut client, &storage, info.tip_block_id)
        .await
        .unwrap();

    let transactions = postgres::extract_relevant_transactions(&blocks);
    assert!(!transactions.is_empty());

    let txids = transactions
        .iter()
        .map(|stx| blockstack_lib::burnchains::Txid::from_bytes(&stx.txid))
        .collect::<Option<HashSet<_>>>()
        .unwrap();

    assert!(txids.contains(&tx.txid()));
}

#[ignore = "This is an integration test that requires a stacks-node to work"]
#[tokio::test]
async fn estimate_tx_fees() {
    sbtc::logging::setup_logging("info", false);
    let client = stacks_client();

    let contract = SbtcRegistryContract;
    let payload = ContractDeploy(contract);

    let _ = client.get_fee_estimate(&payload).await.unwrap();

    let contract_call = CompleteDepositV1 {
        outpoint: bitcoin::OutPoint::null(),
        amount: 123654,
        recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap(),
        deployer: StacksAddress::burn_address(false),
    };
    let payload = ContractCall(contract_call);

    // This should work, but will likely be an estimate for a STX transfer
    // transaction.

    let fee = client
        .estimate_fees(&payload, FeePriority::Medium)
        .await
        .unwrap();
    more_asserts::assert_gt!(fee, 0);
}
