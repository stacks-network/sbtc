use std::collections::HashSet;
use std::sync::OnceLock;

use bitvec::array::BitArray;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::types::Address;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Keypair;
use signer::stacks::contracts::AcceptWithdrawalV1;
use signer::stacks::contracts::AsContractCall;
use signer::stacks::contracts::ContractCall;
use signer::stacks::contracts::RejectWithdrawalV1;
use signer::stacks::contracts::RotateKeysV1;
use tokio::sync::OnceCell;

use signer::config::StacksSettings;
use signer::stacks;
use signer::stacks::api::RejectionReason;
use signer::stacks::api::StacksClient;
use signer::stacks::api::SubmitTxResponse;
use signer::stacks::api::TxRejection;
use signer::stacks::contracts::CompleteDepositV1;
use signer::stacks::wallet::MultisigTx;
use signer::stacks::wallet::SignerStxState;
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

pub struct SignerKeys {
    pub state: SignerStxState,
    pub keys: [Keypair; 3],
    pub stacks_client: &'static StacksClient,
}

fn make_signatures(tx: &StacksTransaction, keys: &[Keypair]) -> Vec<RecoverableSignature> {
    keys.iter()
        .map(|kp| stacks::wallet::sign_ecdsa(tx, &kp.secret_key()))
        .collect()
}

/// Deploy an sBTC smart contract to the stacks node
async fn deploy_smart_contract<T>(state: &SignerKeys, deploy: T)
where
    T: AsContractDeploy,
{
    let mut unsigned = MultisigTx::new_tx(ContractDeploy(deploy), &state.state, TX_FEE);

    let signatures: Vec<RecoverableSignature> = make_signatures(unsigned.tx(), &state.keys);

    // This only fails when we are given an invalid signature.
    for signature in signatures {
        unsigned.add_signature(signature).unwrap();
    }

    let tx = unsigned.finalize_transaction();

    match state.stacks_client.submit_tx(&tx).await.unwrap() {
        SubmitTxResponse::Acceptance(_) => (),
        SubmitTxResponse::Rejection(TxRejection {
            reason: RejectionReason::ContractAlreadyExists,
            ..
        }) => (),
        SubmitTxResponse::Rejection(err) => panic!("{}", serde_json::to_string(&err).unwrap()),
    }
}

/// Deploy all sBTC smart contracts to the stacks node
pub async fn deploy_smart_contracts() -> &'static SignerKeys {
    static SBTC_DEPLOYMENT: OnceCell<()> = OnceCell::const_new();
    static STACKS_CLIENT: OnceLock<StacksClient> = OnceLock::new();
    static SIGNER_STATE: OnceCell<SignerKeys> = OnceCell::const_new();
    
    let (signer_wallet, key_pairs) = testing::wallet::generate_wallet();

    let client = STACKS_CLIENT.get_or_init(|| {
        let settings = StacksSettings::new_from_config().unwrap();
        StacksClient::new(settings)
    });

    let state = SIGNER_STATE
        .get_or_init(|| async {
            let account_info = client.get_account(&signer_wallet.address()).await.unwrap();
            SignerKeys {
                state: SignerStxState::new(signer_wallet.clone(), account_info.nonce),
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
            deploy_smart_contract(state, SbtcRegistryContract).await;
            deploy_smart_contract(state, SbtcTokenContract).await;
            deploy_smart_contract(state, SbtcDepositContract).await;
            deploy_smart_contract(state, SbtcWithdrawalContract).await;
            deploy_smart_contract(state, SbtcBootstrapContract).await;
        })
        .await;

    state
}

#[ignore]
#[test_case(ContractCall(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: StacksAddress::from_string("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y").unwrap(),
    deployer: testing::wallet::generate_wallet().0.address(),
}); "complete-deposit")]
#[test_case(ContractCall(AcceptWithdrawalV1 {
    request_id: 0,
    outpoint: bitcoin::OutPoint::null(),
    tx_fee: 3500,
    signer_bitmap: BitArray::new([0; 2]),
    deployer: testing::wallet::generate_wallet().0.address(),
}); "accept-withdrawal")]
#[test_case(ContractCall(RejectWithdrawalV1 {
    request_id: 0,
    signer_bitmap: BitArray::new([0; 2]),
    deployer: testing::wallet::generate_wallet().0.address(),
}); "reject-withdrawal")]
#[test_case(ContractCall(RotateKeysV1::new(
    &testing::wallet::generate_wallet().0,
    testing::wallet::generate_wallet().0.address(),
)); "rotate-keys")]
#[tokio::test]
async fn complete_deposit_wrapper_tx_accepted<T: AsContractCall>(contract: ContractCall<T>) {
    let signer = deploy_smart_contracts().await;
    let mut unsigned = MultisigTx::new_tx(contract, &signer.state, TX_FEE);

    for signature in make_signatures(unsigned.tx(), &signer.keys) {
        unsigned.add_signature(signature).unwrap();
    }
    let tx = unsigned.finalize_transaction();

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

    // We need a block id
    let info = signer.stacks_client.get_tenure_info().await.unwrap();
    let storage = Store::new_shared();

    let blocks =
        stacks::api::fetch_unknown_ancestors(signer.stacks_client, &storage, info.tip_block_id)
            .await
            .unwrap();

    let transactions = postgres::extract_relevant_transactions(&blocks);
    assert!(!transactions.is_empty());

    let txids = transactions
        .iter()
        .map(|stx| blockstack_lib::burnchains::Txid::from_hex(&stx.txid))
        .collect::<Result<HashSet<_>, _>>()
        .unwrap();

    assert!(txids.contains(&tx.txid()));
}
