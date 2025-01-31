use std::collections::HashSet;
use std::sync::OnceLock;

use bitvec::array::BitArray;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::types::chainstate::StacksAddress;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::Keypair;
use signer::config::Settings;
use signer::stacks::api::StacksInteract;
use signer::stacks::contracts::AcceptWithdrawalV1;
use signer::stacks::contracts::AsContractCall;
use signer::stacks::contracts::RejectWithdrawalV1;
use signer::stacks::contracts::RotateKeysV1;
use signer::stacks::contracts::SmartContract;
use signer::stacks::contracts::SMART_CONTRACTS;
use signer::stacks::wallet::SignerWallet;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::BitcoinTxId;
use signer::testing::wallet::ContractCallWrapper;
use signer::util::ApiFallbackClient;
use tokio::sync::OnceCell;

use signer::stacks;
use signer::stacks::api::FeePriority;
use signer::stacks::api::StacksClient;
use signer::stacks::api::SubmitTxResponse;
use signer::stacks::contracts::CompleteDepositV1;
use signer::stacks::wallet::MultisigTx;
use signer::storage::in_memory::Store;
use signer::storage::postgres;
use signer::testing;
use signer::testing::wallet::InitiateWithdrawalRequest;

use test_case::test_case;

const TX_FEE: u64 = 123000;

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
    pub stacks_client: ApiFallbackClient<StacksClient>,
}

impl SignerStxState {
    /// Deploy an sBTC smart contract to the stacks node
    async fn deploy_smart_contract(&self, contract: SmartContract) {
        // If the smart contract has been deployed already then there is
        // nothing to do;
        let deployer = self.wallet.address();
        let is_deployed_fut = contract.is_deployed(&self.stacks_client, deployer);
        if is_deployed_fut.await.unwrap() {
            return;
        }
        let mut unsigned = MultisigTx::new_tx(&contract, &self.wallet, TX_FEE);
        for signature in make_signatures(unsigned.tx(), &self.keys) {
            unsigned.add_signature(signature).unwrap();
        }

        let tx = unsigned.finalize_transaction();

        match self.stacks_client.submit_tx(&tx).await.unwrap() {
            SubmitTxResponse::Acceptance(_) => (),
            SubmitTxResponse::Rejection(err) => panic!("{}", serde_json::to_string(&err).unwrap()),
        }
    }
}

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

/// Deploy all sBTC smart contracts to the stacks node
pub async fn deploy_smart_contracts() -> &'static SignerStxState {
    static SBTC_DEPLOYMENT: OnceCell<()> = OnceCell::const_new();
    static SIGNER_STATE: OnceCell<SignerStxState> = OnceCell::const_new();

    let (signer_wallet, key_pairs) = testing::wallet::regtest_bootstrap_wallet();

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
            for contract in SMART_CONTRACTS {
                signer.deploy_smart_contract(contract).await;
            }
        })
        .await;

    signer
}

#[ignore]
#[test_case(ContractCallWrapper(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654789,
    recipient: PrincipalData::parse("SN2V7WTJ7BHR03MPHZ1C9A9ZR6NZGR4WM8HT4V67Y").unwrap(),
    deployer: *testing::wallet::WALLET.0.address(),
    sweep_txid: BitcoinTxId::from([0; 32]),
    sweep_block_hash: BitcoinBlockHash::from([0; 32]),
    sweep_block_height: 7,
}); "complete-deposit standard recipient")]
#[test_case(ContractCallWrapper(CompleteDepositV1 {
    outpoint: bitcoin::OutPoint::null(),
    amount: 123654,
    recipient: PrincipalData::parse("ST1RQHF4VE5CZ6EK3MZPZVQBA0JVSMM9H5PMHMS1Y.my-contract-name").unwrap(),
    deployer: *testing::wallet::WALLET.0.address(),
    sweep_txid: BitcoinTxId::from([0; 32]),
    sweep_block_hash: BitcoinBlockHash::from([0; 32]),
    sweep_block_height: 7,
}); "complete-deposit contract recipient")]
#[test_case(ContractCallWrapper(AcceptWithdrawalV1 {
    request_id: 1,
    outpoint: bitcoin::OutPoint::null(),
    tx_fee: 2500,
    signer_bitmap: BitArray::ZERO,
    deployer: *testing::wallet::WALLET.0.address(),
    sweep_block_hash: BitcoinBlockHash::from([0; 32]),
    sweep_block_height: 7,
}); "accept-withdrawal")]
#[test_case(ContractCallWrapper(InitiateWithdrawalRequest {
    amount: 22500,
    recipient: (0x00, vec![0; 20]),
    max_fee: 3000,
    deployer: *testing::wallet::WALLET.0.address(),
}); "create-withdrawal")]
#[test_case(ContractCallWrapper(RejectWithdrawalV1 {
    request_id: 2,
    signer_bitmap: BitArray::ZERO,
    deployer: *testing::wallet::WALLET.0.address(),
}); "reject-withdrawal")]
#[test_case(ContractCallWrapper(RotateKeysV1::new(
    &testing::wallet::WALLET.0,
    *testing::wallet::WALLET.0.address(),
    &signer::keys::PublicKey::from_slice(&[0x02; 33]).unwrap()
)); "rotate-keys")]
#[tokio::test]
async fn complete_deposit_wrapper_tx_accepted<T: AsContractCall>(contract: ContractCallWrapper<T>) {
    let signer = deploy_smart_contracts().await;
    let mut unsigned = MultisigTx::new_tx(&contract, &signer.wallet, TX_FEE);

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

    let client = stacks_client();

    // We need a block id
    let info = client.get_tenure_info().await.unwrap();
    let storage = Store::new_shared();

    let tenures = stacks::api::fetch_unknown_ancestors(&client, &storage, info.tip_block_id)
        .await
        .unwrap();

    let blocks = tenures
        .into_iter()
        .flat_map(|tenure| tenure.into_blocks())
        .collect::<Vec<_>>();

    let transactions = postgres::extract_relevant_transactions(&blocks, &signer.wallet.address());
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
    let client = stacks_client();

    let payload = SmartContract::SbtcRegistry;

    let _ = client
        .get_client()
        .get_fee_estimate(&payload, None)
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
        .estimate_fees(&testing::wallet::WALLET.0, &payload, FeePriority::Medium)
        .await
        .unwrap();
    more_asserts::assert_gt!(fee, 0);
}
