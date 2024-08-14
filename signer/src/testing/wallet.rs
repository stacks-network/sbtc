//! Helper module for constructing the signers multi-sig wallet.

use std::sync::LazyLock;

use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::chainstate::stacks::TransactionSmartContract;
use blockstack_lib::clarity::vm::ContractName;
use blockstack_lib::util_lib::strings::StacksString;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use secp256k1::Keypair;

use crate::config::NetworkKind;
use crate::stacks::contracts::AsTxPayload;
use crate::stacks::contracts::StacksTxPostConditions;
use crate::stacks::wallet::SignerWallet;

/// A static for a test 2-3 multi-sig wallet. This wallet is loaded with
/// funds in the local devnet environment.
pub static WALLET: LazyLock<(SignerWallet, [Keypair; 3], u16)> = LazyLock::new(generate_wallet);

/// Helper function for generating a test 2-3 multi-sig wallet
pub fn generate_wallet() -> (SignerWallet, [Keypair; 3], u16) {
    let mut rng = StdRng::seed_from_u64(100);
    let signatures_required = 2;

    let key_pairs = [
        Keypair::new_global(&mut rng),
        Keypair::new_global(&mut rng),
        Keypair::new_global(&mut rng),
    ];

    let public_keys = key_pairs.map(|kp| kp.public_key().into());
    let wallet =
        SignerWallet::new(&public_keys, signatures_required, NetworkKind::Testnet, 0).unwrap();

    (wallet, key_pairs, signatures_required)
}

/// A trait for deploying the smart contract
pub trait AsContractDeploy {
    /// The name of the clarity smart contract that relates to this struct.
    const CONTRACT_NAME: &'static str;
    /// The actual body of the clarity contract.
    const CONTRACT_BODY: &'static str;
    /// Convert this struct to a Stacks contract deployment.
    fn as_smart_contract(&self) -> TransactionSmartContract {
        TransactionSmartContract {
            name: ContractName::from(Self::CONTRACT_NAME),
            code_body: StacksString::from_str(Self::CONTRACT_BODY).unwrap(),
        }
    }
}

/// A wrapper type for smart contract deployment that implements
/// AsTxPayload. This is analogous to the
/// crate::stacks::contracts::ContractCall struct.
pub struct ContractDeploy<T>(pub T);

impl<T: AsContractDeploy> AsTxPayload for ContractDeploy<T> {
    fn tx_payload(&self) -> TransactionPayload {
        TransactionPayload::SmartContract(self.0.as_smart_contract(), None)
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        StacksTxPostConditions {
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: Vec::new(),
        }
    }
}
