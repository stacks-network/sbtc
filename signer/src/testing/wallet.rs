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
use crate::stacks::contracts::AsContractCall;
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

/// A generic new-type that implements [`AsTxPayload`] for all types that
/// implement [`AsContractCall`].
///
/// # Notes
///
/// Although we already have the [`ContractCall`] enum type, there are
/// other contract calls that are useful for testing purposes, so this
/// struct is to support that seamlessly. Ideally, every type that
/// implements [`AsContractCall`] should implement [`AsTxPayload`]
/// automatically. What we want is to have something like the following:
///
/// ```text
/// impl<T: AsContractCall> AsTxPayload for T { ... }
/// ```
///
/// But that would preclude us from adding something like:
///
/// ```text
/// impl<T: AsSmartContract> AsTxPayload for T { ... }
/// ```
///
/// since doing so is prevented by the compiler because it introduces
/// ambiguity. One work-around is to use a wrapper type that implements the
/// trait that we want.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractCallWrapper<T>(pub T);

impl<T: AsContractCall> AsTxPayload for ContractCallWrapper<T> {
    fn tx_payload(&self) -> TransactionPayload {
        TransactionPayload::ContractCall(self.0.as_contract_call())
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        self.0.post_conditions()
    }
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
/// [`ContractCallWrapper`] struct.
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
