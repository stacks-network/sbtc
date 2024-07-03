//! Helper module for constructing the signers multi-sig wallet.
//!

use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TransactionAnchorMode;
use blockstack_lib::chainstate::stacks::TransactionAuth;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::chainstate::stacks::TransactionSmartContract;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use blockstack_lib::chainstate::stacks::TransactionVersion;
use blockstack_lib::clarity::vm::ContractName;
use blockstack_lib::types::chainstate::StacksAddress;
use blockstack_lib::util::secp256k1::Secp256k1PublicKey;
use blockstack_lib::util_lib::strings::StacksString;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use secp256k1::Keypair;

use crate::config::NetworkKind;
use crate::stacks::contracts::AsTxPayload;
use crate::stacks::contracts::StacksTxPostConditions;
use crate::stacks::wallet::SignerWallet;

/// Helper function for generating a test 2-3 multi-sig wallet
pub fn generate_wallet() -> (SignerWallet, [Keypair; 3]) {
    let mut rng = StdRng::seed_from_u64(100);

    let key_pairs = [
        Keypair::new_global(&mut rng),
        Keypair::new_global(&mut rng),
        Keypair::new_global(&mut rng),
    ];

    for kp in key_pairs {
        let secret_key = blockstack_lib::util::hash::to_hex(kp.secret_key().as_ref());
        let public_key = Secp256k1PublicKey::from_slice(&kp.public_key().serialize()).unwrap();
        let stx_address = StacksAddress::p2pkh(false, &public_key);
        println!("secret_key: {secret_key}");
        println!("stx_address: {stx_address}");
    }

    let public_keys = key_pairs.map(|kp| kp.public_key());
    let wallet = SignerWallet::new(&public_keys, 2, NetworkKind::Testnet).unwrap();

    println!("wallet stx_address: {}", wallet.address());
    (wallet, key_pairs)
}

/// A trait for deploying the smart contract
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

/// A wrapper type for smart contract deployment that implements AsTxPayload.
pub struct SmartContract<T: AsSmartContract>(pub T);

// Continue as in previous examples...
impl<T: AsSmartContract> AsTxPayload for SmartContract<T> {
    fn tx_payload(&self, _: StacksAddress) -> TransactionPayload {
        TransactionPayload::SmartContract(self.0.as_smart_contract(), None)
    }
    fn post_conditions(&self, _: StacksAddress) -> StacksTxPostConditions {
        StacksTxPostConditions {
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: Vec::new(),
        }
    }
}
