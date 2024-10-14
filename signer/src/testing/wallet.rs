//! Helper module for constructing the signers multi-sig wallet.

use std::sync::LazyLock;

use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::chainstate::stacks::TransactionSmartContract;
use blockstack_lib::clarity::vm::ContractName;
use blockstack_lib::util_lib::strings::StacksString;
use clarity::vm::types::TupleData;
use clarity::vm::ClarityName;
use clarity::vm::Value as ClarityValue;
use sbtc::testing::regtest::Recipient;
use secp256k1::Keypair;
use secp256k1::SECP256K1;
use stacks_common::types::chainstate::StacksAddress;

use crate::config::NetworkKind;
use crate::context::Context;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::stacks::contracts::AsContractCall;
use crate::stacks::contracts::AsTxPayload;
use crate::stacks::contracts::ReqContext;
use crate::stacks::contracts::StacksTxPostConditions;
use crate::stacks::wallet::SignerWallet;

/// A static for a test 2-3 multi-sig wallet. This wallet is loaded with
/// funds in the local devnet environment. It matches the signer.deployer
/// address in the default config file.
pub static WALLET: LazyLock<(SignerWallet, [Keypair; 3])> = LazyLock::new(generate_wallet);

/// Helper function for generating a test 2-3 multi-sig wallet.
pub fn generate_wallet() -> (SignerWallet, [Keypair; 3]) {
    let signatures_required = 2;

    let key_pairs = [
        "41634762d89dfa09133a4a8e9c1378d0161d29cd0a9433b51f1e3d32947a73dc",
        "9bfecf16c9c12792589dd2b843f850d5b89b81a04f8ab91c083bdf6709fbefee",
        "3ec0ca5770a356d6cd1a9bfcbf6cd151eb1bd85c388cc00648ec4ef5853fdb74",
    ]
    .map(|sk| Keypair::from_seckey_str(SECP256K1, sk).unwrap());

    let public_keys = key_pairs.map(|kp| kp.public_key().into());
    let wallet =
        SignerWallet::new(&public_keys, signatures_required, NetworkKind::Testnet, 0).unwrap();

    (wallet, key_pairs)
}

/// This function creates a signing set where the aggregate key is the
/// given controller's public key.
pub fn create_signers_keys<R>(rng: &mut R, signer: &Recipient, num_signers: usize) -> Vec<PublicKey>
where
    R: rand::Rng,
{
    // We only take an odd number of signers so that the math works out.
    assert_eq!(num_signers % 2, 1);

    let private_key = PrivateKey::from(signer.keypair.secret_key());
    let aggregate_key = PublicKey::from_private_key(&private_key);
    // The private keys of half of the other signers
    let pks: Vec<secp256k1::SecretKey> = std::iter::repeat_with(|| secp256k1::SecretKey::new(rng))
        .take(num_signers / 2)
        .collect();

    let mut keys: Vec<PublicKey> = pks
        .clone()
        .into_iter()
        .chain(pks.into_iter().map(secp256k1::SecretKey::negate))
        .map(|sk| PublicKey::from_private_key(&PrivateKey::from(sk)))
        .chain([aggregate_key])
        .collect();

    keys.sort();
    keys
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

/// A type for initiating withdrawal requests for testing
#[derive(Debug)]
pub struct InitiateWithdrawalRequest {
    /// The amount of sBTC to send to the recipient, in sats.
    pub amount: u64,
    /// The recipient, defined as a Pox address.
    pub recipient: (u8, Vec<u8>),
    /// The maximum fee amount of sats to pay to the bitcoin miners when
    /// sending to the recipient.
    pub max_fee: u64,
    /// The address that deployed the contract.
    pub deployer: StacksAddress,
}

impl AsContractCall for InitiateWithdrawalRequest {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const FUNCTION_NAME: &'static str = "initiate-withdrawal-request";
    /// The stacks address that deployed the contract.
    fn deployer_address(&self) -> StacksAddress {
        self.deployer
    }
    /// The arguments to the clarity function.
    fn as_contract_args(&self) -> Vec<ClarityValue> {
        let data = vec![
            (
                ClarityName::from("version"),
                ClarityValue::buff_from_byte(self.recipient.0),
            ),
            (
                ClarityName::from("hashbytes"),
                ClarityValue::buff_from(self.recipient.1.clone()).unwrap(),
            ),
        ];
        vec![
            ClarityValue::UInt(self.amount as u128),
            ClarityValue::Tuple(TupleData::from_data(data).unwrap()),
            ClarityValue::UInt(self.max_fee as u128),
        ]
    }
    async fn validate<C>(&self, _db: &C, _ctx: &ReqContext) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::OsRng;
    use test_case::test_case;

    #[test_case(3; "3 signers")]
    #[test_case(5; "5 signers")]
    #[test_case(7; "7 signers")]
    #[test_case(15; "15 signers")]
    fn constructed_signer_set_has_desired_aggregate_key(num_signers: usize) {
        let signer = Recipient::new(bitcoin::AddressType::P2tr);

        let aggregate_key = PublicKey::from(signer.keypair.public_key());
        let keys = create_signers_keys(&mut OsRng, &signer, num_signers);

        assert_eq!(keys.len(), num_signers);
        assert_eq!(PublicKey::combine_keys(&keys).unwrap(), aggregate_key);
    }
}
