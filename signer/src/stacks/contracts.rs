//! This module contains functionality for creating stacks transactions for
//! sBTC contract calls.
//!
//! Contains structs for the following contract calls:
//! * [`CompleteDepositV1`]: Used for calling the complete-deposit-wrapper
//!   function in the sbtc-deposit contract. This finalizes the deposit by
//!   minting sBTC and sending it to the depositor.
//! * [`AcceptWithdrawalV1`]: Used for calling the
//!   accept-withdrawal-request function in the sbtc-withdrawal contract.
//!   This finalizes the withdrawal request by burning the locked sBTC.
//! * [`RejectWithdrawalV1`]: Used for calling the
//!   reject-withdrawal-request function in the sbtc-withdrawal contract.
//!   This finalizes the withdrawal request by returning the locked sBTC to
//!   the requester.
//! * [`RotateKeysV1`]: Used for calling the rotate-keys-wrapper function
//!   in the sbtc-bootstrap-signers contract. This changes the valid caller
//!   of most sBTC related functions to a new multi-sig wallet.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use bitcoin::hashes::Hash as _;
use bitcoin::OutPoint;
use bitvec::array::BitArray;
use bitvec::field::BitField as _;
use blockstack_lib::chainstate::stacks::TransactionContractCall;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPostCondition;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::clarity::vm::types::BuffData;
use blockstack_lib::clarity::vm::types::ListData;
use blockstack_lib::clarity::vm::types::ListTypeData;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::types::SequenceData;
use blockstack_lib::clarity::vm::types::StandardPrincipalData;
use blockstack_lib::clarity::vm::types::BUFF_33;
use blockstack_lib::clarity::vm::ClarityName;
use blockstack_lib::clarity::vm::ContractName;
use blockstack_lib::clarity::vm::Value;
use blockstack_lib::types::chainstate::StacksAddress;
use secp256k1::PublicKey;

use crate::stacks::wallet::SignerWallet;

/// A struct describing any transaction post-execution conditions that we'd
/// like to enforce.
///
/// # Note
///
/// * It's unlikely that this will be necessary since the signers control
///   the contract to begin with, we implicitly trust it.
/// * We cannot enforce any conditions on the destination of any sBTC, just
///   the source and the amount.
/// * SIP-005 describes the post conditions, including its limitations, and
///   can be found here
///   https://github.com/stacksgov/sips/blob/main/sips/sip-005/sip-005-blocks-and-transactions.md#transaction-post-conditions
#[derive(Debug)]
pub struct StacksTxPostConditions {
    /// Specifies whether other asset transfers not covered by the
    /// post-conditions are permitted.
    pub post_condition_mode: TransactionPostConditionMode,
    /// Any post-execution conditions that we'd like to enforce.
    pub post_conditions: Vec<TransactionPostCondition>,
}

/// A trait for constructing the payload for a stacks transaction along
/// with any post execution conditions.
pub trait AsTxPayload {
    /// The payload of the transaction
    fn tx_payload(&self) -> TransactionPayload;
    /// Any post-execution conditions that we'd like to enforce. The
    /// deployer corresponds to the principal in the Transaction
    /// post-conditions, which is the address that sent the asset. The
    /// default is that we do not enforce any conditions since we usually
    /// deployed the contract.
    fn post_conditions(&self) -> StacksTxPostConditions;
}

/// A trait to ease construction of a StacksTransaction making sBTC related
/// contract calls.
pub trait AsContractCall {
    /// The name of the clarity smart contract that relates to this struct.
    const CONTRACT_NAME: &'static str;
    /// The specific function name that relates to this struct.
    const FUNCTION_NAME: &'static str;
    /// The stacks address that deployed the contract.
    fn deployer_address(&self) -> StacksAddress;
    /// The arguments to the clarity function.
    fn as_contract_args(&self) -> Vec<Value>;
    /// Convert this struct to a Stacks contract call.
    fn as_contract_call(&self) -> TransactionContractCall {
        TransactionContractCall {
            address: self.deployer_address(),
            // The following From::from calls are more dangerous than they
            // appear. Under the hood they call their TryFrom::try_from
            // implementation and then unwrap them(!). We check that this
            // is fine in our test.
            function_name: ClarityName::from(Self::FUNCTION_NAME),
            contract_name: ContractName::from(Self::CONTRACT_NAME),
            function_args: self.as_contract_args(),
        }
    }
    /// Any post-execution conditions that we'd like to enforce. The
    /// deployer corresponds to the principal in the Transaction
    /// post-conditions, which is the address that sent the asset. The
    /// default is that we do not enforce any conditions since we usually
    /// deployed the contract.
    fn post_conditions(&self) -> StacksTxPostConditions {
        StacksTxPostConditions {
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: Vec::new(),
        }
    }
}

/// A generic new-type that implements AsTxPayload for all types that
/// implement AsContractCall.
///
/// # Notes
///
/// Ideally, every type that implements AsContractCall should implement
/// AsTxPayload automatically. What we want is to have something like the
/// following:
///
/// impl<T: AsContractCall> AsTxPayload for T { ... }
///
/// But that would preclude us from adding something like:
///
/// impl<T: AsSmartContract> AsTxPayload for T { ... }
///
/// since doing so is prevented by the compiler because it introduces
/// ambiguity. One work-around is to use a wrapper type that implements the
/// trait that we want.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractCall<T>(pub T);

impl<T: AsContractCall> AsTxPayload for ContractCall<T> {
    fn tx_payload(&self) -> TransactionPayload {
        TransactionPayload::ContractCall(self.0.as_contract_call())
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        self.0.post_conditions()
    }
}

impl<T: AsContractCall> From<T> for ContractCall<T> {
    fn from(value: T) -> Self {
        ContractCall(value)
    }
}

impl<T: AsContractCall> std::ops::Deref for ContractCall<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: AsContractCall> std::ops::DerefMut for ContractCall<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the complete-deposit-wrapper function in the sbtc-deposit
/// smart contract.
#[derive(Copy, Clone, Debug)]
pub struct CompleteDepositV1 {
    /// The outpoint of the bitcoin UTXO that was spent as a deposit for
    /// sBTC.
    pub outpoint: OutPoint,
    /// The amount of sats associated with the above UTXO.
    pub amount: u64,
    /// The address where the newly minted sBTC will be deposited.
    pub recipient: StacksAddress,
    /// The address that deployed the contract.
    pub deployer: StacksAddress,
}

impl AsContractCall for CompleteDepositV1 {
    const CONTRACT_NAME: &'static str = "sbtc-deposit";
    const FUNCTION_NAME: &'static str = "complete-deposit-wrapper";

    fn deployer_address(&self) -> StacksAddress {
        self.deployer
    }
    /// Construct the input arguments to the complete-deposit-wrapper
    /// contract call.
    fn as_contract_args(&self) -> Vec<Value> {
        let txid_data = self.outpoint.txid.to_byte_array().to_vec();
        let txid = BuffData { data: txid_data };
        let principle = StandardPrincipalData::from(self.recipient);

        vec![
            Value::Sequence(SequenceData::Buffer(txid)),
            Value::UInt(self.outpoint.vout as u128),
            Value::UInt(self.amount as u128),
            Value::Principal(PrincipalData::Standard(principle)),
        ]
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the accept-withdrawal-request function in the
/// sbtc-withdrawal smart contract.
#[derive(Copy, Clone, Debug)]
pub struct AcceptWithdrawalV1 {
    /// The ID of the withdrawal request generated by the
    /// initiate-withdrawal-request function in the sbtc-withdrawal smart
    /// contract.
    pub request_id: u64,
    /// The outpoint of the bitcoin UTXO that was spent to fulfill the
    /// withdrawal request.
    pub outpoint: OutPoint,
    /// The fee that was spent to the bitcoin miner when fulfilling the
    /// withdrawal request.
    pub tx_fee: u64,
    /// A bitmap of how the signers voted. This structure supports up to
    /// 128 distinct signers. Here, we assume that a 1 (or true) implies
    /// that the signer voted *against* the transaction.
    pub signer_bitmap: BitArray<[u64; 2]>,
    /// The address that deployed the contract.
    pub deployer: StacksAddress,
}

impl AsContractCall for AcceptWithdrawalV1 {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const FUNCTION_NAME: &'static str = "accept-withdrawal-request";

    fn deployer_address(&self) -> StacksAddress {
        self.deployer
    }
    fn as_contract_args(&self) -> Vec<Value> {
        let txid_data = self.outpoint.txid.to_byte_array().to_vec();
        let txid = BuffData { data: txid_data };

        vec![
            Value::UInt(self.request_id as u128),
            Value::Sequence(SequenceData::Buffer(txid)),
            Value::UInt(self.signer_bitmap.load()),
            Value::UInt(self.outpoint.vout as u128),
            Value::UInt(self.tx_fee as u128),
        ]
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the reject-withdrawal-request function in the
/// sbtc-withdrawal smart contract.
#[derive(Copy, Clone, Debug)]
pub struct RejectWithdrawalV1 {
    /// The ID of the withdrawal request generated by the
    /// initiate-withdrawal-request function in the sbtc-withdrawal smart
    /// contract.
    pub request_id: u64,
    /// A bitmap of how the signers voted. This structure supports up to
    /// 128 distinct signers. Here, we assume that a 1 (or true) implies
    /// that the signer voted *against* the transaction.
    pub signer_bitmap: BitArray<[u64; 2]>,
    /// The address that deployed the contract.
    pub deployer: StacksAddress,
}

impl AsContractCall for RejectWithdrawalV1 {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const FUNCTION_NAME: &'static str = "reject-withdrawal-request";

    fn deployer_address(&self) -> StacksAddress {
        self.deployer
    }
    fn as_contract_args(&self) -> Vec<Value> {
        vec![
            Value::UInt(self.request_id as u128),
            Value::UInt(self.signer_bitmap.load()),
        ]
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the rotate-keys-wrapper function in the
/// sbtc-bootstrap-signers smart contract.
#[derive(Clone, Debug)]
pub struct RotateKeysV1 {
    /// The new set of public keys for all known signers during this
    /// PoX cycle.
    new_keys: BTreeSet<PublicKey>,
    /// The aggregate key created by combining the above public keys.
    aggregate_key: PublicKey,
    /// The address that deployed the contract.
    deployer: StacksAddress,
}

impl RotateKeysV1 {
    /// Create a new instance of RotateKeysV1 using the provided wallet.
    pub fn new(wallet: &SignerWallet, deployer: StacksAddress) -> Self {
        Self {
            aggregate_key: wallet.aggregate_key(),
            new_keys: wallet.public_keys().iter().copied().collect(),
            deployer,
        }
    }

    /// This function returns the clarity description of one of the inputs
    /// to the contract call.
    ///
    /// # Notes
    ///
    /// One of the inputs, new-keys, is a (list 128 (buff 33)). This
    /// function represents this data type.
    fn list_data_type() -> &'static ListTypeData {
        static KEYS_ARGUMENT_DATA_TYPE: OnceLock<ListTypeData> = OnceLock::new();
        KEYS_ARGUMENT_DATA_TYPE.get_or_init(|| {
            // A Result::Err is returned whenever the "depth" of the type
            // is too large or if the maximum size of an input with the
            // given type is too large. None of this is true for us, the
            // depth is 1 or 2 and the size is 128 * 33 bytes, which is
            // under the limit of 1 MB.
            ListTypeData::new_list(BUFF_33.clone(), crate::MAX_KEYS as u32)
                .expect("Error: legal ListTypeData marked as invalid")
        })
    }
}

impl AsContractCall for RotateKeysV1 {
    const CONTRACT_NAME: &'static str = "sbtc-bootstrap-signers";
    const FUNCTION_NAME: &'static str = "rotate-keys-wrapper";

    fn deployer_address(&self) -> StacksAddress {
        self.deployer
    }
    /// The arguments to the contract call function
    ///
    /// # Notes
    ///
    /// The signature to this function is:
    ///
    ///   (new-keys (list 128 (buff 33))) (new-aggregate-pubkey (buff 33))
    fn as_contract_args(&self) -> Vec<Value> {
        let new_key_data: Vec<Value> = self
            .new_keys
            .iter()
            .map(|pk| {
                let data = pk.serialize().to_vec();
                Value::Sequence(SequenceData::Buffer(BuffData { data }))
            })
            .collect();

        let new_keys = ListData {
            data: new_key_data,
            type_signature: Self::list_data_type().clone(),
        };

        // The public key needs to be exactly 33 bytes in this contract
        // call.
        let key: [u8; 33] = self.aggregate_key.serialize();

        vec![
            Value::Sequence(SequenceData::List(new_keys)),
            Value::Sequence(SequenceData::Buffer(BuffData { data: key.to_vec() })),
        ]
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng as _;
    use secp256k1::SecretKey;
    use secp256k1::SECP256K1;

    use crate::config::NetworkKind;

    use super::*;

    #[test]
    fn deposit_contract_call_creation() {
        // This is to check that this function doesn't implicitly panic. If
        // it doesn't panic now, it can never panic at runtime.
        let call = CompleteDepositV1 {
            outpoint: OutPoint::null(),
            amount: 15000,
            recipient: StacksAddress::burn_address(true),
            deployer: StacksAddress::burn_address(false),
        };

        let _ = call.as_contract_call();
    }

    #[test]
    fn withdrawal_accept_contract_call_creation() {
        // This is to check that this function doesn't implicitly panic. If
        // it doesn't panic now, it can never panic at runtime.
        let call = AcceptWithdrawalV1 {
            request_id: 42,
            outpoint: OutPoint::null(),
            tx_fee: 125,
            signer_bitmap: BitArray::new([0; 2]),
            deployer: StacksAddress::burn_address(false),
        };

        let _ = call.as_contract_call();
    }

    #[test]
    fn reject_withdrawal_contract_call_creation() {
        // This is to check that this function doesn't implicitly panic. If
        // it doesn't panic now, it can never panic at runtime.
        let call = RejectWithdrawalV1 {
            request_id: 42,
            signer_bitmap: BitArray::new([1; 2]),
            deployer: StacksAddress::burn_address(false),
        };

        let _ = call.as_contract_call();
    }

    #[test]
    fn rotate_keys_wrapper_contract_call_creation() {
        // This is to check that the RotateKeysV1::list_data_type function
        // doesn't panic. If it doesn't panic now, it can never panic at
        // runtime.
        let _ = RotateKeysV1::list_data_type();

        let mut rng = StdRng::seed_from_u64(112);
        let secret_keys = [
            SecretKey::new(&mut rng),
            SecretKey::new(&mut rng),
            SecretKey::new(&mut rng),
        ];
        let public_keys = secret_keys.map(|sk| sk.public_key(SECP256K1));
        let wallet = SignerWallet::new(&public_keys, 2, NetworkKind::Testnet, 0).unwrap();
        let deployer = StacksAddress::burn_address(false);

        let call = RotateKeysV1::new(&wallet, deployer);

        // This is to check that this function doesn't implicitly panic. If
        // it doesn't panic now, it can never panic at runtime.
        let _ = call.as_contract_call();
    }
}
