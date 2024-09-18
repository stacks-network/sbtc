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
use std::future::Future;
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
use blockstack_lib::clarity::vm::types::BUFF_33;
use blockstack_lib::clarity::vm::ClarityName;
use blockstack_lib::clarity::vm::ContractName;
use blockstack_lib::clarity::vm::Value as ClarityValue;
use blockstack_lib::types::chainstate::StacksAddress;

use crate::error::Error;
use crate::keys::PublicKey;
use crate::stacks::wallet::SignerWallet;
use crate::storage::DbRead;

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

impl AsTxPayload for TransactionPayload {
    fn tx_payload(&self) -> TransactionPayload {
        self.clone()
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        StacksTxPostConditions {
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: Vec::new(),
        }
    }
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
    fn as_contract_args(&self) -> Vec<ClarityValue>;
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
    /// Validate that it is okay to sign this contract call transaction,
    /// because the included data matches what this signer knows from the
    /// stacks and bitcoin blockchains.
    fn validate<S>(&self, _: &S) -> impl Future<Output = Result<bool, Error>> + Send
    where
        S: DbRead + Send + Sync;
}

/// An enum representing all contract calls that the signers can make.
#[derive(Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ContractCall {
    /// Call the `complete-deposit-wrapper` function in the `sbtc-deposit`
    /// smart contract
    CompleteDepositV1(CompleteDepositV1),
    /// Call the `accept-withdrawal-request` function in the
    /// `sbtc-withdrawal` smart contract.
    AcceptWithdrawalV1(AcceptWithdrawalV1),
    /// Call the `reject-withdrawal-request` function in the
    /// `sbtc-withdrawal` smart contract.
    RejectWithdrawalV1(RejectWithdrawalV1),
    /// Call the `rotate-keys-wrapper` function in the
    /// `sbtc-bootstrap-signers` smart contract.
    RotateKeysV1(RotateKeysV1),
}

impl AsTxPayload for ContractCall {
    fn tx_payload(&self) -> TransactionPayload {
        let contract_call = match self {
            ContractCall::AcceptWithdrawalV1(contract) => contract.as_contract_call(),
            ContractCall::CompleteDepositV1(contract) => contract.as_contract_call(),
            ContractCall::RejectWithdrawalV1(contract) => contract.as_contract_call(),
            ContractCall::RotateKeysV1(contract) => contract.as_contract_call(),
        };
        TransactionPayload::ContractCall(contract_call)
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        match self {
            ContractCall::AcceptWithdrawalV1(contract) => contract.post_conditions(),
            ContractCall::CompleteDepositV1(contract) => contract.post_conditions(),
            ContractCall::RejectWithdrawalV1(contract) => contract.post_conditions(),
            ContractCall::RotateKeysV1(contract) => contract.post_conditions(),
        }
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the complete-deposit-wrapper function in the sbtc-deposit
/// smart contract.
#[derive(Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CompleteDepositV1 {
    /// The outpoint of the bitcoin UTXO that was spent as a deposit for
    /// sBTC.
    pub outpoint: OutPoint,
    /// The amount of sats associated with the above UTXO.
    pub amount: u64,
    /// The address where the newly minted sBTC will be deposited.
    pub recipient: PrincipalData,
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
    fn as_contract_args(&self) -> Vec<ClarityValue> {
        let txid_data = self.outpoint.txid.to_byte_array().to_vec();
        let txid = BuffData { data: txid_data };

        vec![
            ClarityValue::Sequence(SequenceData::Buffer(txid)),
            ClarityValue::UInt(self.outpoint.vout as u128),
            ClarityValue::UInt(self.amount as u128),
            ClarityValue::Principal(self.recipient.clone()),
        ]
    }
    /// Validates that the Complete deposit request satisfies the following
    /// criteria:
    ///
    /// 1. That the outpoint exists on the canonical bitcoin blockchain.
    /// 2. That the outpoint was used as an input into a signer sweep
    ///    transaction.
    /// 3. That the signer sweep transaction exists on the canonical
    ///    bitcoin blockchain.
    /// 5. That the `amount` matches the amount in the `outpoint` less
    ///    their portion of fees spent in the sweep transaction.
    /// 4. That the principal matches the principal embedded in the deposit
    ///    script locked in the outpoint.
    async fn validate<S>(&self, _storage: &S) -> Result<bool, Error>
    where
        S: DbRead + Send + Sync,
    {
        // TODO(255): Add validation implementation
        Ok(false)
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the accept-withdrawal-request function in the
/// sbtc-withdrawal smart contract.
#[derive(Copy, Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
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
    pub signer_bitmap: BitArray<[u8; 16]>,
    /// The address that deployed the contract.
    pub deployer: StacksAddress,
}

impl AsContractCall for AcceptWithdrawalV1 {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const FUNCTION_NAME: &'static str = "accept-withdrawal-request";

    fn deployer_address(&self) -> StacksAddress {
        self.deployer
    }
    fn as_contract_args(&self) -> Vec<ClarityValue> {
        let txid_data = self.outpoint.txid.to_byte_array().to_vec();
        let txid = BuffData { data: txid_data };

        vec![
            ClarityValue::UInt(self.request_id as u128),
            ClarityValue::Sequence(SequenceData::Buffer(txid)),
            ClarityValue::UInt(self.signer_bitmap.load_le()),
            ClarityValue::UInt(self.outpoint.vout as u128),
            ClarityValue::UInt(self.tx_fee as u128),
        ]
    }
    /// Validates that the accept-withdrawal-request satisfies the
    /// following criteria:
    ///
    /// 1. That the transaction with the associated request_id is stored as
    ///    an event on the canonical Stacks blockchain.
    /// 2. That the transaction associated with the outpoint has been
    ///    confirmed on the canonical bitcoin blockchain.
    /// 3. That the signer bitmap matches the signer decisions stored in
    ///    this signer's database.
    /// 4. That the `tx_fee` matches the amount spent to the bitcoin miner.
    async fn validate<S>(&self, _storage: &S) -> Result<bool, Error>
    where
        S: DbRead + Send + Sync,
    {
        // TODO(255): Add validation implementation
        Ok(false)
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the reject-withdrawal-request function in the
/// sbtc-withdrawal smart contract.
#[derive(Copy, Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RejectWithdrawalV1 {
    /// The ID of the withdrawal request generated by the
    /// initiate-withdrawal-request function in the sbtc-withdrawal smart
    /// contract.
    pub request_id: u64,
    /// A bitmap of how the signers voted. This structure supports up to
    /// 128 distinct signers. Here, we assume that a 1 (or true) implies
    /// that the signer voted *against* the transaction.
    pub signer_bitmap: BitArray<[u8; 16]>,
    /// The address that deployed the contract.
    pub deployer: StacksAddress,
}

impl AsContractCall for RejectWithdrawalV1 {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const FUNCTION_NAME: &'static str = "reject-withdrawal-request";

    fn deployer_address(&self) -> StacksAddress {
        self.deployer
    }
    fn as_contract_args(&self) -> Vec<ClarityValue> {
        vec![
            ClarityValue::UInt(self.request_id as u128),
            ClarityValue::UInt(self.signer_bitmap.load_le()),
        ]
    }
    /// Validates that the reject-withdrawal-request satisfies the
    /// following criteria:
    ///
    /// 1. That the transaction with the associated request_id is stored as
    ///    an event on the canonical Stacks blockchain.
    /// 2. That the signer bitmap matches the signer decisions stored in
    ///    this signer's database.
    async fn validate<S>(&self, _storage: &S) -> Result<bool, Error>
    where
        S: DbRead + Send + Sync,
    {
        // TODO(255): Add validation implementation
        Ok(false)
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the rotate-keys-wrapper function in the
/// sbtc-bootstrap-signers smart contract.
#[derive(Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RotateKeysV1 {
    /// The new set of public keys for all known signers during this
    /// PoX cycle.
    new_keys: BTreeSet<PublicKey>,
    /// The aggregate key created by combining the above public keys.
    aggregate_key: PublicKey,
    /// The address that deployed the contract.
    deployer: StacksAddress,
    /// The number of signatures required for the multi-sig wallet.
    signatures_required: u16,
}

impl RotateKeysV1 {
    /// Create a new instance of RotateKeysV1 using the provided wallet.
    pub fn new(wallet: &SignerWallet, deployer: StacksAddress, signatures_required: u16) -> Self {
        Self {
            aggregate_key: wallet.aggregate_key(),
            new_keys: wallet.public_keys().clone(),
            deployer,
            signatures_required,
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
    fn as_contract_args(&self) -> Vec<ClarityValue> {
        let new_key_data: Vec<ClarityValue> = self
            .new_keys
            .iter()
            .map(|pk| {
                let data = pk.serialize().to_vec();
                ClarityValue::Sequence(SequenceData::Buffer(BuffData { data }))
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
            ClarityValue::Sequence(SequenceData::List(new_keys)),
            ClarityValue::Sequence(SequenceData::Buffer(BuffData { data: key.to_vec() })),
            ClarityValue::UInt(self.signatures_required as u128),
        ]
    }
    /// Validates that the rotate-keys-wrapper satisfies the following
    /// criteria:
    ///
    /// 1. That the aggregate key matches what is expected from the given
    ///    public keys.
    /// 2. That public keys match current known set of signers.
    /// 3. That the proposed signer set is different from last known signer
    ///    set, or the proposed signer set is the same and the signatures
    ///    threshold is different from the last signature threshold.
    /// 4. That the number of required signatures is strictly greater than
    ///    `new_keys as f64 / 2.0`.
    async fn validate<S>(&self, _storage: &S) -> Result<bool, Error>
    where
        S: DbRead + Send + Sync,
    {
        // TODO(255): Add validation implementation
        Ok(false)
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
            recipient: PrincipalData::from(StacksAddress::burn_address(true)),
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
            signer_bitmap: BitArray::ZERO,
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
            signer_bitmap: BitArray::new([1; 16]),
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
        let public_keys = secret_keys.map(|sk| sk.public_key(SECP256K1).into());
        let wallet = SignerWallet::new(&public_keys, 2, NetworkKind::Testnet, 0).unwrap();
        let deployer = StacksAddress::burn_address(false);

        let call = RotateKeysV1::new(&wallet, deployer, 2);

        // This is to check that this function doesn't implicitly panic. If
        // it doesn't panic now, it can never panic at runtime.
        let _ = call.as_contract_call();
    }
}
