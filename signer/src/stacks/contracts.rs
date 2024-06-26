//! This module contains functionality for creating stacks transactions for
//! sBTC contract calls.
//!
//! Contains structs for the following contract calls:
//! * [`CompleteDepositV1`]: Used for calling the complete-deposit-wrapper
//!   function in the sbtc-deposit contract. This finalizes the deposit by
//!   minting sBTC and sending it to the depositor.

use bitcoin::hashes::Hash as _;
use bitcoin::OutPoint;
use blockstack_lib::chainstate::stacks::TransactionContractCall;
use blockstack_lib::chainstate::stacks::TransactionPostCondition;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::clarity::vm::types::BuffData;
use blockstack_lib::clarity::vm::types::PrincipalData;
use blockstack_lib::clarity::vm::types::SequenceData;
use blockstack_lib::clarity::vm::types::StandardPrincipalData;
use blockstack_lib::clarity::vm::ClarityName;
use blockstack_lib::clarity::vm::ContractName;
use blockstack_lib::clarity::vm::Value;
use blockstack_lib::types::chainstate::StacksAddress;

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

/// A trait to ease construction of a StacksTransaction making sBTC related contract calls.
pub trait AsContractCall {
    /// Converts this struct to a Stacks contract call. The deployer is the
    /// stacks address that deployed the contract.
    fn as_contract_call(&self, deployer: StacksAddress) -> TransactionContractCall;
    /// Any post-execution conditions that we'd like to enforce. The
    /// deployer corresponds to the principal in the Transaction
    /// post-conditions, which is the address that sent the asset.
    fn post_conditions(&self, deployer: StacksAddress) -> StacksTxPostConditions;
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
}

impl CompleteDepositV1 {
    const CONTRACT_NAME: &'static str = "sbtc-deposit";
    const FUNCTION_NAME: &'static str = "complete-deposit-wrapper";

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

impl AsContractCall for CompleteDepositV1 {
    /// Converts this struct to a Stacks Contract call
    fn as_contract_call(&self, deployer: StacksAddress) -> TransactionContractCall {
        TransactionContractCall {
            address: deployer,
            // The following From::from calls are more dangerous than they
            // appear. Under the hood they call their TryFrom::try_from
            // implementation and then unwrap them(!). We check that this
            // is fine in our test.
            function_name: ClarityName::from(CompleteDepositV1::FUNCTION_NAME),
            contract_name: ContractName::from(CompleteDepositV1::CONTRACT_NAME),
            function_args: self.as_contract_args(),
        }
    }

    /// The post conditions for the transaction. We do not enforce any
    /// conditions here, since we trust this contract (we deployed it).
    fn post_conditions(&self, _: StacksAddress) -> StacksTxPostConditions {
        StacksTxPostConditions {
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_contract_call_creation() {
        // This is to check that this function doesn't implicitly panic. If
        // it doesn't panic now, it can never panic at runtime.
        let call = CompleteDepositV1 {
            outpoint: OutPoint::null(),
            amount: 15000,
            recipient: StacksAddress::burn_address(true),
        };

        let _ = call.as_contract_call(StacksAddress::burn_address(false));
    }
}
