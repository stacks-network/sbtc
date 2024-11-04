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
use std::ops::Deref;
use std::sync::OnceLock;

use bitcoin::hashes::Hash as _;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::TxOut;
use bitvec::array::BitArray;
use bitvec::field::BitField as _;
use blockstack_lib::chainstate::stacks::TransactionContractCall;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPostCondition;
use blockstack_lib::chainstate::stacks::TransactionPostConditionMode;
use blockstack_lib::chainstate::stacks::TransactionSmartContract;
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
use blockstack_lib::util_lib::strings::StacksString;

use crate::bitcoin::BitcoinInteract;
use crate::context::Context;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::stacks::wallet::SignerWallet;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinBlockRef;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::ScriptPubKey;
use crate::storage::DbRead;

use super::api::StacksInteract;

// use super::api::StacksInteract;

/// This struct is used as supplemental data to help validate a request to
/// sign a contract call transaction.
///
/// Except for the origin, this data is not fetched from the signer that
/// sent the request, but is instead internal to the current signer.
#[derive(Debug, Clone, Copy)]
pub struct ReqContext {
    /// This signer's current view of the chain tip of the canonical
    /// bitcoin blockchain. It is the block hash and height of the block on
    /// the bitcoin blockchain with the greatest height. On ties, we sort
    /// by the block hash descending and take the first one.
    pub chain_tip: BitcoinBlockRef,
    /// How many bitcoin blocks back from the chain tip the signer will
    /// look for requests.
    pub context_window: u16,
    /// The public key of the signer that created the deposit request
    /// transaction. This is very unlikely to ever be used in the
    /// [`AsContractCall::validate`] function, but is here for logging and
    /// tracking purposes.
    pub origin: PublicKey,
    /// This is the aggregate public key used to lock funds on bitcoin that
    /// was the output of DKG. We use it to identify the signing set for
    /// the stacks transaction that the signer was asked to sign.
    pub aggregate_key: PublicKey,
    /// The number of signatures required for an accepted deposit request.
    pub signatures_required: u16,
    /// The expected deployer of the sBTC smart contract.
    pub deployer: StacksAddress,
}

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
    fn validate<C>(
        &self,
        ctx: &C,
        req_ctx: &ReqContext,
    ) -> impl Future<Output = Result<(), Error>> + Send
    where
        C: Context + Send + Sync;
}

/// An enum representing all Contract transaction types that the signers can make.
/// Mainly used for creating StacksTransactionSignRequest messages.
#[derive(Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ContractTx {
    /// A contract call transaction.
    ContractCall(ContractCall),
    /// A contract deploy transaction.
    ContractDeploy(ContractDeploy),
}

impl AsTxPayload for ContractTx {
    fn tx_payload(&self) -> TransactionPayload {
        match self {
            ContractTx::ContractCall(call) => call.tx_payload(),
            ContractTx::ContractDeploy(deploy) => deploy.tx_payload(),
        }
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        match self {
            ContractTx::ContractCall(call) => call.post_conditions(),
            ContractTx::ContractDeploy(deploy) => deploy.post_conditions(),
        }
    }
}

impl From<ContractCall> for ContractTx {
    fn from(val: ContractCall) -> Self {
        ContractTx::ContractCall(val)
    }
}

impl From<ContractDeploy> for ContractTx {
    fn from(val: ContractDeploy) -> Self {
        ContractTx::ContractDeploy(val)
    }
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
        match self {
            ContractCall::AcceptWithdrawalV1(contract) => contract.tx_payload(),
            ContractCall::CompleteDepositV1(contract) => contract.tx_payload(),
            ContractCall::RejectWithdrawalV1(contract) => contract.tx_payload(),
            ContractCall::RotateKeysV1(contract) => contract.tx_payload(),
        }
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        match self {
            ContractCall::AcceptWithdrawalV1(contract) => AsContractCall::post_conditions(contract),
            ContractCall::CompleteDepositV1(contract) => AsContractCall::post_conditions(contract),
            ContractCall::RejectWithdrawalV1(contract) => AsContractCall::post_conditions(contract),
            ContractCall::RotateKeysV1(contract) => AsContractCall::post_conditions(contract),
        }
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the complete-deposit-wrapper function in the sbtc-deposit
/// smart contract.
#[derive(Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CompleteDepositV1 {
    /// The outpoint of the bitcoin UTXO that was spent as a deposit for
    /// sBTC. This is used to identify the deposit transaction when doing
    /// validation, as well as in the clarity contract call to avoid double
    /// minting.
    pub outpoint: OutPoint,
    /// The amount of sats swept in by the signers when they moved in the
    /// above UTXO. This amount is less than the amount associated with the
    /// above UTXO because of bitcoin mining fees.
    pub amount: u64,
    /// The address where the newly minted sBTC will be deposited.
    pub recipient: PrincipalData,
    /// The address that deployed the contract.
    pub deployer: StacksAddress,
    /// The transaction ID for the sweep transaction that moved the deposit
    /// UTXO into the signers' UTXO. One of the inputs to this transaction
    /// must be the above `outpoint`.
    pub sweep_txid: BitcoinTxId,
    /// The block hash of the bitcoin block that contains a sweep
    /// transaction with the above `outpoint` as one of its inputs. This
    /// field, with the `sweep_block_height` field, is used by the
    /// `complete-deposit-wrapper` clarity function to ensure that we do
    /// not mint in case a bitcoin reorg affects the sweep transaction
    /// that is included in this block.
    pub sweep_block_hash: BitcoinBlockHash,
    /// The block height associated with the above bitcoin block hash.
    pub sweep_block_height: u64,
}

impl AsTxPayload for CompleteDepositV1 {
    fn tx_payload(&self) -> TransactionPayload {
        TransactionPayload::ContractCall(self.as_contract_call())
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        AsContractCall::post_conditions(self)
    }
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
        let burn_hash_data = self.sweep_block_hash.to_byte_array().to_vec();
        let burn_hash = BuffData { data: burn_hash_data };

        vec![
            ClarityValue::Sequence(SequenceData::Buffer(txid)),
            ClarityValue::UInt(self.outpoint.vout as u128),
            ClarityValue::UInt(self.amount as u128),
            ClarityValue::Principal(self.recipient.clone()),
            ClarityValue::Sequence(SequenceData::Buffer(burn_hash)),
            ClarityValue::UInt(self.sweep_block_height as u128),
        ]
    }
    /// Validates that the Complete deposit request satisfies the following
    /// criteria:
    ///
    /// 1. That the smart contract deployer matches the deployer in our
    ///    context.
    /// 2. That the signer has a record of the deposit request in its list
    ///    of pending and accepted deposit requests.
    /// 3. That the signer sweep transaction is on the canonical bitcoin
    ///    blockchain.
    /// 4. That the sweep transaction uses the indicated deposit outpoint
    ///    as an input.
    /// 5. That the recipients in the transaction matches that of the
    ///    deposit request.
    /// 6. That the amount to mint does not exceed the deposit amount.
    /// 7. That the fee matches the expected assessed fee for the outpoint.
    /// 8. That the fee is less than the specified max-fee.
    /// 9. That the first input into the sweep transaction is the signers'
    ///    UTXO. This checks that the sweep transaction was generated by
    ///    the signers.
    ///
    /// # Notes
    ///
    /// The `complete-deposit-wrapper` public function will not mint to the
    /// user again if we mistakenly submit two transactions for the same
    /// deposit outpoint. This means we do not need to do a check for
    /// existence of a similar transaction in the stacks mempool. This is
    /// fortunate, because even if we wanted to, the only view into the
    /// stacks-core mempool is through the `POST /new_mempool_tx` webhooks,
    /// which we do not currently ingest.
    async fn validate<C>(&self, ctx: &C, req_ctx: &ReqContext) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        // Covers points 3-4 & 9
        let fee = self.validate_sweep_tx(ctx, req_ctx).await?;
        let db = ctx.get_storage();
        // Covers points 1-2 & 5-8
        self.validate_vars(&db, req_ctx, fee).await
    }
}

impl CompleteDepositV1 {
    /// Validate the variables in this transaction match the input in the
    /// deposit request.
    ///
    /// Specifically, this function checks the following points (from the
    /// docs of [`CompleteDepositV1::validate`]):
    /// 1. That the smart contract deployer matches the deployer in our
    ///    context.
    /// 2. That the signer has a record of the deposit request in its list
    ///    of pending and accepted deposit requests.
    /// 5. That the recipients in the transaction matches that of the
    ///    deposit request.
    /// 6. That the amount to mint does not exceed the deposit amount.
    /// 7. That the fee matches the expected assessed fee for the outpoint.
    /// 8. That the fee is less than the specified max-fee.
    ///
    /// The `fee` input variable is our calculation of the assessed fee for
    /// the deposit.
    async fn validate_vars<S>(&self, db: &S, req_ctx: &ReqContext, fee: Amount) -> Result<(), Error>
    where
        S: DbRead + Send + Sync,
    {
        // 1. That the smart contract deployer matches the deployer in our
        //    context.
        if self.deployer != req_ctx.deployer {
            return Err(DepositErrorMsg::DeployerMismatch.into_error(req_ctx, self));
        }
        // 2. Check that the signer has a record of the deposit request
        //    from our list of pending and accepted deposit requests.
        //
        // Check that this is actually a pending and accepted deposit
        // request.
        let deposit_requests = db
            .get_pending_accepted_deposit_requests(
                &req_ctx.chain_tip.block_hash,
                req_ctx.context_window,
                req_ctx.signatures_required,
            )
            .await?;

        let deposit_request = deposit_requests
            .into_iter()
            .find(|req| req.outpoint() == self.outpoint)
            .ok_or_else(|| DepositErrorMsg::RequestMissing.into_error(req_ctx, self))?;

        // 5. Check that the recipients in the transaction matches that of
        //    the deposit request.
        if &self.recipient != deposit_request.recipient.deref() {
            return Err(DepositErrorMsg::RecipientMismatch.into_error(req_ctx, self));
        }
        // 6. Check that the amount to mint does not exceed the deposit
        //    amount.
        if self.amount > deposit_request.amount {
            return Err(DepositErrorMsg::InvalidMintAmount.into_error(req_ctx, self));
        }
        // 7. That the fee matches the expected assessed fee for the outpoint.
        if fee.to_sat() + self.amount != deposit_request.amount {
            return Err(DepositErrorMsg::IncorrectFee.into_error(req_ctx, self));
        }
        // 8. Check that the fee is less than the specified max-fee.
        //
        // The smart contract cannot check if we exceed the max fee.
        if fee.to_sat() > deposit_request.max_fee {
            return Err(DepositErrorMsg::FeeTooHigh.into_error(req_ctx, self));
        }

        Ok(())
    }

    /// This function validates the sweep transaction.
    ///
    /// Specifically, this function checks the following points (from the
    /// docs of [`CompleteDepositV1::validate`]):
    /// 3. Check that the signer sweep transaction is on the canonical
    ///    bitcoin blockchain.
    /// 4. Check that the sweep transaction uses the indicated deposit
    ///    outpoint as an input.
    /// 9. That the first input into the sweep transaction is the signers'
    ///    UTXO.
    async fn validate_sweep_tx<C>(&self, ctx: &C, req_ctx: &ReqContext) -> Result<Amount, Error>
    where
        C: Context + Send + Sync,
    {
        let db = ctx.get_storage();
        let rpc = ctx.get_bitcoin_client();
        // First we check that bitcoin-core has a record of the transaction
        // where we think it should be.
        let txid = &self.sweep_txid;
        let Some(sweep_tx) = rpc.get_tx_info(txid, &self.sweep_block_hash).await? else {
            return Err(DepositErrorMsg::SweepTransactionMissing.into_error(req_ctx, self));
        };
        // 3. Check that the signer sweep transaction is on the canonical
        //    bitcoin blockchain.
        //
        // From the above, we know that the sweep transaction is in the
        // `sweep_block_hash`. Now we just need to check that this block is
        // on the canonical bitcoin blockchain.
        let block_ref = BitcoinBlockRef {
            block_hash: self.sweep_block_hash,
            block_height: self.sweep_block_height,
        };

        let in_canonical_bitcoin_blockchain = db
            .in_canonical_bitcoin_blockchain(&req_ctx.chain_tip, &block_ref)
            .await?;
        if !in_canonical_bitcoin_blockchain {
            return Err(DepositErrorMsg::SweepTransactionReorged.into_error(req_ctx, self));
        }
        // 4. Check that the sweep transaction uses the indicated deposit
        //    outpoint as an input.
        //
        // Okay great, we know that the sweep transaction exists on the
        // canonical bitcoin blockchain, we just need to do a simple check
        // of the transaction inputs.
        let mut tx_inputs = sweep_tx.tx.input.iter();
        if !tx_inputs.any(|tx_in| tx_in.previous_output == self.outpoint) {
            return Err(DepositErrorMsg::MissingFromSweep.into_error(req_ctx, self));
        }

        // 9. That the first input into the sweep transaction is the
        //    signers' UTXO.
        //
        // There should be a `vin` entry for each input in the transaction,
        // so this shouldn't ever error.
        let script_pub_key = sweep_tx
            .vin
            .first()
            .map(|x| ScriptPubKey::from_bytes(x.prevout.script_pub_key.hex.clone()))
            .ok_or_else(|| DepositErrorMsg::InvalidSweep.into_error(req_ctx, self))?;

        // The real check that this transaction was actually generated by
        // the signers.
        if !db.is_signer_script_pub_key(&script_pub_key).await? {
            return Err(DepositErrorMsg::InvalidSweep.into_error(req_ctx, self));
        }

        // None is only returned from BitcoinTxInfo::assess_output_fee when:
        // a) The indicated output index is 0 or 1, since or those cannot
        //    be valid output indices for sweep transactions, or
        // b) When the output index points to an output that is not in
        //    the transaction.
        // Both cases indicate that the UTXO is missing from the transaction.
        sweep_tx
            .assess_input_fee(&self.outpoint)
            .ok_or_else(|| DepositErrorMsg::MissingFromSweep.into_error(req_ctx, self))
    }
}

/// A struct for a validation error containing all the necessary context.
#[derive(Debug)]
pub struct DepositValidationError {
    /// The specific error that happened during validation.
    pub error: DepositErrorMsg,
    /// The additional information that was used when trying to
    /// validate the complete-deposit contract call. This includes the
    /// public key of the signer that was attempting to generate the
    /// `complete-deposit` transaction.
    pub context: ReqContext,
    /// The specific transaction that was being validated.
    pub tx: CompleteDepositV1,
}

impl std::fmt::Display for DepositValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO(191): Add the other variables to the error message.
        self.error.fmt(f)
    }
}

impl std::error::Error for DepositValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The responses for validation of a complete-deposit smart contract call
/// transactions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DepositErrorMsg {
    /// The smart contract deployer is fixed, so this should always match.
    #[error("The deployer in the transaction does not match the expected deployer")]
    DeployerMismatch,
    /// The fee paid to the bitcoin miners exceeded the max fee.
    #[error("fee paid to the bitcoin miners exceeded the max fee")]
    FeeTooHigh,
    /// The supplied fee does not match what is expected.
    #[error("the supplied fee does not match what is expected")]
    IncorrectFee,
    /// The amount to mint must not exceed the amount in the deposit
    /// request.
    #[error("amount to mint exceeded the amount in the deposit request")]
    InvalidMintAmount,
    /// The deposit outpoint is missing from the indicated sweep
    /// transaction.
    #[error("deposit outpoint is missing from the indicated sweep transaction")]
    MissingFromSweep,
    /// The transaction that swept in the funds must spend a UTXO that the
    /// signers control.
    #[error("the transaction that swept the funds was not one of the signers' transactions")]
    InvalidSweep,
    /// The recipient did not match the recipient in our deposit request
    /// records.
    #[error("recipient did not match the recipient in our deposit request")]
    RecipientMismatch,
    /// We do not have a record of the deposit request in our list of
    /// pending and accepted deposit requests.
    #[error("no record of deposit request in pending and accepted deposit requests")]
    RequestMissing,
    /// The sweep transaction that included the deposit request is missing
    /// from our records.
    #[error("sweep transaction not found")]
    SweepTransactionMissing,
    /// The sweep transaction has been affected by a reorg. Submitting this
    /// transaction now will likely lead to a failed stacks transaction.
    #[error("sweep transaction has been affected by a reorg")]
    SweepTransactionReorged,
}

impl DepositErrorMsg {
    fn into_error(self, ctx: &ReqContext, tx: &CompleteDepositV1) -> Error {
        Error::DepositValidation(Box::new(DepositValidationError {
            error: self,
            context: *ctx,
            tx: tx.clone(),
        }))
    }
}

/// This struct is used to generate a properly formatted Stacks transaction
/// for calling the accept-withdrawal-request function in the
/// sbtc-withdrawal smart contract.
#[derive(Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AcceptWithdrawalV1 {
    /// The ID of the withdrawal request generated by the
    /// initiate-withdrawal-request function in the sbtc-withdrawal smart
    /// contract.
    pub request_id: u64,
    /// The outpoint of the bitcoin UTXO that was spent to fulfill the
    /// withdrawal request.
    pub outpoint: OutPoint,
    /// Fulfilling the withdrawal request involved a transaction fee spent
    /// to bitcoin miners, this the portion of that transaction fee that
    /// was assessed to this request.
    pub tx_fee: u64,
    /// A bitmap of how the signers voted. This structure supports up to
    /// 128 distinct signers. Here, we assume that a 1 (or true) implies
    /// that the signer voted *against* the transaction.
    pub signer_bitmap: BitArray<[u8; 16]>,
    /// The address that deployed the contract.
    pub deployer: StacksAddress,
    /// The block hash of the bitcoin block that contains a sweep
    /// transaction with the above `outpoint` as one of its outputs. This
    /// field, with the `sweep_block_height` field, is used by the
    /// `accept-withdrawal-request` clarity function to ensure that we do
    /// not mint in case a bitcoin reorg affects the sweep transaction that
    /// is included in this block.
    pub sweep_block_hash: BitcoinBlockHash,
    /// The block height associated with the above bitcoin block hash.
    pub sweep_block_height: u64,
}

impl AsTxPayload for AcceptWithdrawalV1 {
    fn tx_payload(&self) -> TransactionPayload {
        TransactionPayload::ContractCall(self.as_contract_call())
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        AsContractCall::post_conditions(self)
    }
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
        let burn_hash_data = self.sweep_block_hash.to_byte_array().to_vec();
        let burn_hash = BuffData { data: burn_hash_data };

        vec![
            ClarityValue::UInt(self.request_id as u128),
            ClarityValue::Sequence(SequenceData::Buffer(txid)),
            ClarityValue::UInt(self.signer_bitmap.load_le()),
            ClarityValue::UInt(self.outpoint.vout as u128),
            ClarityValue::UInt(self.tx_fee as u128),
            ClarityValue::Sequence(SequenceData::Buffer(burn_hash)),
            ClarityValue::UInt(self.sweep_block_height as u128),
        ]
    }
    /// Validates that the accept-withdrawal-request satisfies the
    /// following criteria:
    ///
    ///  1. That the smart contract deployer matches the deployer in our
    ///     context.
    ///  2. That the signer has a record of the withdrawal request in its
    ///     list of pending and accepted withdrawal requests.
    ///  3. That the signer bitcoin transaction sweeping out the users'
    ///     funds is on the canonical bitcoin blockchain.
    ///  4. That the sweep transaction has the UTXO indicated by the
    ///     `outpoint`.
    ///  5. The `scriptPubKey` of the UTXO matches the one in the
    ///     withdrawal request.
    ///  6. The `amount` of the UTXO matches the one in the withdrawal
    ///     request.
    ///  7. That the fee is less than the desired max-fee.
    ///  8. That the fee matches the expected assessed fee for the output.
    ///  9. That the first input into the sweep transaction is the signers'
    ///     UTXO.
    /// 10. That the signer bitmap matches the bitmap from our records.
    async fn validate<C>(&self, db: &C, req_ctx: &ReqContext) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        // Covers points 3-4 & 8-9
        let tx_out = self.validate_sweep(db, req_ctx).await?;
        // Covers points 1-2 & 5-7, & 10
        self.validate_utxo(db, req_ctx, tx_out).await
    }
}

impl AcceptWithdrawalV1 {
    /// Validate the variables in this transaction match the inputs in the
    /// withdrawal request and the actual bitcoin transaction that swept
    /// out the users funds.
    ///
    /// Specifically, this function checks the following points (from the
    /// docs of [`AcceptWithdrawalV1::validate`]):
    ///  1. That the smart contract deployer matches the deployer in our
    ///     context.
    ///  2. That the signer has a record of the withdrawal request in its
    ///     list of pending and accepted withdrawal requests.
    ///  5. The `scriptPubKey` of the UTXO matches the recipient in the
    ///     withdrawal request.
    ///  6. The `amount` of the UTXO matches the one in the withdrawal
    ///     request.
    ///  7. That the fee is less than the desired max-fee.
    /// 10. That the signer bitmap matches the bitmap from our records.
    async fn validate_utxo<C>(
        &self,
        ctx: &C,
        req_ctx: &ReqContext,
        tx_out: TxOut,
    ) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        let db = ctx.get_storage();
        // 1. That the smart contract deployer matches the deployer in our
        //    context.
        if self.deployer != req_ctx.deployer {
            return Err(WithdrawalErrorMsg::DeployerMismatch.into_error(req_ctx, self));
        }
        // 2. That the signer has a record of the withdrawal request in its
        //    list of pending and accepted withdrawal requests.
        //
        // Check that this is actually a pending and accepted withdrawal
        // request.
        let withdrawal_requests = db
            .get_pending_accepted_withdrawal_requests(
                &req_ctx.chain_tip.block_hash,
                req_ctx.context_window,
                req_ctx.signatures_required,
            )
            .await?;

        let request = withdrawal_requests
            .into_iter()
            .find(|req| req.request_id == self.request_id)
            .ok_or_else(|| WithdrawalErrorMsg::RequestMissing.into_error(req_ctx, self))?;

        // 5. The `scriptPubKey` of the UTXO matches the one in the withdrawal
        //    request.
        if &tx_out.script_pubkey != request.recipient.deref() {
            return Err(WithdrawalErrorMsg::RecipientMismatch.into_error(req_ctx, self));
        }
        // 6. The `amount` of the UTXO matches the one in the withdrawal
        //    request.
        if tx_out.value.to_sat() != request.amount {
            return Err(WithdrawalErrorMsg::InvalidAmount.into_error(req_ctx, self));
        }
        // 7. Check that the fee is less than the desired max-fee.
        //
        // The smart contract cannot check if we exceed the max fee, so we
        // do a check ourselves.
        if self.tx_fee > request.max_fee {
            return Err(WithdrawalErrorMsg::FeeTooHigh.into_error(req_ctx, self));
        }
        // 10. That the signer bitmap matches the bitmap formed from our
        //     records.
        let votes = db
            .get_withdrawal_request_signer_votes(&request.qualified_id(), &req_ctx.aggregate_key)
            .await?;
        if self.signer_bitmap != BitArray::from(votes) {
            return Err(WithdrawalErrorMsg::BitmapMismatch.into_error(req_ctx, self));
        }

        Ok(())
    }
    /// This function validates the sweep transaction.
    ///
    /// Specifically, this function checks the following points (from the
    /// docs of [`AcceptWithdrawalV1::validate`]):
    /// 3. That the signer bitcoin transaction sweeping out the users'
    ///    funds is on the canonical bitcoin blockchain.
    /// 4. That the sweep transaction has the UTXO indicated by the
    ///    outpoint.
    /// 8. That the fee matches the expected assessed fee for the output.
    /// 9. That the first input into the sweep transaction is the signers'
    ///    UTXO.
    async fn validate_sweep<C>(&self, ctx: &C, req_ctx: &ReqContext) -> Result<TxOut, Error>
    where
        C: Context + Send + Sync,
    {
        let db = ctx.get_storage();
        let rpc = ctx.get_bitcoin_client();
        // First we check that bitcoin-core has a record of the transaction
        // where we think it should be.
        let txid = &self.outpoint.txid;
        let Some(sweep_tx) = rpc.get_tx_info(txid, &self.sweep_block_hash).await? else {
            return Err(WithdrawalErrorMsg::SweepTransactionMissing.into_error(req_ctx, self));
        };
        // 3. That the signer bitcoin transaction sweeping out the users'
        //    funds is on the canonical bitcoin blockchain.
        //
        // From the above, we know that the sweep transaction is in the
        // `sweep_block_hash`. Now we just need to check that this block is
        // on the canonical bitcoin blockchain.
        let block_ref = BitcoinBlockRef {
            block_hash: self.sweep_block_hash,
            block_height: self.sweep_block_height,
        };

        let in_canonical_bitcoin_blockchain = db
            .in_canonical_bitcoin_blockchain(&req_ctx.chain_tip, &block_ref)
            .await?;
        if !in_canonical_bitcoin_blockchain {
            return Err(WithdrawalErrorMsg::SweepTransactionReorged.into_error(req_ctx, self));
        }
        // 4. That the sweep transaction has the UTXO indicated by the
        //    outpoint.
        //
        // None is only returned from BitcoinTxInfo::assess_output_fee when:
        // a) The indicated output index is 0 or 1, since or those cannot
        //    be valid output indices for sweep transactions, or
        // b) When the output index points to an output that is not in
        //    the transaction.
        // Both cases indicate that the UTXO is missing from the transaction.
        let Some(expected_fee) = sweep_tx.assess_output_fee(self.outpoint.vout as usize) else {
            return Err(WithdrawalErrorMsg::UtxoMissingFromSweep.into_error(req_ctx, self));
        };

        // 8. That the fee matches the expected assessed fee for the output.
        if expected_fee.to_sat() != self.tx_fee {
            return Err(WithdrawalErrorMsg::IncorrectFee.into_error(req_ctx, self));
        };

        // 9. That the first input into the sweep transaction is the
        //    signers' UTXO.
        //
        // There should be a `vin` entry for each input in the transaction,
        // so this shouldn't ever error.
        let script_pub_key = sweep_tx
            .vin
            .first()
            .map(|x| ScriptPubKey::from_bytes(x.prevout.script_pub_key.hex.clone()))
            .ok_or_else(|| WithdrawalErrorMsg::InvalidSweep.into_error(req_ctx, self))?;

        // The real check that this transaction was actually generated by
        // the signers.
        if !db.is_signer_script_pub_key(&script_pub_key).await? {
            return Err(WithdrawalErrorMsg::InvalidSweep.into_error(req_ctx, self));
        }

        sweep_tx
            .tx
            .output
            .get(self.outpoint.vout as usize)
            .cloned()
            .ok_or_else(|| WithdrawalErrorMsg::UtxoMissingFromSweep.into_error(req_ctx, self))
    }
}

/// A struct for a validation error containing all the necessary context.
#[derive(Debug)]
pub struct WithdrawalAcceptValidationError {
    /// The specific error that happened during validation.
    pub error: WithdrawalErrorMsg,
    /// The additional information that was used when trying to validate
    /// the `accept-withdrawal-request` contract call. This includes the
    /// public key of the signer that was attempting to generate the
    /// `accept-withdrawal-request` transaction.
    pub context: ReqContext,
    /// The specific transaction that was being validated.
    pub tx: AcceptWithdrawalV1,
}

impl std::fmt::Display for WithdrawalAcceptValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO(191): Add the other variables to the error message.
        self.error.fmt(f)
    }
}

impl std::error::Error for WithdrawalAcceptValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The responses for validation of an accept-withdrawal-request smart
/// contract call transaction.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WithdrawalErrorMsg {
    /// The bitmap set in the transaction object should match the one in
    /// our database.
    #[error("bitmap does not match expected bitmap from")]
    BitmapMismatch,
    /// The smart contract deployer is fixed, so this should always match.
    #[error("the deployer in the transaction does not match the expected deployer")]
    DeployerMismatch,
    /// The fee paid to the bitcoin miners exceeded the max fee.
    #[error("fee paid to the bitcoin miners exceeded the max fee")]
    FeeTooHigh,
    /// The supplied fee does not match what is expected.
    #[error("the supplied fee does not match what is expected")]
    IncorrectFee,
    /// The amount to withdraw must equal the amount in the withdrawal
    /// request.
    #[error("amount to withdrawn exceeded the amount in the withdrawal request")]
    InvalidAmount,
    /// The transaction that swept in the funds must spend a UTXO that the
    /// signers control.
    #[error("the transaction that swept the funds was not one of the signers' transactions")]
    InvalidSweep,
    /// The recipient did not match the recipient in our withdrawal request
    /// records.
    #[error("recipient did not match the recipient in our withdrawal request")]
    RecipientMismatch,
    /// We do not have a record of the withdrawal request in our list of
    /// pending and accepted withdrawal requests.
    #[error("no record of withdrawal request in pending and accepted withdrawal requests")]
    RequestMissing,
    /// The sweep transaction that included the withdrawal request is missing
    /// from our records.
    #[error("sweep transaction for withdrawal request not found")]
    SweepTransactionMissing,
    /// The sweep transaction has been affected by a reorg. Submitting this
    /// transaction now will likely lead to a failed stacks transaction.
    #[error("sweep transaction has been affected by a reorg")]
    SweepTransactionReorged,
    /// The withdrawal outpoint is missing from the indicated sweep
    /// transaction.
    #[error("withdrawal outpoint is missing from the indicated sweep transaction")]
    UtxoMissingFromSweep,
}

impl WithdrawalErrorMsg {
    fn into_error(self, ctx: &ReqContext, tx: &AcceptWithdrawalV1) -> Error {
        Error::WithdrawalAcceptValidation(Box::new(WithdrawalAcceptValidationError {
            error: self,
            context: *ctx,
            tx: tx.clone(),
        }))
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

impl AsTxPayload for RejectWithdrawalV1 {
    fn tx_payload(&self) -> TransactionPayload {
        TransactionPayload::ContractCall(self.as_contract_call())
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        AsContractCall::post_conditions(self)
    }
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
    async fn validate<C>(&self, _ctx: &C, _req_ctx: &ReqContext) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        // TODO(255): Add validation implementation
        Ok(())
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
    /// Create a new instance of a RotateKeysV1 transaction object where
    /// the new keys will match those provided by the input wallet.
    pub fn new(wallet: &SignerWallet, deployer: StacksAddress) -> Self {
        Self {
            aggregate_key: *wallet.stacks_aggregate_key(),
            new_keys: wallet.public_keys().clone(),
            deployer,
            signatures_required: wallet.signatures_required(),
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

impl AsTxPayload for RotateKeysV1 {
    fn tx_payload(&self) -> TransactionPayload {
        TransactionPayload::ContractCall(self.as_contract_call())
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        AsContractCall::post_conditions(self)
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
    async fn validate<C>(&self, _ctx: &C, _req_ctx: &ReqContext) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        // TODO(255): Add validation implementation
        Ok(())
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
#[derive(Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ContractDeploy {
    /// The sbtc-token contract.
    /// This contract needs to be deployed before any other contract.
    SbtcToken(SbtcTokenContract),
    /// The sbtc-registry contract.
    /// This contract needs to be deployed right after the sbtc-token contract.
    SbtcRegistry(SbtcRegistryContract),
    /// The sbtc-deposit contract.
    /// Can be deployed after the sbtc-registry contract.
    SbtcDeposit(SbtcDepositContract),
    /// The sbtc-withdrawal contract.
    /// Can be deployed after the sbtc-registry contract.
    SbtcWithdrawal(SbtcWithdrawalContract),
    /// The sbtc-bootstrap-signers contract.
    /// Can be deployed after the sbtc-registry contract.
    SbtcBootstrap(SbtcBootstrapContract),
}

impl AsTxPayload for ContractDeploy {
    fn tx_payload(&self) -> TransactionPayload {
        let contract = match self {
            ContractDeploy::SbtcToken(contract) => contract.as_smart_contract(),
            ContractDeploy::SbtcRegistry(contract) => contract.as_smart_contract(),
            ContractDeploy::SbtcDeposit(contract) => contract.as_smart_contract(),
            ContractDeploy::SbtcWithdrawal(contract) => contract.as_smart_contract(),
            ContractDeploy::SbtcBootstrap(contract) => contract.as_smart_contract(),
        };
        TransactionPayload::SmartContract(contract, None)
    }
    fn post_conditions(&self) -> StacksTxPostConditions {
        StacksTxPostConditions {
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: Vec::new(),
        }
    }
}

impl ContractDeploy {
    /// Get the name of the smart contract
    pub fn contract_name(&self) -> &'static str {
        match self {
            ContractDeploy::SbtcToken(_) => SbtcTokenContract::CONTRACT_NAME,
            ContractDeploy::SbtcRegistry(_) => SbtcRegistryContract::CONTRACT_NAME,
            ContractDeploy::SbtcDeposit(_) => SbtcDepositContract::CONTRACT_NAME,
            ContractDeploy::SbtcWithdrawal(_) => SbtcWithdrawalContract::CONTRACT_NAME,
            ContractDeploy::SbtcBootstrap(_) => SbtcBootstrapContract::CONTRACT_NAME,
        }
    }
    /// Validates that The contract is not already deployed on the chain.
    pub async fn validate<C>(&self, ctx: &C, req_ctx: &ReqContext) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        let contract_name = self.contract_name();
        let contract_source = ctx
            .get_stacks_client()
            .get_contract_source(&req_ctx.deployer, contract_name)
            .await;

        match contract_source {
            Ok(_) => Err(Error::ContractAlreadyDeployed(contract_name)),
            Err(Error::StacksNodeResponse(error))
                if error.status() == Some(reqwest::StatusCode::NOT_FOUND) => Ok(()),
            Err(err) => Err(err),
        }
    }
}

/// The smart contract data for the sbtc-token contract.
#[derive(Copy, Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SbtcTokenContract;

impl AsContractDeploy for SbtcTokenContract {
    const CONTRACT_NAME: &'static str = "sbtc-token";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-token.clar");
}

/// The smart contract data for the sbtc-registry contract.
#[derive(Copy, Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SbtcRegistryContract;

impl AsContractDeploy for SbtcRegistryContract {
    const CONTRACT_NAME: &'static str = "sbtc-registry";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-registry.clar");
}

/// The smart contract data for the sbtc-stacks contract.
#[derive(Copy, Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SbtcDepositContract;

impl AsContractDeploy for SbtcDepositContract {
    const CONTRACT_NAME: &'static str = "sbtc-deposit";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-deposit.clar");
}

/// The smart contract data for the sbtc-withdrawal contract.
#[derive(Copy, Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SbtcWithdrawalContract;

impl AsContractDeploy for SbtcWithdrawalContract {
    const CONTRACT_NAME: &'static str = "sbtc-withdrawal";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-withdrawal.clar");
}

/// The smart contract data for the sbtc-bootstrap-signers contract.
#[derive(Copy, Clone, Debug, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SbtcBootstrapContract;

impl AsContractDeploy for SbtcBootstrapContract {
    const CONTRACT_NAME: &'static str = "sbtc-bootstrap-signers";
    const CONTRACT_BODY: &'static str =
        include_str!("../../../contracts/contracts/sbtc-bootstrap-signers.clar");
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
            sweep_txid: BitcoinTxId::from([0; 32]),
            sweep_block_hash: BitcoinBlockHash::from([0; 32]),
            sweep_block_height: 7,
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
            sweep_block_hash: BitcoinBlockHash::from([0; 32]),
            sweep_block_height: 7,
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

        let call = RotateKeysV1::new(&wallet, deployer);

        // This is to check that this function doesn't implicitly panic. If
        // it doesn't panic now, it can never panic at runtime.
        let _ = call.as_contract_call();
    }
}
