//! validation of bitcoin transactions.

use std::collections::HashMap;
use std::collections::HashSet;

use bitcoin::relative::LockTime;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;

use crate::bitcoin::utxo::FeeAssessment;
use crate::bitcoin::utxo::SignerBtcState;
use crate::context::Context;
use crate::context::SbtcLimits;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::message::BitcoinPreSignRequest;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::BitcoinTxSigHash;
use crate::storage::model::BitcoinWithdrawalOutput;
use crate::storage::model::QualifiedRequestId;
use crate::storage::model::SignerVotes;
use crate::storage::DbRead;
use crate::DEPOSIT_DUST_LIMIT;
use crate::DEPOSIT_LOCKTIME_BLOCK_BUFFER;

use super::utxo::DepositRequest;
use super::utxo::RequestRef;
use super::utxo::Requests;
use super::utxo::SignatureHash;
use super::utxo::UnsignedTransaction;
use super::utxo::WithdrawalRequest;

/// Cached validation data to avoid repeated DB queries
#[derive(Default)]
struct ValidationCache<'a> {
    deposit_reports: HashMap<(&'a Txid, u32), (DepositRequestReport, SignerVotes)>,
    withdrawal_reports: HashMap<&'a QualifiedRequestId, (WithdrawalRequestReport, SignerVotes)>,
}

/// The necessary information for validating a bitcoin transaction.
#[derive(Debug, Clone)]
pub struct BitcoinTxContext {
    /// This signer's current view of the chain tip of the canonical
    /// bitcoin blockchain. It is the block hash of the block on the
    /// bitcoin blockchain with the greatest height. On ties, we sort by
    /// the block hash descending and take the first one.
    pub chain_tip: BitcoinBlockHash,
    /// The block height of the bitcoin chain tip identified by the
    /// `chain_tip` field.
    pub chain_tip_height: u64,
    /// How many bitcoin blocks back from the chain tip the signer will
    /// look for the signer UTXO.
    pub context_window: u16,
    /// This signer's public key.
    pub signer_public_key: PublicKey,
    /// The current aggregate key that was the output of DKG.
    pub aggregate_key: PublicKey,
}

/// This type is a container for all deposits and withdrawals that are part
/// of a transaction package.
#[derive(Debug, Clone, PartialEq)]
pub struct TxRequestIds {
    /// The deposit requests associated with the inputs in the transaction.
    pub deposits: Vec<OutPoint>,
    /// The withdrawal requests associated with the outputs in the current
    /// transaction.
    pub withdrawals: Vec<QualifiedRequestId>,
}

impl From<&Requests<'_>> for TxRequestIds {
    fn from(requests: &Requests) -> Self {
        let mut deposits = Vec::new();
        let mut withdrawals = Vec::new();
        for request in requests.iter() {
            match request {
                RequestRef::Deposit(deposit) => deposits.push(deposit.outpoint),
                RequestRef::Withdrawal(withdrawal) => withdrawals.push(withdrawal.qualified_id()),
            }
        }
        TxRequestIds { deposits, withdrawals }
    }
}

/// Check that this does not contain duplicate deposits or withdrawals.
pub fn is_unique(package: &[TxRequestIds]) -> bool {
    let mut deposits_set = HashSet::new();
    let mut withdrawals_set = HashSet::new();
    package.iter().all(|reqs| {
        let deposits = reqs.deposits.iter().all(|out| deposits_set.insert(out));
        let withdrawals = reqs.withdrawals.iter().all(|id| withdrawals_set.insert(id));
        deposits && withdrawals
    })
}

impl BitcoinPreSignRequest {
    /// Check that the request object is valid
    // TODO: Have the type system do these checks. Perhaps TxRequestIds
    // should really be a wrapper around something like a (frozen)
    // NonEmptySet<Either<OutPoint, QualifiedRequestId>> with the
    // `request_package` field being a NonEmptySlice<TxRequestIds>.
    fn pre_validation(&self) -> Result<(), Error> {
        let no_requests = self
            .request_package
            .iter()
            .any(|x| x.deposits.is_empty() && x.withdrawals.is_empty());

        if no_requests || self.request_package.is_empty() {
            return Err(Error::PreSignContainsNoRequests);
        }

        if !is_unique(&self.request_package) {
            return Err(Error::DuplicateRequests);
        }

        if self.fee_rate <= 0.0 {
            return Err(Error::PreSignInvalidFeeRate(self.fee_rate));
        }

        Ok(())
    }

    async fn fetch_all_reports<D>(
        &self,
        db: &D,
        btc_ctx: &BitcoinTxContext,
    ) -> Result<ValidationCache, Error>
    where
        D: DbRead,
    {
        let mut cache = ValidationCache::default();

        for requests in &self.request_package {
            // Fetch all deposit reports and votes
            for outpoint in &requests.deposits {
                let txid = outpoint.txid.into();
                let output_index = outpoint.vout;

                let report_future = db.get_deposit_request_report(
                    &btc_ctx.chain_tip,
                    &txid,
                    output_index,
                    &btc_ctx.signer_public_key,
                );
                let Some(report) = report_future.await? else {
                    return Err(InputValidationResult::Unknown.into_error(btc_ctx));
                };

                let votes = db
                    .get_deposit_request_signer_votes(&txid, output_index, &btc_ctx.aggregate_key)
                    .await?;

                cache
                    .deposit_reports
                    .insert((&outpoint.txid, output_index), (report, votes));
            }

            // Fetch all withdrawal reports and votes
            for id in &requests.withdrawals {
                let report = db.get_withdrawal_request_report(
                    &btc_ctx.chain_tip,
                    id,
                    &btc_ctx.signer_public_key,
                );
                let Some(report) = report.await? else {
                    return Err(WithdrawalValidationResult::Unknown.into_error(btc_ctx));
                };

                let votes = db
                    .get_withdrawal_request_signer_votes(id, &btc_ctx.aggregate_key)
                    .await?;

                cache.withdrawal_reports.insert(id, (report, votes));
            }
        }
        Ok(cache)
    }

    async fn validate_max_mintable<'a, C>(
        &self,
        ctx: &C,
        cache: &ValidationCache<'a>,
    ) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        let max_mintable = ctx.state().get_current_limits().max_mintable_cap().to_sat();

        cache
            .deposit_reports
            .values()
            .try_fold(0u64, |acc, (report, _)| {
                acc.checked_add(report.amount)
                    .ok_or(Error::ExceedsSbtcSupplyCap {
                        total_amount: u64::MAX,
                        max_mintable,
                    })
                    .and_then(|sum| {
                        if sum > max_mintable {
                            Err(Error::ExceedsSbtcSupplyCap {
                                total_amount: sum,
                                max_mintable,
                            })
                        } else {
                            Ok(sum)
                        }
                    })
            })?;

        Ok(())
    }

    /// Construct the reports for each request that this transaction will
    /// service.
    pub async fn construct_package_sighashes<C>(
        &self,
        ctx: &C,
        btc_ctx: &BitcoinTxContext,
    ) -> Result<Vec<BitcoinTxValidationData>, Error>
    where
        C: Context + Send + Sync,
    {
        // Let's do basic validation of the request object itself.
        self.pre_validation()?;
        let cache = self.fetch_all_reports(&ctx.get_storage(), btc_ctx).await?;

        self.validate_max_mintable(ctx, &cache).await?;

        let signer_utxo = ctx
            .get_storage()
            .get_signer_utxo(&btc_ctx.chain_tip)
            .await?
            .ok_or(Error::MissingSignerUtxo)?;

        let mut signer_state = SignerBtcState {
            fee_rate: self.fee_rate,
            utxo: signer_utxo,
            public_key: bitcoin::XOnlyPublicKey::from(btc_ctx.aggregate_key),
            last_fees: self.last_fees,
            magic_bytes: [b'T', b'3'], //TODO(#472): Use the correct magic bytes.
        };
        let mut outputs = Vec::new();

        for requests in self.request_package.iter() {
            let (output, new_signer_state) = self
                .construct_tx_sighashes(ctx, btc_ctx, requests, signer_state, &cache)
                .await?;
            signer_state = new_signer_state;
            outputs.push(output);
        }

        Ok(outputs)
    }

    /// Construct the validation for each request that this transaction
    /// will service.
    ///
    /// This function returns the new signer bitcoin state if we were to
    /// sign and confirmed the bitcoin transaction created using the given
    /// inputs and outputs.
    async fn construct_tx_sighashes<'a, C>(
        &self,
        ctx: &C,
        btc_ctx: &BitcoinTxContext,
        requests: &'a TxRequestIds,
        signer_state: SignerBtcState,
        cache: &ValidationCache<'a>,
    ) -> Result<(BitcoinTxValidationData, SignerBtcState), Error>
    where
        C: Context + Send + Sync,
    {
        let mut deposits = Vec::with_capacity(requests.deposits.len());
        let mut withdrawals = Vec::with_capacity(requests.withdrawals.len());

        for outpoint in requests.deposits.iter() {
            let key = (&outpoint.txid, outpoint.vout);
            let (report, votes) = cache
                .deposit_reports
                .get(&key)
                // This should never happen because we have already validated that we have all the reports.
                .ok_or_else(|| InputValidationResult::Unknown.into_error(btc_ctx))?;
            deposits.push((report.to_deposit_request(votes), report.clone()));
        }

        for id in requests.withdrawals.iter() {
            let (report, votes) = cache
                .withdrawal_reports
                .get(id)
                // This should never happen because we have already validated that we have all the reports.
                .ok_or_else(|| WithdrawalValidationResult::Unknown.into_error(btc_ctx))?;
            withdrawals.push((report.to_withdrawal_request(votes), report.clone()));
        }

        deposits.sort_by_key(|(request, _)| request.outpoint);
        withdrawals.sort_by_key(|(_, report)| report.id);
        let reports = SbtcReports {
            deposits,
            withdrawals,
            signer_state,
        };
        let mut signer_state = signer_state;
        let tx = reports.create_transaction()?;
        let sighashes = tx.construct_digests()?;

        signer_state.utxo = tx.new_signer_utxo();
        // The first transaction is the only one whose input UTXOs that
        // have all been confirmed. Moreover, the fees that it sets aside
        // are enough to make up for the remaining transactions in the
        // transaction package. With that in mind, we do not need to bump
        // their fees anymore in order for them to be accepted by the
        // network.
        signer_state.last_fees = None;
        let out = BitcoinTxValidationData {
            signer_sighash: sighashes.signer_sighash(),
            deposit_sighashes: sighashes.deposit_sighashes(),
            chain_tip: btc_ctx.chain_tip,
            tx: tx.tx.clone(),
            tx_fee: Amount::from_sat(tx.tx_fee),
            reports,
            chain_tip_height: btc_ctx.chain_tip_height,
            // If the cap is None, then we assume that it is unlimited.
            sbtc_limits: ctx.state().get_current_limits(),
        };

        Ok((out, signer_state))
    }
}

/// An intermediate struct to aid in computing validation of deposits and
/// withdrawals and transforming the computed sighash into a
/// [`BitcoinTxSigHash`].
pub struct BitcoinTxValidationData {
    /// The sighash of the signers' prevout
    pub signer_sighash: SignatureHash,
    /// The sighash of each of the deposit request prevout
    pub deposit_sighashes: Vec<SignatureHash>,
    /// The computed deposits and withdrawals reports.
    pub reports: SbtcReports,
    /// The chain tip at the time that this signer received the sign
    /// request.
    pub chain_tip: BitcoinBlockHash,
    /// The transaction that we are (implicitly) requested to help sign.
    pub tx: bitcoin::Transaction,
    /// the transaction fee in sats
    pub tx_fee: Amount,
    /// the chain tip height.
    pub chain_tip_height: u64,
    /// The current sBTC limits.
    pub sbtc_limits: SbtcLimits,
}

impl BitcoinTxValidationData {
    /// Construct the sighashes for the inputs of the associated
    /// transaction.
    ///
    /// This function coalesces the information contained in this struct
    /// into a list of sighashes and a summary of how validation went for
    /// each of them. Signing a sighash depends on
    /// 1. The entire transaction passing an "aggregate" validation. This
    ///    means that each input and output is unfulfilled, and doesn't
    ///    violate protocol rules, such as max fees, lock-time rules, and
    ///    so on.
    /// 2. That the signer has not rejected/blocked any of the deposits or
    ///    withdrawals in the transaction.
    /// 3. That the signer is a party to signing set that controls the
    ///    public key locking the transaction output.
    pub fn to_input_rows(&self) -> Vec<BitcoinTxSigHash> {
        // If any of the inputs or outputs fail validation, then the
        // transaction is invalid, so we won't sign any of the inputs or
        // outputs.
        let is_valid_tx = self.is_valid_tx();

        let validation_results = self.reports.deposits.iter().map(|(_, report)| {
            report.validate(
                self.chain_tip_height,
                &self.tx,
                self.tx_fee,
                &self.sbtc_limits,
            )
        });

        // just a sanity check
        debug_assert_eq!(self.deposit_sighashes.len(), self.reports.deposits.len());

        let deposit_sighashes = self
            .deposit_sighashes
            .iter()
            .copied()
            .zip(validation_results);

        // We know the signers' input is valid. We started by fetching it
        // from our database, so we know it is unspent and valid. Later,
        // each of the signer's inputs were created as part of a
        // transaction chain, so each one is unspent and locked by the
        // signers' "aggregate" private key.
        [(self.signer_sighash, InputValidationResult::Ok)]
            .into_iter()
            .chain(deposit_sighashes)
            .map(|(sighash, validation_result)| BitcoinTxSigHash {
                txid: sighash.txid.into(),
                sighash: sighash.sighash.into(),
                chain_tip: self.chain_tip,
                prevout_txid: sighash.outpoint.txid.into(),
                prevout_output_index: sighash.outpoint.vout,
                prevout_type: sighash.prevout_type,
                validation_result,
                is_valid_tx,
                will_sign: is_valid_tx && validation_result == InputValidationResult::Ok,
            })
            .collect()
    }

    /// Construct objects with withdrawal output identifier with the
    /// validation result.
    pub fn to_withdrawal_rows(&self) -> Vec<BitcoinWithdrawalOutput> {
        let bitcoin_txid = self.tx.compute_txid().into();

        let is_valid_tx = self.is_valid_tx();
        // If we ever construct a transaction with more than u32::MAX then
        // we are dealing with a very different Bitcoin and Stacks than we
        // started with, and there are other things that we need to change
        // first.
        self.reports
            .withdrawals
            .iter()
            .enumerate()
            .map(|(output_index, (_, report))| BitcoinWithdrawalOutput {
                bitcoin_txid,
                bitcoin_chain_tip: self.chain_tip,
                output_index: output_index as u32,
                request_id: report.id.request_id,
                stacks_txid: report.id.txid,
                stacks_block_hash: report.id.block_hash,
                validation_result: report.validate(
                    self.chain_tip_height,
                    &self.tx,
                    self.tx_fee,
                    &self.sbtc_limits,
                ),
                is_valid_tx,
            })
            .collect()
    }

    /// Check whether the transaction is valid. This determines whether
    /// this signer will sign any of the sighashes for the transaction
    ///
    /// This checks that all deposits and withdrawals pass validation. Note
    /// that the transaction can still pass validation if this signer is
    /// not a part of the signing set locking one or more deposits. In such
    /// a case, it will just sign for the deposits that it can.
    pub fn is_valid_tx(&self) -> bool {
        // A transaction is invalid if it is not servicing any deposit or
        // withdrawal requests. Doing so costs fees and the signers do not
        // gain anything by permitting such a transaction.
        if self.reports.deposits.is_empty() && self.reports.withdrawals.is_empty() {
            return false;
        }

        let deposit_validation_results = self.reports.deposits.iter().all(|(_, report)| {
            matches!(
                report.validate(
                    self.chain_tip_height,
                    &self.tx,
                    self.tx_fee,
                    &self.sbtc_limits,
                ),
                InputValidationResult::Ok | InputValidationResult::CannotSignUtxo
            )
        });

        let withdrawal_validation_results = self.reports.withdrawals.iter().all(|(_, report)| {
            match report.validate(
                self.chain_tip_height,
                &self.tx,
                self.tx_fee,
                &self.sbtc_limits,
            ) {
                WithdrawalValidationResult::Unsupported
                | WithdrawalValidationResult::Unknown
                | WithdrawalValidationResult::AmountTooHigh => false,
            }
        });

        deposit_validation_results && withdrawal_validation_results
    }
}

/// The set of sBTC requests with additional relevant
/// information used to construct the next transaction package.
#[derive(Debug)]
pub struct SbtcReports {
    /// Deposit requests with how the signers voted for them.
    pub deposits: Vec<(DepositRequest, DepositRequestReport)>,
    /// Withdrawal requests with how the signers voted for them.
    pub withdrawals: Vec<(WithdrawalRequest, WithdrawalRequestReport)>,
    /// Summary of the Signers' UTXO and information necessary for
    /// constructing their next UTXO.
    pub signer_state: SignerBtcState,
}

impl SbtcReports {
    /// Create the transaction with witness data using the requests.
    pub fn create_transaction(&self) -> Result<UnsignedTransaction, Error> {
        let deposits = self
            .deposits
            .iter()
            .map(|(request, _)| RequestRef::Deposit(request));
        let withdrawals = self
            .withdrawals
            .iter()
            .map(|(request, _)| RequestRef::Withdrawal(request));

        let state = &self.signer_state;
        let requests = Requests::new(deposits.chain(withdrawals).collect());

        UnsignedTransaction::new_stub(requests, state)
    }
}

/// The responses for validation of a sweep transaction on bitcoin.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum InputValidationResult {
    /// The deposit request passed validation
    Ok,
    /// The deposit request amount is below the allowed per-deposit minimum.
    AmountTooLow,
    /// The deposit request amount, less the fees, would be rejected from
    /// the smart contract during the complete-deposit contract call.
    MintAmountBelowDustLimit,
    /// The deposit request amount exceeds the allowed per-deposit cap.
    AmountTooHigh,
    /// The assessed fee exceeds the max-fee in the deposit request.
    FeeTooHigh,
    /// The signer is not part of the signer set that generated the
    /// aggregate public key used to lock the deposit funds.
    ///
    /// TODO: For v1 every signer should be able to sign for all deposits,
    /// but for v2 this will not be the case. So we'll need to decide
    /// whether a particular deposit cannot be signed by a particular
    /// signers means that the entire transaction is rejected from that
    /// signer.
    CannotSignUtxo,
    /// The deposit transaction has been confirmed on a bitcoin block
    /// that is not part of the canonical bitcoin blockchain.
    TxNotOnBestChain,
    /// The deposit UTXO has already been spent.
    DepositUtxoSpent,
    /// Given the current time and block height, it would be imprudent to
    /// attempt to sweep in a deposit request with the given lock-time.
    LockTimeExpiry,
    /// The signer does not have a record of their vote on the deposit
    /// request in their database.
    NoVote,
    /// The signer has rejected the deposit request.
    RejectedRequest,
    /// The signer does not have a record of the deposit request in their
    /// database.
    Unknown,
    /// The locktime in the reclaim script is in time units and that is not
    /// supported. This shouldn't happen, since we will not put it in our
    /// database is this is the case.
    UnsupportedLockTime,
}

impl InputValidationResult {
    fn into_error(self, ctx: &BitcoinTxContext) -> Error {
        Error::BitcoinValidation(Box::new(BitcoinValidationError {
            error: BitcoinSweepErrorMsg::Deposit(self),
            context: ctx.clone(),
        }))
    }
}

/// The responses for validation of the outputs of a sweep transaction on
/// bitcoin.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum WithdrawalValidationResult {
    /// The withdrawal request amount exceeds the allowed per-withdrawal cap
    AmountTooHigh,
    /// The signer does not have a record of the withdrawal request in
    /// their database.
    Unknown,
    /// We do not support withdrawals at the moment so this is always
    /// returned.
    Unsupported,
}

impl WithdrawalValidationResult {
    /// Make into a crate error
    pub fn into_error(self, ctx: &BitcoinTxContext) -> Error {
        Error::BitcoinValidation(Box::new(BitcoinValidationError {
            error: BitcoinSweepErrorMsg::Withdrawal(self),
            context: ctx.clone(),
        }))
    }
}

/// The responses for validation of a sweep transaction on bitcoin.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Copy, Clone)]
pub enum BitcoinSweepErrorMsg {
    /// The error has something to do with the inputs.
    #[error("deposit error")]
    Deposit(InputValidationResult),
    /// The error has something to do with the outputs.
    #[error("withdrawal error")]
    Withdrawal(WithdrawalValidationResult),
}

/// A struct for a bitcoin validation error containing all the necessary
/// context.
#[derive(Debug)]
pub struct BitcoinValidationError {
    /// The specific error that happened during validation.
    pub error: BitcoinSweepErrorMsg,
    /// The additional information that was used when trying to validate
    /// the bitcoin transaction. This includes the public key of the signer
    /// that was attempting to generate the transaction.
    pub context: BitcoinTxContext,
}

impl std::fmt::Display for BitcoinValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO(191): Add the other variables to the error message.
        self.error.fmt(f)
    }
}

impl std::error::Error for BitcoinValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// An enum for the confirmation status of a deposit request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositConfirmationStatus {
    /// We have a record of the deposit request transaction, and it has
    /// been confirmed on the canonical bitcoin blockchain. We have not
    /// spent these funds. The integer is the height of the block
    /// confirming the deposit request.
    Confirmed(u64, BitcoinBlockHash),
    /// We have a record of the deposit request being included as an input
    /// in another bitcoin transaction that has been confirmed on the
    /// canonical bitcoin blockchain.
    Spent(BitcoinTxId),
    /// We have a record of the deposit request transaction, and it has not
    /// been confirmed on the canonical bitcoin blockchain.
    ///
    /// Usually we will almost certainly have a record of a deposit
    /// request, and we require that the deposit transaction be confirmed
    /// before we write it to our database. But the deposit transaction can
    /// be affected by a bitcoin reorg, where it is no longer confirmed on
    /// the canonical bitcoin blockchain. If this happens when we query for
    /// the status then it will come back as unconfirmed.
    Unconfirmed,
}

/// A struct for the status report summary of a deposit request for use
/// in validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositRequestReport {
    /// The deposit UTXO outpoint that uniquely identifies the deposit.
    pub outpoint: OutPoint,
    /// The confirmation status of the deposit request transaction.
    pub status: DepositConfirmationStatus,
    /// Whether this signer was part of the signing set associated with the
    /// deposited funds. If the signer is not part of the signing set, then
    /// we do not do a check of whether we will accept it otherwise.
    ///
    /// This will only be `None` if we do not have a record of the deposit
    /// request.
    pub can_sign: Option<bool>,
    /// Whether this signers' blocklist client accepted the deposit request
    /// or not. This should only be `None` if we do not have a record of
    /// the deposit request.
    pub can_accept: Option<bool>,
    /// The deposit amount
    pub amount: u64,
    /// The max fee embedded in the deposit request.
    pub max_fee: u64,
    /// The lock_time in the reclaim script
    pub lock_time: LockTime,
    /// The deposit script used so that the signers' can spend funds.
    pub deposit_script: ScriptBuf,
    /// The reclaim script for the deposit.
    pub reclaim_script: ScriptBuf,
    /// The public key used in the deposit script.
    pub signers_public_key: XOnlyPublicKey,
}

impl DepositRequestReport {
    /// Validate that the deposit request is okay given the report.
    fn validate<F>(
        &self,
        chain_tip_height: u64,
        tx: &F,
        tx_fee: Amount,
        sbtc_limits: &SbtcLimits,
    ) -> InputValidationResult
    where
        F: FeeAssessment,
    {
        let confirmed_block_height = match self.status {
            // Deposit requests are only written to the database after they
            // have been confirmed, so this means that we have a record of
            // the request, but it has not been confirmed on the canonical
            // bitcoin blockchain.
            DepositConfirmationStatus::Unconfirmed => {
                return InputValidationResult::TxNotOnBestChain;
            }
            // This means that we have a record of the deposit UTXO being
            // spent in a sweep transaction that has been confirmed on the
            // canonical bitcoin blockchain.
            DepositConfirmationStatus::Spent(_) => {
                return InputValidationResult::DepositUtxoSpent;
            }
            // The deposit has been confirmed on the canonical bitcoin
            // blockchain and remains unspent by us.
            DepositConfirmationStatus::Confirmed(block_height, _) => block_height,
        };

        if self.amount < sbtc_limits.per_deposit_minimum().to_sat() {
            return InputValidationResult::AmountTooLow;
        }

        if self.amount > sbtc_limits.per_deposit_cap().to_sat() {
            return InputValidationResult::AmountTooHigh;
        }

        // We only sweep a deposit if the depositor cannot reclaim the
        // deposit within the next DEPOSIT_LOCKTIME_BLOCK_BUFFER blocks.
        let deposit_age = chain_tip_height.saturating_sub(confirmed_block_height);

        match self.lock_time {
            LockTime::Blocks(height) => {
                let max_age = height.value().saturating_sub(DEPOSIT_LOCKTIME_BLOCK_BUFFER) as u64;
                if deposit_age >= max_age {
                    return InputValidationResult::LockTimeExpiry;
                }
            }
            LockTime::Time(_) => {
                return InputValidationResult::UnsupportedLockTime;
            }
        }

        let Some(assessed_fee) = tx.assess_input_fee(&self.outpoint, tx_fee) else {
            return InputValidationResult::Unknown;
        };

        if assessed_fee.to_sat() > self.max_fee.min(self.amount) {
            return InputValidationResult::FeeTooHigh;
        }

        if self.amount.saturating_sub(assessed_fee.to_sat()) < DEPOSIT_DUST_LIMIT {
            return InputValidationResult::MintAmountBelowDustLimit;
        }

        // Let's check whether we rejected this deposit.
        match self.can_accept {
            Some(true) => (),
            // If we are here, we know that we have a record for the
            // deposit request, but we have not voted on it yet, so we do
            // not know if we can sign for it.
            None => return InputValidationResult::NoVote,
            Some(false) => return InputValidationResult::RejectedRequest,
        }

        match self.can_sign {
            Some(true) => (),
            // In this case we know that we cannot sign for the deposit
            // because it is locked with a public key where the current
            // signer is not part of the signing set.
            Some(false) => return InputValidationResult::CannotSignUtxo,
            // We shouldn't ever get None here, since we know that we can
            // accept the request. We do the check for whether we can sign
            // the request at that the same time as the can_accept check.
            None => return InputValidationResult::NoVote,
        }

        InputValidationResult::Ok
    }

    /// As deposit request.
    fn to_deposit_request(&self, votes: &SignerVotes) -> DepositRequest {
        DepositRequest {
            outpoint: self.outpoint,
            max_fee: self.max_fee,
            amount: self.amount,
            deposit_script: self.deposit_script.clone(),
            reclaim_script: self.reclaim_script.clone(),
            signers_public_key: self.signers_public_key,
            signer_bitmap: votes.into(),
        }
    }
}

/// An enum for the confirmation status of a withdrawal request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WithdrawalRequestStatus {
    /// We have a record of the withdrawal request transaction, and it has
    /// been confirmed on the canonical Stacks blockchain. We have not
    /// fulfilled the request. The integer is the height of the bitcoin
    /// block anchoring the Stacks block that confirmed the withdrawal
    /// request, and the block hash is the associated block hash of that
    /// bitcoin block.
    Confirmed(u64, BitcoinBlockHash),
    /// We have a record of the withdrawal request being included as an
    /// output in another bitcoin transaction that has been confirmed on
    /// the canonical bitcoin blockchain.
    Fulfilled(BitcoinTxId),
    /// We have a record of the withdrawal request transaction, and it has
    /// not been confirmed on the canonical Stacks blockchain.
    ///
    /// Usually we will almost certainly have a record of a withdrawal
    /// request, and we require that the withdrawal transaction be
    /// confirmed before we write it to our database. But the withdrawal
    /// transaction can be affected by a bitcoin reorg, where it is no
    /// longer confirmed on the canonical bitcoin blockchain. If this
    /// happens when we query for the status then it will come back as
    /// unconfirmed.
    Unconfirmed,
}

/// A struct for the status report summary of a withdrawal request for use
/// in validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WithdrawalRequestReport {
    /// The unique identifier for the request. It includes the ID generated
    /// by the smart contract when the `initiate-withdrawal-request` public
    /// function was called along with the transaction ID and Stacks block
    /// ID.
    pub id: QualifiedRequestId,
    /// The confirmation status of the withdrawal request transaction.
    pub status: WithdrawalRequestStatus,
    /// The amount of BTC, in sats, to withdraw.
    pub amount: u64,
    /// The max fee amount to use for the bitcoin transaction sweeping out
    /// the funds.
    pub max_fee: u64,
    /// The script_pubkey of the output.
    pub script_pubkey: ScriptBuf,
}

impl WithdrawalRequestReport {
    /// Validate that the withdrawal request is okay given the report.
    pub fn validate<F>(
        &self,
        _: u64,
        _: &F,
        _: Amount,
        _sbtc_limits: &SbtcLimits,
    ) -> WithdrawalValidationResult
    where
        F: FeeAssessment,
    {
        WithdrawalValidationResult::Unsupported
    }

    fn to_withdrawal_request(&self, votes: &SignerVotes) -> WithdrawalRequest {
        WithdrawalRequest {
            request_id: self.id.request_id,
            txid: self.id.txid,
            block_hash: self.id.block_hash,
            amount: self.amount,
            max_fee: self.max_fee,
            script_pubkey: self.script_pubkey.clone().into(),
            signer_bitmap: votes.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::ScriptBuf;
    use bitcoin::Sequence;
    use bitcoin::TxIn;
    use bitcoin::Txid;
    use bitcoin::Witness;
    use test_case::test_case;

    use crate::context::SbtcLimits;
    use crate::storage::model::StacksBlockHash;
    use crate::storage::model::StacksTxId;
    use crate::testing::context::TestContext;

    use super::*;

    /// A helper struct to aid in testing of deposit validation.
    #[derive(Debug)]
    struct DepositReportErrorMapping {
        report: DepositRequestReport,
        status: InputValidationResult,
        chain_tip_height: u64,
        limits: SbtcLimits,
    }

    const TX_FEE: Amount = Amount::from_sat(10000);

    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Unconfirmed,
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::TxNotOnBestChain,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    }; "deposit-reorged")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Spent(BitcoinTxId::from([1; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::DepositUtxoSpent,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    }; "deposit-spent")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: None,
            can_accept: None,
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::NoVote,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "deposit-no-vote")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(false),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::CannotSignUtxo,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "cannot-sign-for-deposit")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(false),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::RejectedRequest,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "rejected-deposit")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 1),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::LockTimeExpiry,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "lock-time-expires-soon-1")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 2),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::LockTimeExpiry,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "lock-time-expires-soon-2")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_512_second_intervals(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::UnsupportedLockTime,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "lock-time-in-time-units-2")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::Ok,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "happy-path")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([1; 32]), 0),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::Unknown,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "unknown-prevout")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::Ok,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "at-the-border")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: TX_FEE.to_sat() - 1,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::FeeTooHigh,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "one-sat-too-high-fee-amount")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: TX_FEE.to_sat() + DEPOSIT_DUST_LIMIT - 1,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::MintAmountBelowDustLimit,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "one-sat-under-dust-amount")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: TX_FEE.to_sat() + DEPOSIT_DUST_LIMIT,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::Ok,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "at-dust-amount")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: TX_FEE.to_sat() - 1,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::FeeTooHigh,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, u64::MAX),
    } ; "one-sat-too-high-fee")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 100_000_000,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::AmountTooHigh,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(0, 99_999_999),
    } ; "amount-too-high")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 99_999_999,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: InputValidationResult::AmountTooLow,
        chain_tip_height: 2,
        limits: SbtcLimits::new_per_deposit(100_000_000, u64::MAX),
    } ; "amount-too-low")]
    fn deposit_report_validation(mapping: DepositReportErrorMapping) {
        let mut tx = crate::testing::btc::base_signer_transaction();
        tx.input.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });

        let status =
            mapping
                .report
                .validate(mapping.chain_tip_height, &tx, TX_FEE, &mapping.limits);

        assert_eq!(status, mapping.status);
    }

    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([2; 32]),
                    },
                ],
            }],
            fee_rate: 1.0,
            last_fees: None,
        }, true; "unique-requests")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([2; 32]),
                    },
                ],
            }],
            fee_rate: 0.0,
            last_fees: None,
        }, false; "unique-requests-zero-fee-rate")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([2; 32]),
                    },
                ],
            }],
            fee_rate: -1.0,
            last_fees: None,
        }, false; "unique-requests-negative-fee-rate")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([2; 32]),
                    },
                ],
            }],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "duplicate-deposits-in-same-tx")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![TxRequestIds {
                deposits: vec![
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 0,
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    },
                ],
                withdrawals: vec![
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                    QualifiedRequestId {
                        request_id: 0,
                        txid: StacksTxId::from([1; 32]),
                        block_hash: StacksBlockHash::from([1; 32]),
                    },
                ],
            }],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "duplicate-withdrawals-in-same-tx")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![
                TxRequestIds {
                    deposits: vec![
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 0,
                        },
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 1,
                        },
                    ],
                    withdrawals: vec![
                        QualifiedRequestId {
                            request_id: 0,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([1; 32]),
                        },
                        QualifiedRequestId {
                            request_id: 1,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([2; 32]),
                        },
                    ],
                },
                TxRequestIds {
                    deposits: vec![OutPoint {
                        txid: Txid::from_byte_array([1; 32]),
                        vout: 1,
                    }],
                    withdrawals: vec![],
                },
            ],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "duplicate-requests-in-different-txs")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: Vec::new(),
            fee_rate: 1.0,
            last_fees: None,
        }, false; "empty-package_requests")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![
                TxRequestIds {
                    deposits: Vec::new(),
                    withdrawals: Vec::new(),
                },
                TxRequestIds {
                    deposits: Vec::new(),
                    withdrawals: Vec::new(),
                },
            ],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "basically-empty-package_requests")]
    #[test_case(
        BitcoinPreSignRequest {
            request_package: vec![
                TxRequestIds {
                    deposits: vec![
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 0,
                        },
                        OutPoint {
                            txid: Txid::from_byte_array([1; 32]),
                            vout: 1,
                        },
                    ],
                    withdrawals: vec![
                        QualifiedRequestId {
                            request_id: 0,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([1; 32]),
                        },
                        QualifiedRequestId {
                            request_id: 0,
                            txid: StacksTxId::from([1; 32]),
                            block_hash: StacksBlockHash::from([2; 32]),
                        },
                    ],
                },
                TxRequestIds {
                    deposits: Vec::new(),
                    withdrawals: Vec::new(),
                },
            ],
            fee_rate: 1.0,
            last_fees: None,
        }, false; "contains-empty-tx-requests")]
    fn test_pre_validation(requests: BitcoinPreSignRequest, result: bool) {
        assert_eq!(requests.pre_validation().is_ok(), result);
    }

    fn create_test_report(idx: u8, amount: u64) -> (DepositRequestReport, SignerVotes) {
        (
            DepositRequestReport {
                outpoint: OutPoint::new(Txid::from_byte_array([idx; 32]), 0),
                status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([idx; 32])),
                can_sign: Some(true),
                can_accept: Some(true),
                amount,
                max_fee: 1000,
                lock_time: LockTime::from_height(100),
                deposit_script: ScriptBuf::new(),
                reclaim_script: ScriptBuf::new(),
                signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
            },
            SignerVotes::from(Vec::new()),
        )
    }

    #[test_case(
        vec![1000, 2000, 3000],
        Amount::from_sat(10_000),
        Amount::from_sat(1_000),
        Ok(());
        "should_accept_deposits_under_max_mintable"
    )]
    #[test_case(
        vec![],
        Amount::from_sat(10_000),
        Amount::from_sat(0),
        Ok(());
        "should_accept_empty_deposits"
    )]
    #[test_case(
        vec![10_000],
        Amount::from_sat(10_000),
        Amount::from_sat(0),
        Ok(());
        "should_accept_deposit_equal_to_max_mintable"
    )]
    #[test_case(
        vec![5000, 5001],
        Amount::from_sat(10_000),
        Amount::from_sat(0),
        Err(Error::ExceedsSbtcSupplyCap {
            total_amount: 10_001,
            max_mintable: 10_000
        });
        "should_reject_deposits_over_max_mintable"
    )]
    #[test_case(
        vec![1, 1, Amount::MAX_MONEY.to_sat() - 2],
        Amount::MAX_MONEY,
        Amount::from_sat(1),
        Err(Error::ExceedsSbtcSupplyCap {
            total_amount: Amount::MAX_MONEY.to_sat(),
            max_mintable: Amount::MAX_MONEY.to_sat() - 1
        });
        "filter_out_deposits_over_max_mintable"
    )]
    #[tokio::test]
    async fn test_validate_max_mintable(
        deposit_amounts: Vec<u64>,
        total_cap: Amount,
        sbtc_supply: Amount,
        expected: Result<(), Error>,
    ) {
        // Create mock context
        let context = TestContext::default_mocked();
        context.state().update_current_limits(SbtcLimits::new(
            Some(total_cap),
            None,
            None,
            None,
            Some(total_cap - sbtc_supply),
        ));
        // Create cache with test data
        let mut cache = ValidationCache::default();

        let deposit_reports: Vec<(DepositRequestReport, SignerVotes)> = deposit_amounts
            .into_iter()
            .enumerate()
            .map(|(idx, amount)| create_test_report(idx as u8, amount))
            .collect();

        cache.deposit_reports = deposit_reports
            .iter()
            .map(|(report, votes)| {
                (
                    (&report.outpoint.txid, report.outpoint.vout),
                    (report.clone(), votes.clone()),
                )
            })
            .collect();

        // Create request and validate
        let request = BitcoinPreSignRequest {
            request_package: vec![],
            fee_rate: 2.0,
            last_fees: None,
        };
        let result = request.validate_max_mintable(&context, &cache).await;

        match (result, expected) {
            (Ok(()), Ok(())) => {}
            (
                Err(Error::ExceedsSbtcSupplyCap {
                    total_amount: a1,
                    max_mintable: m1,
                }),
                Err(Error::ExceedsSbtcSupplyCap {
                    total_amount: a2,
                    max_mintable: m2,
                }),
            ) => {
                assert_eq!(a1, a2);
                assert_eq!(m1, m2);
            }
            (result, expected) => panic!("Expected {:?} but got {:?}", expected, result),
        };
    }
}
