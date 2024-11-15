//! validation of bitcoin transactions.

use bitcoin::relative::LockTime;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TapSighash;
use bitcoin::XOnlyPublicKey;

use crate::bitcoin::utxo::FeeAssessment;
use crate::bitcoin::utxo::Fees;
use crate::bitcoin::utxo::SignerBtcState;
use crate::context::Context;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::QualifiedRequestId;
use crate::storage::model::SignerVotes;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksTxId;
use crate::storage::model::TxPrevoutType;
use crate::storage::DbRead;
use crate::DEPOSIT_LOCKTIME_BLOCK_BUFFER;

use super::utxo::DepositRequest;
use super::utxo::RequestRef;
use super::utxo::Requests;
use super::utxo::UnsignedTransaction;
use super::utxo::WithdrawalRequest;

// use super::utxo::DepositRequest;
// use super::utxo;

/// The necessary information for validating a bitcoin transaction.
#[derive(Debug, Clone)]
pub struct BitcoinTxContext {
    /// This signer's current view of the chain tip of the canonical
    /// bitcoin blockchain. It is the block hash of the block on the
    /// bitcoin blockchain with the greatest height. On ties, we sort by
    /// the block hash descending and take the first one.
    pub chain_tip: BitcoinBlockHash,
    /// How many bitcoin blocks back from the chain tip the signer will
    /// look for requests.
    pub context_window: u16,
    /// The block height of the bitcoin chain tip identified by the
    /// `chain_tip` field.
    pub chain_tip_height: u64,
    /// This contains each of the requests for the entire transaction
    /// package. Each element in the vector corresponds to the requests
    /// that will be included in a single bitcoin transaction.
    pub request_packages: Vec<TxRequestIds>,
    /// The current market fee rate in sat/vByte.
    pub fee_rate: f64,
    /// The total fee amount and the fee rate for the last transaction that
    /// used this UTXO as an input.
    pub last_fee: Option<Fees>,
    /// The public key of the signer that created the bitcoin transaction.
    /// This is very unlikely to ever be used in the
    /// [`BitcoinTx::validate`] function, but is here for logging and
    /// tracking purposes.
    pub origin: PublicKey,
    /// This signers public key.
    pub signer_public_key: PublicKey,
    /// The current aggregate key that was the output of DKG.
    pub aggregate_key: PublicKey,
    /// Two byte prefix for BTC transactions that are related to the Stacks
    /// blockchain.
    pub magic_bytes: [u8; 2],
    /// The state of the signers.
    pub signer_state: SignerBtcState,
}

/// This type is a container for all deposits and withdrawals that are part
/// of a transaction package.
#[derive(Debug, Clone)]
pub struct TxRequestIds {
    /// The deposit requests associated with the inputs in the transaction.
    pub deposits: Vec<OutPoint>,
    /// The withdrawal requests associated with the outputs in the current
    /// transaction.
    pub withdrawals: Vec<QualifiedRequestId>,
}

impl BitcoinTxContext {
    /// Validate the current bitcoin transaction.
    pub async fn validate<C>(&self, _ctx: &C) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        unimplemented!()
    }

    /// Validate the withdrawal UTXOs
    pub async fn validate_withdrawals<C>(&self, _ctx: &C) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        if !self
            .request_packages
            .iter()
            .all(|reqs| reqs.withdrawals.is_empty())
        {
            return Err(Error::MissingBlock);
        }

        Ok(())
    }

    /// Fetch the signers' BTC state and the aggregate key.
    ///
    /// The returned state is the essential information for the signers
    /// UTXO, and information about the current fees and any fees paid for
    /// transactions currently in the mempool.
    pub async fn get_btc_state<C>(&self, ctx: &C) -> Result<SignerBtcState, Error>
    where
        C: Context + Send + Sync,
    {
        // We need to know the signers UTXO, so let's fetch that.
        let db = ctx.get_storage();
        let utxo = db
            .get_signer_utxo(&self.chain_tip, self.context_window)
            .await?
            .ok_or(Error::MissingSignerUtxo)?;

        let btc_state = SignerBtcState {
            fee_rate: self.fee_rate,
            utxo,
            public_key: bitcoin::XOnlyPublicKey::from(self.aggregate_key),
            last_fees: self.last_fee,
            magic_bytes: self.magic_bytes,
        };

        Ok(btc_state)
    }

    /// Construct the reports for each request that this transaction will
    /// service.
    // pub async fn construct_reports2<C>(&self, ctx: &C) -> Result<Vec<TempOutput>, Error>
    // where
    //     C: Context + Send + Sync,
    // {
    //     let db = ctx.get_storage();
    //     let signer_state = self.get_btc_state(ctx).await?;

    //     let signer_public_key = &self.signer_public_key;
    //     let aggregate_key = &self.aggregate_key;
    //     let chain_tip = &self.chain_tip;

    //     let mut output = Vec::new();

    //     for package in self.request_packages.iter() {
    //         let mut deposits = Vec::new();
    //         let mut withdrawals = Vec::new();

    //         for outpoint in package.deposits.iter() {
    //             let txid = outpoint.txid.into();
    //             let output_index = outpoint.vout;
    //             let report_future = db.get_deposit_request_report(
    //                 chain_tip,
    //                 &txid,
    //                 output_index,
    //                 signer_public_key,
    //             );

    //             let Some(report) = report_future.await? else {
    //                 return Err(BitcoinDepositInputError::Unknown(*outpoint).into_error(self));
    //             };

    //             let votes = db
    //                 .get_deposit_request_signer_votes(&txid, output_index, aggregate_key)
    //                 .await?;

    //             deposits.push((report.to_deposit_request(&votes), report));
    //         }

    //         for id in package.withdrawals.iter() {
    //             let report_future =
    //                 db.get_withdrawal_request_report(chain_tip, id, signer_public_key);

    //             let Some(report) = report_future.await? else {
    //                 return Err(BitcoinWithdrawalOutputError::Unknown(*id).into_error(self));
    //             };

    //             let votes = db
    //                 .get_withdrawal_request_signer_votes(id, aggregate_key)
    //                 .await?;

    //             withdrawals.push((report.to_withdrawal_request(&votes), report));
    //         }

    //         let reports = SbtcReports {
    //             deposits,
    //             withdrawals,
    //             signer_state,
    //         };

    //         let mut signer_state = signer_state;
    //         let tx = reports.create_transaction()?;
    //         let sighashes = tx.construct_digests()?.into_sighashes();

    //         let txid = tx.tx_ref().compute_txid().into();

    //         signer_state.utxo = tx.new_signer_utxo();
    //         // The first transaction is the only one whose input UTXOs that
    //         // have all been confirmed. Moreover, the fees that it sets
    //         // aside are enough to make up for the remaining transactions
    //         // in the transaction package. With that in mind, we do not
    //         // need to bump their fees anymore in order for them to be
    //         // accepted by the network.
    //         signer_state.last_fees = None;
    //         output.push(TempOutput { reports, sighashes, txid });
    //     }

    //     Ok(output)
    // }

    /// Construct the reports for each request that this transaction will
    /// service.
    pub async fn construct_sighash<C>(
        &self,
        ctx: &C,
        requests: &TxRequestIds,
        signer_state: SignerBtcState,
    ) -> Result<(TempOutput, SignerBtcState), Error>
    where
        C: Context + Send + Sync,
    {
        let db = ctx.get_storage();

        let signer_public_key = &self.signer_public_key;
        let aggregate_key = &self.aggregate_key;
        let chain_tip = &self.chain_tip;

        let mut deposits = Vec::new();
        let mut withdrawals = Vec::new();

        for outpoint in requests.deposits.iter() {
            let txid = outpoint.txid.into();
            let output_index = outpoint.vout;
            let report_future =
                db.get_deposit_request_report(chain_tip, &txid, output_index, signer_public_key);

            let Some(report) = report_future.await? else {
                return Err(DepositValidationResult::Unknown.into_error(self));
            };

            let votes = db
                .get_deposit_request_signer_votes(&txid, output_index, aggregate_key)
                .await?;

            deposits.push((report.to_deposit_request(&votes), report));
        }

        for id in requests.withdrawals.iter() {
            let report_future = db.get_withdrawal_request_report(chain_tip, id, signer_public_key);

            let Some(report) = report_future.await? else {
                return Err(WithdrawalValidationResult::Unknown.into_error(self));
            };

            let votes = db
                .get_withdrawal_request_signer_votes(id, aggregate_key)
                .await?;

            withdrawals.push((report.to_withdrawal_request(&votes), report));
        }

        deposits.sort_by_key(|(request, _)| request.outpoint);
        withdrawals.sort_by(|(_, report1), (_, report2)| report1.id.cmp(&report2.id));
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

        let out = TempOutput {
            signer_sighash: sighashes.signer_sighash(),
            deposit_sighashes: sighashes.deposit_sighashes(),
            chain_tip: self.chain_tip,
            tx: tx.tx.clone(),
            tx_fee: Amount::from_sat(tx.tx_fee),
            reports,
            chain_tip_height: self.chain_tip_height,
        };

        Ok((out, signer_state))
    }
}

/// Temp struct
pub struct TempOutput {
    /// The info for the stuff
    pub signer_sighash: (OutPoint, TapSighash, TxPrevoutType),
    /// The info for the stuff
    pub deposit_sighashes: Vec<(OutPoint, TapSighash, TxPrevoutType)>,
    /// The info for the stuff
    pub reports: SbtcReports,
    /// The info for the stuff
    pub chain_tip: BitcoinBlockHash,
    /// the transaction
    pub tx: bitcoin::Transaction,
    /// the transaction fee in sats
    pub tx_fee: Amount,
    /// the chain tip height.
    pub chain_tip_height: u64,
}

/// The version of the algorithm that constructed the bitcoin transaction.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::Type, strum::Display)]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[derive(serde::Serialize, serde::Deserialize)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub enum ConstructionVersion {
    /// The first version for constructing a UTXO
    V0,
}

/// the input
pub struct Row {
    /// whatever
    pub txid: BitcoinTxId,
    /// whatevert
    pub chain_tip: BitcoinBlockHash,
    /// whatever
    pub sighash: TapSighash,
    /// whatever
    pub prevout_txid: BitcoinTxId,
    /// whatever
    pub prevout_output_index: u32,
    /// whatever
    pub prevout_type: TxPrevoutType,
    /// whatever
    pub status: DepositValidationResult,
    /// whatever
    pub will_sign: bool,
    /// whatever
    pub construction_version: ConstructionVersion,
}

/// The output
pub struct RowOutput {
    /// whatever
    pub txid: BitcoinTxId,
    /// whatever
    pub request_id: u64,
    /// whatever
    pub stacks_txid: StacksTxId,
    /// whatever
    pub stacks_block_hash: StacksBlockHash,
    /// whatever
    pub validation_status: WithdrawalValidationResult,
    /// whatever
    pub construction_version: ConstructionVersion,
}

impl TempOutput {
    /// get rows
    pub fn to_input_rows(&self) -> Vec<Row> {
        debug_assert_eq!(self.deposit_sighashes.len(), self.reports.deposits.len());

        let is_valid = self.is_valid_tx();
        let txid = self.tx.compute_txid().into();
        self.deposit_sighashes
            .iter()
            .zip(self.reports.deposits.iter())
            .map(|(&(outpoint, sighash, prevout_type), (_, report))| Row {
                txid,
                sighash,
                chain_tip: self.chain_tip,
                prevout_txid: outpoint.txid.into(),
                prevout_output_index: outpoint.vout,
                prevout_type,
                status: report.validate(self.chain_tip_height, &self.tx, self.tx_fee),
                will_sign: is_valid,
                construction_version: ConstructionVersion::V0,
            })
            .collect()
    }

    /// get rows
    pub fn to_output_rows(&self) -> Vec<RowOutput> {
        let txid = self.tx.compute_txid().into();

        self.reports
            .withdrawals
            .iter()
            .map(|(_, report)| RowOutput {
                txid,
                request_id: report.id.request_id,
                stacks_txid: report.id.txid,
                stacks_block_hash: report.id.block_hash,
                construction_version: ConstructionVersion::V0,
                validation_status: WithdrawalValidationResult::Unknown,
            })
            .collect()
    }

    /// Check whether we will sign any of the sighashes for the transaction
    pub fn is_valid_tx(&self) -> bool {
        let deposit_validation_results =
            self.reports.deposits.iter().all(|(_, report)| {
                match report.validate(self.chain_tip_height, &self.tx, self.tx_fee) {
                    DepositValidationResult::Ok | DepositValidationResult::CannotSignUtxo => true,
                    _ => false,
                }
            });

        let withdrawal_validation_results = self.reports.withdrawals.iter().all(|(_, report)| {
            match report.validate(self.chain_tip_height, &self.tx, self.tx_fee) {
                WithdrawalValidationResult::Unknown => false,
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
#[derive(Debug, PartialEq, Eq, Copy, Clone, strum::Display, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum DepositValidationResult {
    /// The deposit request passed validation
    Ok,
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

impl DepositValidationResult {
    fn into_error(self, ctx: &BitcoinTxContext) -> Error {
        Error::BitcoinValidation(Box::new(BitcoinValidationError {
            error: BitcoinSweepErrorMsg::Deposit(self),
            context: ctx.clone(),
        }))
    }
}

/// The responses for validation of the outputs of a sweep transaction on
/// bitcoin.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum WithdrawalValidationResult {
    /// The signer does not have a record of the withdrawal request in
    /// their database.
    Unknown,
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
    #[error("deposit error ")]
    Deposit(DepositValidationResult),
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
    fn validate<F>(&self, chain_tip_height: u64, tx: &F, tx_fee: Amount) -> DepositValidationResult
    where
        F: FeeAssessment,
    {
        let confirmed_block_height = match self.status {
            // Deposit requests are only written to the database after they
            // have been confirmed, so this means that we have a record of
            // the request, but it has not been confirmed on the canonical
            // bitcoin blockchain.
            DepositConfirmationStatus::Unconfirmed => {
                return DepositValidationResult::TxNotOnBestChain;
            }
            // This means that we have a record of the deposit UTXO being
            // spent in a sweep transaction that has been confirmed on the
            // canonical bitcoin blockchain.
            DepositConfirmationStatus::Spent(_) => {
                return DepositValidationResult::DepositUtxoSpent;
            }
            // The deposit has been confirmed on the canonical bitcoin
            // blockchain and remains unspent by us.
            DepositConfirmationStatus::Confirmed(block_height, _) => block_height,
        };

        // We only sweep a deposit if the depositor cannot reclaim the
        // deposit within the next DEPOSIT_LOCKTIME_BLOCK_BUFFER blocks.
        let deposit_age = chain_tip_height.saturating_sub(confirmed_block_height);

        match self.lock_time {
            LockTime::Blocks(height) => {
                let max_age = height.value().saturating_sub(DEPOSIT_LOCKTIME_BLOCK_BUFFER) as u64;
                if deposit_age >= max_age {
                    return DepositValidationResult::LockTimeExpiry;
                }
            }
            LockTime::Time(_) => {
                return DepositValidationResult::UnsupportedLockTime;
            }
        }

        let Some(assessed_fee) = tx.assess_input_fee(&self.outpoint, tx_fee) else {
            return DepositValidationResult::Unknown;
        };

        if assessed_fee.to_sat() > self.max_fee {
            return DepositValidationResult::FeeTooHigh;
        }

        // If we are here then can_sign is Some(true) so can_accept is
        // Some(_). Let's check whether we rejected this deposit.
        if self.can_accept != Some(true) {
            return DepositValidationResult::RejectedRequest;
        }

        match self.can_sign {
            // If we are here, we know that we have a record for the
            // deposit request, but we have not voted on it yet, so we do
            // not know if we can sign for it.
            None => return DepositValidationResult::NoVote,
            // In this case we know that we cannot sign for the deposit
            // because it is locked with a public key where the current
            // signer is not part of the signing set.
            Some(false) => return DepositValidationResult::CannotSignUtxo,
            // Yay.
            Some(true) => (),
        }

        DepositValidationResult::Ok
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalRequestReport {
    /// The confirmation status of the withdrawal request transaction.
    pub status: WithdrawalRequestStatus,
    /// The unique identifier for the request. It includes the ID generated
    /// by the smart contract when the `initiate-withdrawal-request` public
    /// function was called along with the transaction ID and Stacks block
    /// ID.
    pub id: QualifiedRequestId,
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
    pub fn validate<F>(&self, _: u64, _: &F, _: Amount) -> WithdrawalValidationResult
    where
        F: FeeAssessment,
    {
        WithdrawalValidationResult::Unknown
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

    use super::*;

    /// A helper struct to aid in testing of deposit validation.
    #[derive(Debug)]
    struct DepositReportErrorMapping {
        report: DepositRequestReport,
        status: DepositValidationResult,
        chain_tip_height: u64,
    }

    const TX_FEE: Amount = Amount::from_sat(10000);

    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Unconfirmed,
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::TxNotOnBestChain,
        chain_tip_height: 2,
    } ; "deposit-reorged")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Spent(BitcoinTxId::from([1; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::DepositUtxoSpent,
        chain_tip_height: 2,
    } ; "deposit-spent")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: None,
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::NoVote,
        chain_tip_height: 2,
    } ; "deposit-no-vote")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(false),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::CannotSignUtxo,
        chain_tip_height: 2,
    } ; "cannot-sign-for-deposit")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(false),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::RejectedRequest,
        chain_tip_height: 2,
    } ; "rejected-deposit")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 1),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::LockTimeExpiry,
        chain_tip_height: 2,
    } ; "lock-time-expires-soon-1")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 2),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::LockTimeExpiry,
        chain_tip_height: 2,
    } ; "lock-time-expires-soon-2")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_512_second_intervals(u16::MAX),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::UnsupportedLockTime,
        chain_tip_height: 2,
    } ; "lock-time-in-time-units-2")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::Ok,
        chain_tip_height: 2,
    } ; "happy-path")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::Unknown,
        chain_tip_height: 2,
    } ; "unknown-prevout")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: TX_FEE.to_sat(),
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::Ok,
        chain_tip_height: 2,
    } ; "at-the-border")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositConfirmationStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: TX_FEE.to_sat() - 1,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: *sbtc::UNSPENDABLE_TAPROOT_KEY,
        },
        status: DepositValidationResult::FeeTooHigh,
        chain_tip_height: 2,
    } ; "one-sat-too-high-fee")]
    fn deposit_report_validation(mapping: DepositReportErrorMapping) {
        let mut tx = crate::testing::btc::base_signer_transaction();
        tx.input.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });

        let status = mapping
            .report
            .validate(mapping.chain_tip_height, &tx, TX_FEE);

        assert_eq!(status, mapping.status);
    }
}
