//! validation of bitcoin transactions.

use bitcoin::relative::LockTime;
use bitcoin::Amount;
use bitcoin::OutPoint;

use crate::bitcoin::utxo::FeeAssessment;
use crate::bitcoin::utxo::Fees;
use crate::bitcoin::utxo::SignerBtcState;
use crate::context::Context;
use crate::error::Error;
use crate::keys::PublicKey;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::BitcoinTx;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::QualifiedRequestId;
use crate::storage::DbRead as _;
use crate::DEPOSIT_LOCKTIME_BLOCK_BUFFER;

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
    /// The transaction that is being validated.
    pub tx: BitcoinTx,
    /// The deposit requests associated with the inputs in the transaction.
    pub deposit_requests: Vec<OutPoint>,
    /// The total amount of the transaction fee in sats.
    pub tx_fee: u64,
    /// The current market fee rate in sat/vByte.
    pub fee_rate: f64,
    /// The total fee amount and the fee rate for the last transaction that
    /// used this UTXO as an input.
    pub last_fee: Option<Fees>,
    /// The withdrawal requests associated with the outputs in the current
    /// transaction.
    pub request_ids: Vec<QualifiedRequestId>,
    /// The public key of the signer that created the bitcoin transaction.
    /// This is very unlikely to ever be used in the
    /// [`BitcoinTx::validate`] function, but is here for logging and
    /// tracking purposes.
    pub origin: PublicKey,
    /// Two byte prefix for BTC transactions that are related to the Stacks
    /// blockchain.
    pub magic_bytes: [u8; 2],
}

impl BitcoinTxContext {
    /// Validate the current bitcoin transaction.
    pub async fn validate<C>(&self, _ctx: &C) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        unimplemented!()
    }

    /// Validate each of the prevouts that correspond to deposits. This
    /// should be every input except for the first one.
    pub async fn validate_deposit<C>(&self, ctx: &C, outpoint: &OutPoint) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        let db = ctx.get_storage();
        let signer_public_key = PublicKey::from_private_key(&ctx.config().signer.private_key);

        let txid = outpoint.txid.into();
        let report_future = db.get_deposit_request_report(
            &self.chain_tip,
            &txid,
            outpoint.vout,
            &signer_public_key,
        );

        // The DbRead::get_deposit_request_report only returns Ok(None)
        // if there isn't a record of the deposit request.
        let Some(report) = report_future.await? else {
            return Err(BitcoinDepositInputError::Unknown(*outpoint).into_error(self));
        };

        report
            .validate(self.chain_tip_height)
            .map_err(|err| err.into_error(self))?;
        report
            .validate_fee(&self.tx, self.tx_fee)
            .map_err(|err| err.into_error(self))?;

        Ok(())
    }

    /// Validate the withdrawal UTXOs
    pub async fn validate_withdrawals<C>(&self, _ctx: &C) -> Result<(), Error>
    where
        C: Context + Send + Sync,
    {
        if !self.request_ids.is_empty() {
            return Err(Error::MissingBlock);
        }

        Ok(())
    }

    /// Fetch the signers' BTC state.
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

        // If we are here, then we know that we have run DKG. Why? Well,
        // users cannot deposit if they don't have an aggregate key to lock
        // their funds with, and that requires DKG.
        let Some(dkg_shares) = db.get_latest_encrypted_dkg_shares().await? else {
            return Err(Error::NoDkgShares);
        };

        Ok(SignerBtcState {
            fee_rate: self.fee_rate,
            utxo,
            public_key: bitcoin::XOnlyPublicKey::from(dkg_shares.aggregate_key),
            last_fees: self.last_fee,
            magic_bytes: self.magic_bytes,
        })
    }
}

/// The responses for validation of a sweep transaction on bitcoin.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Copy, Clone)]
pub enum BitcoinDepositInputError {
    /// The assessed fee exceeds the max-fee in the deposit request.
    #[error("the assessed fee for a deposit would exceed their max-fee; {0}")]
    FeeTooHigh(OutPoint),
    /// The signer is not part of the signer set that generated the
    /// aggregate public key used to lock the deposit funds.
    ///
    /// TODO: For v1 every signer should be able to sign for all deposits,
    /// but for v2 this will not be the case. So we'll need to decide
    /// whether a particular deposit cannot be signed by a particular
    /// signers means that the entire transaction is rejected from that
    /// signer.
    #[error("the signer is not part of the signing set for the aggregate public key; {0}")]
    CannotSignUtxo(OutPoint),
    /// The deposit transaction has been confirmed on a bitcoin block
    /// that is not part of the canonical bitcoin blockchain.
    #[error("deposit transaction not on canonical bitcoin blockchain; {0}")]
    TxNotOnBestChain(OutPoint),
    /// The deposit UTXO has already been spent.
    #[error("deposit used as input in confirmed sweep transaction; deposit: {0}, txid: {1}")]
    DepositUtxoSpent(OutPoint, BitcoinTxId),
    /// Given the current time and block height, it would be imprudent to
    /// attempt to sweep in a deposit request with the given lock-time.
    #[error("lock-time expiration is too soon; {0}")]
    LockTimeExpiry(OutPoint),
    /// The signer does not have a record of their vote on the deposit
    /// request in their database.
    #[error("the signer does not have a record of their vote on the deposit request; {0}")]
    NoVote(OutPoint),
    /// The signer has rejected the deposit request.
    #[error("the signer has not accepted the deposit request; {0}")]
    RejectedRequest(OutPoint),
    /// The signer does not have a record of the deposit request in their
    /// database.
    #[error("the signer does not have a record of the deposit request; {0}")]
    Unknown(OutPoint),
    /// The locktime in the reclaim script is in time units and that is not
    /// supported. This shouldn't happen, since we will not put it in our
    /// database is this is the case.
    #[error("the deposit locktime is denoted in time and that is not supported; {0}")]
    UnsupportedLockTime(OutPoint),
}

impl BitcoinDepositInputError {
    fn into_error(self, ctx: &BitcoinTxContext) -> Error {
        Error::BitcoinValidation(Box::new(BitcoinValidationError {
            error: BitcoinSweepErrorMsg::Deposit(self),
            context: ctx.clone(),
        }))
    }
}

/// The responses for validation of a sweep transaction on bitcoin.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Copy, Clone)]
pub enum BitcoinSweepErrorMsg {
    /// The error has something to do with the inputs.
    #[error("deposit error; {0}")]
    Deposit(#[from] BitcoinDepositInputError),
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
pub enum DepositRequestStatus {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositRequestReport {
    /// The deposit UTXO outpoint that uniquely identifies the deposit.
    pub outpoint: OutPoint,
    /// The confirmation status of the deposit request transaction.
    pub status: DepositRequestStatus,
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
}

impl DepositRequestReport {
    /// Validate that the deposit request is okay given the report.
    pub fn validate(self, chain_tip_height: u64) -> Result<(), BitcoinDepositInputError> {
        let confirmed_block_height = match self.status {
            // Deposit requests are only written to the database after they
            // have been confirmed, so this means that we have a record of
            // the request, but it has not been confirmed on the canonical
            // bitcoin blockchain.
            DepositRequestStatus::Unconfirmed => {
                return Err(BitcoinDepositInputError::TxNotOnBestChain(self.outpoint));
            }
            // This means that we have a record of the deposit UTXO being
            // spent in a sweep transaction that has been confirmed on the
            // canonical bitcoin blockchain.
            DepositRequestStatus::Spent(txid) => {
                return Err(BitcoinDepositInputError::DepositUtxoSpent(
                    self.outpoint,
                    txid,
                ));
            }
            // The deposit has been confirmed on the canonical bitcoin
            // blockchain and remains unspent by us.
            DepositRequestStatus::Confirmed(block_height, _) => block_height,
        };

        // We only sweep a deposit if the depositor cannot reclaim the
        // deposit within the next DEPOSIT_LOCKTIME_BLOCK_BUFFER blocks.
        let deposit_age = chain_tip_height.saturating_sub(confirmed_block_height);

        match self.lock_time {
            LockTime::Blocks(height) => {
                let max_age = height.value().saturating_sub(DEPOSIT_LOCKTIME_BLOCK_BUFFER) as u64;
                if deposit_age >= max_age {
                    return Err(BitcoinDepositInputError::LockTimeExpiry(self.outpoint));
                }
            }
            LockTime::Time(_) => {
                return Err(BitcoinDepositInputError::UnsupportedLockTime(self.outpoint))
            }
        }

        match self.can_sign {
            // If we are here, we know that we have a record for the
            // deposit request, but we have not voted on it yet, so we do
            // not know if we can sign for it.
            None => return Err(BitcoinDepositInputError::NoVote(self.outpoint)),
            // In this case we know that we cannot sign for the deposit
            // because it is locked with a public key where the current
            // signer is not part of the signing set.
            Some(false) => return Err(BitcoinDepositInputError::CannotSignUtxo(self.outpoint)),
            // Yay.
            Some(true) => (),
        }
        // If we are here then can_sign is Some(true) so can_accept is
        // Some(_). Let's check whether we rejected this deposit.
        if self.can_accept != Some(true) {
            return Err(BitcoinDepositInputError::RejectedRequest(self.outpoint));
        }

        Ok(())
    }

    /// Validate that the fees assessed to the deposit prevout is below the
    /// max fee.
    pub fn validate_fee<F>(&self, tx: &F, tx_fee: u64) -> Result<(), BitcoinDepositInputError>
    where
        F: FeeAssessment,
    {
        let tx_fee = Amount::from_sat(tx_fee);
        let Some(assessed_fee) = tx.assess_input_fee(&self.outpoint, tx_fee) else {
            return Err(BitcoinDepositInputError::Unknown(self.outpoint));
        };

        if assessed_fee.to_sat() > self.max_fee {
            return Err(BitcoinDepositInputError::FeeTooHigh(self.outpoint));
        }
        Ok(())
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
        error: Option<BitcoinDepositInputError>,
        chain_tip_height: u64,
    }

    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Unconfirmed,
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::TxNotOnBestChain(OutPoint::null())),
        chain_tip_height: 2,
    } ; "deposit-reorged")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Spent(BitcoinTxId::from([1; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::DepositUtxoSpent(OutPoint::null(), BitcoinTxId::from([1; 32]))),
        chain_tip_height: 2,
    } ; "deposit-spent")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: None,
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::NoVote(OutPoint::null())),
        chain_tip_height: 2,
    } ; "deposit-no-vote")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(false),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::CannotSignUtxo(OutPoint::null())),
        chain_tip_height: 2,
    } ; "cannot-sign-for-deposit")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(false),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(u16::MAX),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::RejectedRequest(OutPoint::null())),
        chain_tip_height: 2,
    } ; "rejected-deposit")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 1),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::LockTimeExpiry(OutPoint::null())),
        chain_tip_height: 2,
    } ; "lock-time-expires-soon-1")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 2),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::LockTimeExpiry(OutPoint::null())),
        chain_tip_height: 2,
    } ; "lock-time-expires-soon-2")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_512_second_intervals(u16::MAX),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::UnsupportedLockTime(OutPoint::null())),
        chain_tip_height: 2,
    } ; "lock-time-in-time-units-2")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: u64::MAX,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
        },
        error: None,
        chain_tip_height: 2,
    } ; "happy-path")]
    fn deposit_report_validation(mapping: DepositReportErrorMapping) {
        match mapping.error {
            Some(expected_error) => {
                let error = mapping
                    .report
                    .validate(mapping.chain_tip_height)
                    .unwrap_err();

                assert_eq!(error, expected_error);
            }
            None => mapping.report.validate(mapping.chain_tip_height).unwrap(),
        }
    }

    const TX_FEE: u64 = 10000;

    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: TX_FEE,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
        },
        error: Some(BitcoinDepositInputError::Unknown(OutPoint::new(Txid::from_byte_array([1; 32]), 0))),
        chain_tip_height: 2,
    } ; "unknown-prevout")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: TX_FEE,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
        },
        error: None,
        chain_tip_height: 2,
    } ; "at-the-border")]
    #[test_case(DepositReportErrorMapping {
        report: DepositRequestReport {
            status: DepositRequestStatus::Confirmed(0, BitcoinBlockHash::from([0; 32])),
            can_sign: Some(true),
            can_accept: Some(true),
            amount: 0,
            max_fee: TX_FEE - 1,
            lock_time: LockTime::from_height(DEPOSIT_LOCKTIME_BLOCK_BUFFER + 3),
            outpoint: OutPoint::null(),
        },
        error: Some(BitcoinDepositInputError::FeeTooHigh(OutPoint::null())),
        chain_tip_height: 2,
    } ; "one-sat-too-high-fee")]
    fn deposit_report_fee_validation(mapping: DepositReportErrorMapping) {
        // This is a base sweep transaction without any deposit inputs or
        // withdrawal outputs. We add one input so that there is exactly
        // one deposit request being serviced by this transaction. This
        // means it pays for the entire transaction fee.
        let mut tx = crate::testing::btc::base_signer_transaction();
        tx.input.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        });

        match mapping.error {
            Some(expected_error) => {
                let error = mapping.report.validate_fee(&tx, TX_FEE).unwrap_err();
                assert_eq!(error, expected_error);
            }
            None => mapping.report.validate_fee(&tx, TX_FEE).unwrap(),
        }
    }
}
