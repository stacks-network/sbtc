//! Utxo management and transaction construction

use std::collections::HashSet;
use std::ops::Deref as _;
use std::sync::LazyLock;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::Version;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::TapLeafHash;
use bitcoin::TapSighash;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::Weight;
use bitcoin::Witness;
use bitvec::array::BitArray;
use bitvec::field::BitField;
use secp256k1::XOnlyPublicKey;
use secp256k1::SECP256K1;
use serde::Deserialize;
use serde::Serialize;

use crate::bitcoin::packaging::compute_optimal_packages;
use crate::bitcoin::packaging::Weighted;
use crate::bitcoin::rpc::BitcoinTxInfo;
use crate::context::SbtcLimits;
use crate::error::Error;
use crate::keys::SignerScriptPubKey as _;
use crate::storage::model;
use crate::storage::model::BitcoinTx;
use crate::storage::model::BitcoinTxId;
use crate::storage::model::QualifiedRequestId;
use crate::storage::model::ScriptPubKey;
use crate::storage::model::SignerVotes;
use crate::storage::model::StacksBlockHash;
use crate::storage::model::StacksTxId;
use crate::storage::model::TxOutput;
use crate::storage::model::TxOutputType;
use crate::storage::model::TxPrevout;
use crate::storage::model::TxPrevoutType;
use crate::DEPOSIT_DUST_LIMIT;
use crate::MAX_MEMPOOL_PACKAGE_TX_COUNT;

/// The minimum incremental fee rate in sats per virtual byte for RBF
/// transactions.
const DEFAULT_INCREMENTAL_RELAY_FEE_RATE: f64 =
    bitcoin::policy::DEFAULT_INCREMENTAL_RELAY_FEE as f64 / 1000.0;

/// This constant represents the virtual size (in vBytes) of a BTC
/// transaction that includes two inputs and one output. The inputs consist
/// of the signers' input UTXO and a UTXO for a deposit request. The output
/// is the signers' new UTXO. The deposit request is such that the sweep
/// transaction has the largest size of solo deposit sweep transactions.
const SOLO_DEPOSIT_TX_VSIZE: f64 = 267.0;

/// This constant represents the virtual size (in vBytes) of a BTC
/// transaction servicing only one withdrawal request, except the
/// withdrawal output is not in the transaction. This way the sweep
/// transaction's OP_RETURN output is the right size, and we can handle the
/// variability of output sizes.
const BASE_WITHDRAWAL_TX_VSIZE: f64 = MAX_BASE_TX_VSIZE as f64;

/// This constant represents the maximum virtual size (in vBytes) of a BTC
/// transaction excluding withdrawals outputs and deposit inputs.
pub const MAX_BASE_TX_VSIZE: u64 = 164;

/// It appears that bitcoin-core tracks fee rates in sats per kilo-vbyte
/// (or BTC per kilo-vbyte). Since we work in sats per vbyte, this constant
/// is the smallest detectable increment for bumping the fee rate in sats
/// per vbyte.
const SATS_PER_VBYTE_INCREMENT: f64 = 0.001;

/// The OP_RETURN version byte for deposit or withdrawal sweep
/// transactions.
const OP_RETURN_VERSION: u8 = 0;

/// A dummy Schnorr signature.
static DUMMY_SIGNATURE: LazyLock<Signature> = LazyLock::new(|| Signature {
    signature: secp256k1::schnorr::Signature::from_slice(&[0; 64]).unwrap(),
    sighash_type: TapSighashType::All,
});

/// Describes the fees for a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Fees {
    /// The total fee paid in sats for the transaction.
    pub total: u64,
    /// The fee rate paid in sats per virtual byte.
    pub rate: f64,
}

impl Fees {
    /// A zero-fee [`Fees`] instance.
    pub const ZERO: Self = Self { total: 0, rate: 0.0 };
}

/// A trait for getting the fees for a given instance.
pub trait GetFees {
    /// Get the [`Fees`] for this instance. If the basis for fee calculation is
    /// not available, this function should return `None`.
    fn get_fees(&self) -> Result<Option<Fees>, Error>;
}

/// Filter out the deposit requests that do not meet the amount or fee requirements.
pub struct SbtcRequestsFilter<'a> {
    sbtc_limits: &'a SbtcLimits,
    minimum_fee: u64,
}

impl<'a> SbtcRequestsFilter<'a> {
    /// Create a new [`DepositFilter`] instance.
    pub fn new(sbtc_limits: &'a SbtcLimits, minimum_fee: u64) -> Self {
        Self { sbtc_limits, minimum_fee }
    }

    /// Validate deposit requests based on four constraints:
    /// 1. The user's max fee must be >= our minimum required fee for deposits
    ///     (based on fixed deposit tx size)
    /// 2. The deposit amount must be greater than or equal to the per-deposit minimum
    /// 3. The deposit amount must be less than or equal to the per-deposit cap
    /// 4. The total amount being minted must stay under the maximum allowed mintable amount
    fn validate_deposit_amount(
        &self,
        amount_to_mint: &mut Amount,
        req: &'a DepositRequest,
    ) -> Option<RequestRef<'a>> {
        let is_fee_valid = req.max_fee.min(req.amount) >= self.minimum_fee;
        let is_above_dust = req.amount.saturating_sub(self.minimum_fee) >= DEPOSIT_DUST_LIMIT;
        let req_amount = Amount::from_sat(req.amount);
        let is_above_per_deposit_minimum = req_amount >= self.sbtc_limits.per_deposit_minimum();
        let is_within_per_deposit_cap = req_amount <= self.sbtc_limits.per_deposit_cap();
        let is_within_max_mintable_cap =
            if let Some(new_amount) = amount_to_mint.checked_add(req_amount) {
                new_amount <= self.sbtc_limits.max_mintable_cap()
            } else {
                false
            };

        if is_fee_valid
            && is_above_dust
            && is_above_per_deposit_minimum
            && is_within_per_deposit_cap
            && is_within_max_mintable_cap
        {
            *amount_to_mint += req_amount;
            Some(RequestRef::Deposit(req))
        } else {
            None
        }
    }

    /// Filter sbtc deposits that don't meet the validation criteria.
    pub fn filter_deposits(&self, deposits: &'a [DepositRequest]) -> Vec<RequestRef<'a>> {
        deposits
            .iter()
            .scan(Amount::from_sat(0), |amount_to_mint, deposit| {
                Some(self.validate_deposit_amount(amount_to_mint, deposit))
            })
            .flatten()
            .collect()
    }
}

/// Summary of the Signers' UTXO and information necessary for
/// constructing their next UTXO.
#[derive(Debug, Clone, Copy)]
pub struct SignerBtcState {
    /// The outstanding signer UTXO.
    pub utxo: SignerUtxo,
    /// The current market fee rate in sat/vByte.
    pub fee_rate: f64,
    /// The current public key of the signers
    pub public_key: XOnlyPublicKey,
    /// The total fee amount and the fee rate for the last transaction that
    /// used this UTXO as an input.
    pub last_fees: Option<Fees>,
    /// Two byte prefix for BTC transactions that are related to the Stacks
    /// blockchain.
    pub magic_bytes: [u8; 2],
}

/// The set of sBTC requests with additional relevant
/// information used to construct the next transaction package.
#[derive(Debug)]
pub struct SbtcRequests {
    /// Accepted and pending deposit requests.
    pub deposits: Vec<DepositRequest>,
    /// Accepted and pending withdrawal requests.
    pub withdrawals: Vec<WithdrawalRequest>,
    /// Summary of the Signers' UTXO and information necessary for
    /// constructing their next UTXO.
    pub signer_state: SignerBtcState,
    /// The minimum acceptable number of votes for any given request.
    pub accept_threshold: u16,
    /// The total number of signers.
    pub num_signers: u16,
    /// The maximum amount of sBTC that can be minted in sats.
    pub sbtc_limits: SbtcLimits,
    /// The maximum number of deposit request inputs that can be included
    /// in a single bitcoin transaction. The purpose of this constant is to
    /// ensure that each sweep transaction is constructed in such a way
    /// that there is enough time for the signers to sign all the inputs
    /// during the tenure of a single bitcoin block.
    pub max_deposits_per_bitcoin_tx: u16,
}

impl SbtcRequests {
    /// Construct the next transaction package given requests and the
    /// signers' UTXO.
    ///
    /// This function can fail if the output amounts are greater than the
    /// input amounts.
    pub fn construct_transactions(&self) -> Result<Vec<UnsignedTransaction>, Error> {
        if self.deposits.is_empty() && self.withdrawals.is_empty() {
            tracing::info!("No deposits or withdrawals so no BTC transaction");
            return Ok(Vec::new());
        }

        // Now we filter withdrawal requests where the user's max fee
        // could be less than fee we may charge.
        let withdrawals = self
            .withdrawals
            .iter()
            .filter(|req| {
                // This is the size for a BTC transaction servicing
                // a single withdrawal.
                let withdrawal_output = req.as_tx_output();
                let tx_vsize = BASE_WITHDRAWAL_TX_VSIZE + withdrawal_output.size() as f64;
                req.max_fee >= self.compute_minimum_fee(tx_vsize)
            })
            .map(RequestRef::Withdrawal);

        let request_filter = SbtcRequestsFilter::new(
            &self.sbtc_limits,
            self.compute_minimum_fee(SOLO_DEPOSIT_TX_VSIZE),
        );
        let deposits = request_filter.filter_deposits(&self.deposits);

        // Create a list of requests where each request can be approved on its own.
        let items = deposits.into_iter().chain(withdrawals);

        let max_votes_against = self.reject_capacity();
        let max_needs_signature = self.max_deposits_per_bitcoin_tx;
        compute_optimal_packages(items, max_votes_against, max_needs_signature)
            .scan(self.signer_state, |state, request_refs| {
                let requests = Requests::new(request_refs);
                let tx = UnsignedTransaction::new(requests, state);
                if let Ok(tx_ref) = tx.as_ref() {
                    state.utxo = tx_ref.new_signer_utxo();
                    // The first transaction is the only one whose input
                    // UTXOs that have all been confirmed. Moreover, the
                    // fees that it sets aside are enough to make up for
                    // the remaining transactions in the transaction package.
                    // With that in mind, we do not need to bump their fees
                    // anymore in order for them to be accepted by the
                    // network.
                    state.last_fees = None;
                }
                Some(tx)
            })
            .take(MAX_MEMPOOL_PACKAGE_TX_COUNT as usize)
            .collect()
    }

    fn reject_capacity(&self) -> u32 {
        self.num_signers.saturating_sub(self.accept_threshold) as u32
    }

    /// Calculates the minimum fee threshold for servicing a user's
    /// request based on the maximum transaction vsize the user is
    /// required to pay for.
    fn compute_minimum_fee(&self, tx_vsize: f64) -> u64 {
        let fee_rate = self.signer_state.fee_rate;
        let last_fees = self.signer_state.last_fees;
        compute_transaction_fee(tx_vsize, fee_rate, last_fees)
    }
}

/// Calculate the total fee necessary for a transaction of the given size
/// to be accepted by the network. Supports computing the fee in case this
/// is a replace-by-fee (RBF) transaction by specifying the fees paid
/// in the prior transaction.
///
/// ## Notes
///
/// Here are the fee related requirements for a replace-by-fee as
/// described in BIP-125:
///
/// 3. The replacement transaction pays an absolute fee of at least the
///    sum paid by the original transactions.
/// 4. The replacement transaction must also pay for its own bandwidth
///    at or above the rate set by the node's minimum relay fee setting.
///    For example, if the minimum relay fee is 1 satoshi/byte and the
///    replacement transaction is 500 bytes total, then the replacement
///    must pay a fee at least 500 satoshis higher than the sum of the
///    originals.
///
/// Also, noteworthy is that the fee rate of the RBF transaction
/// must also be greater than the fee rate of the old transaction.
///
/// ## References
///
/// RBF: https://bitcoinops.org/en/topics/replace-by-fee/
/// BIP-125: https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki#implementation-details
fn compute_transaction_fee(tx_vsize: f64, fee_rate: f64, last_fees: Option<Fees>) -> u64 {
    match last_fees {
        Some(Fees { total, rate }) => {
            // The requirement for an RBF transaction is that the new fee
            // amount be greater than the old fee amount.
            let minimum_fee_rate = fee_rate.max(rate + rate * SATS_PER_VBYTE_INCREMENT);
            let fee_increment = tx_vsize * DEFAULT_INCREMENTAL_RELAY_FEE_RATE;
            (total as f64 + fee_increment)
                .max(tx_vsize * minimum_fee_rate)
                .ceil() as u64
        }
        None => (tx_vsize * fee_rate).ceil() as u64,
    }
}

/// An accepted or pending deposit request.
///
/// Deposit requests are assumed to happen via taproot BTC spend where the
/// key-spend path is assumed to be unspendable since the public key has no
/// known private key.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DepositRequest {
    /// The UTXO to be spent by the signers.
    pub outpoint: OutPoint,
    /// The max fee amount to use for the BTC deposit transaction.
    pub max_fee: u64,
    /// A bitmap of how the signers voted. This structure supports up to
    /// 128 distinct signers. Here, we assume that a 1 (or true) implies
    /// that the signer voted *against* the transaction.
    pub signer_bitmap: BitArray<[u8; 16]>,
    /// The amount of sats in the deposit UTXO.
    pub amount: u64,
    /// The deposit script used so that the signers' can spend funds.
    pub deposit_script: ScriptBuf,
    /// The reclaim script for the deposit.
    pub reclaim_script: ScriptBuf,
    /// The public key used in the deposit script.
    ///
    /// Note that taproot public keys for Schnorr signatures are slightly
    /// different from the usual compressed public keys since they use only
    /// the x-coordinate with the y-coordinate assumed to be even. This
    /// means they use 32 bytes instead of the 33 byte public keys used
    /// before where the additional byte indicated the y-coordinate's
    /// parity.
    pub signers_public_key: XOnlyPublicKey,
}

impl DepositRequest {
    /// Create a TxIn object with witness data for the deposit script of
    /// the given request. Only a valid signature is needed to satisfy the
    /// deposit script.
    fn as_tx_input(&self, signature: Signature) -> TxIn {
        TxIn {
            previous_output: self.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0),
            witness: self.construct_witness_data(signature),
        }
    }

    /// Construct the deposit UTXO associated with this deposit request.
    fn as_tx_out(&self) -> TxOut {
        let ver = LeafVersion::TapScript;
        let merkle_root = self.construct_taproot_info(ver).merkle_root();
        let internal_key = *sbtc::UNSPENDABLE_TAPROOT_KEY;

        TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, internal_key, merkle_root),
        }
    }

    /// Construct the witness data for the taproot script of the deposit.
    ///
    /// Deposit UTXOs are taproot spend with a "null" key spend path,
    /// a deposit script-path spend, and a reclaim script-path spend. This
    /// function creates the witness data for the deposit script-path
    /// spend where the script takes only one piece of data as input, the
    /// signature. The deposit script is:
    ///
    /// ```text
    ///   <data> OP_DROP <public-key> OP_CHECKSIG
    /// ```
    ///
    /// where `<data>` is the stacks deposit address and <pubkey_hash> is
    /// given by self.signers_public_key. The public key used for key-path
    /// spending is self.taproot_public_key, and is supposed to be a dummy
    /// public key.
    pub fn construct_witness_data(&self, signature: Signature) -> Witness {
        let ver = LeafVersion::TapScript;
        let taproot = self.construct_taproot_info(ver);

        // TaprootSpendInfo::control_block returns None if the key given,
        // (script, version), is not in the tree. But this key is definitely
        // in the tree (see the variable leaf1 in the `construct_taproot_info`
        // function).
        let control_block = taproot
            .control_block(&(self.deposit_script.clone(), ver))
            .expect("We just inserted the deposit script into the tree");

        let witness_data = [
            signature.to_vec(),
            self.deposit_script.to_bytes(),
            control_block.serialize(),
        ];
        Witness::from_slice(&witness_data)
    }

    /// Constructs the taproot spending information for the UTXO associated
    /// with this deposit request.
    fn construct_taproot_info(&self, ver: LeafVersion) -> TaprootSpendInfo {
        // For such a simple tree, we construct it by hand.
        let leaf1 = NodeInfo::new_leaf_with_ver(self.deposit_script.clone(), ver);
        let leaf2 = NodeInfo::new_leaf_with_ver(self.reclaim_script.clone(), ver);

        // A Result::Err is returned by NodeInfo::combine if the depth of
        // our taproot tree exceeds the maximum depth of taproot trees,
        // which is 128. We have two nodes so the depth is 1 so this will
        // never panic.
        let node =
            NodeInfo::combine(leaf1, leaf2).expect("This tree depth greater than max of 128");
        let internal_key = *sbtc::UNSPENDABLE_TAPROOT_KEY;

        TaprootSpendInfo::from_node_info(SECP256K1, internal_key, node)
    }

    /// Try convert from a model::DepositRequest with some additional info.
    pub fn from_model(request: model::DepositRequest, votes: SignerVotes) -> Self {
        Self {
            outpoint: request.outpoint(),
            max_fee: request.max_fee,
            signer_bitmap: votes.into(),
            amount: request.amount,
            deposit_script: ScriptBuf::from_bytes(request.spend_script),
            reclaim_script: ScriptBuf::from_bytes(request.reclaim_script),
            signers_public_key: request.signers_public_key.into(),
        }
    }
}

impl Weighted for DepositRequest {
    fn needs_signature(&self) -> bool {
        true
    }
    fn votes(&self) -> u128 {
        self.signer_bitmap.load_le()
    }
    fn vsize(&self) -> u64 {
        self.as_tx_input(*DUMMY_SIGNATURE)
            .segwit_weight()
            .to_vbytes_ceil()
    }
}

/// An accepted or pending withdraw request.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct WithdrawalRequest {
    /// The request id generated by the smart contract when the
    /// `initiate-withdrawal-request` public function was called.
    pub request_id: u64,
    /// The stacks transaction ID that lead to the creation of the
    /// withdrawal request.
    pub txid: StacksTxId,
    /// Stacks block ID of the block that includes the transaction
    /// associated with this withdrawal request.
    pub block_hash: StacksBlockHash,
    /// The amount of BTC, in sats, to withdraw.
    pub amount: u64,
    /// The max fee amount to use for the sBTC deposit transaction.
    pub max_fee: u64,
    /// The script_pubkey of the output.
    pub script_pubkey: ScriptPubKey,
    /// A bitmap of how the signers voted. This structure supports up to
    /// 128 distinct signers. Here, we assume that a 1 (or true) implies
    /// that the signer voted *against* the transaction.
    pub signer_bitmap: BitArray<[u8; 16]>,
}

impl WithdrawalRequest {
    /// Withdrawal UTXOs pay to the given address
    fn as_tx_output(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: self.script_pubkey.clone().into(),
        }
    }

    /// Return a byte array with enough data to uniquely identify this
    /// withdrawal request on the Stacks blockchain.
    ///
    /// The data returned from this function is a concatenation of the
    /// stacks block ID, the stacks transaction ID, and the request-id
    /// associated with this withdrawal request. Thus, the layout of the
    /// data is as follows:
    ///
    /// ```text
    /// 0                 32                             64           72
    /// |-----------------|------------------------------|------------|
    ///   Stacks block ID   Txid of Stacks withdrawal tx   request-id
    /// ```
    ///
    /// where the request-id is encoded as an 8 byte big endian unsigned
    /// integer. We need all three because a transaction can be included in
    /// more than one stacks block (because of reorgs), and a transaction
    /// can generate more than one withdrawal request.
    fn sbtc_data(&self) -> [u8; 72] {
        let mut data = [0u8; 72];
        data[..32].copy_from_slice(&self.block_hash.into_bytes());
        data[32..64].copy_from_slice(&self.txid.into_bytes());
        data[64..72].copy_from_slice(&self.request_id.to_be_bytes());

        data
    }

    /// Try convert from a model::DepositRequest with some additional info.
    pub fn from_model(request: model::WithdrawalRequest, votes: SignerVotes) -> Self {
        Self {
            amount: request.amount,
            max_fee: request.max_fee,
            script_pubkey: request.recipient,
            signer_bitmap: votes.into(),
            request_id: request.request_id,
            txid: request.txid,
            block_hash: request.block_hash,
        }
    }

    /// Return the identifier for the withdrawal request.
    pub fn qualified_id(&self) -> QualifiedRequestId {
        QualifiedRequestId {
            request_id: self.request_id,
            txid: self.txid,
            block_hash: self.block_hash,
        }
    }
}

impl Weighted for WithdrawalRequest {
    fn needs_signature(&self) -> bool {
        false
    }
    fn votes(&self) -> u128 {
        self.signer_bitmap.load_le()
    }
    fn vsize(&self) -> u64 {
        self.as_tx_output().weight().to_vbytes_ceil()
    }
}

/// A reference to either a deposit or withdraw request
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestRef<'a> {
    /// A reference to a deposit request
    Deposit(&'a DepositRequest),
    /// A reference to a withdrawal request
    Withdrawal(&'a WithdrawalRequest),
}

impl<'a> RequestRef<'a> {
    /// Extract the inner withdraw request if any
    pub fn as_withdrawal(&self) -> Option<&'a WithdrawalRequest> {
        match self {
            RequestRef::Withdrawal(req) => Some(req),
            _ => None,
        }
    }

    /// Extract the inner deposit request if any
    pub fn as_deposit(&self) -> Option<&'a DepositRequest> {
        match self {
            RequestRef::Deposit(req) => Some(req),
            _ => None,
        }
    }

    /// Extract the signer bitmap for the underlying request.
    pub fn signer_bitmap(&self) -> BitArray<[u8; 16]> {
        match self {
            RequestRef::Deposit(req) => req.signer_bitmap,
            RequestRef::Withdrawal(req) => req.signer_bitmap,
        }
    }
}

impl<'a> Weighted for RequestRef<'a> {
    fn needs_signature(&self) -> bool {
        match self {
            Self::Deposit(req) => req.needs_signature(),
            Self::Withdrawal(req) => req.needs_signature(),
        }
    }
    fn votes(&self) -> u128 {
        match self {
            Self::Deposit(req) => req.votes(),
            Self::Withdrawal(req) => req.votes(),
        }
    }
    fn vsize(&self) -> u64 {
        match self {
            Self::Deposit(req) => req.vsize(),
            Self::Withdrawal(req) => req.vsize(),
        }
    }
}

/// A struct for constructing transaction inputs and outputs from deposit
/// and withdrawal requests.
#[derive(Debug)]
pub struct Requests<'a> {
    /// A sorted list of requests.
    request_refs: Vec<RequestRef<'a>>,
}

impl<'a> std::ops::Deref for Requests<'a> {
    type Target = Vec<RequestRef<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.request_refs
    }
}

impl<'a> Requests<'a> {
    /// Create a new one
    pub fn new(mut request_refs: Vec<RequestRef<'a>>) -> Self {
        // We sort them so that we are guaranteed to create the same
        // bitcoin transaction with the same input requests.
        request_refs.sort();
        Self { request_refs }
    }

    /// Return an iterator for the transaction inputs for the deposit
    /// requests. These transaction inputs include a dummy signature so
    /// that the transaction inputs have the correct weight.
    pub fn tx_ins(&'a self) -> impl Iterator<Item = TxIn> + 'a {
        self.request_refs
            .iter()
            .filter_map(|req| Some(req.as_deposit()?.as_tx_input(*DUMMY_SIGNATURE)))
    }

    /// Return an iterator for the transaction outputs for the withdrawal
    /// requests.
    pub fn tx_outs(&'a self) -> impl Iterator<Item = TxOut> + 'a {
        self.request_refs
            .iter()
            .filter_map(|req| Some(req.as_withdrawal()?.as_tx_output()))
    }
}

/// An object for using UTXOs associated with the signers' peg wallet.
///
/// This object is useful for transforming the UTXO into valid input and
/// output in another transaction. Some notes:
///
/// * This struct assumes that the spend script for each signer UTXO uses
///   taproot. This is necessary because the signers collectively generate
///   Schnorr signatures, which requires taproot.
/// * The taproot script for each signer UTXO is a key-spend only script.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SignerUtxo {
    /// The outpoint of the signers' UTXO
    pub outpoint: OutPoint,
    /// The amount associated with the above UTXO
    pub amount: u64,
    /// The public key used to create the key-spend only taproot script.
    pub public_key: XOnlyPublicKey,
}

impl SignerUtxo {
    /// Create a TxIn object for the signers' UTXO
    ///
    /// The signers' UTXO is always a key-spend only taproot UTXO, so a
    /// valid signature is all that is needed to spend it.
    fn as_tx_input(&self, signature: &Signature) -> TxIn {
        TxIn {
            previous_output: self.outpoint,
            sequence: Sequence::ZERO,
            witness: Witness::p2tr_key_spend(signature),
            script_sig: ScriptBuf::new(),
        }
    }

    /// Construct the UTXO associated with this outpoint.
    fn as_tx_output(&self) -> TxOut {
        Self::new_tx_output(self.public_key, self.amount)
    }

    /// Construct the new signers' UTXO
    ///
    /// The signers' UTXO is always a key-spend only taproot UTXO.
    fn new_tx_output(public_key: XOnlyPublicKey, sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: public_key.signers_script_pubkey(),
        }
    }
}

/// Given a set of requests, create a BTC transaction that can be signed.
///
/// This BTC transaction in this struct has correct amounts but no witness
/// data for its UTXO inputs.
///
/// The Bitcoin transaction has the following layout:
/// 1. The signer input UTXO is the first input.
/// 2. All other inputs are deposit inputs.
/// 3. The signer output UTXO is the first output.
/// 4. The second output is the OP_RETURN data output.
/// 5. All other outputs are withdrawal outputs.
#[derive(Debug)]
pub struct UnsignedTransaction<'a> {
    /// The requests used to construct the transaction.
    pub requests: Requests<'a>,
    /// The BTC transaction that needs to be signed.
    pub tx: Transaction,
    /// The public key used for the public key of the signers' UTXO output.
    pub signer_public_key: XOnlyPublicKey,
    /// The signers' UTXO used as inputs to this transaction.
    pub signer_utxo: SignerBtcState,
    /// The total amount of fees associated with the transaction.
    pub tx_fee: u64,
    /// The total virtual size of the transaction.
    pub tx_vsize: u32,
}

/// A struct containing Taproot-tagged hashes used for computing taproot
/// signature hashes.
#[derive(Debug)]
pub struct SignatureHashes<'a> {
    /// The ID of the transaction that these sighashes are associated with.
    pub txid: Txid,
    /// The outpoint associated with the signers' [`TapSighash`].
    pub signer_outpoint: OutPoint,
    /// The sighash of the signers' input UTXO for the transaction.
    pub signers: TapSighash,
    /// The aggregate key associated with the signers' UTXO that is being
    /// spent in the transaction.
    pub signers_aggregate_key: XOnlyPublicKey,
    /// Each deposit request is associated with a UTXO input for the peg-in
    /// transaction. This field contains digests/signature hashes that need
    /// Schnorr signatures and the associated deposit request for each hash.
    pub deposits: Vec<(&'a DepositRequest, TapSighash)>,
}

/// A signature hash of a transaction with the associated outpoint.
#[derive(Debug, Copy, Clone)]
pub struct SignatureHash {
    /// The ID of the transaction that these sighashes are associated with.
    pub txid: Txid,
    /// The outpoint associated with the signers' [`TapSighash`].
    pub outpoint: OutPoint,
    /// The sighash of the signers' input UTXO for the transaction.
    pub sighash: TapSighash,
    /// The type of prevout that we are referring to.
    pub prevout_type: TxPrevoutType,
    /// The aggregate key that is locking the output associated with this
    /// signature hash.
    pub aggregate_key: XOnlyPublicKey,
}

impl<'a> SignatureHashes<'a> {
    /// Get deposit sighashes
    pub fn deposit_sighashes(mut self) -> Vec<SignatureHash> {
        self.deposits.sort_by_key(|(x, _)| x.outpoint);
        self.deposits
            .into_iter()
            .map(|(deposit, sighash)| SignatureHash {
                txid: self.txid,
                outpoint: deposit.outpoint,
                sighash,
                prevout_type: TxPrevoutType::Deposit,
                aggregate_key: deposit.signers_public_key,
            })
            .collect()
    }

    /// Get the signers' sighash
    pub fn signer_sighash(&self) -> SignatureHash {
        SignatureHash {
            txid: self.txid,
            outpoint: self.signer_outpoint,
            sighash: self.signers,
            prevout_type: TxPrevoutType::SignersInput,
            aggregate_key: self.signers_aggregate_key,
        }
    }
}

impl<'a> UnsignedTransaction<'a> {
    /// Construct an unsigned transaction.
    ///
    /// This function can fail if the output amounts are greater than the
    /// input amounts or if the [`Requests`] object is empty.
    ///
    /// The returned BTC transaction has the following properties:
    ///   1. The amounts for each output has taken fees into consideration.
    ///   2. The signer input UTXO is the first input.
    ///   3. The signer output UTXO is the first output. The second output
    ///      is the OP_RETURN data output.
    ///   4. Each input needs a signature in the witness data.
    ///   5. There is no witness data for deposit UTXOs.
    pub fn new(requests: Requests<'a>, state: &SignerBtcState) -> Result<Self, Error> {
        // Construct a transaction. This transaction's inputs have witness
        // data with dummy signatures so that our virtual size estimates
        // are accurate. Afterward we remove the witness data.
        let mut unsigned = Self::new_stub(requests, state)?;
        // Now we can reset the witness data, since this is an unsigned
        // transaction.
        unsigned.reset_witness_data();

        Ok(unsigned)
    }

    /// Construct a transaction with stub witness data.
    ///
    /// This function can fail if the output amounts are greater than the
    /// input amounts or if the [`Requests`] object is empty.
    ///
    /// The returned BTC transaction has the following properties:
    ///   1. The amounts for each output has taken fees into consideration.
    ///   2. The signer input UTXO is the first input.
    ///   3. The signer output UTXO is the first output. The second output
    ///      is the OP_RETURN data output.
    ///   4. Each input has a fake signature in the witness data.
    ///   5. All witness data is correctly set, except for the fake
    ///      signatures from (4).
    pub fn new_stub(requests: Requests<'a>, state: &SignerBtcState) -> Result<Self, Error> {
        if requests.is_empty() {
            return Err(Error::BitcoinNoRequests);
        }
        // Construct a transaction base. This transaction's inputs have
        // witness data with dummy signatures so that our virtual size
        // estimates are accurate. Later we will update the fees.
        let mut tx = Self::new_transaction(&requests, state)?;
        // We now compute the total fees for the transaction.
        let tx_vsize: u32 = tx.vsize().try_into().map_err(|_| Error::TypeConversion)?;

        let tx_fee = compute_transaction_fee(tx_vsize as f64, state.fee_rate, state.last_fees);
        // Now adjust the amount for the signers UTXO for the transaction
        // fee.
        Self::adjust_amounts(&mut tx, tx_fee);

        Ok(Self {
            tx,
            requests,
            signer_public_key: state.public_key,
            signer_utxo: *state,
            tx_fee,
            tx_vsize,
        })
    }

    /// Constructs the set of digests that need to be signed before broadcasting
    /// the transaction.
    ///
    /// # Notes
    ///
    /// This function uses the fact certain invariants about this struct are
    /// upheld. They are
    /// 1. The first input to the Transaction in the `tx` field is the signers'
    ///    UTXO.
    /// 2. The other inputs to the Transaction in the `tx` field are ordered
    ///    the same order as DepositRequests in the `requests` field.
    ///
    /// Other noteworthy assumptions is that the signers' UTXO is always a
    /// key-spend path only taproot UTXO.
    pub fn construct_digests(&self) -> Result<SignatureHashes, Error> {
        let deposit_requests = self.requests.iter().filter_map(RequestRef::as_deposit);
        let deposit_utxos = deposit_requests.clone().map(DepositRequest::as_tx_out);
        // All the transaction's inputs are used to construct the sighash
        // That is eventually signed
        let input_utxos: Vec<TxOut> = std::iter::once(self.signer_utxo.utxo.as_tx_output())
            .chain(deposit_utxos)
            .collect();

        let prevouts = Prevouts::All(input_utxos.as_slice());
        let sighash_type = TapSighashType::All;
        let mut sighasher = SighashCache::new(&self.tx);
        // The signers' UTXO is always the first input in the transaction.
        // Moreover, the signers can only spend this UTXO using the taproot
        // key-spend path of UTXO.
        let signer_sighash =
            sighasher.taproot_key_spend_signature_hash(0, &prevouts, sighash_type)?;
        // Each deposit UTXO is spendable by using the script path spend
        // of the taproot address. These UTXO inputs are after the sole
        // signer UTXO input.
        let deposit_sighashes = deposit_requests
            .enumerate()
            .map(|(input_index, deposit)| {
                let index = input_index + 1;
                let script = deposit.deposit_script.as_script();
                let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);

                sighasher
                    .taproot_script_spend_signature_hash(index, &prevouts, leaf_hash, sighash_type)
                    .map(|sighash| (deposit, sighash))
                    .map_err(Error::from)
            })
            .collect::<Result<_, _>>()?;

        // Combine them all together to get an ordered list of taproot
        // signature hashes.
        Ok(SignatureHashes {
            txid: self.tx.compute_txid(),
            signer_outpoint: self.signer_utxo.utxo.outpoint,
            signers_aggregate_key: self.signer_utxo.utxo.public_key,
            signers: signer_sighash,
            deposits: deposit_sighashes,
        })
    }

    /// Compute the sum of the input amounts of the transaction
    pub fn input_amounts(&self) -> u64 {
        self.requests
            .iter()
            .filter_map(RequestRef::as_deposit)
            .map(|dep| dep.amount)
            .chain([self.signer_utxo.utxo.amount])
            .sum()
    }

    /// Compute the sum of the output amounts of the transaction.
    pub fn output_amounts(&self) -> u64 {
        self.tx.output.iter().map(|out| out.value.to_sat()).sum()
    }

    /// Construct a "stub" BTC transaction from the given requests.
    ///
    /// The returned BTC transaction is signed with dummy signatures, so it
    /// has the same virtual size as a proper transaction. Note that the
    /// output amounts haven't been adjusted for fees.
    ///
    /// An Err is returned if the amounts withdrawn is greater than the sum
    /// of all the input amounts.
    fn new_transaction(reqs: &Requests, state: &SignerBtcState) -> Result<Transaction, Error> {
        let signature = *DUMMY_SIGNATURE;

        let signer_input = state.utxo.as_tx_input(&signature);
        let signer_output_sats = Self::compute_signer_amount(reqs, state)?;
        let signer_output = SignerUtxo::new_tx_output(state.public_key, signer_output_sats);

        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: std::iter::once(signer_input).chain(reqs.tx_ins()).collect(),
            output: std::iter::once(signer_output)
                .chain(Self::new_op_return_output(reqs, state))
                .chain(reqs.tx_outs())
                .collect(),
        })
    }

    /// Create the new SignerUtxo for this transaction.
    pub fn new_signer_utxo(&self) -> SignerUtxo {
        SignerUtxo {
            outpoint: OutPoint {
                txid: self.tx.compute_txid(),
                vout: 0,
            },
            amount: self.tx.output[0].value.to_sat(),
            public_key: self.signer_public_key,
        }
    }

    /// An OP_RETURN output with the bitmap for how the signers voted for
    /// the package.
    ///
    /// None is only returned if there are no requests in the input slice.
    ///
    /// The data layout for the OP_RETURN depends on whether there are
    /// withdrawal requests in the input slice. If there are withdrawal
    /// requests then the output data is:
    ///
    /// ```text
    ///  0       2    3     5        21            41
    ///  |-------|----|-----|--------|-------------|
    ///    magic   op   N_d   bitmap   merkle root
    /// ```
    ///
    /// A more full description of the merkle root can be found in the
    /// comments for [`UnsignedTransaction::withdrawal_merkle_root`]. If
    /// there are no withdrawal requests in the input slice then the layout
    /// looks like:
    ///
    /// ```text
    ///  0       2    3     5        21
    ///  |-------|----|-----|--------|
    ///    magic   op   N_d   bitmap
    /// ```
    ///
    /// In the above layout, magic is the UTF-8 encoded string "ST", op is
    /// the version byte, and N_d is the of deposits in this transaction
    /// encoded as a big-endian two byte unsigned integer.
    ///
    /// `None` is only returned if there are no requests in the input slice.
    fn new_op_return_output(reqs: &Requests, state: &SignerBtcState) -> Option<TxOut> {
        let sbtc_data = Self::sbtc_data(reqs, state)?;
        let script_pubkey = match Self::withdrawal_merkle_root(reqs) {
            Some(merkle_root) => {
                let mut data: [u8; 41] = [0; 41];
                data[..21].copy_from_slice(&sbtc_data);
                data[21..].copy_from_slice(&merkle_root);

                ScriptBuf::new_op_return(data)
            }
            None => ScriptBuf::new_op_return(sbtc_data),
        };

        let value = Amount::ZERO;
        Some(TxOut { value, script_pubkey })
    }

    /// Return the first part of the sbtc related data included in the
    /// OP_RETURN output.
    ///
    /// BTC sweep transactions include an OP_RETURN output with data on how
    /// the signers voted for the transaction. This function returns that
    /// data, which is laid out as follows:
    ///
    /// ```text
    ///  0       2    3     5                21
    ///  |-------|----|-----|----------------|
    ///    magic   op   N_d   signer  bitmap
    /// ```
    ///
    /// In the above layout, magic is the UTF-8 encoded string "ST", op is
    /// the version byte, and N_d is the of deposits in this transaction
    /// encoded as a big-endian two byte unsigned integer.
    ///
    /// `None` is only returned if there are no requests in the input
    /// slice.
    fn sbtc_data(reqs: &Requests, state: &SignerBtcState) -> Option<[u8; 21]> {
        let bitmap: BitArray<[u8; 16]> = reqs
            .iter()
            .map(RequestRef::signer_bitmap)
            .reduce(|bm1, bm2| bm1 | bm2)?;
        let num_deposits = reqs.iter().filter_map(RequestRef::as_deposit).count() as u16;

        let mut data: [u8; 21] = [0; 21];
        // The magic_bytes is exactly 2 bytes
        data[0..2].copy_from_slice(&state.magic_bytes);
        // Yeah, this is one byte.
        data[2..3].copy_from_slice(&[OP_RETURN_VERSION]);
        // The num_deposits variable is an u16, so 2 bytes.
        data[3..5].copy_from_slice(&num_deposits.to_be_bytes());
        // The bitmap is 16 bytes so this fits exactly.
        data[5..].copy_from_slice(&bitmap.into_inner());

        Some(data)
    }

    /// The OP_RETURN output includes a merkle tree of the Stacks
    /// transactions that lead to the inclusion of the UTXOs in this
    /// transaction.
    ///
    /// Create the OP_RETURN UTXO for the associated withdrawal request.
    ///
    /// The data returned from this function is a merkle tree constructed
    /// from the HASH160 of each withdrawal request's sBTC data returned by
    /// the [`WithdrawalRequest::sbtc_data`].
    ///
    /// For more on the rationale for this output, see this ticket:
    /// <https://github.com/stacks-network/sbtc/issues/483>.
    ///
    /// `None` is returned if there are no withdrawal requests in the input
    /// slice.
    fn withdrawal_merkle_root(reqs: &Requests) -> Option<[u8; 20]> {
        let hashes = reqs
            .iter()
            .filter_map(RequestRef::as_withdrawal)
            .map(|req| Hash160::hash(&req.sbtc_data()));

        bitcoin::merkle_tree::calculate_root(hashes).map(|hash| hash.to_byte_array())
    }

    /// Compute the final amount for the signers' UTXO given the current
    /// UTXO amount and the incoming requests.
    ///
    /// This amount does not take into account fees.
    fn compute_signer_amount(reqs: &Requests, state: &SignerBtcState) -> Result<u64, Error> {
        let amount = reqs
            .iter()
            .fold(state.utxo.amount as i64, |amount, req| match req {
                RequestRef::Deposit(req) => amount + req.amount as i64,
                RequestRef::Withdrawal(req) => amount - req.amount as i64,
            });

        // This should never happen
        if amount < 0 {
            tracing::error!("Transaction deposits greater than the inputs!");
            return Err(Error::InvalidAmount(amount));
        }

        Ok(amount as u64)
    }

    /// Adjust the amounts for each output given the transaction fee.
    ///
    /// The bitcoin mining fees are ultimately paid for by the users during
    /// deposit and withdrawal sweep transactions. These fees are captured
    /// on the sBTC side of things:
    /// * for deposits the minted amount is the deposited amount less any
    ///   fees.
    /// * for withdrawals the user locks the amount spent to the desired
    ///   recipient on plus their max fee.
    ///
    /// Since mining fees come out of the new UTXOs, that means the signers
    /// UTXO appears to pay the fee on chain. Thus, to adjust the output
    /// amounts, for fees we only need to change the amount associated with
    /// the signers' UTXO.
    fn adjust_amounts(tx: &mut Transaction, tx_fee: u64) {
        // The first output is the signer's UTXO and this UTXO pays for all
        // on-chain fees.
        if let Some(utxo_out) = tx.output.first_mut() {
            let signers_amount = utxo_out.value.to_sat().saturating_sub(tx_fee);
            utxo_out.value = Amount::from_sat(signers_amount);
        }
    }

    /// We originally populated the witness with dummy data to get an
    /// accurate estimate of the "virtual size" of the transaction. This
    /// function resets the witness data to be empty.
    pub fn reset_witness_data(&mut self) {
        self.tx
            .input
            .iter_mut()
            .for_each(|tx_in| tx_in.witness = Witness::new());
    }
}

/// A trait where we return all inputs and outputs for a bitcoin
/// transaction.
pub trait BitcoinInputsOutputs {
    /// Return a reference to the transaction
    fn tx_ref(&self) -> &Transaction;

    /// Returns all transaction inputs as a slice.
    fn inputs(&self) -> &[TxIn] {
        &self.tx_ref().input
    }

    /// Returns all transaction outputs as a slice.
    fn outputs(&self) -> &[TxOut] {
        &self.tx_ref().output
    }
}

/// A trait for figuring out the fees assessed to deposit prevouts and
/// withdrawal outputs in a bitcoin transaction.
///
/// This trait and the default implementations includes functions for
/// apportioning fees to a bitcoin transaction that has already been
/// confirmed. This implementation is located in this module because the
/// assumptions it makes for how the transaction is organized follows the
/// logic in [`UnsignedTransaction::new`].
pub trait FeeAssessment: BitcoinInputsOutputs {
    /// Assess how much of the bitcoin miner fee should be apportioned to
    /// the input associated with the given `outpoint`.
    ///
    /// # Notes
    ///
    /// Each input and output is assessed a fee that is proportional to
    /// their weight amount all the requests serviced by this transaction.
    ///
    /// This function assumes that this transaction is an sBTC transaction,
    /// which implies that the first input and the first two outputs are
    /// always the signers'. So `None` is returned if there is no input,
    /// after the first input, with the given `outpoint`.
    ///
    /// The logic for the fee assessment is from
    /// <https://github.com/stacks-network/sbtc/issues/182>.
    fn assess_input_fee(&self, outpoint: &OutPoint, tx_fee: Amount) -> Option<Amount> {
        // The Weight::to_wu function just returns the inner weight units
        // as an u64, so this is really just the weight.
        let request_weight = self.request_weight().to_wu();
        // We skip the first input because that is always the signers'
        // input UTXO.
        let input_weight = self
            .inputs()
            .iter()
            .skip(1)
            .find(|tx_in| &tx_in.previous_output == outpoint)?
            .segwit_weight()
            .to_wu();

        // This computation follows the logic laid out in
        // <https://github.com/stacks-network/sbtc/issues/182>.
        let fee_sats = (input_weight * tx_fee.to_sat()).div_ceil(request_weight);
        Some(Amount::from_sat(fee_sats))
    }

    /// Assess how much of the bitcoin miner fee should be apportioned to
    /// the output at the given output index `vout`.
    ///
    /// # Notes
    ///
    /// Each input and output is assessed a fee that is proportional to
    /// their weight amount all the requests serviced by this transaction.
    ///
    /// This function assumes that this transaction is an sBTC transaction,
    /// which implies that the first input and the first two outputs are
    /// always the signers'. So `None` is returned if the given `vout` is 0
    /// or 1 or if there is no output in the transaction at `vout`.
    ///
    /// The logic for the fee assessment is from
    /// <https://github.com/stacks-network/sbtc/issues/182>.
    fn assess_output_fee(&self, vout: usize, tx_fee: Amount) -> Option<Amount> {
        // We skip the first input because that is always the signers'
        // input UTXO.
        if vout < 2 {
            return None;
        }
        let request_weight = self.request_weight().to_wu();
        let output_weight = self.outputs().get(vout)?.weight().to_wu();

        // This computation follows the logic laid out in
        // <https://github.com/stacks-network/sbtc/issues/182>.
        let fee_sats = (output_weight * tx_fee.to_sat()).div_ceil(request_weight);
        Some(Amount::from_sat(fee_sats))
    }

    /// Computes the total weight of the inputs and the outputs, excluding
    /// the ones related to the signers.
    fn request_weight(&self) -> Weight {
        // We skip the first input and first two outputs because those are
        // always the signers' UTXO input and outputs.
        self.inputs()
            .iter()
            .skip(1)
            .map(|x| x.segwit_weight())
            .chain(self.outputs().iter().skip(2).map(TxOut::weight))
            .sum()
    }
}

impl<T: BitcoinInputsOutputs> FeeAssessment for T {}

impl BitcoinInputsOutputs for Transaction {
    fn tx_ref(&self) -> &Transaction {
        self
    }
}

impl<'a> BitcoinInputsOutputs for UnsignedTransaction<'a> {
    fn tx_ref(&self) -> &Transaction {
        &self.tx
    }
}

impl BitcoinInputsOutputs for BitcoinTx {
    fn tx_ref(&self) -> &Transaction {
        self.deref()
    }
}

impl BitcoinInputsOutputs for BitcoinTxInfo {
    fn tx_ref(&self) -> &Transaction {
        &self.tx
    }
}

impl BitcoinTxInfo {
    /// Assess how much of the bitcoin miner fee should be apportioned to
    /// the input associated with the given `outpoint`.
    pub fn assess_input_fee(&self, outpoint: &OutPoint) -> Option<Amount> {
        FeeAssessment::assess_input_fee(self, outpoint, self.fee)
    }
    /// Assess how much of the bitcoin miner fee should be apportioned to
    /// the output at the given output index `vout`.
    pub fn assess_output_fee(&self, vout: usize) -> Option<Amount> {
        FeeAssessment::assess_output_fee(self, vout, self.fee)
    }
}

/// An output used as an input into a transaction, a previous output.
#[derive(Copy, Clone, Debug)]
pub struct PrevoutRef<'a> {
    /// The amount locked but the output
    pub amount: Amount,
    /// The `scriptPubKey` locking the output
    pub script_pubkey: &'a ScriptBuf,
    /// The ID of the transaction that created the output.
    pub txid: &'a Txid,
    /// The index of the output in the transactions outputs.
    pub output_index: u32,
}

/// A trait for deconstructing a bitcoin transaction related to the signers
/// into its inputs and outputs.
pub trait TxDeconstructor: BitcoinInputsOutputs {
    /// Returns a prevout given the input index.
    ///
    /// This function must return `Some(_)` for each `index` where
    /// `self.inputs().get(index)` returns `Some(_)`, and must be `None`
    /// otherwise.
    fn prevout(&self, index: usize) -> Option<PrevoutRef>;

    /// Return all inputs in this transaction if it is an sBTC transaction.
    ///
    /// This function returns an empty vector if it was not generated by
    /// the signers, where the signers are identified by their
    /// `signer_script_pubkeys`.
    fn to_inputs(&self, signer_script_pubkeys: &HashSet<ScriptBuf>) -> Vec<TxPrevout> {
        // If someone else created this transaction then we are not a party
        // to any of the inputs, so we can exit early.
        if !self.is_signer_created(signer_script_pubkeys) {
            return Vec::new();
        };

        // This is a transaction that the signers have created. It follows
        // a layout described in the description of `UnsignedTransaction`.
        self.inputs()
            .iter()
            .enumerate()
            .filter_map(|(index, _)| match index {
                0 => self.vin_to_prevout(index, TxPrevoutType::SignersInput),
                _ => self.vin_to_prevout(index, TxPrevoutType::Deposit),
            })
            .collect()
    }

    /// Return all outputs in this transaction that are related to the
    /// signers.
    ///
    /// This function returns all outputs if the transaction is an
    /// sBTC transaction, and only outputs that the signers can sign for
    /// otherwise.
    fn to_outputs(&self, signer_script_pubkeys: &HashSet<ScriptBuf>) -> Vec<TxOutput> {
        // This transaction might not be related to the signers at all. If
        // not then we can exit early.
        let mut outputs = self.outputs().iter();
        if !outputs.any(|tx_out| signer_script_pubkeys.contains(&tx_out.script_pubkey)) {
            return Vec::new();
        }

        // If the signers did not create this transaction, but the signers
        // control at least one output then the outputs that the signers
        // control are donations. So we scan the outputs and exit early.
        //
        // Note that these cannot be deposits because deposits aren't
        // key-path spendable by the signers.
        if !self.is_signer_created(signer_script_pubkeys) {
            return self
                .outputs()
                .iter()
                .enumerate()
                .filter(|(_, tx_out)| signer_script_pubkeys.contains(&tx_out.script_pubkey))
                .filter_map(|(index, _)| self.vout_to_output(index, TxOutputType::Donation))
                .collect();
        }

        self.outputs()
            .iter()
            .enumerate()
            .filter_map(|(index, _)| match index {
                0 => self.vout_to_output(index, TxOutputType::SignersOutput),
                1 => self.vout_to_output(index, TxOutputType::SignersOpReturn),
                _ => self.vout_to_output(index, TxOutputType::Withdrawal),
            })
            .collect()
    }

    /// Take an output index and the known output type and return the
    /// output.
    fn vout_to_output(&self, index: usize, output_type: TxOutputType) -> Option<TxOutput> {
        let tx_out = self.outputs().get(index)?;
        Some(TxOutput {
            txid: self.tx_ref().compute_txid().into(),
            output_index: index as u32,
            script_pubkey: tx_out.script_pubkey.clone().into(),
            amount: tx_out.value.to_sat(),
            output_type,
        })
    }

    /// Take an input index and the known output type and return a prevout.
    fn vin_to_prevout(&self, index: usize, input_type: TxPrevoutType) -> Option<TxPrevout> {
        let prevout = self.prevout(index)?;
        Some(TxPrevout {
            txid: self.tx_ref().compute_txid().into(),
            prevout_txid: BitcoinTxId::from(*prevout.txid),
            prevout_output_index: prevout.output_index,
            script_pubkey: prevout.script_pubkey.clone().into(),
            amount: prevout.amount.to_sat(),
            prevout_type: input_type,
        })
    }

    /// Whether this transaction was created by the signers given the
    /// possible scriptPubKeys.
    ///
    /// If the first input in the transaction is one that the signers
    /// control then we know that the signers created this transaction.
    fn is_signer_created(&self, signer_script_pubkeys: &HashSet<ScriptBuf>) -> bool {
        let Some(signer_input) = self.prevout(0) else {
            return false;
        };

        signer_script_pubkeys.contains(signer_input.script_pubkey)
    }
}

impl TxDeconstructor for BitcoinTxInfo {
    fn prevout(&self, index: usize) -> Option<PrevoutRef> {
        let vin = self.vin.get(index)?;
        Some(PrevoutRef {
            amount: vin.prevout.value,
            script_pubkey: &vin.prevout.script_pub_key.script,
            txid: vin.details.txid.as_ref()?,
            output_index: vin.details.vout?,
        })
    }
}

bitcoin::hashes::hash_newtype! {
    /// For some reason, the rust-bitcoin folks do not implement both
    /// [`bitcoin::consensus::Encodable`] and [`bitcoin::hashes::Hash`] for
    /// their [`bitcoin::hashes::hash160::Hash`] type. So we create a
    /// newtype that implements both of those traits so that we can use
    /// [`bitcoin::merkle_tree::calculate_root`].
    struct Hash160(pub bitcoin::hashes::hash160::Hash);
}

impl bitcoin::consensus::Encodable for Hash160 {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        use bitcoin::consensus::WriteExt as _;
        // All types that implement bitcoin::io::Write implement the
        // extension type. And this implementation follows the
        // implementation of their other types.
        writer.emit_slice(&self.0[..])?;
        Ok(Self::LEN)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::str::FromStr;

    use super::*;
    use bitcoin::BlockHash;
    use bitcoin::CompressedPublicKey;
    use bitcoin::Txid;
    use clarity::vm::types::PrincipalData;
    use fake::Fake as _;
    use model::SignerVote;
    use rand::distributions::Distribution;
    use rand::distributions::Uniform;
    use rand::rngs::OsRng;
    use rand::Rng;
    use rand::SeedableRng as _;
    use ripemd::Ripemd160;
    use sbtc::deposits::DepositScriptInputs;
    use secp256k1::Keypair;
    use secp256k1::SecretKey;
    use sha2::Digest as _;
    use sha2::Sha256;
    use stacks_common::types::chainstate::StacksAddress;
    use test_case::test_case;

    use crate::testing;
    use crate::testing::btc::base_signer_transaction;
    use crate::DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX;
    use crate::MAX_MEMPOOL_PACKAGE_TX_COUNT;

    /// The maximum virtual size of a transaction package in v-bytes.
    const MEMPOOL_MAX_PACKAGE_SIZE: u32 = 101000;

    const X_ONLY_PUBLIC_KEY1: &'static str =
        "2e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";

    fn generate_x_only_public_key() -> XOnlyPublicKey {
        let secret_key = SecretKey::new(&mut OsRng);
        secret_key.x_only_public_key(SECP256K1).0
    }

    fn generate_address() -> ScriptPubKey {
        let secret_key = SecretKey::new(&mut OsRng);
        let pk = CompressedPublicKey(secret_key.public_key(SECP256K1));

        ScriptBuf::new_p2wpkh(&pk.wpubkey_hash()).into()
    }

    fn generate_outpoint(amount: u64, vout: u32) -> OutPoint {
        let sats: u64 = Uniform::new(1, 500_000_000).sample(&mut OsRng);

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: vec![
                TxOut {
                    value: Amount::from_sat(sats),
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: ScriptBuf::new(),
                },
            ],
        };

        OutPoint { txid: tx.compute_txid(), vout }
    }

    fn create_limits_for_deposits_and_max_mintable(
        per_deposit_minimum: u64,
        per_deposit_cap: u64,
        max_mintable_cap: u64,
    ) -> SbtcLimits {
        SbtcLimits::new(
            None,
            Some(Amount::from_sat(per_deposit_minimum)),
            Some(Amount::from_sat(per_deposit_cap)),
            None,
            Some(Amount::from_sat(max_mintable_cap)),
        )
    }

    /// Create a new deposit request depositing from a random public key.
    fn create_deposit(amount: u64, max_fee: u64, signer_bitmap: u128) -> DepositRequest {
        let signers_public_key = generate_x_only_public_key();

        let contract_name = std::iter::repeat('a').take(128).collect::<String>();
        let principal_str = format!("{}.{contract_name}", StacksAddress::burn_address(false));

        let deposit_inputs = DepositScriptInputs {
            signers_public_key,
            max_fee: 10000,
            recipient: PrincipalData::parse(&principal_str).unwrap(),
        };

        DepositRequest {
            outpoint: generate_outpoint(amount, 1),
            max_fee,
            signer_bitmap: BitArray::new(signer_bitmap.to_le_bytes()),
            amount,
            deposit_script: deposit_inputs.deposit_script(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key,
        }
    }

    /// Create a new withdrawal request withdrawing to a random address.
    fn create_withdrawal(amount: u64, max_fee: u64, signer_bitmap: u128) -> WithdrawalRequest {
        WithdrawalRequest {
            max_fee,
            signer_bitmap: BitArray::new(signer_bitmap.to_le_bytes()),
            amount,
            script_pubkey: generate_address(),
            txid: fake::Faker.fake_with_rng(&mut OsRng),
            request_id: (0..u32::MAX as u64).fake_with_rng(&mut OsRng),
            block_hash: fake::Faker.fake_with_rng(&mut OsRng),
        }
    }

    fn random_withdrawal<R: Rng>(rng: &mut R, votes_against: usize) -> WithdrawalRequest {
        let mut signer_bitmap: BitArray<[u8; 16]> = BitArray::ZERO;
        signer_bitmap[..votes_against].fill(true);

        WithdrawalRequest {
            max_fee: rng.next_u32() as u64,
            signer_bitmap,
            amount: rng.next_u32() as u64,
            script_pubkey: generate_address(),
            txid: fake::Faker.fake_with_rng(rng),
            request_id: (0..u32::MAX as u64).fake_with_rng(rng),
            block_hash: fake::Faker.fake_with_rng(rng),
        }
    }

    /// This is a naive implementation of a function that computes a merkle root
    fn calculate_merkle_root(reqs: &mut [WithdrawalRequest]) -> Option<[u8; 20]> {
        // The withdrawals' are sorted before inclusion as a bitcoin
        // transaction output.
        reqs.sort();
        let mut leafs = reqs
            .iter()
            .map(|req| {
                // We use the Hash160 for the hash function, which is
                // SHA256 followed by RIPEMD160.
                let sha256_data = Sha256::digest(req.sbtc_data());
                let rip160_data = Ripemd160::digest(sha256_data);
                rip160_data.as_slice().try_into().unwrap()
            })
            .collect::<Vec<[u8; 20]>>();

        while leafs.len() > 1 {
            leafs = leafs
                .chunks(2)
                .map(|nodes| {
                    let [leaf1, leaf2] = match nodes {
                        [leaf1, leaf2] => [leaf1, leaf2],
                        // If a leaf node does not have a partner, it gets paired with itself.
                        [leaf] => [leaf, leaf],
                        // Yeah chunks(2) return slices of size 1 or 2 here.
                        _ => unreachable!(),
                    };
                    // Compute the hash160 of the two leafs
                    let sha256_data = Sha256::default()
                        .chain_update(leaf1)
                        .chain_update(leaf2)
                        .finalize();

                    Ripemd160::digest(sha256_data)
                        .as_slice()
                        .try_into()
                        .unwrap()
                })
                .collect();
        }

        // There are either 1 or 0 elements in the leafs vector, so lets get it
        leafs.pop()
    }

    impl BitcoinTxInfo {
        fn from_tx(tx: Transaction, fee: Amount) -> BitcoinTxInfo {
            BitcoinTxInfo {
                in_active_chain: true,
                fee,
                txid: tx.compute_txid(),
                hash: tx.compute_wtxid(),
                size: tx.base_size() as u64,
                vsize: tx.vsize() as u64,
                tx,
                vin: Vec::new(),
                vout: Vec::new(),
                block_hash: BlockHash::from_byte_array([0; 32]),
                confirmations: 1,
                block_time: 0,
            }
        }
    }

    #[ignore = "For generating the SOLO_(DEPOSIT|WITHDRAWAL)_SIZE constants"]
    #[test]
    fn create_deposit_only_tx() {
        // For solo deposits
        let mut requests = SbtcRequests {
            deposits: vec![create_deposit(123456, 30_000, 0)],
            withdrawals: Vec::new(),
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(550_000_000, 0),
                    amount: 550_000_000,
                    public_key: generate_x_only_public_key(),
                },
                fee_rate: 5.0,
                public_key: generate_x_only_public_key(),
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 2,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };
        let keypair = Keypair::new_global(&mut OsRng);

        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let mut unsigned = transactions.pop().unwrap();
        testing::set_witness_data(&mut unsigned, keypair);

        println!("Solo deposit vsize: {}", unsigned.tx.vsize());

        // For solo withdrawals
        requests.deposits = Vec::new();
        requests.withdrawals = vec![create_withdrawal(154_321, 40_000, 0)];

        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let mut unsigned = transactions.pop().unwrap();
        assert_eq!(unsigned.tx.input.len(), 1);
        assert_eq!(unsigned.tx.output.len(), 3);

        // We need to zero out the withdrawal script since this value
        // changes depending on the user.
        unsigned.tx.output.pop();
        testing::set_witness_data(&mut unsigned, keypair);

        println!("Solo withdrawal vsize: {}", unsigned.tx.vsize());
    }

    #[ignore = "this is for generating the MIN_BITCOIN_INPUT_VSIZE constant"]
    #[test]
    fn create_taproot_utxo_min_size() {
        // This generates a UTXO with the same vsize as the signers input
        // or donation. This is smaller than the min deposit vsize.
        let utxo = TxIn {
            previous_output: OutPoint::null(),
            sequence: Sequence::ZERO,
            witness: Witness::p2tr_key_spend(&DUMMY_SIGNATURE),
            script_sig: ScriptBuf::new(),
        };
        println!("Min input vsize: {}", utxo.segwit_weight().to_vbytes_ceil());
    }

    #[test_case(&[true, true, false, true, false, false, false], 3; "case 1")]
    #[test_case(&[true, true, false, false, false, false, false], 2; "case 2")]
    #[test_case(&[false, false, false, false, false, false, false], 0; "case 3")]
    fn test_deposit_votes_against(signer_bitmap: &[bool], expected: u32) {
        let mut bitmap: BitArray<[u8; 16]> = BitArray::ZERO;
        for (index, value) in signer_bitmap.iter().enumerate() {
            bitmap.set(index, *value);
        }

        let deposit = DepositRequest {
            outpoint: OutPoint::null(),
            max_fee: 0,
            signer_bitmap: bitmap,
            amount: 100_000,
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap(),
        };

        assert_eq!(deposit.votes().count_ones(), expected);
    }

    /// Some functions call functions that "could" panic. Check that they
    /// don't.
    #[test]
    fn deposit_witness_data_no_error() {
        let deposit = DepositRequest {
            outpoint: OutPoint::null(),
            max_fee: 0,
            signer_bitmap: BitArray::ZERO,
            amount: 100_000,
            deposit_script: ScriptBuf::from_bytes(vec![1, 2, 3]),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap(),
        };

        let sig = Signature::from_slice(&[0u8; 64]).unwrap();
        let witness = deposit.construct_witness_data(sig);
        assert!(witness.tapscript().is_some());

        let sig = *DUMMY_SIGNATURE;
        let tx_in = deposit.as_tx_input(sig);

        // The deposits are taproot spend and do not have a script. The
        // actual spend script and input data gets put in the witness data
        assert!(tx_in.script_sig.is_empty());
    }

    /// The first input and output are related to the signers' UTXO. The
    /// second output is a data output.
    #[test]
    fn the_first_input_and_output_is_signers_second_output_data() {
        let requests = SbtcRequests {
            deposits: vec![create_deposit(123456, 0, 0)],
            withdrawals: vec![create_withdrawal(1000, 0, 0), create_withdrawal(2000, 0, 0)],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(5500, 0),
                    amount: 5500,
                    public_key: generate_x_only_public_key(),
                },
                fee_rate: 0.0,
                public_key: generate_x_only_public_key(),
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 0,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        // This should all be in one transaction since there are no votes
        // against any of the requests.
        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let unsigned_tx = transactions.pop().unwrap();
        assert_eq!(unsigned_tx.tx.input.len(), 2);

        // Let's make sure the first input references the UTXO from the
        // signer_state variable.
        let signers_utxo_input = unsigned_tx.tx.input.first().unwrap();
        let old_outpoint = requests.signer_state.utxo.outpoint;
        assert_eq!(signers_utxo_input.previous_output.txid, old_outpoint.txid);
        assert_eq!(signers_utxo_input.previous_output.vout, old_outpoint.vout);

        // There are always two outputs whenever there are requests to
        // service, and we had two withdrawal requests so there should be 4
        // outputs.
        assert_eq!(unsigned_tx.tx.output.len(), 4);

        // The signers' UTXO, the first one, contains the balance of all
        // deposits and withdrawals. It's also a P2TR script.
        let signers_utxo_output = unsigned_tx.tx.output.first().unwrap();
        assert_eq!(
            signers_utxo_output.value.to_sat(),
            5500 + 123456 - 1000 - 2000
        );
        assert!(signers_utxo_output.script_pubkey.is_p2tr());

        // The second output is an OP_RETURN output.
        assert!(unsigned_tx.tx.output[1].script_pubkey.is_op_return());
        // All the other UTXOs are P2WPKH outputs.
        unsigned_tx.tx.output.iter().skip(2).for_each(|output| {
            assert!(output.script_pubkey.is_p2wpkh());
        });

        // The new UTXO should be using the signer public key from the
        // signer state.
        let new_utxo = unsigned_tx.new_signer_utxo();
        assert_eq!(new_utxo.public_key, requests.signer_state.public_key);
    }

    /// You cannot create sweep transactions that do not service requests.
    #[test]
    fn no_requests_no_sweep() {
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let signer_state = SignerBtcState {
            utxo: SignerUtxo {
                outpoint: OutPoint::null(),
                amount: 55,
                public_key,
            },
            fee_rate: 0.0,
            public_key,
            last_fees: None,
            magic_bytes: [0; 2],
        };

        let requests = Requests::new(Vec::new());
        let sweep = UnsignedTransaction::new(requests, &signer_state);
        assert!(sweep.is_err());
    }

    /// We aggregate the bitmaps to form a single one at the end. Check
    /// that it is aggregated correctly.
    #[test]
    fn the_bitmaps_merge_correctly() {
        const OP_RETURN: u8 = bitcoin::opcodes::all::OP_RETURN.to_u8();
        const OP_PUSHBYTES_41: u8 = bitcoin::opcodes::all::OP_PUSHBYTES_41.to_u8();

        let mut requests = SbtcRequests {
            deposits: vec![create_deposit(123456, 0, 0)],
            withdrawals: vec![create_withdrawal(1000, 0, 0), create_withdrawal(2000, 0, 0)],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(5500, 0),
                    amount: 5500,
                    public_key: generate_x_only_public_key(),
                },
                fee_rate: 0.0,
                public_key: generate_x_only_public_key(),
                last_fees: None,
                magic_bytes: [b'T', b'3'],
            },
            num_signers: 10,
            accept_threshold: 0,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        // We'll have the deposit get two vote against, and the withdrawals
        // each have three votes against. We will have each them share one
        // overlapping voter. The votes look like this:
        //
        // 1 1 0 0 0 0 0 0 0 0
        // 0 1 1 1 0 0 0 0 0 0
        // 0 1 0 0 1 1 0 0 0 0
        //
        // So the aggregated bit map should look like this
        //
        // 1 1 1 1 1 1 0 0 0 0

        // Okay, this one looks like
        // 1 1 0 0 0 0 0 0 0 0
        requests.deposits[0].signer_bitmap.set(0, true);
        requests.deposits[0].signer_bitmap.set(1, true);
        // This one looks like
        // 0 1 1 1 0 0 0 0 0 0
        requests.withdrawals[0].signer_bitmap.set(1, true);
        requests.withdrawals[0].signer_bitmap.set(2, true);
        requests.withdrawals[0].signer_bitmap.set(3, true);
        // And this one looks like
        // 0 1 0 0 1 1 0 0 0 0
        requests.withdrawals[1].signer_bitmap.set(1, true);
        requests.withdrawals[1].signer_bitmap.set(4, true);
        requests.withdrawals[1].signer_bitmap.set(5, true);

        // This should all be in one transaction given the threshold
        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let unsigned_tx = transactions.pop().unwrap();
        // We have one input for the signers' UTXO and another input for
        // the deposit.
        assert_eq!(unsigned_tx.tx.input.len(), 2);
        // We have one output for the signers' UTXO and another for the
        // OP_RETURN output, and two more for the withdrawals.
        assert_eq!(unsigned_tx.tx.output.len(), 4);

        let sbtc_data = match unsigned_tx.tx.output[1].script_pubkey.as_bytes() {
            // The data layout is detailed in the documentation for the
            // UnsignedTransaction::new_op_return_output function.
            [OP_RETURN, OP_PUSHBYTES_41, b'T', b'3', OP_RETURN_VERSION, 0, 1, data @ ..] => data,
            _ => panic!("Invalid OP_RETURN FORMAT"),
        };
        // Since there are withdrawal requests in this transaction, the
        // merkle root is included at the end of the `data`, bringing its
        // length from 16 to 36 bytes.
        assert_eq!(sbtc_data.len(), 36);
        // This is the aggregate bitmap for the votes, so it should start
        // like this:
        // 1 1 1 1 1 1 0 0 0 0
        // Note that the first 16 bytes are the bitmap, and the merkle root
        // follows this data.
        let bitmap_data = *sbtc_data.first_chunk().unwrap();
        let bitmap = BitArray::<[u8; 16]>::new(bitmap_data);

        assert_eq!(bitmap.count_ones(), 6);
        // And the first six bits are all ones followed by all zeros.
        assert!(bitmap[..6].all());
        assert!(!bitmap[6..].any());
    }

    #[test_case(Vec::new(), vec![create_deposit(123456, 0, 0)]; "no withdrawals, one deposits")]
    #[test_case([create_withdrawal(1000, 0, 0)], Vec::new(); "one withdrawals")]
    #[test_case({
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        std::iter::repeat_with(move || random_withdrawal(&mut rng, 0)).take(2)
    }, Vec::new(); "two withdrawals")]
    #[test_case({
        let mut rng = rand::rngs::StdRng::seed_from_u64(30);
        std::iter::repeat_with(move || random_withdrawal(&mut rng, 0)).take(3)
    }, Vec::new(); "three withdrawals")]
    #[test_case({
        let mut rng = rand::rngs::StdRng::seed_from_u64(300);
        std::iter::repeat_with(move || random_withdrawal(&mut rng, 0)).take(5)
    }, Vec::new(); "five withdrawals")]
    #[test_case({
        let mut rng = rand::rngs::StdRng::seed_from_u64(3000);
        std::iter::repeat_with(move || random_withdrawal(&mut rng, 0)).take(20)
    }, Vec::new(); "twenty withdrawals")]
    fn merkle_root_in_op_return<I>(withdrawals: I, deposits: Vec<DepositRequest>)
    where
        I: IntoIterator<Item = WithdrawalRequest>,
    {
        const OP_RETURN: u8 = bitcoin::opcodes::all::OP_RETURN.to_u8();
        const OP_PUSHBYTES_21: u8 = bitcoin::opcodes::all::OP_PUSHBYTES_21.to_u8();
        const OP_PUSHBYTES_41: u8 = bitcoin::opcodes::all::OP_PUSHBYTES_41.to_u8();

        let mut requests = SbtcRequests {
            deposits,
            withdrawals: withdrawals.into_iter().collect(),
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(500_000_000_000, 0),
                    amount: 500_000_000_000,
                    public_key: generate_x_only_public_key(),
                },
                fee_rate: 0.0,
                public_key: generate_x_only_public_key(),
                last_fees: None,
                magic_bytes: [b'T', b'3'],
            },
            num_signers: 10,
            accept_threshold: 0,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let unsigned_tx = transactions.pop().unwrap();
        // Okay, the let's look at the raw data in our OP_RETURN UTXO
        let sbtc_data = match unsigned_tx.tx.output[1].script_pubkey.as_bytes() {
            // The data layout is detailed in the documentation for the
            // UnsignedTransaction::new_op_return_output function when
            // there are withdrawal request UTXOs.
            [OP_RETURN, OP_PUSHBYTES_41, b'T', b'3', OP_RETURN_VERSION, 0, nd, data @ ..]
                if *nd == requests.deposits.len() as u8 =>
            {
                data
            }
            // The data layout is detailed in the documentation for the
            // UnsignedTransaction::new_op_return_output function when
            // there are no withdrawal request UTXOs.
            [OP_RETURN, OP_PUSHBYTES_21, b'T', b'3', OP_RETURN_VERSION, 0, nd, data @ ..]
                if *nd == requests.deposits.len() as u8 =>
            {
                data
            }
            data => panic!("Invalid OP_RETURN FORMAT {data:?}"),
        };
        // If there are no deposits or withdrawals then there is no bitmap
        // and no merkle root.

        // I apologize for the nested if statements :(.
        if let Some((_bitmap, actual_merkle_root)) = sbtc_data.split_first_chunk::<16>() {
            // if we have 16 bytes here then we know that we have at
            // least one deposit or withdrawal request.
            assert!(requests.deposits.is_empty() || requests.withdrawals.is_empty());

            // If we do not have any withdrawal requests then there is no
            // merkle root for the depositors to pay for.
            if requests.withdrawals.is_empty() {
                assert!(actual_merkle_root.is_empty());
            } else {
                // If we have a withdrawal then there is a merkle root, and
                // it's constructed in a standard way.
                let actual_merkle_root: [u8; 20] = actual_merkle_root.try_into().unwrap();
                let expected_merkle_root =
                    calculate_merkle_root(&mut requests.withdrawals).unwrap();

                assert_eq!(actual_merkle_root, expected_merkle_root);
            }
        } else {
            // If there isn't 16 bytes here then there is nothing. Note
            // that this isn't hit in our test cases, it's only ever hit if
            // there are no deposits and no withdrawals we do not create a
            // transaction in that case.
            assert!(sbtc_data.is_empty());
        }
    }

    /// Deposit requests add to the signers' UTXO.
    #[test]
    fn deposits_with_low_amount_and_high_max_fee() {
        // The bad deposit
        let deposit_amount = 100;
        let max_fee = 123456;

        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let requests = SbtcRequests {
            deposits: vec![
                create_deposit(deposit_amount, max_fee, 0),
                create_deposit(345678, 345678, 0),
            ],
            withdrawals: Vec::new(),
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: OutPoint::null(),
                    amount: 55,
                    public_key,
                },
                fee_rate: 1.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 0,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        // This should all be in one transaction since there are no votes
        // against any of the requests.
        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        // There should be two outputs, one for the signer and another for
        // the one of the deposits.
        let unsigned_tx = transactions.pop().unwrap();
        assert_eq!(unsigned_tx.tx.output.len(), 2);

        // The input amounts should be the sum of the signer amount and the
        // one deposit amount.
        let signer_amount = requests.signer_state.utxo.amount;
        let input_amount = unsigned_tx.input_amounts();
        assert_eq!(input_amount, signer_amount + 345678)
    }

    /// Deposit requests add to the signers' UTXO.
    #[test]
    fn deposits_increase_signers_utxo_amount() {
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let requests = SbtcRequests {
            deposits: vec![
                create_deposit(123456, 0, 0),
                create_deposit(789012, 0, 0),
                create_deposit(345678, 0, 0),
            ],
            withdrawals: Vec::new(),
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: OutPoint::null(),
                    amount: 55,
                    public_key,
                },
                fee_rate: 0.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 0,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        // This should all be in one transaction since there are no votes
        // against any of the requests.
        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        // The transaction should have two output corresponding to the
        // signers' UTXO and the OP_RETURN output.
        let unsigned_tx = transactions.pop().unwrap();
        assert_eq!(unsigned_tx.tx.output.len(), 2);

        assert!(unsigned_tx.tx.output[0].script_pubkey.is_p2tr());
        assert!(unsigned_tx.tx.output[1].script_pubkey.is_op_return());

        // The new amount should be the sum of the old amount plus the deposits.
        let new_amount: u64 = unsigned_tx
            .tx
            .output
            .iter()
            .map(|out| out.value.to_sat())
            .sum();
        assert_eq!(new_amount, 55 + 123456 + 789012 + 345678)
    }

    /// Withdrawal requests remove funds from the signers' UTXO.
    #[test]
    fn withdrawals_decrease_signers_utxo_amount() {
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let requests = SbtcRequests {
            deposits: Vec::new(),
            withdrawals: vec![
                create_withdrawal(1000, 0, 0),
                create_withdrawal(2000, 0, 0),
                create_withdrawal(3000, 0, 0),
            ],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: OutPoint::null(),
                    amount: 9500,
                    public_key,
                },
                fee_rate: 0.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 0,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let unsigned_tx = transactions.pop().unwrap();
        // We have 3 withdrawals so with the signers output and the
        // OP_RETURN output we have a total of 5 outputs.
        assert_eq!(unsigned_tx.tx.output.len(), 5);

        assert!(unsigned_tx.tx.output[0].script_pubkey.is_p2tr());
        assert!(unsigned_tx.tx.output[1].script_pubkey.is_op_return());

        let signer_utxo = unsigned_tx.tx.output.first().unwrap();
        assert_eq!(signer_utxo.value.to_sat(), 9500 - 1000 - 2000 - 3000);
    }

    /// We chain transactions so that we have a single signer UTXO at the end.
    #[test]
    fn returned_txs_form_a_tx_chain() {
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let requests = SbtcRequests {
            deposits: vec![
                create_deposit(1234, 0, 1 << 1),
                create_deposit(5678, 0, 1 << 2),
                create_deposit(9012, 0, 1 << 3 | 1 << 4),
            ],
            withdrawals: vec![
                create_withdrawal(1000, 0, 1 << 5),
                create_withdrawal(2000, 0, 1 << 6),
                create_withdrawal(3000, 0, 1 << 7),
                create_withdrawal(4000, 0, 1 << 8 | 1 << 9),
            ],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(300_000, 0),
                    amount: 300_000,
                    public_key,
                },
                fee_rate: 0.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 8,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let transactions = requests.construct_transactions().unwrap();
        more_asserts::assert_gt!(transactions.len(), 1);

        transactions.windows(2).for_each(|unsigned| {
            let utx0 = &unsigned[0];
            let utx1 = &unsigned[1];

            let previous_output1 = utx1.tx.input[0].previous_output;
            assert_eq!(utx0.tx.compute_txid(), previous_output1.txid);
            assert_eq!(previous_output1.vout, 0);

            assert!(utx0.tx.output[0].script_pubkey.is_p2tr());
            assert!(utx0.tx.output[1].script_pubkey.is_op_return());

            assert!(utx1.tx.output[0].script_pubkey.is_p2tr());
            assert!(utx1.tx.output[1].script_pubkey.is_op_return());
        })
    }

    /// Check that each deposit and withdrawal is included as an input or
    /// deposit in the transaction package.
    #[test]
    fn requests_in_unsigned_transaction_are_in_btc_tx() {
        // The requests in the UnsignedTransaction correspond to
        // inputs and outputs in the transaction
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let requests = SbtcRequests {
            deposits: vec![
                create_deposit(1234, 0, 1 << 1),
                create_deposit(5678, 0, 1 << 2),
                create_deposit(9012, 0, 1 << 3 | 1 << 4),
                create_deposit(3456, 0, 1 << 5),
                create_deposit(7890, 0, 0),
            ],
            withdrawals: vec![
                create_withdrawal(1000, 0, 1 << 6),
                create_withdrawal(2000, 0, 1 << 7),
                create_withdrawal(3000, 0, 1 << 8),
                create_withdrawal(4000, 0, 1 << 9 | 1 << 10),
                create_withdrawal(5000, 0, 0),
                create_withdrawal(6000, 0, 0),
                create_withdrawal(7000, 0, 0),
            ],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(300_000, 0),
                    amount: 300_000,
                    public_key,
                },
                fee_rate: 0.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 8,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let transactions = requests.construct_transactions().unwrap();
        more_asserts::assert_gt!(transactions.len(), 1);

        // Create collections of identifiers for each deposit and withdrawal
        // request.
        let mut input_txs: BTreeSet<Txid> =
            requests.deposits.iter().map(|x| x.outpoint.txid).collect();
        let mut output_scripts: BTreeSet<String> = requests
            .withdrawals
            .iter()
            .map(|req| req.script_pubkey.to_hex_string())
            .collect();

        // Now we check that the counts of the withdrawals and deposits
        // line up.
        transactions.iter().for_each(|utx| {
            let num_inputs = utx.tx.input.len();
            let num_outputs = utx.tx.output.len();
            assert_eq!(utx.requests.len() + 3, num_inputs + num_outputs);

            let num_deposits = utx.requests.iter().filter_map(|x| x.as_deposit()).count();
            assert_eq!(utx.tx.input.len(), num_deposits + 1);

            let num_withdrawals = utx
                .requests
                .iter()
                .filter_map(|x| x.as_withdrawal())
                .count();
            assert_eq!(utx.tx.output.len(), num_withdrawals + 2);

            assert!(utx.tx.output[0].script_pubkey.is_p2tr());
            assert!(utx.tx.output[1].script_pubkey.is_op_return());

            // Check that each deposit is referenced exactly once
            // We ship the first one since that is the signers' UTXO
            for tx_in in utx.tx.input.iter().skip(1) {
                assert!(input_txs.remove(&tx_in.previous_output.txid));
            }
            // We skip the first two outputs because they are the signers'
            // new UTXO and the OP_RETURN output.
            for tx_out in utx.tx.output.iter().skip(2) {
                assert!(output_scripts.remove(&tx_out.script_pubkey.to_hex_string()));
            }
        });

        assert!(input_txs.is_empty());
        assert!(output_scripts.is_empty());
    }

    /// Check the following:
    /// * The fees for each transaction is at least as large as the
    ///   fee_rate in the signers' state.
    /// * Each deposit and withdrawal request pays a fee proportional to
    ///   their weight in the transaction.
    /// * The total fees are equal to the number of request times the fee
    ///   per request amount.
    /// * Deposit requests pay fees too, but implicitly by the amounts
    ///   deducted from the signers.
    #[test]
    fn returned_txs_match_fee_rate() {
        // Each deposit and withdrawal has a max fee greater than the current market fee rate
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        // Any old keypair will do here, we need it to construct the
        // witness data of the right size.
        let keypair = Keypair::new_global(&mut OsRng);

        let requests = SbtcRequests {
            deposits: vec![
                create_deposit(12340, 100_000, 1 << 1),
                create_deposit(56780, 100_000, 1 << 2),
                create_deposit(90120, 100_000, 1 << 3 | 1 << 4),
                create_deposit(34560, 100_000, 1 << 5),
                create_deposit(78900, 100_000, 0),
            ],
            withdrawals: vec![
                create_withdrawal(10000, 100_000, 1 << 6),
                create_withdrawal(20000, 100_000, 1 << 7),
                create_withdrawal(30000, 100_000, 1 << 8),
                create_withdrawal(40000, 100_000, 1 << 9 | 1 << 10),
                create_withdrawal(50000, 100_000, 0),
                create_withdrawal(60000, 100_000, 0),
                create_withdrawal(70000, 100_000, 0),
            ],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(300_000, 0),
                    amount: 300_000_000,
                    public_key,
                },
                fee_rate: 25.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 8,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let mut transactions = requests.construct_transactions().unwrap();
        more_asserts::assert_gt!(transactions.len(), 1);

        transactions.iter_mut().for_each(|utx| {
            // The unsigned transaction has all witness data removed,
            // so it should have a much smaller size than the "signed"
            // version returned from UnsignedTransaction::new_transaction.
            let unsigned_size = utx.tx.vsize();
            testing::set_witness_data(utx, keypair);
            let signed_vsize = utx.tx.vsize();

            more_asserts::assert_lt!(unsigned_size, signed_vsize);

            let output_amounts: u64 = utx.output_amounts();
            let input_amounts: u64 = utx.input_amounts();

            let reqs = utx.requests.iter().filter_map(RequestRef::as_withdrawal);
            for (output, req) in utx.tx.output.iter().skip(2).zip(reqs) {
                // One of the invariants is that the amount spent to the
                // withdrawal recipient is the amount in the withdrawal
                // request. The fees are already paid for separately.
                assert_eq!(req.amount, output.value.to_sat());
            }

            more_asserts::assert_gt!(input_amounts, output_amounts);
            more_asserts::assert_gt!(utx.requests.len(), 0);

            // The final fee rate should still be greater than the market fee rate
            let fee_rate = (input_amounts - output_amounts) as f64 / signed_vsize as f64;
            more_asserts::assert_le!(requests.signer_state.fee_rate, fee_rate);
        });
    }

    #[test]
    fn rbf_txs_have_greater_total_fee() {
        // Each deposit and withdrawal has a max fee greater than the current market fee rate
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let mut requests = SbtcRequests {
            deposits: vec![
                create_deposit(12340, 100_000, 0),
                create_deposit(56780, 100_000, 0),
                create_deposit(90120, 100_000, 0),
                create_deposit(34560, 100_000, 0),
                create_deposit(78900, 100_000, 0),
            ],
            withdrawals: vec![
                create_withdrawal(10000, 100_000, 0),
                create_withdrawal(20000, 100_000, 0),
            ],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(300_000, 0),
                    amount: 300_000_000,
                    public_key,
                },
                fee_rate: 25.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 8,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let (old_fee_total, old_fee_rate) = {
            let utx = requests.construct_transactions().unwrap().pop().unwrap();

            let output_amounts: u64 = utx.output_amounts();
            let input_amounts: u64 = utx.input_amounts();

            more_asserts::assert_gt!(input_amounts, output_amounts);
            let fee_total = input_amounts - output_amounts;
            let fee_rate = fee_total as f64 / utx.tx.vsize() as f64;
            (fee_total, fee_rate)
        };

        requests.signer_state.last_fees = Some(Fees {
            total: old_fee_total,
            rate: old_fee_rate,
        });

        let utx = requests.construct_transactions().unwrap().pop().unwrap();

        let output_amounts: u64 = utx.output_amounts();
        let input_amounts: u64 = utx.input_amounts();

        more_asserts::assert_gt!(input_amounts, output_amounts);
        more_asserts::assert_gt!(input_amounts - output_amounts, old_fee_total);
        more_asserts::assert_gt!(utx.requests.len(), 0);

        // Since there are often both deposits and withdrawal, the
        // following assertion checks that we capture the fees that
        // depositors must pay.
        assert_eq!(input_amounts, output_amounts + utx.tx_fee);

        let state = &requests.signer_state;
        let signed_vsize = UnsignedTransaction::new_transaction(&utx.requests, state)
            .unwrap()
            .vsize();

        // The unsigned transaction has all witness data removed,
        // so it should have a much smaller size than the "signed"
        // version returned from UnsignedTransaction::new_transaction.
        more_asserts::assert_lt!(utx.tx.vsize(), signed_vsize);
        // The final fee rate should still be greater than the market fee rate
        let fee_rate = (input_amounts - output_amounts) as f64 / signed_vsize as f64;
        more_asserts::assert_le!(requests.signer_state.fee_rate, fee_rate);
    }

    #[test_case(2; "Some deposits")]
    #[test_case(0; "No deposits")]
    fn unsigned_tx_digests(num_deposits: usize) {
        // Each deposit and withdrawal has a max fee greater than the current market fee rate
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let requests = SbtcRequests {
            deposits: std::iter::repeat_with(|| create_deposit(123456, 100_000, 0))
                .take(num_deposits)
                .collect(),
            withdrawals: vec![
                create_withdrawal(10000, 100_000, 0),
                create_withdrawal(20000, 100_000, 0),
                create_withdrawal(30000, 100_000, 0),
                create_withdrawal(40000, 100_000, 0),
                create_withdrawal(50000, 100_000, 0),
                create_withdrawal(60000, 100_000, 0),
                create_withdrawal(70000, 100_000, 0),
            ],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(300_000, 0),
                    amount: 300_000_000,
                    public_key,
                },
                fee_rate: 25.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 8,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };
        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let unsigned = transactions.pop().unwrap();
        let sighashes = unsigned.construct_digests().unwrap();

        assert_eq!(sighashes.deposits.len(), num_deposits)
    }

    /// If the signer's UTXO does not have enough to cover the requests
    /// then we return an error.
    #[test]
    fn negative_amounts_give_error() {
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let requests = SbtcRequests {
            deposits: Vec::new(),
            withdrawals: vec![
                create_withdrawal(1000, 0, 0),
                create_withdrawal(2000, 0, 0),
                create_withdrawal(3000, 0, 0),
            ],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: OutPoint::null(),
                    amount: 3000,
                    public_key,
                },
                fee_rate: 0.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 0,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let transactions = requests.construct_transactions();
        assert!(transactions.is_err());
    }

    #[test_case(3, 2, 2, 1; "Low fee deposits and withdrawals")]
    #[test_case(2, 5, 3, 0; "Low fee deposits and all good withdrawals")]
    #[test_case(2, 0, 3, 2; "All good deposits and low fee withdrawals")]
    #[test_case(6, 0, 3, 0; "All good deposits and withdrawals")]
    fn respecting_withdrawal_request_max_fee(
        good_deposit_count: usize,
        low_fee_deposit_count: usize,
        good_withdrawal_count: usize,
        low_fee_withdrawal_count: usize,
    ) {
        // Each deposit and withdrawal has a max fee greater than the current market fee rate
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let fee_rate = 10.0;
        let uniform = Uniform::new(200_000, 500_000);

        // Create deposit and withdrawal requests, some with too low of a
        // max fees and some with a good max fee.
        let deposit_low_fee = ((SOLO_DEPOSIT_TX_VSIZE - 1.0) * fee_rate) as u64;
        let low_fee_deposits = std::iter::repeat_with(|| uniform.sample(&mut OsRng))
            .take(low_fee_deposit_count)
            .map(|amount| create_deposit(amount, deposit_low_fee, 0));
        let good_fee_deposits = std::iter::repeat_with(|| uniform.sample(&mut OsRng))
            .take(good_deposit_count)
            .map(|amount| create_deposit(amount, 100_000, 0));

        let withdrawal_low_fee = ((BASE_WITHDRAWAL_TX_VSIZE - 1.0) * fee_rate) as u64;
        let low_fee_withdrawals = std::iter::repeat_with(|| uniform.sample(&mut OsRng))
            .take(low_fee_withdrawal_count)
            .map(|amount| create_withdrawal(amount, withdrawal_low_fee, 0));
        let good_fee_withdrawals = std::iter::repeat_with(|| uniform.sample(&mut OsRng))
            .take(good_withdrawal_count)
            .map(|amount| create_withdrawal(amount, 100_000, 0));

        // Okay now generate the (unsigned) transaction that we will submit.
        let requests = SbtcRequests {
            deposits: good_fee_deposits.chain(low_fee_deposits).collect(),
            withdrawals: good_fee_withdrawals.chain(low_fee_withdrawals).collect(),
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(300_000_000, 0),
                    amount: 300_000_000,
                    public_key,
                },
                fee_rate,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 10,
            accept_threshold: 8,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let unsigned = transactions.pop().unwrap();

        // Okay now how many of the requests were actual used
        let used_deposits = unsigned
            .requests
            .iter()
            .filter_map(RequestRef::as_deposit)
            .count();
        let used_withdrawals = unsigned
            .requests
            .iter()
            .filter_map(RequestRef::as_withdrawal)
            .count();

        assert_eq!(used_deposits, good_deposit_count);
        assert_eq!(used_withdrawals, good_withdrawal_count);

        // The additional 1 is for the signers' UTXO
        assert_eq!(unsigned.tx.input.len(), 1 + good_deposit_count);
        assert_eq!(unsigned.tx.output.len(), 2 + good_withdrawal_count);
    }

    /// Check that the signer bitmap is recoded correctly when going from
    /// the model type to the required type here.
    #[test]
    fn creating_deposit_request_from_model_bitmap_is_right() {
        let signer_votes = [
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: Some(true),
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: Some(false),
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: Some(true),
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: Some(true),
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: None,
            },
        ];
        let votes = SignerVotes::from(signer_votes.to_vec());
        let request: model::DepositRequest = fake::Faker.fake_with_rng(&mut OsRng);
        let deposit_request = DepositRequest::from_model(request, votes.clone());

        // One explicit vote against and one implicit vote against.
        assert_eq!(deposit_request.votes().count_ones(), 2);
        // An appropriately named function ...
        votes.iter().enumerate().for_each(|(index, vote)| {
            let vote_against = *deposit_request.signer_bitmap.get(index).unwrap();
            assert_eq!(vote_against, !vote.is_accepted.unwrap_or(false));
        })
    }

    /// Check that the signer bitmap is recoded correctly when going from
    /// the model type to the required type here.
    #[test]
    fn creating_withdrawal_request_from_model_bitmap_is_right() {
        let signer_votes = [
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: Some(true),
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: None,
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: Some(false),
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: Some(true),
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: Some(true),
            },
            SignerVote {
                signer_public_key: fake::Faker.fake_with_rng(&mut OsRng),
                is_accepted: None,
            },
        ];
        let votes = SignerVotes::from(signer_votes.to_vec());
        let request: model::WithdrawalRequest = fake::Faker.fake_with_rng(&mut OsRng);
        let withdrawal_request = WithdrawalRequest::from_model(request, votes.clone());

        // One explicit vote against and one implicit vote against.
        assert_eq!(withdrawal_request.votes().count_ones(), 3);
        // An appropriately named function ...
        votes.iter().enumerate().for_each(|(index, vote)| {
            let vote_against = *withdrawal_request.signer_bitmap.get(index).unwrap();
            assert_eq!(vote_against, !vote.is_accepted.unwrap_or(false));
        })
    }

    #[test]
    fn sole_deposit_gets_entire_fee() {
        let deposit_outpoint = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
        let mut tx = base_signer_transaction();
        let deposit = bitcoin::TxIn {
            previous_output: deposit_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        };
        tx.input.push(deposit);

        let fee = Amount::from_sat(500_000);

        let tx_info = BitcoinTxInfo::from_tx(tx, fee);
        let assessed_fee = tx_info.assess_input_fee(&deposit_outpoint).unwrap();
        assert_eq!(assessed_fee, fee);
    }

    #[test]
    fn sole_withdrawal_gets_entire_fee() {
        let mut tx = base_signer_transaction();
        let locking_script = ScriptBuf::new_op_return([0; 10]);
        // This represents the signers' new UTXO.
        let withdrawal = bitcoin::TxOut {
            value: Amount::from_sat(250_000),
            script_pubkey: ScriptBuf::new_p2sh(&locking_script.script_hash()),
        };
        tx.output.push(withdrawal);
        let fee = Amount::from_sat(500_000);

        let tx_info = BitcoinTxInfo::from_tx(tx, fee);
        let assessed_fee = tx_info.assess_output_fee(2).unwrap();
        assert_eq!(assessed_fee, fee);
    }

    #[test]
    fn first_input_and_first_two_outputs_return_none() {
        let tx = base_signer_transaction();
        let fee = Amount::from_sat(500_000);

        let tx_info = BitcoinTxInfo::from_tx(tx, fee);
        assert!(tx_info.assess_output_fee(0).is_none());
        assert!(tx_info.assess_output_fee(1).is_none());
        // Since we always skip the first input, and
        // `base_signer_transaction()` only adds one input, the search for
        // the given input when `assess_input_fee` executes will always
        // fail, simulating that the specified outpoint wasn't found.
        assert!(tx_info.assess_input_fee(&OutPoint::null()).is_none());
    }

    #[test]
    fn two_deposits_same_weight_split_the_fee() {
        // These deposit inputs are essentially identical by weight. Since
        // they are the only requests serviced by this transaction, they
        // will have equal weight.
        let deposit_outpoint1 = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
        let deposit_outpoint2 = OutPoint::new(Txid::from_byte_array([2; 32]), 0);

        let mut tx = base_signer_transaction();
        let deposit1 = bitcoin::TxIn {
            previous_output: deposit_outpoint1,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        };
        let deposit2 = bitcoin::TxIn {
            previous_output: deposit_outpoint2,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        };
        tx.input.push(deposit1);
        tx.input.push(deposit2);

        let fee = Amount::from_sat(500_000);

        let tx_info = BitcoinTxInfo::from_tx(tx, fee);
        let assessed_fee1 = tx_info.assess_input_fee(&deposit_outpoint1).unwrap();
        assert_eq!(assessed_fee1, fee / 2);

        let assessed_fee2 = tx_info.assess_input_fee(&deposit_outpoint2).unwrap();
        assert_eq!(assessed_fee2, fee / 2);
    }

    #[test]
    fn two_withdrawals_same_weight_split_the_fee() {
        let mut tx = base_signer_transaction();
        let locking_script = ScriptBuf::new_op_return([0; 10]);
        let withdrawal = bitcoin::TxOut {
            value: Amount::from_sat(250_000),
            script_pubkey: ScriptBuf::new_p2sh(&locking_script.script_hash()),
        };
        tx.output.push(withdrawal.clone());
        tx.output.push(withdrawal);
        let fee = Amount::from_sat(500_000);

        let tx_info = BitcoinTxInfo::from_tx(tx, fee);
        let assessed_fee1 = tx_info.assess_output_fee(2).unwrap();
        assert_eq!(assessed_fee1, fee / 2);

        let assessed_fee2 = tx_info.assess_output_fee(3).unwrap();
        assert_eq!(assessed_fee2, fee / 2);
    }

    #[test_case(500_000; "fee 500_000")]
    #[test_case(123_456; "fee 123_456")]
    #[test_case(1_234_567; "fee 1_234_567")]
    #[test_case(10_007; "fee 10_007")]
    fn one_deposit_two_withdrawals_fees_add(fee_sats: u64) {
        // We're just testing that a "regular" bitcoin transaction,
        // servicing a deposit and two withdrawals, will assess the fees in
        // a normal way. Here we test that the fee is
        let deposit_outpoint = OutPoint::new(Txid::from_byte_array([1; 32]), 0);

        let mut tx = base_signer_transaction();
        let deposit = bitcoin::TxIn {
            previous_output: deposit_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ZERO,
            witness: bitcoin::Witness::new(),
        };
        tx.input.push(deposit);

        let locking_script = ScriptBuf::new_op_return([0; 10]);
        let withdrawal = bitcoin::TxOut {
            value: Amount::from_sat(250_000),
            script_pubkey: ScriptBuf::new_p2sh(&locking_script.script_hash()),
        };
        tx.output.push(withdrawal.clone());
        tx.output.push(withdrawal);

        let fee = Amount::from_sat(fee_sats);

        let tx_info = BitcoinTxInfo::from_tx(tx, fee);
        let input_assessed_fee = tx_info.assess_input_fee(&deposit_outpoint).unwrap();
        let output1_assessed_fee = tx_info.assess_output_fee(2).unwrap();
        let output2_assessed_fee = tx_info.assess_output_fee(3).unwrap();

        assert!(input_assessed_fee > Amount::ZERO);
        assert!(output1_assessed_fee > Amount::ZERO);
        assert!(output2_assessed_fee > Amount::ZERO);

        let combined_fee = input_assessed_fee + output1_assessed_fee + output2_assessed_fee;

        assert!(combined_fee >= fee);
        // Their fees, in sats, should not add up to more than `fee +
        // number-of-requests`.
        assert!(combined_fee <= (fee + Amount::from_sat(3u64)));
    }

    #[test_case(
        create_deposit(
            DEPOSIT_DUST_LIMIT + SOLO_DEPOSIT_TX_VSIZE as u64,
            10_000,
            0
        ),
        true; "deposit amounts over the dust limit accepted")]
    #[test_case(
        create_deposit(
            DEPOSIT_DUST_LIMIT + SOLO_DEPOSIT_TX_VSIZE as u64 - 1,
            10_000,
            0
        ),
        false; "deposit amounts under the dust limit rejected")]
    fn deposit_requests_respect_dust_limits(req: DepositRequest, is_included: bool) {
        let outpoint = req.outpoint;
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();

        // We use a fee rate of 1 to simplify the computation. The
        // filtering done here uses a heuristic where we take the maximum
        // fee that the user could pay, and subtract that amount from the
        // deposit amount. The maximum fee that a user could pay is the
        // SOLO_DEPOSIT_TX_VSIZE times the fee rate so with a fee rate of 1
        // we should filter the request if the deposit amount is less than
        // SOLO_DEPOSIT_TX_VSIZE + DEPOSIT_DUST_LIMIT.
        let requests = SbtcRequests {
            deposits: vec![create_deposit(2500000, 100000, 0), req],
            withdrawals: vec![],
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: generate_outpoint(300_000, 0),
                    amount: 300_000_000,
                    public_key,
                },
                fee_rate: 1.0,
                public_key,
                last_fees: None,
                magic_bytes: [0; 2],
            },
            num_signers: 11,
            accept_threshold: 6,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        // Let's construct the unsigned transaction and check to see if we
        // include it in the deposit requests in the transaction.
        let tx = requests.construct_transactions().unwrap().pop().unwrap();
        let request_is_included = tx
            .requests
            .iter()
            .filter_map(RequestRef::as_deposit)
            .find(|req| req.outpoint == outpoint)
            .is_some();

        assert_eq!(request_is_included, is_included);
    }

    #[test]
    fn construct_transactions_limits_transaction_count() {
        // With 30 deposits and 30 withdrawals each with one nonoverlapping
        // vote against, we should generate 60 distinct transactions since
        // each transaction can tolerate a max of one vote against. But we
        // should cap the number of transactions returned to
        // MAX_MEMPOOL_PACKAGE_TX_COUNT.
        let deposits: Vec<DepositRequest> = (0..30)
            .map(|shift| create_deposit(10_000, 10_000, 1 << shift))
            .collect();
        let withdrawals: Vec<WithdrawalRequest> = (0..30)
            .map(|shift| create_withdrawal(10_000, 10_000, 1 << shift + 30))
            .collect();

        let requests = SbtcRequests {
            deposits,
            withdrawals,
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: OutPoint::null(),
                    amount: 1000000,
                    public_key: generate_x_only_public_key(),
                },
                fee_rate: 1.0,
                public_key: generate_x_only_public_key(),
                last_fees: None,
                magic_bytes: [0; 2],
            },
            accept_threshold: 127,
            num_signers: 128,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), MAX_MEMPOOL_PACKAGE_TX_COUNT as usize);
        let total_size: u32 = transactions.iter().map(|tx| tx.tx_vsize).sum();
        more_asserts::assert_le!(total_size, MEMPOOL_MAX_PACKAGE_SIZE);
    }

    #[test]
    fn construct_transactions_limits_package_vsize() {
        const NUM_DEPOSITS: usize =
            DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX as usize * MAX_MEMPOOL_PACKAGE_TX_COUNT as usize;
        // We set the signer bitmap to 3, so that each deposit is
        // interpreted as having two votes against (two bits are one in the
        // binary representation of 3). Since the withdrawals all have one
        // vote against, the packager will place all deposits in the
        // transaction package because we use a variant of the best-fit
        // decreasing algorithm when packaging requests.
        let deposits: Vec<DepositRequest> =
            std::iter::repeat_with(|| create_deposit(10_000, 10_000, 3))
                .take(NUM_DEPOSITS)
                .collect();
        // Each withdrawal request weighs about 31 vbytes (with the first
        // adding 51 vbytes). So, this would add about 124000 vbytes to the
        // transaction size, putting it over the bitcoin limit. This means
        // many of these should be excluded from the transaction package,
        // respecting the bitcoin limit.
        //
        // The packager is supposed to make sure that the transaction
        // package vsize is under the bitcoin limit. It gets closest to
        // that limit when the transaction package comprises 25 different
        // transactions. We create a package with 25 transactions by
        // ensuring lots of votes against the set of request.
        const MAX_WITHDRAWALS: usize = 4000;
        let withdrawals: Vec<WithdrawalRequest> = (0..MAX_WITHDRAWALS)
            .map(|shift| create_withdrawal(1000, 10_000, 1 << (shift % 14)))
            .collect();

        let requests = SbtcRequests {
            deposits,
            withdrawals,
            signer_state: SignerBtcState {
                utxo: SignerUtxo {
                    outpoint: OutPoint::null(),
                    amount: 100000000,
                    public_key: generate_x_only_public_key(),
                },
                fee_rate: 1.0,
                public_key: generate_x_only_public_key(),
                last_fees: None,
                magic_bytes: [0; 2],
            },
            accept_threshold: 10,
            num_signers: 14,
            sbtc_limits: SbtcLimits::unlimited(),
            max_deposits_per_bitcoin_tx: DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX,
        };

        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), MAX_MEMPOOL_PACKAGE_TX_COUNT as usize);
        // Let's check that each transaction has the maximum allowed number
        // of deposit inputs. We add one in the check because the signers
        // UTXO is always included as an input.
        let expected_input_count = DEFAULT_MAX_DEPOSITS_PER_BITCOIN_TX as usize + 1;
        transactions
            .iter()
            .for_each(|unsigned| assert_eq!(unsigned.tx.input.len(), expected_input_count));

        // Now for the actual check of this test.
        let total_vsize: u32 = transactions.iter().map(|tx| tx.tx_vsize).sum();
        more_asserts::assert_le!(total_vsize, MEMPOOL_MAX_PACKAGE_SIZE);

        // Now we double-check that some withdrawal requests were excluded,
        // while other were included.
        let num_requests = transactions
            .iter()
            .map(|tx| tx.requests.len())
            .sum::<usize>();
        more_asserts::assert_gt!(num_requests, NUM_DEPOSITS);
        more_asserts::assert_lt!(num_requests, MAX_WITHDRAWALS);

        // As a sanity check, we sign each transaction input to get "full"
        // transactions. We then make sure that we are below the limit and
        // that our earlier total_vsize value is accurate.
        let keypair = secp256k1::Keypair::new_global(&mut OsRng);
        let package_vsize = transactions
            .iter_mut()
            .map(|unsigned| {
                testing::set_witness_data(unsigned, keypair);
                unsigned.tx.vsize() as u32
            })
            .sum::<u32>();

        assert_eq!(package_vsize, total_vsize);
    }

    #[test_case(
        &vec![create_deposit(
            DEPOSIT_DUST_LIMIT + SOLO_DEPOSIT_TX_VSIZE as u64, 10_000, 0
        )],
        &create_limits_for_deposits_and_max_mintable(0, 20_000, 100_000),
        SOLO_DEPOSIT_TX_VSIZE as u64,
        1, DEPOSIT_DUST_LIMIT + SOLO_DEPOSIT_TX_VSIZE as u64; "deposit_amounts_over_the_dust_limit_accepted")]
    #[test_case(
        &vec![create_deposit(
            DEPOSIT_DUST_LIMIT + SOLO_DEPOSIT_TX_VSIZE as u64 - 1, 10_000, 0
        )],
        &create_limits_for_deposits_and_max_mintable(0, 20_000, 100_000),
        SOLO_DEPOSIT_TX_VSIZE as u64,
        0, 0; "should_reject_deposits_under_dust_limit")]
    #[test_case(
        &vec![
            create_deposit(10_000, 1_000, 0),
            create_deposit(11_000, 100, 0),
            create_deposit(12_000, 2_000, 0),
            create_deposit(13_000, 0, 0),
        ],
        &create_limits_for_deposits_and_max_mintable(0, 20_000, 100_000),
        1_000,
        2, 22_000; "should_accept_all_deposits_above_or_equal_min_fee")]
    #[test_case(
        &vec![
            create_deposit(10_000, 10_000, 0),
            create_deposit(10_000, 10_000, 0),
            create_deposit(10_000, 10_000, 0),
            create_deposit(10_000, 10_000, 0),
            create_deposit(10_000, 10_000, 0),
        ],
        &create_limits_for_deposits_and_max_mintable(0, 10_000, 30_000),
        1_000,
        3, 30_000; "should_accept_deposits_until_max_mintable_reached")]
    #[test_case(
        &vec![
            create_deposit(10_000, 10_000, 0),
            create_deposit(10_000, 10_000, 0),
        ],
        &create_limits_for_deposits_and_max_mintable(0, 10_000, 15_000),
        1_000,
        1, 10_000; "should_accept_all_deposits_when_under_max_mintable")]
    #[test_case(
        &vec![create_deposit(10_000, 10_000, 0),],
        &create_limits_for_deposits_and_max_mintable(0, 0, 0),
        1_000,
        0, 0; "should_handle_empty_deposit_list")]
    #[test_case(
        &vec![
            create_deposit(10_000, 0, 0),
            create_deposit(11_000, 10_000, 0),
            create_deposit(9_000, 10_000, 0),
        ],
        &create_limits_for_deposits_and_max_mintable(0, 10_000, 10_000),
        1_000,
        1, 9_000; "should_skip_invalid_fee_and_accept_valid_deposits")]
    #[test_case(
        &vec![
            create_deposit(10_001, 10_000, 0),
        ],
        &create_limits_for_deposits_and_max_mintable(0, 10_001, 10_000),
        1_000,
        0, 0; "should_reject_single_deposit_exceeding_max_mintable")]
    #[test_case(
        &vec![
            create_deposit(10_000, 10_000, 0),
        ],
        &create_limits_for_deposits_and_max_mintable(0, 8_000, 10_000),
        1_000,
        0, 0; "should_reject_single_deposit_exceeding_per_deposit_cap")]
    #[test_case(
        &vec![
            create_deposit(5_000, 2_000, 0),
            create_deposit(15_000, 2_000, 0),
        ],
        &create_limits_for_deposits_and_max_mintable(10_000, 20_000, 30_000),
        1_000,
        1, 15_000; "should_reject_deposits_below_per_deposit_minimum")]
    #[test_case(
        &vec![
            create_deposit(10_000, 10_000, 0), // accepted
            create_deposit(DEPOSIT_DUST_LIMIT + 999, 10_000, 0), // rejected (1 below dust limit) min_fee is 1_000
            create_deposit(9_000, 10_000, 0),  // rejected (below per_deposit_minimum)
            create_deposit(21_000, 10_000, 0), // rejected (above per_deposit_cap)
            create_deposit(20_000, 10_000, 0), // accepted
            create_deposit(20_000, 10_000, 0), // rejected (above max_mintable)
            create_deposit(5_000, 500, 0),     // rejected (below minimum_fee)
        ],
        &create_limits_for_deposits_and_max_mintable(10_000, 20_000, 40_000),
        1_000,
        2, 30_000; "should_respect_all_limits")]
    #[tokio::test]
    async fn test_deposit_filter_filters_deposits_over_limits(
        deposits: &Vec<DepositRequest>,
        sbtc_limits: &SbtcLimits,
        minimum_fee: u64,
        num_accepted_deposits: usize,
        accepted_amount: u64,
    ) {
        let filter = SbtcRequestsFilter::new(sbtc_limits, minimum_fee);

        let deposits = filter.filter_deposits(deposits);
        // Each deposit and withdrawal has a max fee greater than the current market fee rate
        // let txs = requests.construct_transactions().unwrap();
        let total_amount: u64 = deposits
            .iter()
            .map(|req| req.as_deposit().unwrap().amount)
            .sum();

        assert_eq!(deposits.len(), num_accepted_deposits);
        assert_eq!(total_amount, accepted_amount);
    }
}
