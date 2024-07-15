//! Utxo management and transaction construction

use std::sync::OnceLock;

use bitcoin::absolute::LockTime;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SECP256K1;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::Version;
use bitcoin::Address;
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
use bitcoin::Weight;
use bitcoin::Witness;
use bitcoin::XOnlyPublicKey;
use secp256k1::Keypair;
use secp256k1::Message;

use crate::error::Error;
use crate::packaging::compute_optimal_packages;
use crate::packaging::Weighted;

/// The minimum incremental fee rate in sats per virtual byte for RBF
/// transactions.
const DEFAULT_INCREMENTAL_RELAY_FEE_RATE: f64 =
    bitcoin::policy::DEFAULT_INCREMENTAL_RELAY_FEE as f64 / 1000.0;

/// This constant represents the virtual size (in vBytes) of a BTC
/// transaction that includes two inputs and one output. The inputs
/// consist of the signers' input UTXO and a UTXO for a deposit request.
/// The output is the signers' new UTXO.
const SOLO_DEPOSIT_TX_VSIZE: f64 = 207.0;

/// This constant represents the virtual size (in vBytes) of a BTC
/// transaction with only one input and two outputs. The input is the
/// signers' input UTXO. The outputs include the withdrawal UTXO for a
/// withdrawal request and the signers' new UTXO. This size assumes
/// the script in the withdrawal UTXO is empty.
const BASE_WITHDRAWAL_TX_VSIZE: f64 = 120.0;

/// It appears that bitcoin-core tracks fee rates in sats per kilo-vbyte
/// (or BTC per kilo-vbyte). Since we work in sats per vbyte, this constant
/// is the smallest detectable increment for bumping the fee rate in sats
/// per vbyte.
const SATS_PER_VBYTE_INCREMENT: f64 = 0.001;

/// The x-coordinate public key with no known discrete logarithm.
///
/// # Notes
///
/// This particular X-coordinate was discussed in the original taproot BIP
/// on spending rules BIP-0341[1]. Specifically, the X-coordinate is formed
/// by taking the hash of the standard uncompressed encoding of the 
/// secp256k1 base point G as the X-coordinate. In that BIP the authors
/// wrote the X-coordinate that is reproduced below.
///
/// [1]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
#[rustfmt::skip]
const NUMS_X_COORDINATE: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Returns an address with no known private key, since it has no known
/// discrete logarithm.
///
/// # Notes
///
/// This function returns the public key to used in the key-spend path of
/// the taproot address. Since we do not want a key-spend path for sBTC
/// deposit transactions, this address is such that it does not have a
/// known private key.
pub fn unspendable_taproot_key() -> &'static XOnlyPublicKey {
    static UNSPENDABLE_KEY: OnceLock<XOnlyPublicKey> = OnceLock::new();
    UNSPENDABLE_KEY.get_or_init(|| XOnlyPublicKey::from_slice(&NUMS_X_COORDINATE).unwrap())
}

/// Describes the fees for a transaction.
#[derive(Debug, Clone, Copy)]
pub struct Fees {
    /// The total fee paid in sats for the transaction.
    pub total: u64,
    /// The fee rate paid in sats per virtual byte.
    pub rate: f64,
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
    pub accept_threshold: u32,
    /// The total number of signers.
    pub num_signers: u32,
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
                let tx_vsize = BASE_WITHDRAWAL_TX_VSIZE + req.address.script_pubkey().len() as f64;
                req.max_fee >= self.compute_minimum_fee(tx_vsize)
            })
            .map(RequestRef::Withdrawal);

        // Now we filter deposit requests where the user's max fee could
        // be less than the fee we may charge. This is simpler because
        // deposit UTXOs have a known fixed size.
        let minimum_deposit_fee = self.compute_minimum_fee(SOLO_DEPOSIT_TX_VSIZE);
        let deposits = self
            .deposits
            .iter()
            .filter(|req| req.max_fee >= minimum_deposit_fee)
            .map(RequestRef::Deposit);

        // Create a list of requests where each request can be approved on its own.
        let items = deposits.chain(withdrawals);

        compute_optimal_packages(items, self.reject_capacity())
            .scan(self.signer_state, |state, requests| {
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
            .collect()
    }

    fn reject_capacity(&self) -> u32 {
        self.num_signers.saturating_sub(self.accept_threshold)
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
/// Also noteworthy is that the fee rate of the RBF transaction
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
#[derive(Debug, Clone)]
pub struct DepositRequest {
    /// The UTXO to be spent by the signers.
    pub outpoint: OutPoint,
    /// The max fee amount to use for the BTC deposit transaction.
    pub max_fee: u64,
    /// How each of the signers voted for the transaction.
    pub signer_bitmap: Vec<bool>,
    /// The amount of sats in the deposit UTXO.
    pub amount: u64,
    /// The deposit script used so that the signers' can spend funds.
    pub deposit_script: ScriptBuf,
    /// The reclaim script for the deposit.
    pub reclaim_script: ScriptBuf,
    /// The public key used in the deposit script. The signers public key
    /// is a Schnorr public key.
    ///
    /// Note that taproot Schnorr public keys are slightly different from
    /// the usual compressed public keys since they use only the x-coordinate
    /// with the y-coordinate assumed to be even. This means they use
    /// 32 bytes instead of the 33 byte public keys used before where the
    /// additional byte indicated the y-coordinate's parity.
    pub signers_public_key: XOnlyPublicKey,
}

impl DepositRequest {
    /// Returns the number of signers who voted against this request.
    fn votes_against(&self) -> u32 {
        self.signer_bitmap.iter().map(|vote| !vote as u32).sum()
    }

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
        let internal_key = unspendable_taproot_key();

        TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, *internal_key, merkle_root),
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
    ///   <data> OP_DROP OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
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
            self.signers_public_key.serialize().to_vec(),
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
        let internal_key = unspendable_taproot_key();

        TaprootSpendInfo::from_node_info(SECP256K1, *internal_key, node)
    }
}

/// An accepted or pending withdraw request.
#[derive(Debug, Clone)]
pub struct WithdrawalRequest {
    /// The amount of BTC, in sats, to withdraw.
    pub amount: u64,
    /// The max fee amount to use for the sBTC deposit transaction.
    pub max_fee: u64,
    /// The address to spend the output.
    pub address: Address,
    /// How each of the signers voted for the transaction.
    pub signer_bitmap: Vec<bool>,
}

impl WithdrawalRequest {
    /// Returns the number of signers who voted against this request.
    fn votes_against(&self) -> u32 {
        self.signer_bitmap.iter().map(|vote| !vote as u32).sum()
    }

    /// Withdrawal UTXOs pay to the given address
    fn as_tx_output(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: self.address.script_pubkey(),
        }
    }
}

/// A reference to either a deposit or withdraw request
#[derive(Debug, Clone, Copy)]
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
}

impl<'a> Weighted for RequestRef<'a> {
    fn weight(&self) -> u32 {
        match self {
            Self::Deposit(req) => req.votes_against(),
            Self::Withdrawal(req) => req.votes_against(),
        }
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
#[derive(Debug, Clone, Copy)]
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
        let secp = Secp256k1::new();

        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new_p2tr(&secp, public_key, None),
        }
    }
}

/// Given a set of requests, create a BTC transaction that can be signed.
///
/// This BTC transaction in this struct has correct amounts but no witness
/// data for its UTXO inputs.
#[derive(Debug)]
pub struct UnsignedTransaction<'a> {
    /// The requests used to construct the transaction.
    pub requests: Vec<RequestRef<'a>>,
    /// The BTC transaction that needs to be signed.
    pub tx: Transaction,
    /// The public key used for the public key of the signers' UTXO output.
    pub signer_public_key: XOnlyPublicKey,
    /// The signers' UTXO used as inputs to this transaction.
    pub signer_utxo: SignerBtcState,
    /// The total amount of fees associated with the deposit requests.
    pub deposit_fees: u64,
}

/// A struct containing Taproot-tagged hashes used for computing taproot
/// signature hashes.
#[derive(Debug)]
pub struct SignatureHashes<'a> {
    /// The sighash of the signers' input UTXO for the transaction.
    pub signers: TapSighash,
    /// Each deposit request is associated with a UTXO input for the peg-in
    /// transaction. This field contains digests/signature hashes that need
    /// Schnorr signatures and the associated deposit request for each hash.
    pub deposits: Vec<(&'a DepositRequest, TapSighash)>,
}

impl<'a> UnsignedTransaction<'a> {
    /// Construct an unsigned transaction.
    ///
    /// This function can fail if the output amounts are greater than the
    /// input amounts.
    ///
    /// The returned BTC transaction has the following properties:
    ///   1. The amounts for each output has taken fees into consideration.
    ///   2. The signer input UTXO is the first input.
    ///   3. The signer output UTXO is the first output.
    ///   4. Each input needs a signature in the witness data.
    ///   5. There is no witness data for deposit UTXOs.
    pub fn new(requests: Vec<RequestRef<'a>>, state: &SignerBtcState) -> Result<Self, Error> {
        // Construct a transaction base. This transaction's inputs have
        // witness data with dummy signatures so that our virtual size
        // estimates are accurate. Later we will update the fees and
        // remove the witness data.
        let mut tx = Self::new_transaction(&requests, state)?;
        // We now compute the total fees for the transaction.
        let tx_vsize = tx.vsize() as f64;
        let tx_fee = compute_transaction_fee(tx_vsize, state.fee_rate, state.last_fees);
        // Now adjust the deposits and withdrawals by an amount proportional
        // to their weight.
        let deposit_fees = Self::adjust_amounts(&mut tx, tx_fee);

        // Now we can reset the witness data.
        Self::reset_witness_data(&mut tx);

        Ok(Self {
            tx,
            requests,
            signer_public_key: state.public_key,
            signer_utxo: *state,
            deposit_fees,
        })
    }

    /// Construct a "stub" BTC transaction from the given requests.
    ///
    /// The returned BTC transaction is signed with dummy signatures, so it
    /// has the same virtual size as a proper transaction. Note that the
    /// output amounts haven't been adjusted for fees.
    ///
    /// An Err is returned if the amounts withdrawn is greater than the sum
    /// of all the input amounts.
    fn new_transaction(reqs: &[RequestRef], state: &SignerBtcState) -> Result<Transaction, Error> {
        let signature = Self::generate_dummy_signature();

        let deposits = reqs
            .iter()
            .filter_map(|req| Some(req.as_deposit()?.as_tx_input(signature)));
        let withdrawals = reqs
            .iter()
            .filter_map(|req| Some(req.as_withdrawal()?.as_tx_output()));

        let signer_input = state.utxo.as_tx_input(&signature);
        let signer_output_sats = Self::compute_signer_amount(reqs, state)?;
        let signer_output = SignerUtxo::new_tx_output(state.public_key, signer_output_sats);

        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: std::iter::once(signer_input).chain(deposits).collect(),
            output: std::iter::once(signer_output).chain(withdrawals).collect(),
        })
    }

    /// Create the new SignerUtxo for this transaction.
    fn new_signer_utxo(&self) -> SignerUtxo {
        SignerUtxo {
            outpoint: OutPoint {
                txid: self.tx.compute_txid(),
                vout: 0,
            },
            amount: self.tx.output[0].value.to_sat(),
            public_key: self.signer_public_key,
        }
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
        let sighash_type = TapSighashType::Default;
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

    /// Compute the final amount for the signers' UTXO given the current
    /// UTXO amount and the incoming requests.
    ///
    /// This amount does not take into account fees.
    fn compute_signer_amount(reqs: &[RequestRef], state: &SignerBtcState) -> Result<u64, Error> {
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
    /// This function adjusts each output by an amount that is proportional
    /// to their weight (but considering only the weight of the requests).
    /// The signers' UTXOs amount absorbs the fee on-chain that the
    /// depositors are supposed to pay. This amount must be accounted for
    /// when minting sBTC.
    fn adjust_amounts(tx: &mut Transaction, tx_fee: u64) -> u64 {
        // Since the first input and first output correspond to the signers'
        // UTXOs, we subtract them when computing the number of requests.
        let num_requests = (tx.input.len() + tx.output.len()).saturating_sub(2) as u64;
        // This is a bizarre case that should never happen.
        if num_requests == 0 {
            tracing::warn!("No deposit or withdrawal related inputs in the transaction");
            return 0;
        }
        // Fees are assigned proportionally to their weight amongst all
        // requests in the transaction. So let's get the total request weight.
        let requests_vsize = Self::request_weight(tx).to_vbytes_ceil();
        // The sum of all fees paid for each withdrawal UTXO.
        let mut withdrawal_fees: u64 = 0;
        // We now update the remaining withdrawal amounts to account for fees.
        tx.output.iter_mut().skip(1).for_each(|tx_out| {
            let fee = (tx_out.weight().to_vbytes_ceil() * tx_fee).div_ceil(requests_vsize);
            withdrawal_fees += fee;
            tx_out.value = Amount::from_sat(tx_out.value.to_sat().saturating_sub(fee));
        });

        // The first output is the signer's UTXO. The correct fee amount
        // for this UTXO is the total transaction fee minus the fees paid
        // by the other UTXOs in this transaction. This fee is later deducted
        // in the amount that is minted in sBTC to each depositor.
        let deposit_fees = tx_fee.saturating_sub(withdrawal_fees);
        if let Some(utxo_out) = tx.output.first_mut() {
            let signers_amount = utxo_out.value.to_sat().saturating_sub(deposit_fees);
            utxo_out.value = Amount::from_sat(signers_amount);
        }

        deposit_fees
    }

    /// Computes the total weight of the inputs and the outputs, excluding
    /// the ones related to the signers' UTXO.
    fn request_weight(tx: &Transaction) -> Weight {
        // We skip the first input and output because those are always the
        // signers' UTXO input and output.
        tx.input
            .iter()
            .skip(1)
            .map(|x| x.segwit_weight())
            .chain(tx.output.iter().skip(1).map(|x| x.weight()))
            .sum()
    }

    /// Helper function for generating dummy Schnorr signatures.
    fn generate_dummy_signature() -> Signature {
        let key_pair = Keypair::new_global(&mut rand::rngs::OsRng);

        Signature {
            signature: key_pair.sign_schnorr(Message::from_digest([0; 32])),
            sighash_type: TapSighashType::Default,
        }
    }

    /// We originally populated the witness with dummy data to get an
    /// accurate estimate of the "virtual size" of the transaction. This
    /// function resets the witness data to be empty.
    fn reset_witness_data(tx: &mut Transaction) {
        tx.input
            .iter_mut()
            .for_each(|tx_in| tx_in.witness = Witness::new());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::str::FromStr;

    use super::*;
    use bitcoin::CompressedPublicKey;
    use bitcoin::KnownHrp;
    use bitcoin::Txid;
    use rand::distributions::Distribution;
    use rand::distributions::Uniform;
    use rand::rngs::OsRng;
    use secp256k1::SecretKey;
    use test_case::test_case;

    use crate::testing;

    const X_ONLY_PUBLIC_KEY1: &'static str =
        "2e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";

    fn generate_x_only_public_key() -> XOnlyPublicKey {
        let secret_key = SecretKey::new(&mut OsRng);
        secret_key.x_only_public_key(SECP256K1).0
    }

    fn generate_address() -> Address {
        let secret_key = SecretKey::new(&mut OsRng);
        let pk = CompressedPublicKey(secret_key.public_key(SECP256K1));

        Address::p2wpkh(&pk, KnownHrp::Regtest)
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

    /// Create a new deposit request depositing from a random public key.
    fn create_deposit(amount: u64, max_fee: u64, votes_against: usize) -> DepositRequest {
        let signers_public_key = generate_x_only_public_key();

        DepositRequest {
            outpoint: generate_outpoint(amount, 1),
            max_fee,
            signer_bitmap: std::iter::repeat(false).take(votes_against).collect(),
            amount,
            deposit_script: testing::peg_in_deposit_script(&signers_public_key),
            reclaim_script: ScriptBuf::new(),
            signers_public_key,
        }
    }

    /// Create a new withdrawal request withdrawing to a random address.
    fn create_withdrawal(amount: u64, max_fee: u64, votes_against: usize) -> WithdrawalRequest {
        WithdrawalRequest {
            max_fee,
            signer_bitmap: std::iter::repeat(false).take(votes_against).collect(),
            amount,
            address: generate_address(),
        }
    }

    #[test]
    fn unspendable_taproot_key_no_panic() {
        // The following function calls unwrap() when called the first
        // time, check that it does not panic.
        let var1 = unspendable_taproot_key();
        let var2 = unspendable_taproot_key();
        assert_eq!(var1, var2);
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
            },
            num_signers: 10,
            accept_threshold: 2,
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
        assert_eq!(unsigned.tx.output.len(), 2);

        // We need to zero out the withdrawal script since this value
        // changes depending on the user.
        unsigned.tx.output[1].script_pubkey = ScriptBuf::new();
        testing::set_witness_data(&mut unsigned, keypair);

        println!("Solo withdrawal vsize: {}", unsigned.tx.vsize());
    }

    #[test_case(&[false, false, true, false, true, true, true], 3; "case 1")]
    #[test_case(&[false, false, true, true, true, true, true], 2; "case 2")]
    #[test_case(&[true, true, true, true, true, true, true], 0; "case 3")]
    fn test_deposit_votes_against(signer_bitmap: &[bool], expected: u32) {
        let deposit = DepositRequest {
            outpoint: OutPoint::null(),
            max_fee: 0,
            signer_bitmap: signer_bitmap.to_vec(),
            amount: 100_000,
            deposit_script: ScriptBuf::new(),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap(),
        };

        assert_eq!(deposit.votes_against(), expected);
    }

    /// Some functions call functions that "could" panic. Check that they
    /// don't.
    #[test]
    fn deposit_witness_data_no_error() {
        let deposit = DepositRequest {
            outpoint: OutPoint::null(),
            max_fee: 0,
            signer_bitmap: Vec::new(),
            amount: 100_000,
            deposit_script: ScriptBuf::from_bytes(vec![1, 2, 3]),
            reclaim_script: ScriptBuf::new(),
            signers_public_key: XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap(),
        };

        let sig = Signature::from_slice(&[0u8; 64]).unwrap();
        let witness = deposit.construct_witness_data(sig);
        assert!(witness.tapscript().is_some());

        let sig = UnsignedTransaction::generate_dummy_signature();
        let tx_in = deposit.as_tx_input(sig);

        // The deposits are taproot spend and do not have a script. The
        // actual spend script and input data gets put in the witness data
        assert!(tx_in.script_sig.is_empty());
    }

    /// The first input and output are related to the signers' UTXO.
    #[test]
    fn the_first_input_and_output_is_signers() {
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
            },
            num_signers: 10,
            accept_threshold: 0,
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

        // We had two withdrawal requests so there should be 1 + 2 outputs
        assert_eq!(unsigned_tx.tx.output.len(), 3);

        // The signers' UTXO, the first one, contains the balance of all
        // deposits and withdrawals. It's also a P2TR script.
        let signers_utxo_output = unsigned_tx.tx.output.first().unwrap();
        assert_eq!(
            signers_utxo_output.value.to_sat(),
            5500 + 123456 - 1000 - 2000
        );
        assert!(signers_utxo_output.script_pubkey.is_p2tr());

        // All the other UTXOs are P2WPKH outputs.
        unsigned_tx.tx.output.iter().skip(1).for_each(|output| {
            assert!(output.script_pubkey.is_p2wpkh());
        });

        // The new UTXO should be using the signer public key from the
        // signer state.
        let new_utxo = unsigned_tx.new_signer_utxo();
        assert_eq!(new_utxo.public_key, requests.signer_state.public_key);
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
            },
            num_signers: 10,
            accept_threshold: 0,
        };

        // This should all be in one transaction since there are no votes
        // against any of the requests.
        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        // The transaction should have one output corresponding to the
        // signers' UTXO
        let unsigned_tx = transactions.pop().unwrap();
        assert_eq!(unsigned_tx.tx.output.len(), 1);

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
            },
            num_signers: 10,
            accept_threshold: 0,
        };

        let mut transactions = requests.construct_transactions().unwrap();
        assert_eq!(transactions.len(), 1);

        let unsigned_tx = transactions.pop().unwrap();
        assert_eq!(unsigned_tx.tx.output.len(), 4);

        let signer_utxo = unsigned_tx.tx.output.first().unwrap();
        assert_eq!(signer_utxo.value.to_sat(), 9500 - 1000 - 2000 - 3000);
    }

    /// We chain transactions so that we have a single signer UTXO at the end.
    #[test]
    fn returned_txs_form_a_tx_chain() {
        let public_key = XOnlyPublicKey::from_str(X_ONLY_PUBLIC_KEY1).unwrap();
        let requests = SbtcRequests {
            deposits: vec![
                create_deposit(1234, 0, 1),
                create_deposit(5678, 0, 1),
                create_deposit(9012, 0, 2),
            ],
            withdrawals: vec![
                create_withdrawal(1000, 0, 1),
                create_withdrawal(2000, 0, 1),
                create_withdrawal(3000, 0, 1),
                create_withdrawal(4000, 0, 2),
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
            },
            num_signers: 10,
            accept_threshold: 8,
        };

        let transactions = requests.construct_transactions().unwrap();
        more_asserts::assert_gt!(transactions.len(), 1);

        transactions.windows(2).for_each(|unsigned| {
            let utx0 = &unsigned[0];
            let utx1 = &unsigned[1];

            let previous_output1 = utx1.tx.input[0].previous_output;
            assert_eq!(utx0.tx.compute_txid(), previous_output1.txid);
            assert_eq!(previous_output1.vout, 0);
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
                create_deposit(1234, 0, 1),
                create_deposit(5678, 0, 1),
                create_deposit(9012, 0, 2),
                create_deposit(3456, 0, 1),
                create_deposit(7890, 0, 0),
            ],
            withdrawals: vec![
                create_withdrawal(1000, 0, 1),
                create_withdrawal(2000, 0, 1),
                create_withdrawal(3000, 0, 1),
                create_withdrawal(4000, 0, 2),
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
            },
            num_signers: 10,
            accept_threshold: 8,
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
            .map(|req| req.address.script_pubkey().to_hex_string())
            .collect();

        // Now we check that the counts of the withdrawals and deposits
        // line up.
        transactions.iter().for_each(|utx| {
            let num_inputs = utx.tx.input.len();
            let num_outputs = utx.tx.output.len();
            assert_eq!(utx.requests.len() + 2, num_inputs + num_outputs);

            let num_deposits = utx.requests.iter().filter_map(|x| x.as_deposit()).count();
            assert_eq!(utx.tx.input.len(), num_deposits + 1);

            let num_withdrawals = utx
                .requests
                .iter()
                .filter_map(|x| x.as_withdrawal())
                .count();
            assert_eq!(utx.tx.output.len(), num_withdrawals + 1);

            // Check that each deposit is referenced exactly once
            // We ship the first one since that is the signers' UTXO
            for tx_in in utx.tx.input.iter().skip(1) {
                assert!(input_txs.remove(&tx_in.previous_output.txid));
            }
            for tx_out in utx.tx.output.iter().skip(1) {
                assert!(output_scripts.remove(&tx_out.script_pubkey.to_hex_string()));
            }
        });

        assert!(input_txs.is_empty());
        assert!(output_scripts.is_empty());
    }

    /// Check the following:
    /// * The fees for each transaction is at least as large as the fee_rate
    ///   in the signers' state.
    /// * Each deposit and withdrawal request pays the same fee.
    /// * The total fees are equal to the number of request times the fee per
    ///   request amount.
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
                create_deposit(12340, 100_000, 1),
                create_deposit(56780, 100_000, 1),
                create_deposit(90120, 100_000, 2),
                create_deposit(34560, 100_000, 1),
                create_deposit(78900, 100_000, 0),
            ],
            withdrawals: vec![
                create_withdrawal(10000, 100_000, 1),
                create_withdrawal(20000, 100_000, 1),
                create_withdrawal(30000, 100_000, 1),
                create_withdrawal(40000, 100_000, 2),
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
            },
            num_signers: 10,
            accept_threshold: 8,
        };

        // It's tough to match the outputs to the original request. We do
        // that here by matching the expected scripts, which are unique for
        // each public key. Since each public key is unique, this works.
        let mut withdrawal_amounts: BTreeMap<String, u64> = requests
            .withdrawals
            .iter()
            .map(|req| (req.address.script_pubkey().to_hex_string(), req.amount))
            .collect();

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
            let total_fees = input_amounts - output_amounts;

            let request_vsize = UnsignedTransaction::request_weight(&utx.tx).to_vbytes_ceil();

            let reqs = utx.requests.iter().filter_map(RequestRef::as_withdrawal);
            for (output, req) in utx.tx.output.iter().skip(1).zip(reqs) {
                let expected_fee =
                    (output.weight().to_vbytes_ceil() * total_fees).div_ceil(request_vsize);
                let fee = req.amount - output.value.to_sat();

                assert_eq!(fee, expected_fee);
                let original_amount = withdrawal_amounts
                    .remove(&output.script_pubkey.to_hex_string())
                    .unwrap();
                assert_eq!(original_amount, output.value.to_sat() + fee);
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
            },
            num_signers: 10,
            accept_threshold: 8,
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
        let deposit_requests = utx.requests.iter().filter_map(RequestRef::as_withdrawal);
        let withdrawal_fees: u64 = utx
            .tx
            .output
            .iter()
            .skip(1)
            .zip(deposit_requests)
            .map(|(tx_out, req)| req.amount - tx_out.value.to_sat())
            .sum();

        assert_eq!(
            input_amounts,
            output_amounts + withdrawal_fees + utx.deposit_fees
        );

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
            },
            num_signers: 10,
            accept_threshold: 8,
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
            },
            num_signers: 10,
            accept_threshold: 0,
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
            },
            num_signers: 10,
            accept_threshold: 8,
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
        assert_eq!(unsigned.tx.output.len(), 1 + good_withdrawal_count);
    }
}
