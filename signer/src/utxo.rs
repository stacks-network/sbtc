use bitcoin::absolute::LockTime;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SECP256K1;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::NodeInfo;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::Version;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::PublicKey;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::XOnlyPublicKey;
use secp256k1::Keypair;
use secp256k1::Message;

use crate::error::Error;
use crate::packaging::compute_optimal_packages;
use crate::packaging::Weighted;

#[derive(Debug, Clone, Copy)]
pub struct SignerState {
    /// The outstanding signer UTXO.
    pub utxo: SignerUtxo,
    /// The current market fee rate in sat/vByte.
    pub fee_rate: u64,
    /// The current public key of the signers
    pub public_key: PublicKey,
}

#[derive(Debug)]
pub struct SbtcRequests {
    /// Accepted and pending deposit requests.
    pub deposits: Vec<DepositRequest>,
    /// Accepted and pending withdrawal requests.
    pub withdrawals: Vec<WithdrawalRequest>,
    /// Summary of the Signers' UTXO and information necessary for
    /// constructing their next UTXO.
    pub signer_state: SignerState,
    /// The maximum acceptable number of votes against for any given
    /// request.
    pub reject_capacity: u32,
}

impl SbtcRequests {
    /// Construct the next transaction package given requests and the
    /// signers' UTXO.
    ///
    /// This function can fail if the output amounts are greater than the
    /// input amounts. This should never happen in practice.
    pub fn construct_transactions(&self) -> Result<Vec<UnsignedTransaction>, Error> {
        let withdrawals = self.withdrawals.iter().map(Request::Withdrawal);
        let deposits = self.deposits.iter().map(Request::Deposit);

        // Create a list of requests where each request can be approved on it's own.
        let items = deposits.chain(withdrawals);

        compute_optimal_packages(items, self.reject_capacity)
            .scan(self.signer_state, |state, requests| {
                let tx = UnsignedTransaction::new(requests, state);
                if let Ok(tx_ref) = tx.as_ref() {
                    state.utxo = tx_ref.new_signer_utxo();
                }
                Some(tx)
            })
            .collect()
    }
}

#[derive(Debug)]
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
    /// The redeem script for the deposit.
    pub redeem_script: ScriptBuf,
    /// The public key used for the key-spend path of the taproot script.
    pub taproot_public_key: PublicKey,
    /// The public key use in the deposit script.
    pub deposit_public_key: PublicKey,
}

impl DepositRequest {
    /// Returns the number of signers who voted against this request.
    fn votes_against(&self) -> u32 {
        self.signer_bitmap.iter().map(|vote| !vote as u32).sum()
    }

    /// Create a TxIn object with witness data for the deposit script of
    /// the given request. Only a valid signature is needed to satisfy the
    /// deposit script.
    fn as_tx_input(&self, sig: Signature) -> TxIn {
        TxIn {
            previous_output: self.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0),
            witness: self.construct_witness_data(sig),
        }
    }

    /// Construct the witness data for the taproot script of the deposit.
    ///
    /// Deposit UTXOs are taproot spend what a "null" key spend path,
    /// a deposit script-path spend, and a redeem script-path spend. This
    /// function creates the witness data for the deposit script-path
    /// spend where the script takes only one piece of data as input, the
    /// signature. The deposit script is:
    ///
    ///   <data> OP_DROP OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    ///
    /// where <data> is the stacks deposit address and <pubkey_hash> is
    /// given by self.deposit_public_key. The public key used for key-path
    /// spending is self.taproot_public_key, and is supposed to be a dummy
    /// public key.
    pub fn construct_witness_data(&self, sig: Signature) -> Witness {
        let (internal_key, _) = self.taproot_public_key.inner.x_only_public_key();
        let ver = LeafVersion::TapScript;

        // For such a simple tree, we construct it by hand.
        let leaf1 = NodeInfo::new_leaf_with_ver(self.deposit_script.clone(), ver);
        let leaf2 = NodeInfo::new_leaf_with_ver(self.redeem_script.clone(), ver);

        // A Result::Err is returned by NodeInfo::combine if the depth of
        // our taproot tree exceeds the maximum depth of taproot trees,
        // which is 128. We have two nodes so the depth is 1 so this will
        // never panic.
        let node =
            NodeInfo::combine(leaf1, leaf2).expect("This tree depth greater than max of 128");
        let taproot = TaprootSpendInfo::from_node_info(&SECP256K1, internal_key, node);

        // TaprootSpendInfo::control_block returns None if the key given,
        // (script, version), is not in the tree. But this key is definitely
        // in the tree (see the variable leaf1 above).
        let control_block = taproot
            .control_block(&(self.deposit_script.clone(), ver))
            .expect("We just inserted the deposit script into the tree");

        let witness_data = [
            sig.serialize().to_vec(),
            self.deposit_script.to_bytes(),
            control_block.serialize(),
        ];
        Witness::from_slice(&witness_data)
    }
}

#[derive(Debug)]
pub struct WithdrawalRequest {
    /// The amount of sBTC sats to withdraw.
    pub amount: u64,
    /// The max fee amount to use for the sBTC deposit transaction.
    pub max_fee: u64,
    /// The public key that will be able to spend the output.
    pub public_key: PublicKey,
    /// How each of the signers voted for the transaction.
    pub signer_bitmap: Vec<bool>,
}

impl WithdrawalRequest {
    /// Returns the number of signers who voted against this request.
    fn votes_against(&self) -> u32 {
        self.signer_bitmap.iter().map(|vote| !vote as u32).sum()
    }

    /// Withdrawal UTXOs are Pay-to-Witness Public Key Hash (P2WPKH)
    fn as_tx_output(&self) -> TxOut {
        let compressed = bitcoin::CompressedPublicKey(self.public_key.inner);
        let pubkey_hash = compressed.wpubkey_hash();
        TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: ScriptBuf::new_p2wpkh(&pubkey_hash),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Request<'a> {
    Deposit(&'a DepositRequest),
    Withdrawal(&'a WithdrawalRequest),
}

impl<'a> Request<'a> {
    pub fn as_withdrawal(&self) -> Option<&'a WithdrawalRequest> {
        match self {
            Request::Withdrawal(req) => Some(req),
            _ => None,
        }
    }

    pub fn as_deposit(&self) -> Option<&'a DepositRequest> {
        match self {
            Request::Deposit(req) => Some(req),
            _ => None,
        }
    }
}

impl<'a> Weighted for Request<'a> {
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
    /// The amount associated with that UTXO
    pub amount: u64,
    /// The public key used to create the key-spend only taproot script.
    pub public_key: PublicKey,
}

impl SignerUtxo {
    /// Create a TxIn object for the signers' UTXO
    ///
    /// The signers' UTXO is always a key-spend only taproot UTXO, so a
    /// valid signature is all that is needed to spend it.
    fn as_tx_input(&self, sig: &Signature) -> TxIn {
        TxIn {
            previous_output: self.outpoint,
            sequence: Sequence::ZERO,
            witness: Witness::p2tr_key_spend(&sig),
            script_sig: ScriptBuf::new(),
        }
    }

    /// Construct the new signers' UTXO
    ///
    /// The signers' UTXO is always a key-spend only taproot UTXO.
    fn new_tx_output(public_key: PublicKey, sats: u64) -> TxOut {
        let (internal_key, _): (XOnlyPublicKey, _) = public_key.inner.x_only_public_key();
        let secp = Secp256k1::new();

        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new_p2tr(&secp, internal_key, None),
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
    pub requests: Vec<Request<'a>>,
    /// The BTC transaction that needs to be signed.
    pub tx: Transaction,
    /// The public key used for the public key of the signers' UTXO output.
    pub signer_public_key: PublicKey,
    /// The amount of fees changed to each request.
    pub fee_per_request: u64,
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
    ///   5. The is no witness data for deposit UTXOs.
    pub fn new(requests: Vec<Request<'a>>, state: &SignerState) -> Result<Self, Error> {
        // Construct a transaction base. This transaction's inputs have
        // witness data with dummy signatures so that our virtual size
        // estimates are accurate. Later we will update the fees and
        // remove the witness data.
        let mut tx = Self::construct_transaction(&requests, state)?;
        // We now compute the fee that each request must pay given the
        // size of the transaction and the fee rate. Once we have the fee
        // we adjust the output amounts accordingly.
        let fee = Self::compute_request_fee(&tx, state.fee_rate);
        Self::adjust_amounts(&mut tx, fee);
        // Now we can reset the witness data.
        Self::reset_witness_data(&mut tx);

        Ok(Self {
            tx,
            requests,
            signer_public_key: state.public_key,
            fee_per_request: fee,
        })
    }

    /// Construct a "stub" BTC transaction from the given requests.
    ///
    /// The returned BTC transaction is signed with dummy signatures so it
    /// has the same virtual size as a proper transaction. Note that the
    /// output amounts haven't been adjusted for fees.
    ///
    /// An Err is returned if the amounts withdrawn is greater than the sum
    /// of all the input amounts.
    fn construct_transaction(reqs: &[Request], state: &SignerState) -> Result<Transaction, Error> {
        let sig = Self::generate_dummy_signature();

        let deposits = reqs
            .iter()
            .filter_map(|req| Some(req.as_deposit()?.as_tx_input(sig)));
        let withdrawals = reqs
            .iter()
            .filter_map(|req| Some(req.as_withdrawal()?.as_tx_output()));

        let signer_input = state.utxo.as_tx_input(&sig);
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

    /// Compute the fee that each deposit and withdrawal request must pay
    /// for the transaction given the fee rate
    ///
    /// If each deposit and withdrawal associated with this transaction
    /// paid the fees retured by this function then the fee rate for the
    /// entire transaction will be at least as much as the fee rate.
    ///
    /// Note that each deposit and withdrawal pays an equal amount for the
    /// transaction. To compute this amount we divide the total fee by the
    /// number of requests in the transaction.
    fn compute_request_fee(tx: &Transaction, fee_rate: u64) -> u64 {
        let tx_fee = tx.vsize() as u64 * fee_rate;
        let num_requests = (tx.input.len() + tx.output.len()).saturating_sub(2) as u64;
        tx_fee.div_ceil(num_requests)
    }

    /// Compute the final amount for the signers' UTXO given the current
    /// UTXO amount and the incomming requests.
    ///
    /// This amount does not take into account fees.
    fn compute_signer_amount(reqs: &[Request], state: &SignerState) -> Result<u64, Error> {
        let amount = reqs
            .iter()
            .fold(state.utxo.amount as i64, |amount, req| match req {
                Request::Deposit(req) => amount + req.amount as i64,
                Request::Withdrawal(req) => amount - req.amount as i64,
            });

        // This should never happen
        // TODO: Log this.
        if amount < 0 {
            return Err(Error::InvalidAmount(amount));
        }

        Ok(amount as u64)
    }

    /// Adjust the amounts for each output given the fee.
    ///
    /// This function adjusts each output by the given fee amount. The
    /// signers' UTXOs amount absorbs the fee on-chain that the depositors
    /// are supposed to pay. This amount must be accounted for when
    /// minting sBTC.
    fn adjust_amounts(tx: &mut Transaction, fee: u64) {
        // Since the first input and first output correspond to the signers'
        // UTXOs, we subtract them when computing the number of requests.
        let num_requests = (tx.input.len() + tx.output.len()).saturating_sub(2) as u64;
        // This is a bizarre case that should never happen.
        if num_requests == 0 {
            // TODO: logs
            return;
        }

        // The first output is the signer's UTXO. To determine the correct
        // amount for this UTXO deduct the fee payable by the depositors
        // from the currently set amount. This deduction is reflected in
        // the amount of sBTC minted to each depositor.
        if let Some(utxo_out) = tx.output.first_mut() {
            let deposit_fees = fee * (tx.input.len() - 1) as u64;
            let signers_amount = utxo_out.value.to_sat().saturating_sub(deposit_fees);
            utxo_out.value = Amount::from_sat(signers_amount);
        }
        // We now update the remaining withdrawal amounts to account for fees.
        tx.output.iter_mut().skip(1).for_each(|tx_out| {
            tx_out.value = Amount::from_sat(tx_out.value.to_sat().saturating_sub(fee));
        });
    }

    /// Helper function for generating dummy Schnorr signatures.
    fn generate_dummy_signature() -> Signature {
        let key_pair = Keypair::new_global(&mut secp256k1::rand::thread_rng());

        Signature {
            signature: key_pair.sign_schnorr(Message::from_digest([0; 32])),
            sighash_type: bitcoin::TapSighashType::Default,
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
    use std::str::FromStr;

    use super::*;
    use test_case::test_case;

    const PUBLIC_KEY: &'static str =
        "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";

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
            redeem_script: ScriptBuf::new(),
            taproot_public_key: PublicKey::from_str(PUBLIC_KEY).unwrap(),
            deposit_public_key: PublicKey::from_str(PUBLIC_KEY).unwrap(),
        };

        assert_eq!(deposit.votes_against(), expected);
    }

    #[test]
    fn deposit_witness_data_no_error() {
        let deposit = DepositRequest {
            outpoint: OutPoint::null(),
            max_fee: 0,
            signer_bitmap: Vec::new(),
            amount: 100_000,
            deposit_script: ScriptBuf::from_bytes(vec![1, 2, 3]),
            redeem_script: ScriptBuf::new(),
            taproot_public_key: PublicKey::from_str(PUBLIC_KEY).unwrap(),
            deposit_public_key: PublicKey::from_str(PUBLIC_KEY).unwrap(),
        };

        let sig = Signature::from_slice(&[0u8; 64]).unwrap();
        let witness = deposit.construct_witness_data(sig);
        assert!(witness.tapscript().is_some());

        let sig = UnsignedTransaction::generate_dummy_signature();
        let tx_in = deposit.as_tx_input(sig);
        assert!(tx_in.script_sig.is_empty());
    }
}
