//! Signer message definition for network communication

use bitcoin::OutPoint;
use secp256k1::ecdsa::RecoverableSignature;
use sha2::Digest;

use crate::bitcoin::utxo::Fees;
use crate::bitcoin::validation::TxRequestIds;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey as _;
use crate::signature::RecoverableEcdsaSignature as _;
use crate::stacks::contracts::StacksTx;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::QualifiedRequestId;
use crate::storage::model::StacksTxId;

/// Messages exchanged between signers
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignerMessage {
    /// The bitcoin chain tip defining the signers view of the blockchain at the time the message was created
    pub bitcoin_chain_tip: BitcoinBlockHash,
    /// The message payload
    pub payload: Payload,
}

/// The different variants of signer messages
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Payload {
    /// A decision related to signer deposit
    SignerDepositDecision(SignerDepositDecision),
    /// A decision related to signer withdrawal
    SignerWithdrawalDecision(SignerWithdrawalDecision),
    /// A request to sign a Stacks transaction
    StacksTransactionSignRequest(StacksTransactionSignRequest),
    /// A signature of a Stacks transaction
    StacksTransactionSignature(StacksTransactionSignature),
    /// A request to sign a Bitcoin transaction
    BitcoinTransactionSignRequest(BitcoinTransactionSignRequest),
    /// An acknowledgment of a signed Bitcoin transaction
    BitcoinTransactionSignAck(BitcoinTransactionSignAck),
    /// Contains all variants for DKG and WSTS signing rounds
    WstsMessage(WstsMessage),
    /// Information about a new sweep transaction
    SweepTransactionInfo(SweepTransactionInfo),
    /// Information about a new Bitcoin block sign request
    BitcoinPreSignRequest(BitcoinPreSignRequest),
    /// An acknowledgment of a BitconPreSignRequest
    BitcoinPreSignAck(BitcoinPreSignAck),
}

impl std::fmt::Display for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignerDepositDecision(_) => write!(f, "SignerDepositDecision(..)"),
            Self::SignerWithdrawalDecision(_) => write!(f, "SignerWithdrawDecision(..)"),
            Self::StacksTransactionSignRequest(_) => write!(f, "StacksTransactionSignRequest(..)"),
            Self::StacksTransactionSignature(_) => write!(f, "StacksTransactionSignature(..)"),
            Self::BitcoinTransactionSignRequest(_) => {
                write!(f, "BitcoinTransactionSignRequest(..)")
            }
            Self::BitcoinTransactionSignAck(_) => write!(f, "BitcoinTransactionSignAck(..)"),
            Self::WstsMessage(msg) => {
                write!(f, "WstsMessage(")?;
                match msg.inner {
                    wsts::net::Message::DkgBegin(_) => write!(f, "DkgBegin(..)")?,
                    wsts::net::Message::DkgEnd(_) => write!(f, "DkgEnd(..)")?,
                    wsts::net::Message::DkgEndBegin(_) => write!(f, "DkgEndBegin(..)")?,
                    wsts::net::Message::DkgPrivateBegin(_) => write!(f, "DkgPrivateBegin(..)")?,
                    wsts::net::Message::DkgPrivateShares(_) => write!(f, "DkgPrivateShares(..)")?,
                    wsts::net::Message::DkgPublicShares(_) => write!(f, "DkgPublicShares(..)")?,
                    wsts::net::Message::NonceRequest(_) => write!(f, "NonceRequest(..)")?,
                    wsts::net::Message::NonceResponse(_) => write!(f, "NonceResponse(..)")?,
                    wsts::net::Message::SignatureShareRequest(_) => {
                        write!(f, "SignatureShareRequest(..)")?
                    }
                    wsts::net::Message::SignatureShareResponse(_) => {
                        write!(f, "SignatureShareResponse(..)")?
                    }
                }
                write!(f, ")")
            }
            Self::SweepTransactionInfo(_) => write!(f, "SweepTransactionInfo(..)"),
            Self::BitcoinPreSignRequest(_) => write!(f, "BitcoinPreSignRequest(..)"),
            Self::BitcoinPreSignAck(_) => write!(f, "BitcoinPreSignAck(..)"),
        }
    }
}

impl Payload {
    /// Converts the payload into a signer message with the given Bitcoin chain tip
    pub fn to_message(self, bitcoin_chain_tip: BitcoinBlockHash) -> SignerMessage {
        SignerMessage {
            bitcoin_chain_tip,
            payload: self,
        }
    }
}

impl From<SignerDepositDecision> for Payload {
    fn from(value: SignerDepositDecision) -> Self {
        Self::SignerDepositDecision(value)
    }
}

impl From<SignerWithdrawalDecision> for Payload {
    fn from(value: SignerWithdrawalDecision) -> Self {
        Self::SignerWithdrawalDecision(value)
    }
}

impl From<BitcoinTransactionSignRequest> for Payload {
    fn from(value: BitcoinTransactionSignRequest) -> Self {
        Self::BitcoinTransactionSignRequest(value)
    }
}

impl From<BitcoinTransactionSignAck> for Payload {
    fn from(value: BitcoinTransactionSignAck) -> Self {
        Self::BitcoinTransactionSignAck(value)
    }
}

impl From<StacksTransactionSignRequest> for Payload {
    fn from(value: StacksTransactionSignRequest) -> Self {
        Self::StacksTransactionSignRequest(value)
    }
}

impl From<StacksTransactionSignature> for Payload {
    fn from(value: StacksTransactionSignature) -> Self {
        Self::StacksTransactionSignature(value)
    }
}

impl From<WstsMessage> for Payload {
    fn from(value: WstsMessage) -> Self {
        Self::WstsMessage(value)
    }
}

impl From<SweepTransactionInfo> for Payload {
    fn from(value: SweepTransactionInfo) -> Self {
        Self::SweepTransactionInfo(value)
    }
}

impl From<BitcoinPreSignRequest> for Payload {
    fn from(value: BitcoinPreSignRequest) -> Self {
        Self::BitcoinPreSignRequest(value)
    }
}

impl From<BitcoinPreSignAck> for Payload {
    fn from(value: BitcoinPreSignAck) -> Self {
        Self::BitcoinPreSignAck(value)
    }
}

/// Represents information about a new sweep transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SweepTransactionInfo {
    /// The Bitcoin transaction id of the sweep transaction.
    pub txid: bitcoin::Txid,
    /// The transaction id of the signer UTXO consumed by this transaction.
    pub signer_prevout_txid: bitcoin::Txid,
    /// The index of the signer UTXO consumed by this transaction.
    pub signer_prevout_output_index: u32,
    /// The amount of the signer UTXO consumed by this transaction.
    pub signer_prevout_amount: u64,
    /// The public key of the signer UTXO consumed by this transaction.
    pub signer_prevout_script_pubkey: bitcoin::ScriptBuf,
    /// The total **output** amount of this transaction.
    pub amount: u64,
    /// The fee paid for this transaction.
    pub fee: u64,
    /// The virtual size of this transaction (in bytes).
    pub vsize: u32,
    /// The Bitcoin block hash at which this transaction was created.
    pub created_at_block_hash: bitcoin::BlockHash,
    /// The market fee rate at the time of this transaction.
    pub market_fee_rate: f64,
    /// List of deposits which were swept-in by this transaction.
    pub swept_deposits: Vec<SweptDeposit>,
    /// List of withdrawals which were swept-out by this transaction.
    pub swept_withdrawals: Vec<SweptWithdrawal>,
}

impl SweepTransactionInfo {
    /// Creates a [`SweepTransactionInfo`] from an [`UnsignedTransaction`] and a
    /// Bitcoin block hash.
    pub fn from_unsigned_at_block(
        block_hash: &bitcoin::BlockHash,
        unsigned: &crate::bitcoin::utxo::UnsignedTransaction,
    ) -> SweepTransactionInfo {
        let swept_deposits = unsigned
            .requests
            .iter()
            .filter_map(|request| request.as_deposit())
            .enumerate()
            .map(|(index, request)| {
                SweptDeposit {
                    input_index: index as u32 + 1, // Account for the signer's UTXO
                    deposit_request_txid: request.outpoint.txid,
                    deposit_request_output_index: request.outpoint.vout,
                }
            })
            .collect();

        let swept_withdrawals = unsigned
            .requests
            .iter()
            .filter_map(|request| request.as_withdrawal())
            .enumerate()
            .map(|(index, withdrawal)| {
                SweptWithdrawal {
                    output_index: index as u32 + 2, // Account for the signer's UTXO and OP_RETURN
                    withdrawal_request_id: withdrawal.request_id,
                    withdrawal_request_block_hash: *withdrawal.block_hash.as_bytes(),
                }
            })
            .collect();

        SweepTransactionInfo {
            txid: unsigned.tx.compute_txid(),
            signer_prevout_txid: unsigned.signer_utxo.utxo.outpoint.txid,
            signer_prevout_output_index: unsigned.signer_utxo.utxo.outpoint.vout,
            signer_prevout_amount: unsigned.signer_utxo.utxo.amount,
            signer_prevout_script_pubkey: unsigned
                .signer_utxo
                .utxo
                .public_key
                .signers_script_pubkey(),
            amount: unsigned.output_amounts(),
            fee: unsigned.tx_fee,
            vsize: unsigned.tx_vsize,
            market_fee_rate: unsigned.signer_utxo.fee_rate,
            created_at_block_hash: *block_hash,
            swept_deposits,
            swept_withdrawals,
        }
    }
}

/// Represents information about a deposit request being swept-in by a sweep transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SweptDeposit {
    /// The index of the deposit input in the sBTC sweep transaction.
    pub input_index: u32,
    /// The Bitcoin txid of the deposit request UTXO being swept-in by this
    /// transaction.
    pub deposit_request_txid: bitcoin::Txid,
    /// The Bitcoin output index of the deposit request UTXO being swept-in by
    /// this transaction.
    pub deposit_request_output_index: u32,
}

/// Represents information about a withdrawal request being swept-out by a sweep transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SweptWithdrawal {
    /// The index of the withdrawal output in the sBTC sweep transaction.
    pub output_index: u32,
    /// The public request id of the withdrawal request serviced by this
    /// transaction.
    pub withdrawal_request_id: u64,
    /// The Stacks block hash of the Stacks block which included the withdrawal
    /// request transaction.
    pub withdrawal_request_block_hash: StacksBlockHash,
}

/// Represents a decision related to signer deposit
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignerDepositDecision {
    /// ID of the transaction containing the deposit request.
    pub txid: bitcoin::Txid,
    /// Index of the deposit request UTXO.
    pub output_index: u32,
    /// This specifies whether the sending signer's blocklist client
    /// blocked the deposit request. `true` here means the blocklist client
    /// did not block the request.
    pub can_accept: bool,
    /// This specifies whether the sending signer can provide signature
    /// shares for the associated deposit request.
    pub can_sign: bool,
}

/// Represents a decision related to signer withdrawal.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SignerWithdrawalDecision {
    /// ID of the withdrawal request.
    pub request_id: u64,
    /// ID of the Stacks block containing the request.
    pub block_hash: StacksBlockHash,
    /// The stacks transaction ID that lead to the creation of the
    /// withdrawal request.
    pub txid: StacksTxId,
    /// Whether the signer has accepted the deposit request.
    pub accepted: bool,
}

/// Represents a request to sign a Stacks transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StacksTransactionSignRequest {
    /// This is the bitcoin aggregate key that was output from DKG. It is used
    /// to identify the signing set for the transaction.
    pub aggregate_key: PublicKey,
    /// The contract call transaction to sign.
    pub contract_tx: StacksTx,
    /// The nonce to use for the transaction.
    pub nonce: u64,
    /// The transaction fee in microSTX.
    pub tx_fee: u64,
    /// The expected digest of the transaction than needs to be signed.
    /// It's essentially a hash of the contract call struct, the nonce, the
    /// tx_fee and a few other things.
    pub digest: [u8; 32],
    /// The transaction ID of the associated contract call transaction.
    pub txid: blockstack_lib::burnchains::Txid,
}

/// Represents a signature of a Stacks transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StacksTransactionSignature {
    /// Id of the signed transaction.
    pub txid: blockstack_lib::burnchains::Txid,
    /// A recoverable ECDSA signature over the transaction.
    #[serde(with = "crate::signature::serde_utils")]
    pub signature: RecoverableSignature,
}

/// Represents a request to sign a Bitcoin transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinTransactionSignRequest {
    /// The transaction.
    pub tx: bitcoin::Transaction,
    /// The aggregate key used to sign the transaction,
    pub aggregate_key: PublicKey,
}

/// Represents an acknowledgment of a signed Bitcoin transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinTransactionSignAck {
    /// The ID of the acknowledged transaction.
    pub txid: bitcoin::Txid,
}

/// The message version of an the [`OutPoint`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct OutPointMessage {
    /// The referenced transaction's txid.
    pub txid: bitcoin::Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}

impl From<OutPoint> for OutPointMessage {
    fn from(outpoint: OutPoint) -> Self {
        OutPointMessage {
            txid: outpoint.txid,
            vout: outpoint.vout,
        }
    }
}

impl From<OutPointMessage> for OutPoint {
    fn from(val: OutPointMessage) -> Self {
        OutPoint { txid: val.txid, vout: val.vout }
    }
}

/// The transaction context needed by the signers to reconstruct the transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinPreSignRequest {
    /// The set of sBTC request identifiers. This contains each of the
    /// requests for the entire transaction package. Each element in the
    /// vector corresponds to the requests that will be included in a
    /// single bitcoin transaction.
    pub request_package: Vec<TxRequestIds>,
    /// The current market fee rate in sat/vByte.
    pub fee_rate: f64,
    /// The total fee amount and the fee rate for the last transaction that
    /// used this UTXO as an input.
    pub last_fees: Option<Fees>,
}

/// An acknowledgment of a [`BitcoinPreSignRequest`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinPreSignAck;

/// A wsts message.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WstsMessage {
    /// The transaction ID this message relates to,
    /// will be a dummy ID for DKG messages
    pub txid: bitcoin::Txid,
    /// The wsts message
    pub inner: wsts::net::Message,
}

impl wsts::net::Signable for SignerMessage {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SBTC_SIGNER_MESSAGE");
        hasher.update(self.bitcoin_chain_tip.as_ref());
        self.payload.hash(hasher);
    }
}

impl wsts::net::Signable for Payload {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        match self {
            Self::WstsMessage(msg) => msg.hash(hasher),
            Self::SignerDepositDecision(msg) => msg.hash(hasher),
            Self::SignerWithdrawalDecision(msg) => msg.hash(hasher),
            Self::BitcoinTransactionSignRequest(msg) => msg.hash(hasher),
            Self::BitcoinTransactionSignAck(msg) => msg.hash(hasher),
            Self::StacksTransactionSignRequest(msg) => msg.hash(hasher),
            Self::StacksTransactionSignature(msg) => msg.hash(hasher),
            Self::SweepTransactionInfo(msg) => msg.hash(hasher),
            Self::BitcoinPreSignRequest(msg) => msg.hash(hasher),
            Self::BitcoinPreSignAck(msg) => msg.hash(hasher),
        }
    }
}

impl wsts::net::Signable for SweepTransactionInfo {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SWEEP_TRANSACTION_INFO");
        hasher.update(self.txid);
        hasher.update(self.signer_prevout_txid);
        hasher.update(self.signer_prevout_output_index.to_be_bytes());
        hasher.update(self.signer_prevout_amount.to_be_bytes());
        hasher.update(self.signer_prevout_script_pubkey.as_bytes());
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.fee.to_be_bytes());
        hasher.update(self.created_at_block_hash);
        hasher.update(self.market_fee_rate.to_be_bytes());
        for deposit in &self.swept_deposits {
            deposit.hash(hasher);
        }
        for withdrawal in &self.swept_withdrawals {
            withdrawal.hash(hasher);
        }
    }
}

impl wsts::net::Signable for SweptDeposit {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update(self.input_index.to_be_bytes());
        hasher.update(self.deposit_request_txid);
        hasher.update(self.deposit_request_output_index.to_be_bytes());
    }
}

impl wsts::net::Signable for SweptWithdrawal {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update(self.output_index.to_be_bytes());
        hasher.update(self.withdrawal_request_id.to_be_bytes());
        hasher.update(self.withdrawal_request_block_hash);
    }
}

impl wsts::net::Signable for SignerDepositDecision {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_DEPOSIT_DECISION");
        hasher.update(self.txid);
        hasher.update(self.output_index.to_be_bytes());
        hasher.update([self.can_accept as u8]);
    }
}

impl wsts::net::Signable for SignerWithdrawalDecision {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_WITHDRAW_DECISION");
        hasher.update(self.request_id.to_be_bytes());
        hasher.update(self.block_hash);
        hasher.update([self.accepted as u8]);
    }
}

impl wsts::net::Signable for BitcoinTransactionSignRequest {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_BITCOIN_TRANSACTION_SIGN_REQUEST");
        hasher.update(bitcoin::consensus::serialize(&self.tx));
    }
}

impl wsts::net::Signable for BitcoinTransactionSignAck {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_BITCOIN_TRANSACTION_SIGN_ACK");
        hasher.update(self.txid);
    }
}

impl wsts::net::Signable for StacksTransactionSignRequest {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        // The digest is supposed to be a hash of the contract call data,
        // the nonce, the fee and a few more things.
        hasher.update("SIGNER_STACKS_TRANSACTION_SIGN_REQUEST");
        hasher.update(self.digest);
        hasher.update(self.aggregate_key.serialize());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(self.tx_fee.to_be_bytes());
    }
}

impl wsts::net::Signable for StacksTransactionSignature {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_STACKS_TRANSACTION_SIGNATURE");
        hasher.update(self.txid);
        hasher.update(self.signature.to_byte_array());
    }
}

impl wsts::net::Signable for WstsMessage {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_WSTS_MESSAGE");
        hasher.update(self.txid);
        self.inner.hash(hasher);
    }
}

impl wsts::net::Signable for OutPointMessage {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update(self.txid);
        hasher.update(self.vout.to_be_bytes());
    }
}

impl wsts::net::Signable for QualifiedRequestId {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update(self.request_id.to_be_bytes());
        hasher.update(self.txid.as_bytes());
        hasher.update(self.block_hash.as_bytes());
    }
}

impl wsts::net::Signable for TxRequestIds {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        for deposit in &self.deposits {
            deposit.hash(hasher);
        }
        for withdrawal in &self.withdrawals {
            withdrawal.hash(hasher);
        }
    }
}

impl wsts::net::Signable for BitcoinPreSignRequest {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_NEW_BITCOIN_TX_CONTEXT");
        for request in &self.request_package {
            request.hash(hasher);
        }
        hasher.update(self.fee_rate.to_be_bytes());
    }
}

impl wsts::net::Signable for BitcoinPreSignAck {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_BITCOIN_PRE_SIGN_ACK")
    }
}

/// Convenient type aliases
type StacksBlockHash = [u8; 32];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decode, Encode};
    use crate::ecdsa::{SignEcdsa, Signed};
    use crate::keys::PrivateKey;

    use rand::SeedableRng;

    #[test]
    fn signer_messages_should_be_signable() {
        assert_signer_messages_should_be_signable_with_type::<SignerDepositDecision>();
        assert_signer_messages_should_be_signable_with_type::<SignerWithdrawalDecision>();
        assert_signer_messages_should_be_signable_with_type::<BitcoinTransactionSignRequest>();
        assert_signer_messages_should_be_signable_with_type::<BitcoinTransactionSignAck>();
        assert_signer_messages_should_be_signable_with_type::<StacksTransactionSignRequest>();
        assert_signer_messages_should_be_signable_with_type::<StacksTransactionSignature>();
        assert_signer_messages_should_be_signable_with_type::<WstsMessage>();
    }

    #[test]
    fn signer_messages_should_be_encodable() {
        assert_signer_messages_should_be_encodable_with_type::<SignerDepositDecision>();
        assert_signer_messages_should_be_encodable_with_type::<SignerWithdrawalDecision>();
        assert_signer_messages_should_be_encodable_with_type::<BitcoinTransactionSignRequest>();
        assert_signer_messages_should_be_encodable_with_type::<BitcoinTransactionSignAck>();
        assert_signer_messages_should_be_encodable_with_type::<StacksTransactionSignRequest>();
        assert_signer_messages_should_be_encodable_with_type::<StacksTransactionSignature>();
        assert_signer_messages_should_be_encodable_with_type::<WstsMessage>();
    }

    fn assert_signer_messages_should_be_signable_with_type<P>()
    where
        P: fake::Dummy<fake::Faker> + Into<Payload>,
    {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(1337);
        let private_key = PrivateKey::new(rng);

        let signed_message = SignerMessage::random_with_payload_type::<P, _>(rng)
            .sign_ecdsa(&private_key)
            .expect("Failed to sign message");

        assert!(signed_message.verify());
    }

    fn assert_signer_messages_should_be_encodable_with_type<P>()
    where
        P: fake::Dummy<fake::Faker> + Into<Payload>,
    {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(42);
        let private_key = PrivateKey::new(rng);

        let signed_message = SignerMessage::random_with_payload_type::<P, _>(rng)
            .sign_ecdsa(&private_key)
            .expect("Failed to sign message");

        let encoded = signed_message.clone().encode_to_vec();

        let decoded =
            Signed::<SignerMessage>::decode(encoded.as_slice()).expect("Failed to decode");

        assert_eq!(decoded, signed_message);
    }
}
