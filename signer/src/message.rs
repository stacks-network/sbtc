//! Signer message definition for network communication

use secp256k1::ecdsa::RecoverableSignature;

use crate::bitcoin::utxo::Fees;
use crate::bitcoin::validation::TxRequestIds;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey as _;
use crate::stacks::contracts::StacksTx;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::StacksTxId;

/// Messages exchanged between signers
#[derive(Debug, Clone, PartialEq)]
pub struct SignerMessage {
    /// The bitcoin chain tip defining the signers view of the blockchain at the time the message was created
    pub bitcoin_chain_tip: BitcoinBlockHash,
    /// The message payload
    pub payload: Payload,
}

/// The different variants of signer messages
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
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
    /// The transaction ID of the associated contract call transaction.
    pub txid: blockstack_lib::burnchains::Txid,
}

/// Represents a signature of a Stacks transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct StacksTransactionSignature {
    /// Id of the signed transaction.
    pub txid: blockstack_lib::burnchains::Txid,
    /// A recoverable ECDSA signature over the transaction.
    pub signature: RecoverableSignature,
}

/// Represents a request to sign a Bitcoin transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinTransactionSignRequest {
    /// The transaction.
    pub tx: bitcoin::Transaction,
    /// The aggregate key used to sign the transaction,
    pub aggregate_key: PublicKey,
}

/// Represents an acknowledgment of a signed Bitcoin transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinTransactionSignAck {
    /// The ID of the acknowledged transaction.
    pub txid: bitcoin::Txid,
}

/// The transaction context needed by the signers to reconstruct the transaction.
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub struct WstsMessage {
    /// The transaction ID this message relates to,
    /// will be a dummy ID for DKG messages
    pub txid: bitcoin::Txid,
    /// The wsts message
    pub inner: wsts::net::Message,
}

/// Convenient type aliases
type StacksBlockHash = [u8; 32];

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;
    use crate::codec::{Decode, Encode};
    use crate::ecdsa::{SignEcdsa, Signed};
    use crate::keys::PrivateKey;

    use rand::SeedableRng;
    use test_case::test_case;

    #[test_case(PhantomData::<SignerDepositDecision> ; "SignerDepositDecision")]
    #[test_case(PhantomData::<SignerWithdrawalDecision> ; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<StacksTransactionSignRequest> ; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<StacksTransactionSignature> ; "StacksTransactionSignature")]
    #[test_case(PhantomData::<BitcoinTransactionSignRequest> ; "BitcoinTransactionSignRequest")]
    #[test_case(PhantomData::<BitcoinTransactionSignAck> ; "BitcoinTransactionSignAck")]
    #[test_case(PhantomData::<WstsMessage> ; "WstsMessage")]
    #[test_case(PhantomData::<SweepTransactionInfo> ; "SweepTransactionInfo")]
    #[test_case(PhantomData::<BitcoinPreSignRequest> ; "BitcoinPreSignRequest")]
    fn signer_messages_should_be_signable_with_type<P>(_: PhantomData<P>)
    where
        P: fake::Dummy<fake::Faker> + Into<Payload>,
    {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(1337);
        let private_key = PrivateKey::new(rng);
        let public_key = PublicKey::from_private_key(&private_key);

        let signed_message =
            SignerMessage::random_with_payload_type::<P, _>(rng).sign_ecdsa(&private_key);

        assert!(signed_message.verify(public_key));
    }

    #[test_case(PhantomData::<SignerDepositDecision> ; "SignerDepositDecision")]
    #[test_case(PhantomData::<SignerWithdrawalDecision> ; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<StacksTransactionSignRequest> ; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<StacksTransactionSignature> ; "StacksTransactionSignature")]
    #[test_case(PhantomData::<BitcoinTransactionSignRequest> ; "BitcoinTransactionSignRequest")]
    #[test_case(PhantomData::<BitcoinTransactionSignAck> ; "BitcoinTransactionSignAck")]
    #[test_case(PhantomData::<WstsMessage> ; "WstsMessage")]
    #[test_case(PhantomData::<SweepTransactionInfo> ; "SweepTransactionInfo")]
    #[test_case(PhantomData::<BitcoinPreSignRequest> ; "BitcoinPreSignRequest")]
    fn signer_messages_should_be_encodable_with_type<P>(_: PhantomData<P>)
    where
        P: fake::Dummy<fake::Faker> + Into<Payload>,
    {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(42);
        let private_key = PrivateKey::new(rng);

        let signed_message =
            SignerMessage::random_with_payload_type::<P, _>(rng).sign_ecdsa(&private_key);

        let encoded = signed_message.clone().encode_to_vec();

        let decoded =
            Signed::<SignerMessage>::decode(encoded.as_slice()).expect("Failed to decode");

        assert_eq!(decoded, signed_message);
    }
}
