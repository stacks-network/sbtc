//! Signer message definition for network communication

use secp256k1::ecdsa::RecoverableSignature;

use crate::bitcoin::utxo::Fees;
use crate::bitcoin::validation::TxRequestIds;
use crate::keys::PublicKey;
use crate::stacks::contracts::ContractCall;
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
    /// Contains all variants for DKG and WSTS signing rounds
    WstsMessage(WstsMessage),
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

impl StacksTransactionSignRequest {
    /// Return the kind of transaction that that is being asked to be
    /// signed.
    pub fn tx_kind(&self) -> &'static str {
        match &self.contract_tx {
            StacksTx::ContractCall(ContractCall::CompleteDepositV1(_)) => "complete-deposit",
            StacksTx::ContractCall(ContractCall::AcceptWithdrawalV1(_)) => "accept-withdrawal",
            StacksTx::ContractCall(ContractCall::RejectWithdrawalV1(_)) => "reject-withdrawal",
            StacksTx::ContractCall(ContractCall::RotateKeysV1(_)) => "rotate-keys",
            StacksTx::SmartContract(_) => "smart-contract-deployment",
        }
    }
}

/// Represents a signature of a Stacks transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct StacksTransactionSignature {
    /// Id of the signed transaction.
    pub txid: blockstack_lib::burnchains::Txid,
    /// A recoverable ECDSA signature over the transaction.
    pub signature: RecoverableSignature,
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
    #[test_case(PhantomData::<WstsMessage> ; "WstsMessage")]
    #[test_case(PhantomData::<BitcoinPreSignRequest> ; "BitcoinPreSignRequest")]
    fn signer_messages_should_be_signable_with_type<P>(_: PhantomData<P>)
    where
        P: fake::Dummy<fake::Faker> + Into<Payload>,
    {
        let rng = &mut rand::rngs::StdRng::seed_from_u64(1337);
        let private_key = PrivateKey::new(rng);

        let signed_message =
            SignerMessage::random_with_payload_type::<P, _>(rng).sign_ecdsa(&private_key);

        assert!(signed_message.verify());
    }

    #[test_case(PhantomData::<SignerDepositDecision> ; "SignerDepositDecision")]
    #[test_case(PhantomData::<SignerWithdrawalDecision> ; "SignerWithdrawalDecision")]
    #[test_case(PhantomData::<StacksTransactionSignRequest> ; "StacksTransactionSignRequest")]
    #[test_case(PhantomData::<StacksTransactionSignature> ; "StacksTransactionSignature")]
    #[test_case(PhantomData::<WstsMessage> ; "WstsMessage")]
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
