//! Signer message definition for network communication

use blockstack_lib::chainstate::stacks;
use sha2::Digest;

#[cfg(feature = "testing")]
pub mod testing;

/// Messages exchanged between signers
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignerMessage {
    /// The bitcoin chain tip defining the signers view of the blockchain at the time the message was created
    pub bitcoin_chain_tip: bitcoin::BlockHash,
    /// The message payload
    pub payload: Payload,
}

/// The different variants of signer messages
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Payload {
    /// A decision related to signer deposit
    SignerDepositDecision(SignerDepositDecision),
    /// A decision related to signer withdrawal
    SignerWithdrawDecision(SignerWithdrawDecision),
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
}

impl Payload {
    /// Converts the payload into a signer message with the given Bitcoin chain tip
    pub fn to_message(self, bitcoin_chain_tip: bitcoin::BlockHash) -> SignerMessage {
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

impl From<SignerWithdrawDecision> for Payload {
    fn from(value: SignerWithdrawDecision) -> Self {
        Self::SignerWithdrawDecision(value)
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

/// Represents a decision related to signer deposit
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignerDepositDecision {
    /// ID of the transaction containing the deposit request.
    pub txid: bitcoin::Txid,
    /// Index of the deposit request UTXO.
    pub output_index: usize,
    /// Whether or not the signer has accepted the deposit request.
    pub accepted: bool,
}

/// Represents a decision related to signer withdrawal.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "testing", derive(fake::Dummy))]
pub struct SignerWithdrawDecision {
    /// ID of the withdraw request.
    pub request_id: u64,
    /// ID of the Stacks block containing the request.
    pub block_hash: StacksBlockHash,
    /// Whether or not the signer has accepted the deposit request.
    pub accepted: bool,
}

/// Represents a request to sign a Stacks transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StacksTransactionSignRequest {
    /// The transaction to sign.
    tx: stacks::StacksTransaction,
}

/// Represents a signature of a Stacks transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StacksTransactionSignature {
    /// Id of the signed transaction.
    txid: blockstack_lib::burnchains::Txid,
    /// An ECDSA signature over the transaction.
    signature: p256k1::ecdsa::Signature,
}

/// Represents a request to sign a Bitcoin transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinTransactionSignRequest {
    /// The transaction.
    tx: bitcoin::Transaction,
}

/// Represents an acknowledgment of a signed Bitcoin transaction.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BitcoinTransactionSignAck {
    /// The ID of the acknowledged transaction.
    txid: bitcoin::Txid,
}

/// A wsts message.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WstsMessage(wsts::net::Message);

impl wsts::net::Signable for SignerMessage {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SBTC_SIGNER_MESSAGE");
        hasher.update(self.bitcoin_chain_tip);
        self.payload.hash(hasher);
    }
}

impl wsts::net::Signable for Payload {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        match self {
            Self::WstsMessage(msg) => msg.0.hash(hasher),
            Self::SignerDepositDecision(msg) => msg.hash(hasher),
            Self::SignerWithdrawDecision(msg) => msg.hash(hasher),
            Self::BitcoinTransactionSignRequest(msg) => msg.hash(hasher),
            Self::BitcoinTransactionSignAck(msg) => msg.hash(hasher),
            Self::StacksTransactionSignRequest(msg) => msg.hash(hasher),
            Self::StacksTransactionSignature(msg) => msg.hash(hasher),
        }
    }
}

impl wsts::net::Signable for SignerDepositDecision {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_DEPOSIT_DECISION");
        hasher.update(self.txid);
        hasher.update(self.output_index.to_be_bytes());
        hasher.update([self.accepted as u8]);
    }
}

impl wsts::net::Signable for SignerWithdrawDecision {
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
        hasher.update("SIGNER_STACKS_TRANSACTION_SIGN_REQUEST");
        hasher.update(self.tx.txid());
    }
}

impl wsts::net::Signable for StacksTransactionSignature {
    fn hash(&self, hasher: &mut sha2::Sha256) {
        hasher.update("SIGNER_STACKS_TRANSACTION_SIGNATURE");
        hasher.update(self.txid);
        hasher.update(self.signature.to_bytes());
    }
}

/// Convenient type aliases
type StacksBlockHash = [u8; 32];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decode, Encode};
    use crate::ecdsa::{SignEcdsa, Signed};

    use p256k1::scalar::Scalar;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn signer_messages_should_be_signable() {
        assert_signer_messages_should_be_signable_with_type::<SignerDepositDecision>();
        assert_signer_messages_should_be_signable_with_type::<SignerWithdrawDecision>();
        assert_signer_messages_should_be_signable_with_type::<BitcoinTransactionSignRequest>();
        assert_signer_messages_should_be_signable_with_type::<BitcoinTransactionSignAck>();
        assert_signer_messages_should_be_signable_with_type::<StacksTransactionSignRequest>();
        assert_signer_messages_should_be_signable_with_type::<StacksTransactionSignature>();
        assert_signer_messages_should_be_signable_with_type::<WstsMessage>();
    }

    #[test]
    fn signer_messages_should_be_encodable() {
        assert_signer_messages_should_be_encodable_with_type::<SignerDepositDecision>();
        assert_signer_messages_should_be_encodable_with_type::<SignerWithdrawDecision>();
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
        let private_key = Scalar::from(rng.next_u32());

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
        let private_key = Scalar::from(rng.next_u32());

        let signed_message = SignerMessage::random_with_payload_type::<P, _>(rng)
            .sign_ecdsa(&private_key)
            .expect("Failed to sign message");

        let encoded = signed_message.encode_to_vec().expect("Failed to encode");

        let decoded =
            Signed::<SignerMessage>::decode(encoded.as_slice()).expect("Failed to decode");

        assert_eq!(decoded, signed_message);
    }
}
