use sha2::Digest;

#[derive(Debug, Clone, PartialEq)]
pub struct SignerMessage {
    /// The bitcoin chain tip defining the signers view of the blockchain at the time the message was created
    pub bitcoin_chain_tip: bitcoin::BlockHash,
    /// The message payload
    pub payload: Payload,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    SignerDepositDecision(SignerDepositDecision),
    SignerWithdrawDecision(SignerWithdrawDecision),
    StacksTransactionSignRequest(StacksTransactionSignRequest),
    StacksTransactionSignature(StacksTransactionSignature),
    BitcoinTransactionSignRequest(BitcoinTransactionSignRequest),
    BitcoinTransactionSignAck(BitcoinTransactionSignAck),
    /// Contains all variants for DKG and WSTS signing rounds
    WstsMessage(wsts::net::Message),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignerDepositDecision;

#[derive(Debug, Clone, PartialEq)]
pub struct SignerWithdrawDecision;

#[derive(Debug, Clone, PartialEq)]
pub struct StacksTransactionSignRequest;

#[derive(Debug, Clone, PartialEq)]
pub struct StacksTransactionSignature;

#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinTransactionSignRequest;

#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinTransactionSignAck;

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
            Self::WstsMessage(msg) => hash_message(msg, hasher),
            _ => unimplemented!(),
        }
    }
}

/// Utility method because wsts::net::Message doesn't implement wsts::net::Signable
fn hash_message(msg: &wsts::net::Message, hasher: &mut sha2::Sha256) {
    use wsts::net::Signable;

    match msg {
        wsts::net::Message::DkgBegin(msg) => msg.hash(hasher),
        wsts::net::Message::DkgPublicShares(msg) => msg.hash(hasher),
        wsts::net::Message::DkgPrivateBegin(msg) => msg.hash(hasher),
        wsts::net::Message::DkgPrivateShares(msg) => msg.hash(hasher),
        wsts::net::Message::DkgEndBegin(msg) => msg.hash(hasher),
        wsts::net::Message::DkgEnd(msg) => msg.hash(hasher),
        wsts::net::Message::NonceRequest(msg) => msg.hash(hasher),
        wsts::net::Message::NonceResponse(msg) => msg.hash(hasher),
        wsts::net::Message::SignatureShareRequest(msg) => msg.hash(hasher),
        wsts::net::Message::SignatureShareResponse(msg) => msg.hash(hasher),
    }
}
