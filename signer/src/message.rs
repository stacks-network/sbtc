use p256k1::ecdsa;

#[derive(Debug, Clone, PartialEq)]
pub struct SignerMessage {
    /// The message payload
    pub payload: Payload,
    /// The bitcoin chain tip defining the signers view of the blockchain at the time the message was created
    pub bitcoin_chain_tip: bitcoin::BlockHash,
    /// The public key of the signer
    pub signer_pub_key: ecdsa::PublicKey,
    /// A signature over the payload and chain tip verifiable by the public key
    pub signature: ecdsa::Signature,
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
