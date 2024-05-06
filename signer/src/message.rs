use p256k1::ecdsa;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub enum Payload {}
