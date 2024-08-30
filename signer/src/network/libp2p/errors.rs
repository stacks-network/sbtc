use libp2p::gossipsub::{PublishError, SubscriptionError};
use libp2p::TransportError;

/// Errors that can occur when using the libp2p network
#[derive(Debug, thiserror::Error)]
pub enum SignerSwarmError {
    /// An error occurred while decoding a keypair
    #[error("Error decoding a private key to a keypair: {0}")]
    KeyDecodingError(#[from] libp2p::identity::DecodingError),

    /// LibP2P builder error
    #[error("libp2p builder error: {0}")]
    Builder(&'static str),

    /// LibP2P error
    #[error("libp2p error: {0}")]
    LibP2P(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// LibP2P error (with custom message)
    #[error("libp2p error: {0}")]
    LibP2PMessage(&'static str),

    /// An error occurred while subscribing to a topic
    #[error("libp2p subscription error: {0}")]
    Subscription(#[from] SubscriptionError),

    /// LibP2P swarm error
    #[error("libp2p swarm error: {0}")]
    Swarm(String),

    /// An error occurred while publishing (broadcasting) a message
    #[error("libp2p broadcast error: {0}")]
    Publish(#[from] PublishError),

    /// An error occurred while receiving a message
    #[error("libp2p receive error: {0}")]
    Receive(String),

    /// An error occurred while decoding a message
    #[error("bincode error: {0}")]
    Bincode(#[from] bincode::Error),

    /// A transport error occurred
    #[error("transport error: {0}")]
    Transport(#[from] TransportError<std::io::Error>),

    /// An error occurred while dialing a peer
    #[error("dial error: {0}")]
    Dial(#[from] libp2p::swarm::DialError),

    /// An error occurred while parsing a multiaddr
    #[error("multiaddr error: {0}")]
    ParseMultiAddr(#[from] libp2p::multiaddr::Error),

    /// An error occurred while parsing a URL
    #[error("url parse error: {0}")]
    ParseUrl(#[from] url::ParseError),

    /// A general locking error occurred.
    #[error("Locking error")]
    LockingError,

    /// An error occurred while sending a message on an MPSC channel
    #[error("Error sending message on MPSC channel: {0}")]
    MpscSendError(#[from] futures::channel::mpsc::SendError),
}
