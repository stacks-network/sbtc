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
}
