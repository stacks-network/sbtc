/// Configuration error variants.
#[derive(Debug, thiserror::Error)]
pub enum SignerConfigError {
    /// Invalid Stacks private key length
    #[error("The Stacks private key provided is invalid, it must be either 64 or 66 hex characters long, got {0}")]
    InvalidStacksPrivateKeyLength(usize),

    /// Invalid Stacks private key compression byte marker
    #[error("The Stacks private key provided contains an invalid compression byte marker: {0}")]
    InvalidStacksPrivateKeyCompressionByte(String),

    /// Invalid P2P URI
    #[error("Invalid P2P URI: Failed to parse: {0}")]
    InvalidP2PUri(#[from] url::ParseError),

    /// The NetworkKind set in the config must match the network kind of
    /// the deployer address.
    #[error("The network set in the config must match the network kind of the deployer address")]
    NetworkDeployerMismatch,

    /// Invalid P2P URI
    #[error("Invalid P2P URI: Only schemes 'tcp' and 'quic-v1' are supported; got '{0}'")]
    InvalidP2PScheme(String),

    /// P2P port is required
    #[error("Invalid P2P URI: Port is required")]
    P2PPortRequired,

    /// P2P paths not supported
    #[error("Invalid P2P URI: Paths are not supported: '{0}'")]
    P2PPathsNotSupported(String),

    /// Usernames are not supported in P2P URIs
    #[error("Invalid P2P URI: Usernames are not supported: '{0}'")]
    P2PUsernameNotSupported(String),

    /// Passwords are not supported in P2P URIs
    #[error("Invalid P2P URI: Passwords are not supported: '{0}'")]
    P2PPasswordNotSupported(String),

    /// Query strings are not supported in P2P URIs
    #[error("Invalid P2P URI: Query strings are not supported: '{0}'")]
    P2PQueryStringsNotSupported(String),

    /// P2P host is required
    #[error("Invalid P2P URI: Host is required")]
    P2PHostRequired,

    /// When the network kind is 'mainnet' or 'testnet', at least one P2P seed peer is required.
    /// Otherwise, we'll allow mDNS to discover any local peers (for testing).
    #[error(
        "At least one P2P seed peer is required when the network kind is 'mainnet' or 'testnet'."
    )]
    P2PSeedPeerRequired,

    /// Unsupported database driver
    #[error("Unsupported database driver: {0}. Supported drivers are: 'postgresql'.")]
    UnsupportedDatabaseDriver(String),

    /// An error for a bitcoin_processing_delay value that exceeded the
    /// [`crate::config::MAX_BITCOIN_PROCESSING_DELAY_SECONDS`].
    #[error("The provided Bitcoin processing delay must be small than {0}s, got {1}s")]
    InvalidBitcoinProcessingDelay(u64, u64),

    /// An error returned for duration parameters that must be positive.
    #[error("Duration for {0} must be nonzero")]
    ZeroDurationForbidden(&'static str),
}
