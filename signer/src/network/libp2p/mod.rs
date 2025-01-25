//! The libp2p module contains the libp2p network implementation for the signer.

use std::sync::LazyLock;

use libp2p::gossipsub::IdentTopic;

mod bootstrap;
mod errors;
mod event_loop;
mod multiaddr;
mod network;
mod swarm;

pub use self::errors::SignerSwarmError;
pub use self::multiaddr::MultiaddrExt;
pub use self::network::P2PNetwork;
pub use self::swarm::SignerSwarmBuilder;

/// The default port for the libp2p network
pub const DEFAULT_P2P_PORT: u16 = 4122;

/// The topic used for signer gossipsub messages
// NOTE: Using LazyLock (static) instead of LazyCell (const) as IdentTopic is interior mutable.
pub static TOPIC: LazyLock<IdentTopic> = LazyLock::new(|| IdentTopic::new("sbtc-signer"));
