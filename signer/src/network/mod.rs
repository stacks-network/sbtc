//! # Signer network interface
//!
//! This module provides the MessageTransfer trait that the signer implementation
//! will rely on for inter-signer communication, along with an in-memory
//! implementation of this trait for testing purposes.

#[cfg(any(test, feature = "testing"))]
pub mod in_memory;

pub mod libp2p;

use std::future::Future;

use crate::ecdsa;
use crate::error::Error;
use crate::message;

#[cfg(any(test, feature = "testing"))]
pub use in_memory::InMemoryNetwork;
pub use libp2p::P2PNetwork;

/// The supported message type of the signer network
pub type Msg = ecdsa::Signed<message::SignerMessage>;
/// The unique identifier for a message
pub type MsgId = [u8; 32];

/// Represents the interaction point between signers and the signer network,
/// allowing signers to exchange messages with each other.
pub trait MessageTransfer {
    /// Send `msg` to all other signers
    fn broadcast(&mut self, msg: Msg) -> impl Future<Output = Result<(), Error>> + Send;
    /// Receive a message from the network
    fn receive(&mut self) -> impl Future<Output = Result<Msg, Error>> + Send;
}

impl std::fmt::Display for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Msg({})", self.payload)
    }
}
