//! # Signer network interface
//!
//! This module provides the MessageTransfer trait that the signer implementation
//! will rely on for inter-signer communication, along with an in-memory
//! implementation of this trait for testing purposes.

pub mod grpc_relay;
pub mod in_memory;

use std::future::Future;

use crate::ecdsa;
use crate::message;

/// The supported message type of the signer network
pub type Msg = ecdsa::Signed<message::SignerMessage>;

/// Represents the interaction point between signers and the signer network,
/// allowing signers to exchange messages with each other.
pub trait MessageTransfer {
    /// Errors occuring during either [`broadcast`] or [`receive`]
    type Error: std::error::Error;
    /// Send `msg` to all other signers
    fn broadcast(&mut self, msg: Msg) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Receive a message from the network
    fn receive(&mut self) -> impl Future<Output = Result<Msg, Self::Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing;

    #[tokio::test]
    async fn two_clients_should_be_able_to_exchange_messages_given_an_in_memory_network() {
        let network = in_memory::Network::new();

        let client_1 = network.connect();
        let client_2 = network.connect();

        testing::network::assert_clients_can_exchange_messages(client_1, client_2).await;
    }
}
