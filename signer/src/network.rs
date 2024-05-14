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

pub type Msg = ecdsa::Signed<message::SignerMessage>;

/// Represents the interaction point between signers and the signer network,
/// allowing signers to exchange messages with each other.
pub trait MessageTransfer {
    type Error: std::error::Error;
    /// Send `msg` to all other signers
    fn broadcast(&mut self, msg: Msg) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Receive a message from the network
    fn receive(&mut self) -> impl Future<Output = Result<Msg, Self::Error>> + Send;
}

#[cfg(test)]
pub async fn assert_clients_should_be_able_to_exchange_messages<
    C: MessageTransfer + Send + 'static,
>(
    mut client_1: C,
    mut client_2: C,
) {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
    let number_of_messages = 32;

    let client_1_messages: Vec<_> = (0..number_of_messages)
        .map(|_| Msg::random(&mut rng))
        .collect();
    let client_2_messages: Vec<_> = (0..number_of_messages)
        .map(|_| Msg::random(&mut rng))
        .collect();

    let client_1_expected_received_messages = client_2_messages.clone();
    let client_2_expected_received_messages = client_1_messages.clone();

    let handle_1 = tokio::spawn(async move {
        for msg in client_1_messages {
            client_1.broadcast(msg).await.expect("Failed to broadcast");
        }

        for msg in client_1_expected_received_messages {
            let received = client_1.receive().await.expect("Failed to receive message");
            assert_eq!(received, msg);
        }
    });

    let handle_2 = tokio::spawn(async move {
        for msg in client_2_messages {
            client_2.broadcast(msg).await.expect("Failed to broadcast");
        }

        for msg in client_2_expected_received_messages {
            let received = client_2.receive().await.expect("Failed to receive message");
            assert_eq!(received, msg);
        }
    });

    handle_1.await.unwrap();
    handle_2.await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn two_clients_should_be_able_to_exchange_messages_given_an_in_memory_network() {
        let network = in_memory::Network::new();

        let client_1 = network.connect();
        let client_2 = network.connect();

        assert_clients_should_be_able_to_exchange_messages(client_1, client_2).await;
    }
}
