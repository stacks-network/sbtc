//! # Signer network interface
//!
//! This module provides the MessageTransfer trait that the signer implementation
//! will rely on for inter-signer communication, along with an in-memory
//! implementation of this trait for testing purposes.

#[cfg(test)]
pub mod in_memory;

use std::future::Future;

use crate::ecdsa;
use crate::message;

pub type Msg = ecdsa::Signed<message::SignerMessage>;

pub trait MessageTransfer {
    type Error;
    /// Send `msg` to all other signers
    fn broadcast(&mut self, msg: Msg) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Receive a message from the network
    fn receive(&mut self) -> impl Future<Output = Result<Msg, Self::Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::hashes::Hash;
    use p256k1::scalar;
    use rand::SeedableRng;

    use crate::ecdsa::SignEcdsa;

    #[tokio::test]
    async fn two_clients_should_be_able_to_exchange_messages_given_an_in_memory_network() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1337);

        let network = in_memory::Network::new();

        let number_of_messages = 32;

        let mut client_1 = network.connect();
        let mut client_2 = network.connect();

        let client_1_messages: Vec<_> = (0..number_of_messages)
            .map(|_| random_signed_message(&mut rng))
            .collect();
        let client_2_messages: Vec<_> = (0..number_of_messages)
            .map(|_| random_signed_message(&mut rng))
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

    fn random_signed_message<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Msg {
        let num_ids: u8 = rng.gen();
        let dkg_end_begin = wsts::net::DkgEndBegin {
            dkg_id: rng.next_u64(),
            signer_ids: (0..num_ids).map(|_| rng.next_u32()).collect(),
            key_ids: (0..num_ids).map(|_| rng.next_u32()).collect(),
        };

        let private_key = scalar::Scalar::random(rng);
        let payload = message::Payload::WstsMessage(wsts::net::Message::DkgEndBegin(dkg_end_begin));

        let mut block_hash_data = [0; 32];
        rng.fill_bytes(&mut block_hash_data);
        let block_hash = bitcoin::BlockHash::from_slice(&block_hash_data).unwrap();

        payload
            .to_message(block_hash)
            .sign_ecdsa(&private_key)
            .expect("Failed to sign message")
    }
}
