//! # Signer network interface
//!
//! This module provides the MessageTransfer trait that the signer implementation
//! will rely on for inter-signer communication, along with an in-memory
//! implementation of this trait for testing purposes.

pub mod grpc_relay;
pub mod in_memory;

pub mod libp2p;

use std::future::Future;

use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::Sender;

use crate::context::Context;
use crate::context::SignerCommand;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::ecdsa;
use crate::message;

/// The supported message type of the signer network
pub type Msg = ecdsa::Signed<message::SignerMessage>;
/// The unique identifier for a message
pub type MsgId = [u8; 32];

/// Represents the interaction point between signers and the signer network,
/// allowing signers to exchange messages with each other.
pub trait MessageTransfer {
    /// Errors occuring during either [`MessageTransfer::broadcast`] or [`MessageTransfer::receive`]
    type Error: std::error::Error;
    /// Send `msg` to all other signers
    fn broadcast(&mut self, msg: Msg) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Receive a message from the network
    fn receive(&mut self) -> impl Future<Output = Result<Msg, Self::Error>> + Send;
}

/// MessageTransfer interface for the application signalling channel.
/// TODO: Better name?
pub struct P2PNetwork {
    signal_tx: Sender<SignerSignal>,
    signal_rx: Receiver<SignerSignal>,
}

impl P2PNetwork {
    /// Create a new broadcast channel network instance. This requires an active
    /// [`Context`] and will retrieve its own signalling sender and receiver.
    pub fn new(ctx: &impl Context) -> Self {
        Self {
            signal_tx: ctx.get_signal_sender(),
            signal_rx: ctx.get_signal_receiver(),
        }
    }
}

impl MessageTransfer for P2PNetwork {
    type Error = crate::error::Error;

    /// This will broadcast the message to the application signalling channel
    /// using a [`SignerCommand::P2PPublish`] command. This implementation does
    /// not actually send the message to the P2P network, but rather signals
    /// to the active network implementation to do so.
    ///
    /// Note that this is not a blocking operation, and this method will return
    /// as soon as the message has been sent to the signalling channel.
    ///
    /// If you need to wait for a receipt (success/fail), you can use your own
    /// [`Receiver<SignerSignal>`] to listen for the
    /// [`SignerEvent::P2PPublishFailure`] and [`SignerEvent::P2PPublishSuccess`]
    /// events, which will provide you with the [`MsgId`] to match against your
    /// in-flight requests.
    async fn broadcast(&mut self, msg: Msg) -> Result<(), Self::Error> {
        self.signal_tx
            .send(SignerSignal::Command(SignerCommand::P2PPublish(msg)))
            .map_err(|error| error.into())
            .map(|_| ())
    }

    /// This will listen for incoming messages on the application signalling
    /// channel, and return the message once it has been received.
    ///
    /// This is a blocking operation, and will wait until a message has been
    /// received before returning.
    ///
    /// ### Important Note
    /// To avoid ending up in a slow-receiver situation, you should queue
    /// messages in a local buffer (i.e. [`std::collections::VecDeque`]) and
    /// process them in your own time. Otherwise, if there are a large number
    /// of messages being sent, you risk lagging and eventually having the tail
    /// of the receiver being dropped, thus missing messages.
    ///
    /// In other words, you should be calling this method as rapidly as possible.
    async fn receive(&mut self) -> Result<Msg, Self::Error> {
        loop {
            match self.signal_rx.recv().await {
                // We are only interested in received P2P messages
                Ok(SignerSignal::Event(SignerEvent::P2PMessageReceived(msg))) => {
                    return Ok(msg);
                }
                // And if we get an error when attempting to read from the
                // channel.
                Err(error) => {
                    return Err(error.into());
                }
                // Anything else, we ignore.
                _ => continue,
            }
        }
    }
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
