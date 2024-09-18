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
use crate::context::TerminationHandle;
use crate::ecdsa;
use crate::error::Error;
use crate::message;

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

/// MessageTransfer interface for the application signalling channel.
/// TODO: Better name?
pub struct P2PNetwork {
    signal_tx: Sender<SignerSignal>,
    signal_rx: Receiver<SignerSignal>,
    term: TerminationHandle,
}

impl P2PNetwork {
    /// Create a new broadcast channel network instance. This requires an active
    /// [`Context`] and will retrieve its own signalling sender and receiver.
    pub fn new(ctx: &impl Context) -> Self {
        Self {
            signal_tx: ctx.get_signal_sender(),
            signal_rx: ctx.get_signal_receiver(),
            term: ctx.get_termination_handle(),
        }
    }
}

impl MessageTransfer for P2PNetwork {
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
    async fn broadcast(&mut self, msg: Msg) -> Result<(), Error> {
        self.signal_tx
            .send(SignerSignal::Command(SignerCommand::P2PPublish(msg)))
            .map_err(|_| Error::SignerShutdown)
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
    async fn receive(&mut self) -> Result<Msg, Error> {
        loop {
            tokio::select! {
                _ = self.term.wait_for_shutdown() => {
                    return Err(Error::SignerShutdown);
                },
                recv = self.signal_rx.recv() => {
                    match recv {
                        Ok(SignerSignal::Event(SignerEvent::P2PMessageReceived(msg))) => {
                            return Ok(msg);
                        },
                        // We're only interested in the above messages, so we ignore
                        // the rest.
                        _ => continue,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use super::*;

    use crate::{
        config::Settings,
        context::SignerContext,
        keys::PrivateKey,
        storage::in_memory::Store,
        testing::{self, clear_env},
    };

    #[tokio::test]
    async fn two_clients_should_be_able_to_exchange_messages_given_an_in_memory_network() {
        let network = in_memory::Network::new();

        let client_1 = network.connect();
        let client_2 = network.connect();

        testing::network::assert_clients_can_exchange_messages(client_1, client_2).await;
    }

    #[tokio::test]
    async fn two_clients_should_be_able_to_exchange_messages_given_a_libp2p_network() {
        clear_env();

        let key1 = PrivateKey::new(&mut rand::thread_rng());
        let key2 = PrivateKey::new(&mut rand::thread_rng());

        let settings = Settings::new_from_default_config().unwrap();

        let context1 = SignerContext::init(settings.clone(), Store::new_shared()).unwrap();
        let context2 = SignerContext::init(settings, Store::new_shared()).unwrap();

        let term1 = context1.get_termination_handle();
        let term2 = context2.get_termination_handle();

        let mut swarm1 = libp2p::SignerSwarmBuilder::new(&key1)
            .add_listen_endpoint("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .build()
            .expect("Failed to build swarm 1");

        let mut swarm2 = libp2p::SignerSwarmBuilder::new(&key2)
            .add_listen_endpoint("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .build()
            .expect("Failed to build swarm 2");

        let network1 = P2PNetwork::new(&context1);
        let network2 = P2PNetwork::new(&context2);

        tracing::info!("starting swarms");

        let handle1 = tokio::spawn(async move {
            swarm1.start(&context1).await.unwrap();
        });

        let handle2 = tokio::spawn(async move {
            swarm2.start(&context2).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        tracing::info!("starting test");

        if let Err(_) = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            testing::network::assert_clients_can_exchange_messages(network1, network2),
        )
        .await
        {
            handle1.abort();
            handle2.abort();
            panic!(
                r#"Test timed out, we waited for 30 seconds but this usually takes around 5 seconds. 
            This is generally due to connectivity issues between the two swarms."#
            );
        }

        term1.signal_shutdown();
        term2.signal_shutdown();
    }
}
