//! # In-memory signer network client.
//!
//! The client itself is a thin wrapper over a tokio broadcast
//! channel, with deduplication logic to prevent a single client
//! from receiving it's own messages.

use std::{
    collections::VecDeque,
    sync::{atomic::AtomicU16, Arc},
};

use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;

use crate::context::P2PEvent;
use crate::context::SignerSignal;
use crate::error::Error;

const BROADCAST_CHANNEL_CAPACITY: usize = 10_000;

type MsgId = [u8; 32];

/// Represents an in-memory communication network useful for tests
#[derive(Debug)]
pub struct InMemoryNetwork {
    last_id: AtomicU16,
    sender: broadcast::Sender<super::Msg>,
}

/// A handle to the in-memory network, usable for unit tests that
/// require a simple implementation of [`super::MessageTransfer`]
#[derive(Debug)]
pub struct MpmcBroadcaster {
    id: u16,
    sender: broadcast::Sender<super::Msg>,
    receiver: broadcast::Receiver<super::Msg>,
    recently_sent: Arc<Mutex<VecDeque<MsgId>>>,
}

impl Clone for MpmcBroadcaster {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            sender: self.sender.clone(),
            receiver: self.sender.subscribe(),
            recently_sent: Arc::clone(&self.recently_sent),
        }
    }
}

impl MpmcBroadcaster {
    /// Get the unique identifier of this broadcaster
    pub fn id(&self) -> u16 {
        self.id
    }
}

impl InMemoryNetwork {
    /// Construct a new in-memory communication entwork
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        Self {
            sender,
            last_id: AtomicU16::new(0),
        }
    }

    /// Connect a new signer to this network
    pub fn connect(&self) -> MpmcBroadcaster {
        let id = self
            .last_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        MpmcBroadcaster {
            id,
            sender: self.sender.clone(),
            receiver: self.sender.subscribe(),
            recently_sent: Default::default(),
        }
    }
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl super::MessageTransfer for MpmcBroadcaster {
    async fn broadcast(&mut self, msg: super::Msg) -> Result<(), Error> {
        tracing::trace!("[network{:0>2}] broadcasting: {}", self.id, msg);
        self.recently_sent.lock().await.push_back(msg.id());
        self.sender.send(msg).map_err(|_| Error::SendMessage)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<super::Msg, Error> {
        let mut msg = self.receiver.recv().await.map_err(Error::ChannelReceive)?;
        tracing::trace!("[network{:0>2}] received: {}", self.id, msg);

        while Some(&msg.id()) == self.recently_sent.lock().await.front() {
            self.recently_sent.lock().await.pop_front();
            msg = self.receiver.recv().await.map_err(Error::ChannelReceive)?;
        }

        Ok(msg)
    }

    fn receiver_stream(&self) -> BroadcastStream<SignerSignal> {
        let (sender, receiver) = tokio::sync::broadcast::channel(1000);
        let mut signal_rx = self.receiver.resubscribe();
        let recently_sent = self.recently_sent.clone();
        tokio::spawn(async move {
            loop {
                match signal_rx.recv().await {
                    Ok(mut msg) => {
                        while Some(&msg.id()) == recently_sent.lock().await.front() {
                            recently_sent.lock().await.pop_front();
                            msg = signal_rx.recv().await.map_err(Error::ChannelReceive)?;
                        }
                        let _ = sender.send(P2PEvent::MessageReceived(msg).into());
                    }
                    Err(error) => {
                        tracing::error!(%error, "got a receive error");
                        return Err::<(), _>(Error::SignerShutdown);
                    }
                }
            }
        });
        BroadcastStream::new(receiver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[tokio::test]
    async fn two_clients_should_be_able_to_exchange_messages_given_an_in_memory_network() {
        let network = InMemoryNetwork::new();

        let client_1 = network.connect();
        let client_2 = network.connect();

        testing::network::assert_clients_can_exchange_messages(client_1, client_2).await;
    }
}
