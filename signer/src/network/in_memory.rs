//! # In-memory signer network client.
//!
//! The client itself is a thin wrapper over a tokio broadcast
//! channel, with deduplication logic to prevent a single client
//! from receiving it's own messages.

use std::{
    collections::VecDeque,
    sync::{Arc, atomic::AtomicU16},
};

use tokio::sync::Mutex;
use tokio::sync::broadcast;

use crate::{
    codec::{Decode as _, Encode as _},
    error::Error,
};

const BROADCAST_CHANNEL_CAPACITY: usize = 10_000;

type MsgId = [u8; 32];

/// Represents an in-memory communication network useful for tests
#[derive(Debug)]
pub struct InMemoryNetwork {
    last_id: AtomicU16,
    sender: broadcast::Sender<Vec<u8>>,
}

/// A handle to the in-memory network, usable for unit tests that
/// require a simple implementation of [`super::MessageTransfer`]
#[derive(Debug)]
pub struct MpmcBroadcaster {
    id: u16,
    sender: broadcast::Sender<Vec<u8>>,
    receiver: broadcast::Receiver<Vec<u8>>,
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
        let encoded_msg = msg.encode_to_vec();
        self.sender
            .send(encoded_msg)
            .map_err(|_| Error::SendMessage)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<super::Msg, Error> {
        let mut encoded_msg = self.receiver.recv().await.map_err(Error::ChannelReceive)?;
        let mut msg = super::Msg::decode(encoded_msg.as_slice())?;

        tracing::trace!("[network{:0>2}] received: {}", self.id, msg);
        while Some(&msg.id()) == self.recently_sent.lock().await.front() {
            self.recently_sent.lock().await.pop_front();
            encoded_msg = self.receiver.recv().await.map_err(Error::ChannelReceive)?;
            msg = super::Msg::decode(encoded_msg.as_slice())?;
        }

        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;
    use crate::keys::PrivateKey;
    use crate::testing;

    #[tokio::test]
    async fn two_clients_should_be_able_to_exchange_messages_given_an_in_memory_network() {
        let network = InMemoryNetwork::new();

        let client_1 = network.connect();
        let client_2 = network.connect();

        let pk = PrivateKey::new(&mut OsRng);

        testing::network::assert_clients_can_exchange_messages(client_1, client_2, pk, pk).await;
    }
}
