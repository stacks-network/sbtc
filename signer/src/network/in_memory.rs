//! # In-memory signer network client.
//!
//! The client itself is a thin wrapper over a tokio broadcast
//! channel, with deduplication logic to prevent a single client
//! from receiving it's own messages.

use std::{collections::VecDeque, sync::atomic::AtomicU16};

use tokio::sync::broadcast;

use crate::error::Error;

const BROADCAST_CHANNEL_CAPACITY: usize = 10_000;

type MsgId = [u8; 32];

/// Represents an in-memory communication network useful for tests
#[derive(Debug)]
pub struct Network {
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
    recently_sent: VecDeque<MsgId>,
}

impl MpmcBroadcaster {
    /// Get the unique identifier of this broadcaster
    pub fn id(&self) -> u16 {
        self.id
    }
}

impl Network {
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
        let sender = self.sender.clone();
        let receiver = sender.subscribe();
        let recently_sent = VecDeque::new();
        let id = self
            .last_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        MpmcBroadcaster {
            id,
            sender,
            receiver,
            recently_sent,
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

impl super::MessageTransfer for MpmcBroadcaster {
    async fn broadcast(&mut self, msg: super::Msg) -> Result<(), Error> {
        tracing::trace!("[network{:0>2}] broadcasting: {}", self.id, msg);
        self.recently_sent.push_back(msg.id());
        self.sender.send(msg).map_err(|_| Error::SendMessage)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<super::Msg, Error> {
        let mut msg = self.receiver.recv().await.map_err(Error::ChannelReceive)?;
        tracing::trace!("[network{:0>2}] received: {}", self.id, msg);

        while Some(&msg.id()) == self.recently_sent.front() {
            self.recently_sent.pop_front();
            msg = self.receiver.recv().await.map_err(Error::ChannelReceive)?;
        }

        Ok(msg)
    }
}
