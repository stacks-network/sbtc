//! # In-memory signer network client.
//!
//! The client itself is a thin wrapper over a tokio broadcast
//! channel, with deduplication logic to prevent a single client
//! from receiving it's own messages.

use std::collections::VecDeque;

use tokio::sync::broadcast;

const BROADCAST_CHANNEL_CAPACITY: usize = 10_000;

type MsgId = [u8; 32];

/// Represents an in-memory communication network useful for tests
#[derive(Debug)]
pub struct Network {
    sender: broadcast::Sender<super::Msg>,
}

/// A handle to the in-memory network, usable for unit tests that
/// require a simple implementation of [`super::MessageTransfer`]
#[derive(Debug)]
pub struct MpmcBroadcaster {
    sender: broadcast::Sender<super::Msg>,
    receiver: broadcast::Receiver<super::Msg>,
    recently_sent: VecDeque<MsgId>,
}

impl Network {
    /// Construct a new in-memory communication entwork
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        Self { sender }
    }

    /// Connect a new signer to this network
    pub fn connect(&self) -> MpmcBroadcaster {
        let sender = self.sender.clone();
        let receiver = sender.subscribe();
        let recently_sent = VecDeque::new();

        MpmcBroadcaster {
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
    type Error = Error;
    async fn broadcast(&mut self, msg: super::Msg) -> Result<(), Self::Error> {
        self.recently_sent.push_back(msg.id());
        self.sender.send(msg).map_err(|_| Error::Send)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<super::Msg, Self::Error> {
        let mut msg = self.receiver.recv().await?;

        while Some(&msg.id()) == self.recently_sent.front() {
            self.recently_sent.pop_front();
            msg = self.receiver.recv().await?;
        }

        Ok(msg)
    }
}

/// In memory network error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Send error
    #[error("send error")]
    Send,
    #[error("receive error")]
    /// Receive error
    Recv(#[from] broadcast::error::RecvError),
}
