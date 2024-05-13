//! # In-memory signer network client.
//!
//! The client itself is a thin wrapper over a tokio broadcast
//! channel, with deduplication logic to prevent a single client
//! from receiving it's own messages.

use std::collections::VecDeque;

use tokio::sync::broadcast;

pub const BROADCAST_CHANNEL_CAPACITY: usize = 10_000;

type MsgId = [u8; 32];

#[derive(Debug)]
pub struct MpmcBroadcaster {
    sender: broadcast::Sender<super::Msg>,
    receiver: broadcast::Receiver<super::Msg>,
    recently_sent: VecDeque<MsgId>,
}

/// In-memory communication network
#[derive(Debug)]
pub struct Network {
    sender: broadcast::Sender<super::Msg>,
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

impl super::MessageTransfer for MpmcBroadcaster {
    type Error = Error;
    async fn broadcast(&mut self, msg: super::Msg) -> Result<(), Self::Error> {
        self.recently_sent.push_back(msg.id());
        self.sender.send(msg)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<super::Msg, Self::Error> {
        let mut msg = self.receiver.recv().await?;

        while Some(&msg.id()) == self.recently_sent.get(0) {
            self.recently_sent.pop_front();
            msg = self.receiver.recv().await?;
        }

        Ok(msg)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("send error")]
    Send(#[from] broadcast::error::SendError<super::Msg>),
    #[error("receive error")]
    Recv(#[from] broadcast::error::RecvError),
}
