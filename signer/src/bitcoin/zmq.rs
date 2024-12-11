//! This module provides functionality for receiving new blocks from
//! bitcoin-core's ZeroMQ interface[1]. From the bitcoin-core docs:
//!
//! > The ZeroMQ facility implements a notification interface through a set of
//! > specific notifiers. Currently, there are notifiers that publish blocks and
//! > transactions. This read-only facility requires only the connection of a
//! > corresponding ZeroMQ subscriber port in receiving software; it is not
//! > authenticated nor is there any two-way protocol involvement. Therefore,
//! > subscribers should validate the received data since it may be out of date,
//! > incomplete or even invalid.
//!
//! > ZeroMQ sockets are self-connecting and self-healing; that is, connections
//! > made between two endpoints will be automatically restored after an outage,
//! > and either end may be freely started or stopped in any order.
//!
//! > Because ZeroMQ is message oriented, subscribers receive transactions and
//! > blocks all-at-once and do not need to implement any sort of buffering or
//! > reassembly.
//!
//! [^1]: https://github.com/bitcoin/bitcoin/blob/870447fd585e5926b4ce4e83db31c59b1be45a50/doc/zmq.md
//!
//! ### Testing Notes
//!
//! - When testing this module within the signer (i.e. in `devenv`), it is
//!   important that bitcoind's state be preserved between stops/starts. For
//!   docker compose, this means that you should use the `stop` command and not
//!   the `down` command.

use std::future::ready;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoincore_zmq::subscribe_async_monitor_stream::MessageStream;
use bitcoincore_zmq::Message;
use bitcoincore_zmq::SocketEvent;
use bitcoincore_zmq::SocketMessage;
use futures::stream::Stream;
use futures::stream::StreamExt as _;

use crate::error::Error;

/// A struct for messages over bitcoin-core's ZeroMQ interface.
pub struct BitcoinCoreMessageStream {
    /// The inner stream we're wrapping.
    inner_stream: MessageStream,
}

impl BitcoinCoreMessageStream {
    /// Create a new one using the endpoint(s) in the config.
    pub async fn new_from_endpoint<T>(endpoint: &str, _subscriptions: &[T]) -> Result<Self, Error>
    where
        T: AsRef<str>,
    {
        let inner_stream = tokio::time::timeout(Duration::from_secs(10), async {
            bitcoincore_zmq::subscribe_async_monitor(&[endpoint])
        })
        .await
        .map_err(|_| Error::BitcoinCoreZmqConnectTimeout(endpoint.to_string()))?
        .map_err(Error::BitcoinCoreZmq)?;

        Ok(Self { inner_stream })
    }

    /// Method we use to inspect incoming messages and log things.
    fn inspect_message(msg: &Result<SocketMessage, Error>) {
        match msg {
            Ok(SocketMessage::Event(event)) => match event.event {
                SocketEvent::Connected { fd } => {
                    tracing::info!(%fd, endpoint = event.source_url, "connected to ZeroMQ endpoint");
                }
                SocketEvent::Disconnected { fd } => {
                    tracing::warn!(%fd, endpoint = event.source_url, "disconnected from ZeroMQ endpoint");
                }
                _ => {}
            },
            Ok(SocketMessage::Message(msg)) => match msg {
                Message::Block(block, height) => {
                    tracing::trace!(block_hash = %block.block_hash(), block_height = %height, "received block");
                }
                Message::HashBlock(hash, height) => {
                    tracing::trace!(block_hash = %hash, block_height = %height, "received block hash");
                }
                _ => {}
            },
            Err(error) => {
                tracing::error!(%error, "error receiving message from ZeroMQ");
            }
        }
    }

    /// Convert this stream into one that returns only blocks
    pub fn to_block_stream(self) -> impl Stream<Item = Result<Block, Error>> {
        self.inspect(Self::inspect_message)
            .filter_map(|msg| match msg {
                Ok(SocketMessage::Message(Message::Block(block, _))) => ready(Some(Ok(block))),
                Err(err) => ready(Some(Err(err))),
                Ok(_) => ready(None),
            })
    }

    /// Convert this stream into one that returns only block hashes
    pub fn to_block_hash_stream(self) -> impl Stream<Item = Result<BlockHash, Error>> {
        self.inspect(Self::inspect_message)
            .filter_map(|msg| match msg {
                Ok(SocketMessage::Message(Message::HashBlock(hash, _))) => ready(Some(Ok(hash))),
                Err(err) => ready(Some(Err(err))),
                Ok(_) => ready(None),
            })
    }
}

impl Stream for BitcoinCoreMessageStream {
    type Item = Result<SocketMessage, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner_stream
            .poll_next_unpin(cx)
            .map_err(Error::BitcoinCoreZmq)
    }
}
