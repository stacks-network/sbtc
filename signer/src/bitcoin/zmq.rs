//! This module provides functionality for receiving new blocks from
//! bitcoin-core's ZeroMQ interface[1]. From the bitcoin-core docs:
//!
//! > The ZeroMQ facility implements a notification interface through a set
//! > of specific notifiers. Currently, there are notifiers that publish
//! > blocks and transactions. This read-only facility requires only the
//! > connection of a corresponding ZeroMQ subscriber port in receiving
//! > software; it is not authenticated nor is there any two-way protocol
//! > involvement. Therefore, subscribers should validate the received data
//! > since it may be out of date, incomplete or even invalid.
//!
//! > ZeroMQ sockets are self-connecting and self-healing; that is,
//! > connections made between two endpoints will be automatically restored
//! > after an outage, and either end may be freely started or stopped in
//! > any order.
//!
//! > Because ZeroMQ is message oriented, subscribers receive transactions
//! > and blocks all-at-once and do not need to implement any sort of
//! > buffering or reassembly.
//!
//! The code here can only process bitcoin blocks and bitcoin block hash
//! notifications, and there is currently no code for receiving
//! notifications about transactions. It does not attempt to "validate" the
//! transactions in the received blocks, it only attempts to parse the data
//! using the rust-bitcoin library.
//!
//! [^1]: https://github.com/bitcoin/bitcoin/blob/870447fd585e5926b4ce4e83db31c59b1be45a50/doc/zmq.md

use std::future::ready;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::Block;
use bitcoin::BlockHash;
use futures::stream::Stream;
use futures::stream::StreamExt as _;
use zeromq::Socket as _;
use zeromq::SocketRecv as _;
use zeromq::SubSocket;
use zeromq::ZmqMessage;

use crate::error::Error;

/// These are the types of messages that we can get from bitcoin-core by
/// listing to its zeromq socket subscriptions.
///
/// There are 5 message types, but we only care about the ones below: The
/// documentation for each type is taken from:
/// https://github.com/bitcoin/bitcoin/blob/870447fd585e5926b4ce4e83db31c59b1be45a50/doc/zmq.md
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinCoreMessage {
    /// `hashblock`: Notifies when the chain tip is updated. When
    /// assumeutxo is in use, this notification will not be issued for
    /// historical blocks connected to the background validation
    /// chainstate. Messages are ZMQ multipart messages with three parts.
    /// The first part is the topic (hashblock), the second part is the
    /// 32-byte block hash, and the last part is a sequence number
    /// (representing the message count to detect lost messages). The
    /// format of the messages are:
    ///
    /// ```text
    /// | hashblock | <32-byte block hash in Little Endian> | <uint32 sequence number in Little Endian>
    /// ```
    HashBlock(BlockHash, u32),
    /// `rawblock`: Notifies when the chain tip is updated. When assumeutxo
    /// is in use, this notification will not be issued for historical
    /// blocks connected to the background validation chainstate. Messages
    /// are ZMQ multipart messages with three parts. The first part is the
    /// topic (rawblock), the second part is the serialized block, and the
    /// last part is a sequence number (representing the message count to
    /// detect lost messages).
    /// ```text
    /// | rawblock | <serialized block> | <uint32 sequence number in Little Endian>
    /// ```
    RawBlock(Block, u32),
}

/// Parse the given ZmqMessage from bitcoin-core.
///
/// # Notes
///
/// Bitcoin core sends one of 5 different message types. The messages
/// themselves all follow a similar multipart layout: topic, body,
/// sequence. This parses `hashblock` and `rawblock` messages.
///
/// The bitcoin repo has a nice python example for what to expect here:
/// https://github.com/bitcoin/bitcoin/blob/902dd14382256c9d33bce667795a64079f3bee6b/contrib/zmq/zmq_sub.py
pub fn parse_bitcoin_core_message(message: ZmqMessage) -> Result<BitcoinCoreMessage, Error> {
    // We expect three parts to the message, so let's expect get that.
    let data: [&[u8]; 3] = message
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<&[u8]>>()
        .try_into()
        .map_err(|err: Vec<_>| Error::BitcoinCoreZmqMessageLayout(err.len()))?;

    // The sequence number is always sent as a little endian 4 byte
    // unsigned integer.
    match data {
        [b"hashblock", block_hash, seq] => {
            // The hash here is returned as Little-endian bytes while the
            // BlockHash::from_byte_array function expects Big-endian
            // bytes, so we need to reverse them.
            let mut block_hash_bytes: [u8; 32] = block_hash
                .try_into()
                .map_err(|_| Error::BitcoinCoreZmqBlockHash(block_hash.len()))?;
            block_hash_bytes.reverse();
            let block_hash = BlockHash::from_byte_array(block_hash_bytes);

            let sequence_bytes: [u8; 4] = seq
                .try_into()
                .map_err(|_| Error::BitcoinCoreZmqSequenceNumber(seq.len()))?;
            let sequence = u32::from_le_bytes(sequence_bytes);

            Ok(BitcoinCoreMessage::HashBlock(block_hash, sequence))
        }
        [b"rawblock", mut raw_block, seq] => {
            let block =
                Block::consensus_decode(&mut raw_block).map_err(Error::DecodeBitcoinBlock)?;

            let sequence_bytes: [u8; 4] = seq
                .try_into()
                .map_err(|_| Error::BitcoinCoreZmqSequenceNumber(seq.len()))?;
            let sequence = u32::from_le_bytes(sequence_bytes);

            Ok(BitcoinCoreMessage::RawBlock(block, sequence))
        }
        // We do not implement parsing for any other message types but if
        // we're here, then we probably have a valid message from
        // bitcoin-core (we know `data` has three parts). Let's try to note
        // the topic for easier debugging.
        _ => {
            let topic = core::str::from_utf8(data[0]).map(ToString::to_string);
            Err(Error::BitcoinCoreZmqUnsupported(topic))
        }
    }
}

/// A struct for messages over bitcoin-core's ZeroMQ interface.
pub struct BitcoinCoreMessageStream {
    /// We actually want this type to be a futures::stream::Unfold<...>, or
    /// maybe a pinned version of that, but we cannot write the type down,
    /// so we Box it up.
    inner: Pin<Box<dyn Stream<Item = Result<BitcoinCoreMessage, Error>> + Send>>,
}

impl BitcoinCoreMessageStream {
    /// Create a new `BitcoinCoreMessageStream`.
    pub fn new_from_socket(socket: SubSocket) -> Self {
        let stream = futures::stream::unfold(socket, |mut socket| async move {
            let item = socket
                .recv()
                .await
                .map_err(Error::ZmqReceive)
                .and_then(parse_bitcoin_core_message);
            Some((item, socket))
        });
        Self { inner: Box::pin(stream) }
    }

    /// Creat a new one using the endpoint(s) in the config.
    ///
    /// Note that setting the subscription to the empty string is
    /// equivalent to setting the subscription to all available
    /// subscriptions enabled on bitcoin-core.
    pub async fn new_from_endpoint<T>(endpoint: &str, subscriptions: &[T]) -> Result<Self, Error>
    where
        T: AsRef<str>,
    {
        let mut socket = SubSocket::new();
        socket.connect(endpoint).await.map_err(Error::ZmqConnect)?;
        for subscription in subscriptions {
            socket
                .subscribe(subscription.as_ref())
                .await
                .map_err(Error::ZmqSubscribe)?;
        }

        Ok(Self::new_from_socket(socket))
    }

    /// Convert this stream into one that returns only blocks
    pub fn to_block_stream(self) -> impl Stream<Item = Result<Block, Error>> {
        self.filter_map(|msg| match msg {
            Ok(BitcoinCoreMessage::RawBlock(block, _)) => ready(Some(Ok(block))),
            Ok(_) => ready(None),
            Err(err) => ready(Some(Err(err))),
        })
    }

    /// Convert this stream into one that returns only block hashes
    pub fn to_block_hash_stream(self) -> impl Stream<Item = Result<BlockHash, Error>> {
        self.filter_map(|msg| match msg {
            Ok(BitcoinCoreMessage::HashBlock(hash, _)) => ready(Some(Ok(hash))),
            Ok(_) => ready(None),
            Err(err) => ready(Some(Err(err))),
        })
    }
}

impl Stream for BitcoinCoreMessageStream {
    type Item = Result<BitcoinCoreMessage, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}
