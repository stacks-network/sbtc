//! # Relay server and client for signer communication over gRPC
//!
//! This module provides an implementation of the
//! [`crate::network::MessageTransfer`] trait over gRPC.
//!
//! ## Features
//!
//! - **RelayServer**: Server implementation that listens to incoming
//!   connections and forwards incoming messages to all connected clients.
//! - **RelayClient**: Client implementation which exposes the
//!   `MessageTransfer` interface for the signer.
//!
//! ## Examples
//!
//! - `src/bin/relay-server.rs` shows how to properly spin up a relay
//!   server.
//!
//! - `examples/relay-client.rs` is an an example of how to concurrently
//!   send messages to and receive messages from the server.

#[allow(missing_docs)]
pub mod proto {
    tonic::include_proto!("stacks.signer");
}

use std::collections::VecDeque;
use std::net::ToSocketAddrs;
use std::pin::Pin;

use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tokio_stream::StreamExt;

use crate::codec;
use crate::codec::Decode;
use crate::codec::Encode;

const CHANNEL_CAPACITY: usize = 10_000;

type Msg = crate::ecdsa::Signed<crate::message::SignerMessage>;
type MsgId = [u8; 32];

/// Relay server that broadcasts incoming messages over gRPC.
/// The internal logic is just wrapping a tokio broadcast channel.
#[derive(Debug)]
pub struct RelayServer {
    broadcast_tx: broadcast::Sender<Result<proto::Message, tonic::Status>>,
}

impl RelayServer {
    /// Construct a new Relay server
    pub fn new() -> Self {
        let (broadcast_tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { broadcast_tx }
    }

    /// Run the server at the provided address
    #[tracing::instrument(skip(self, addr))]
    pub async fn serve(self, addr: impl ToSocketAddrs) -> Result<(), ConnectError> {
        let socket_address = addr
            .to_socket_addrs()
            .map_err(|_| ConnectError::AddressParsing)?
            .next()
            .ok_or(ConnectError::AddressParsing)?;

        tracing::info!(address = ?socket_address, "starting relay server");
        tonic::transport::Server::builder()
            .add_service(proto::relay_server::RelayServer::new(self))
            .serve(
                addr.to_socket_addrs()
                    .map_err(|_| ConnectError::AddressParsing)?
                    .next()
                    .ok_or(ConnectError::AddressParsing)?,
            )
            .await?;

        Ok(())
    }
}

#[tonic::async_trait]
impl proto::relay_server::Relay for RelayServer {
    type BroadcastStream =
        Pin<Box<dyn Stream<Item = Result<proto::Message, tonic::Status>> + Send>>;

    #[tracing::instrument(skip(self, request))]
    async fn broadcast(
        &self,
        request: tonic::Request<tonic::Streaming<proto::Message>>,
    ) -> Result<tonic::Response<Self::BroadcastStream>, tonic::Status> {
        let mut in_stream = request.into_inner();

        let broadcast_tx = self.broadcast_tx.clone();
        let broadcast_rx = self.broadcast_tx.subscribe();

        tokio::spawn(async move {
            tracing::debug!("listening to messages from client");
            while let Some(Ok(msg)) = in_stream.next().await {
                tracing::debug!(?msg, "broadcasting message");
                if broadcast_tx.send(Ok(msg)).is_err() {
                    tracing::debug!("all receivers closed");
                    break;
                }
            }
            tracing::debug!("disconnected from client")
        });

        let out_stream =
            Box::pin(BroadcastStream::new(broadcast_rx).map_while(|msg_result| msg_result.ok()));

        Ok(tonic::Response::new(out_stream))
    }
}

impl Default for RelayServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay client that connects to the relay server over gRPC.
/// Once constructed, the client should be used through the methods defined in [`crate::network::MessageTransfer`].
pub struct RelayClient {
    sender: mpsc::Sender<proto::Message>,
    response_stream: tonic::Streaming<proto::Message>,
    recently_sent: VecDeque<MsgId>,
}

impl RelayClient {
    /// Attempt to connect to the server at the provided address.
    /// Returns the client upon successful connection.
    /// This method will retry with an exponential backoff for maximum 15 minutes before failing.
    #[tracing::instrument(skip(addr))]
    pub async fn connect<Addr>(addr: Addr) -> Result<Self, ConnectError>
    where
        Addr: TryInto<tonic::transport::Endpoint>,
        <Addr as TryInto<tonic::transport::Endpoint>>::Error:
            Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let endpoint = tonic::transport::Endpoint::new(addr)?;
        let try_connect = move || {
            let endpoint = endpoint.clone();
            async move {
                proto::relay_client::RelayClient::connect(endpoint)
                    .await
                    .map_err(backoff::Error::transient)
            }
        };

        let mut client = backoff::future::retry_notify(
            backoff::ExponentialBackoff::default(),
            try_connect,
            |err, duration: std::time::Duration| {
                tracing::debug!(
                    error = %err,
                    "failed to connect to relay server, retrying in {}",
                    duration.as_secs(),
                )
            },
        )
        .await?;

        let (sender, in_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let in_stream = ReceiverStream::new(in_rx);

        let response = client.broadcast(in_stream).await?;
        let response_stream = response.into_inner();

        let recently_sent = VecDeque::new();

        tracing::debug!("connected to relay server");

        Ok(Self {
            sender,
            response_stream,
            recently_sent,
        })
    }

    async fn receive_next(&mut self) -> Result<Msg, RelayError> {
        let msg = self
            .response_stream
            .next()
            .await
            .ok_or(RelayError::StreamClosed)??;

        Ok(Msg::decode(msg.message.as_slice())?)
    }
}

impl super::MessageTransfer for RelayClient {
    type Error = RelayError;

    #[tracing::instrument(skip(self))]
    async fn broadcast(&mut self, msg: Msg) -> Result<(), Self::Error> {
        let msg_id = msg.id();

        let proto_msg = proto::Message { message: msg.encode_to_vec()? };

        self.sender
            .send(proto_msg)
            .await
            .map_err(|_| RelayError::StreamClosed)?;

        self.recently_sent.push_back(msg_id);

        tracing::debug!("broadcasted message");

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn receive(&mut self) -> Result<Msg, Self::Error> {
        let mut msg = self.receive_next().await?;

        while Some(&msg.id()) == self.recently_sent.front() {
            self.recently_sent.pop_front();
            msg = self.receive_next().await?;
        }

        tracing::debug!("received message");

        Ok(msg)
    }
}

/// Errors occuring during relay message handling
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// Codec error
    #[error("codec error")]
    Codec(#[from] codec::Error),

    /// Closed stream
    #[error("closed stream")]
    StreamClosed,

    /// Tonic error
    #[error("Tonic error")]
    Tonic(#[from] tonic::Status),
}

/// Errors occurring when connecting
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// Address parsing
    #[error("failed to parse socket address")]
    AddressParsing,

    /// Tonic transport error
    #[error("Transport error")]
    TonicTransport(#[from] tonic::transport::Error),

    /// Tonic error
    #[error("Tonic error")]
    Tonic(#[from] tonic::Status),
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testing;

    #[tokio::test]
    #[cfg_attr(not(feature = "integration-tests"), ignore)]
    async fn two_clients_should_be_able_to_exchange_messages_through_a_grpc_relay() {
        let server = RelayServer::new();
        let addr = server_address();
        let socket_addr = addr.trim_start_matches("http://").to_owned();

        tokio::spawn(async move { server.serve(socket_addr).await.expect("Failed to serve") });

        let client_1 = RelayClient::connect(addr.clone())
            .await
            .expect("Failed to connect");

        let client_2 = RelayClient::connect(addr).await.expect("Failed to connect");

        testing::network::assert_clients_can_exchange_messages(client_1, client_2).await;
    }

    fn server_address() -> String {
        let port = find_unused_port();
        format!("http://127.0.0.1:{port}")
    }

    fn find_unused_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
}
