//! New version of the in-memory network

use std::sync::atomic::AtomicU8;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::broadcast::Sender;
use tokio_stream::wrappers::BroadcastStream;

use crate::codec::Encode as _;
use crate::context::Context;
use crate::context::P2PEvent;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::error::Error;

use super::MessageTransfer;
use super::Msg;

const DEFAULT_WAN_CAPACITY: usize = 10_000;

/// In-memory representation of a WAN network between different signers.
pub struct WanNetwork {
    /// A sender that passes the message along with the ID of the signer
    /// that sent it.
    tx: Sender<(u8, Vec<u8>)>,
    /// A variable with the last ID of the signers.
    id: AtomicU8,
}

impl WanNetwork {
    /// Create a new in-memory WAN network with the specified channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(capacity);
        let id = AtomicU8::new(0);
        Self { tx, id }
    }

    /// Connect to the in-memory WAN network, returning a new signer-scoped
    /// network instance.
    pub fn connect<C: Context>(&self, ctx: &C) -> SignerNetwork {
        let id = self.id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let network = SignerNetwork::new(ctx, self.tx.clone(), id);
        network.start();
        network
    }
}

impl Default for WanNetwork {
    fn default() -> Self {
        Self::new(DEFAULT_WAN_CAPACITY)
    }
}

/// Represents a single signer's network within the in-memory WAN network. This
/// network can send and receive messages to and from other signers and instances
/// [`Self::spawn`]'d from this instance will not receive messages sent from this
/// same network.
#[derive(Debug, Clone)]
pub struct SignerNetwork {
    wan_tx: Sender<(u8, Vec<u8>)>,
    signer_tx: Sender<SignerSignal>,
    id: u8,
}

impl SignerNetwork {
    /// Start the in-memory signer network
    fn start(&self) {
        // We listen to the WAN network and forward messages to the signer network.
        let mut rx = BroadcastStream::new(self.wan_tx.subscribe());
        // We clone the sender to the signer network to be able to send messages
        let tx = self.signer_tx.clone();

        // We spawn a task that listens to the WAN network and forwards messages
        // to the signer network, but only if this signer instance isn't the
        // sender.
        let my_id = self.id;
        tokio::spawn(async move {
            while let Some(item) = rx.next().await {
                match item {
                    // We do not send messages where the ID is the same as
                    // ours, since those originated with us.
                    Ok((id, msg)) if id != my_id => {
                        let msg = match Msg::decode_with_digest(msg.as_slice()) {
                            Ok((msg, digest)) if msg.verify_digest(digest).is_ok() => msg,
                            Ok(_) => {
                                tracing::error!("received improperly signed message");
                                continue;
                            }
                            Err(error) => {
                                tracing::error!(%error, "failed to decode the message");
                                continue;
                            }
                        };
                        if let Err(error) = tx.send(P2PEvent::MessageReceived(msg).into()) {
                            tracing::error!(%error, "instance channel has been closed");
                        };
                    }
                    Ok(_) => {}
                    Err(error) => tracing::error!(%error, "The channel is lagging"),
                }
            }
        });
    }

    /// Create a new in-memory signer network with a single signer instance.
    /// You can use this if you do not need to simulate multiple signers.
    pub fn single<C: Context>(ctx: &C) -> Self {
        let (wan_tx, _) = tokio::sync::broadcast::channel(DEFAULT_WAN_CAPACITY);
        Self::new(ctx, wan_tx, 0)
    }

    /// Create a new in-memory signer network.
    fn new<C: Context>(ctx: &C, wan_tx: Sender<(u8, Vec<u8>)>, id: u8) -> Self {
        // We create a new broadcast channel for this signer's network.
        let signer_tx = ctx.get_signal_sender();

        Self { wan_tx, signer_tx, id }
    }

    /// Sends a message to the WAN network.
    fn send(&self, msg: Msg) -> Result<(), Error> {
        let encoded_msg = msg.encode_to_vec();
        // Send the message out to the WAN.
        self.wan_tx
            .send((self.id, encoded_msg))
            .inspect_err(|error| tracing::error!(%error, "could not send over the network"))
            .map(|_| ())
            .map_err(|_| Error::SendMessage)
    }

    /// Spawns a new instance of the in-memory signer network.
    pub fn spawn(&self) -> SignerNetworkInstance {
        SignerNetworkInstance {
            signer_network: self.clone(),
            instance_rx: self.signer_tx.subscribe(),
        }
    }
}

/// Represents a single instance of the in-memory signer network. This is used
/// in tests to simulate the disperate signer components which each take their
/// own `MessageTransfer` instance, but in reality are all connected to the same
/// in-memory network and should behave as such.
pub struct SignerNetworkInstance {
    signer_network: SignerNetwork,
    instance_rx: tokio::sync::broadcast::Receiver<SignerSignal>,
}

impl Clone for SignerNetworkInstance {
    fn clone(&self) -> Self {
        Self {
            signer_network: self.signer_network.clone(),
            instance_rx: self.signer_network.signer_tx.subscribe(),
        }
    }
}

impl MessageTransfer for SignerNetworkInstance {
    async fn broadcast(&mut self, msg: Msg) -> Result<(), Error> {
        self.signer_network.send(msg)
    }

    async fn receive(&mut self) -> Result<Msg, Error> {
        let mut interval = tokio::time::interval(Duration::from_millis(5));
        loop {
            if let Ok(SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(msg)))) =
                self.instance_rx.recv().await
            {
                return Ok(msg);
            }
            interval.tick().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::Arc;

    use futures::future::join_all;
    use rand::rngs::OsRng;

    use crate::keys::PrivateKey;
    use crate::testing::context::TestContext;

    use super::*;

    #[tokio::test]
    async fn signer_2_can_receive_messages_from_signer_1() {
        let network = WanNetwork::new(100);
        let ctx1 = TestContext::default_mocked();
        let ctx2 = TestContext::default_mocked();
        let signer_1 = network.connect(&ctx1);
        let signer_2 = network.connect(&ctx2);

        let mut client_1 = signer_1.spawn();
        let mut client_2 = signer_2.spawn();

        let msg = Msg::random(&mut OsRng);

        tokio::spawn(async {
            tokio::time::timeout(Duration::from_secs(1), async move {
                client_2.receive().await.unwrap();
            })
            .await
            .expect("client 2 did not receive message in time")
        });

        client_1.broadcast(msg).await.unwrap();
    }

    #[tokio::test]
    async fn signer_2_can_receive_messages_from_signer_1_concurrent_send() {
        let network = WanNetwork::new(1_000);

        let ctx1 = TestContext::default_mocked();
        let ctx2 = TestContext::default_mocked();
        let signer_1 = network.connect(&ctx1);
        let signer_2 = network.connect(&ctx2);

        let mut client_1a = signer_1.spawn();
        let mut client_1b = signer_1.spawn();
        let mut client_2 = signer_2.spawn();

        let recv_count = Arc::new(AtomicU16::new(0));
        let recv_count_clone = Arc::clone(&recv_count);
        let client2_handle = tokio::spawn(async {
            tokio::time::timeout(Duration::from_secs(3), async move {
                while recv_count_clone.load(Ordering::SeqCst) < 200 {
                    client_2.receive().await.unwrap();
                    recv_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .await
            .expect("client 2 did not receive all messages in time")
        });

        let send1_handle = tokio::spawn(async move {
            for _ in 0..100 {
                client_1a.broadcast(Msg::random(&mut OsRng)).await.unwrap();
            }
        });

        let send2_handle = tokio::spawn(async move {
            for _ in 0..100 {
                client_1b.broadcast(Msg::random(&mut OsRng)).await.unwrap();
            }
        });

        join_all([send1_handle, send2_handle, client2_handle]).await;
        assert_eq!(recv_count.load(Ordering::SeqCst), 200);
    }

    #[tokio::test]
    async fn network_instance_does_not_receive_messages_from_same_signer_network() {
        let network = WanNetwork::new(100);

        let ctx = TestContext::default_mocked();
        let client = network.connect(&ctx);

        let mut client_a = client.spawn();
        let mut client_b = client.spawn();

        let msg = Msg::random(&mut OsRng);

        tokio::spawn(async {
            tokio::time::timeout(Duration::from_secs(1), async move {
                client_b.receive().await.unwrap();
            })
            .await
            .expect_err("client received its own message")
        });

        client_a.broadcast(msg).await.unwrap();
    }

    #[tokio::test]
    async fn two_clients_can_exchange_messages_simple() {
        let network = WanNetwork::new(100);

        let ctx1 = TestContext::default_mocked();
        let ctx2 = TestContext::default_mocked();
        let client_1 = network.connect(&ctx1);
        let client_2 = network.connect(&ctx2);

        let mut client_1 = client_1.spawn();
        let mut client_2 = client_2.spawn();
        let mut client_2b = client_2.clone();

        let msg = Msg::random(&mut OsRng);

        tokio::spawn(async {
            tokio::time::timeout(Duration::from_secs(1), async move {
                client_2.receive().await.unwrap();
            })
            .await
            .expect("client 2 did not receive message in time")
        });

        client_1.broadcast(msg.clone()).await.unwrap();

        tokio::spawn(async {
            tokio::time::timeout(Duration::from_secs(1), async move {
                client_1.receive().await.unwrap();
            })
            .await
            .expect("client 1 did not receive message in time")
        });

        client_2b.broadcast(msg).await.unwrap();
    }

    #[tokio::test]
    async fn two_clients_can_exchange_messages_advanced() {
        let network = WanNetwork::new(100);

        let ctx1 = TestContext::default_mocked();
        let ctx2 = TestContext::default_mocked();
        let client_1 = network.connect(&ctx1);
        let client_2 = network.connect(&ctx2);

        let instance_1 = client_1.spawn();
        let instance_2 = client_2.spawn();

        let pk = PrivateKey::new(&mut OsRng);

        crate::testing::network::assert_clients_can_exchange_messages(
            instance_1, instance_2, pk, pk,
        )
        .await;
    }
}
