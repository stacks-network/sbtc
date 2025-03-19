//! MessageTransfer implementation for the application signalling channel
//! together with LibP2P.

use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::Sender;

use crate::context::Context;
use crate::context::P2PEvent;
use crate::context::SignerCommand;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::context::TerminationHandle;
use crate::error::Error;
use crate::network::MessageTransfer;
use crate::network::Msg;

/// MessageTransfer interface for the application signalling channel.
pub struct P2PNetwork {
    signal_tx: Sender<SignerSignal>,
    signal_rx: Receiver<SignerSignal>,
    term: TerminationHandle,
}

impl Clone for P2PNetwork {
    fn clone(&self) -> Self {
        Self {
            signal_tx: self.signal_tx.clone(),
            signal_rx: self.signal_tx.subscribe(),
            term: self.term.clone(),
        }
    }
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
    /// messages in a local buffer (i.e. [`VecDeque`](std::collections::VecDeque) and
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
                        Ok(SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(msg)))) => {
                            return Ok(msg);
                        },
                        Err(_) => {
                            return Err(Error::SignerShutdown);
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
    use std::{str::FromStr, time::Duration};

    use futures::StreamExt;
    use libp2p::Multiaddr;
    use test_log::test;
    use tokio_stream::wrappers::BroadcastStream;

    use super::*;

    use crate::{
        keys::{PrivateKey, PublicKey},
        network::libp2p::SignerSwarmBuilder,
        testing::{self, clear_env, context::*, network::RandomMemoryMultiaddr},
    };

    #[test(tokio::test)]
    async fn two_clients_should_be_able_to_exchange_messages_given_a_libp2p_network() {
        clear_env();

        // PeerId = 16Uiu2HAm46BSFWYYWzMjhTRDRwXHpDWpQ32iu93nzDwd1F4Tt256
        let key1 = PrivateKey::from_slice(
            hex::decode("ab0893ecf683dc188c3fb219dd6489dc304bb5babb8151a41245a70e60cb7258")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        // PeerId = 16Uiu2HAkuyB8ECXxACm8hzQj4vZ2iWrYMF3xcKNf1oJJ1NuQEMvQ
        let key2 = PrivateKey::from_slice(
            hex::decode("0dd4077c8bcec09c803f9ba23a0f5b56eba75769b2d1b96a33b579dbbe5055ce")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let context1 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key1;
            })
            .build();
        context1
            .state()
            .current_signer_set()
            .add_signer(PublicKey::from_private_key(&key2));

        let context2 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key2;
            })
            .build();
        context2
            .state()
            .current_signer_set()
            .add_signer(PublicKey::from_private_key(&key1));

        let term1 = context1.get_termination_handle();
        let term2 = context2.get_termination_handle();

        let swarm1_addr = Multiaddr::random_memory();
        let swarm2_addr = Multiaddr::random_memory();

        let mut swarm1 = SignerSwarmBuilder::new(&key1)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm1_addr.clone())
            .add_seed_addr(swarm2_addr.clone())
            .build()
            .expect("Failed to build swarm 1");

        let mut swarm2 = SignerSwarmBuilder::new(&key2)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm2_addr)
            .add_seed_addr(swarm1_addr)
            .build()
            .expect("Failed to build swarm 2");

        let network1 = P2PNetwork::new(&context1);
        let network2 = P2PNetwork::new(&context2);

        // Start the two swarms.
        let handle1 = tokio::spawn(async move {
            swarm1.start(&context1).await.unwrap();
        });
        let handle2 = tokio::spawn(async move {
            swarm2.start(&context2).await.unwrap();
        });

        // The swarms are discovering themselves via mDNS, so we need to give
        // them a bit of time to connect.
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Run the test with a 30-second timeout for the swarms to exchange messages.
        if let Err(_) = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            testing::network::assert_clients_can_exchange_messages(network1, network2, key1, key2),
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

        // Ensure we're shutting down
        term1.signal_shutdown();
        term2.signal_shutdown();
    }

    #[test(tokio::test)]
    async fn connected_peers_gossip_to_one_another() {
        clear_env();

        let mut rng = rand::rngs::OsRng;
        let key1 = PrivateKey::new(&mut rng);
        let key2 = PrivateKey::new(&mut rng);
        let key3 = PrivateKey::new(&mut rng);

        let context1 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key1;
                settings.signer.p2p.enable_mdns = false;
            })
            .build();
        let context2 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key2;
                settings.signer.p2p.enable_mdns = false;
            })
            .build();
        let context3 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key3;
                settings.signer.p2p.enable_mdns = false;
            })
            .build();

        // Let's make sure all signers know about all other signers.
        let current_signer_set1 = context1.state().current_signer_set();
        let current_signer_set2 = context2.state().current_signer_set();
        let current_signer_set3 = context3.state().current_signer_set();

        for key in [key1, key2, key3] {
            current_signer_set1.add_signer(PublicKey::from_private_key(&key));
            current_signer_set2.add_signer(PublicKey::from_private_key(&key));
            current_signer_set3.add_signer(PublicKey::from_private_key(&key));
        }

        let swarm1_addr = Multiaddr::random_memory();
        let swarm2_addr = Multiaddr::random_memory();
        let swarm3_addr = Multiaddr::random_memory();

        // Configure the swarms to listen on hard-coded ports
        let mut swarm1 = SignerSwarmBuilder::new(&key1)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm1_addr.clone())
            .add_seed_addr(swarm2_addr.clone())
            .build()
            .expect("Failed to build swarm 1");

        let mut swarm2 = SignerSwarmBuilder::new(&key2)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm2_addr.clone())
            .add_seed_addr(swarm1_addr.clone())
            .add_seed_addr(swarm3_addr.clone())
            .build()
            .expect("Failed to build swarm 2");

        let mut swarm3 = SignerSwarmBuilder::new(&key3)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm3_addr.clone())
            .add_seed_addr(swarm2_addr.clone())
            .build()
            .expect("Failed to build swarm 3");

        let mut network1 = P2PNetwork::new(&context1);
        let mut network2 = P2PNetwork::new(&context2);
        let mut network3 = P2PNetwork::new(&context3);

        // Start three swarms.
        tokio::spawn(async move {
            swarm1.start(&context1).await.unwrap();
        });
        tokio::spawn(async move {
            swarm2.start(&context2).await.unwrap();
        });
        tokio::spawn(async move {
            swarm3.start(&context3).await.unwrap();
        });

        // The swarms are discovering themselves via mDNS, so we need to give
        // them a bit of time to connect.
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Let's generate some messages for signer 3 to try to send to signer 1.
        let number_of_messages = 10;
        let mut signed_messages: Vec<Msg> =
            std::iter::repeat_with(|| Msg::random_with_private_key(&mut rng, &key3))
                .take(number_of_messages)
                .collect();
        signed_messages.sort_by_cached_key(|x| x.inner.bitcoin_chain_tip);

        let (broadcast_signer_msg, rx) = tokio::sync::broadcast::channel(20);
        let origin_msg_stream = BroadcastStream::new(rx);

        let (gossip_signer_msg, rx) = tokio::sync::broadcast::channel(20);
        let gossip_msg_stream = BroadcastStream::new(rx);

        let broadcast_messages = signed_messages.clone();
        tokio::spawn(async move {
            for msg in broadcast_messages {
                network3.broadcast(msg).await.expect("Failed to broadcast");
            }
        });

        // Let's make sure that signer 2 is getting the messages as well.
        tokio::spawn(async move {
            loop {
                let message = network2.receive().await.expect("Failed to receive message");
                gossip_signer_msg.send(message).unwrap();
            }
        });

        // Signer 1 let's us know when it receives a message
        tokio::spawn(async move {
            loop {
                let message = network1.receive().await.expect("Failed to receive message");
                broadcast_signer_msg.send(message).unwrap();
            }
        });

        // The swarms have 4-seconds to exchange messages.
        let mut gossiped_messages = gossip_msg_stream
            .take(number_of_messages)
            .take_until(tokio::time::sleep(Duration::from_secs(4)))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut received_messages = origin_msg_stream
            .take(number_of_messages)
            .take_until(tokio::time::sleep(Duration::from_secs(4)))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        gossiped_messages.sort_by_cached_key(|x| x.inner.bitcoin_chain_tip);
        received_messages.sort_by_cached_key(|x| x.inner.bitcoin_chain_tip);

        assert_eq!(received_messages, signed_messages);
        assert_eq!(gossiped_messages, signed_messages);
    }

    #[test(tokio::test)]
    async fn signers_check_source_peer_ids() {
        clear_env();

        let mut rng = rand::rngs::OsRng;
        let key1 = PrivateKey::new(&mut rng);
        let key2 = PrivateKey::new(&mut rng);
        let key3 = PrivateKey::new(&mut rng);

        let context1 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key1;
                settings.signer.p2p.enable_mdns = false;
            })
            .build();
        let context2 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key2;
                settings.signer.p2p.enable_mdns = false;
            })
            .build();
        let context3 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key3;
                settings.signer.p2p.enable_mdns = false;
            })
            .build();

        let current_signer_set1 = context1.state().current_signer_set();
        let current_signer_set2 = context2.state().current_signer_set();
        let current_signer_set3 = context3.state().current_signer_set();

        // The first signer does not have signer 3 in it's signer set.
        current_signer_set1.add_signer(PublicKey::from_private_key(&key1));
        current_signer_set1.add_signer(PublicKey::from_private_key(&key2));

        for key in [key1, key2, key3] {
            current_signer_set2.add_signer(PublicKey::from_private_key(&key));
            current_signer_set3.add_signer(PublicKey::from_private_key(&key));
        }

        let swarm1_addr = Multiaddr::random_memory();
        let swarm2_addr = Multiaddr::random_memory();
        let swarm3_addr = Multiaddr::random_memory();

        let mut swarm1 = SignerSwarmBuilder::new(&key1)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm1_addr.clone())
            .add_seed_addr(swarm2_addr.clone())
            .build()
            .expect("Failed to build swarm 1");

        let mut swarm2 = SignerSwarmBuilder::new(&key2)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm2_addr.clone())
            .add_seed_addr(swarm1_addr.clone())
            .add_seed_addr(swarm3_addr.clone())
            .build()
            .expect("Failed to build swarm 2");

        let mut swarm3 = SignerSwarmBuilder::new(&key3)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm3_addr.clone())
            .add_seed_addr(swarm2_addr.clone())
            .build()
            .expect("Failed to build swarm 3");

        let mut network1 = P2PNetwork::new(&context1);
        let mut network2 = P2PNetwork::new(&context2);
        let mut network3 = P2PNetwork::new(&context3);

        // Start three swarms.
        tokio::spawn(async move {
            swarm1.start(&context1).await.unwrap();
        });
        tokio::spawn(async move {
            swarm2.start(&context2).await.unwrap();
        });
        tokio::spawn(async move {
            swarm3.start(&context3).await.unwrap();
        });

        // The swarms are discovering themselves via mDNS, so we need to give
        // them a bit of time to connect.
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Let's generate some messages for signer 3 to try to send to signer 1.
        let number_of_messages = 10;
        let mut signed_messages: Vec<Msg> =
            std::iter::repeat_with(|| Msg::random_with_private_key(&mut rng, &key3))
                .take(number_of_messages)
                .collect();
        signed_messages.sort_by_cached_key(|x| x.inner.bitcoin_chain_tip);

        let (origin_signer_msg, rx) = tokio::sync::broadcast::channel(20);
        let origin_msg_stream = BroadcastStream::new(rx);

        let (gossip_signer_msg, rx) = tokio::sync::broadcast::channel(20);
        let gossip_msg_stream = BroadcastStream::new(rx);

        // Okay let's have signer 3 broadcast the messages.
        let broadcast_messages = signed_messages.clone();
        tokio::spawn(async move {
            for msg in broadcast_messages {
                network3.broadcast(msg).await.expect("Failed to broadcast");
            }
        });

        // Let's make sure that signer 2 is getting the messages as well.
        tokio::spawn(async move {
            loop {
                let message = network2.receive().await.expect("Failed to receive message");
                gossip_signer_msg.send(message).unwrap();
            }
        });

        // Signer 1 shouldn't receive anything, but let's set him up to
        // try.
        tokio::spawn(async move {
            loop {
                let message = network1.receive().await.expect("Failed to receive message");
                origin_signer_msg.send(message).unwrap();
            }
        });

        // This is the connected signer, signer 2, it should receive all
        // messages pretty quicky.
        let mut gossiped_messages = gossip_msg_stream
            .take(number_of_messages)
            .take_until(tokio::time::sleep(Duration::from_secs(4)))
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // This is for signer 1, who does not have signer 3 in it's signer
        // set. It should not get any messages in receive(). To check the
        // expected behavior we wait for our first message, but not for too
        // long, life is short.
        let received_messages = origin_msg_stream
            .take(1)
            .take_until(tokio::time::sleep(Duration::from_secs(4)))
            .collect::<Vec<_>>()
            .await;

        // Messages from signer 3 should not be propogated to signer 1,
        // since it is not in that signer's signing set.
        assert!(received_messages.is_empty());

        // Now let's check that the gossipped messages are received and
        // accepted by signer 2.
        gossiped_messages.sort_by_cached_key(|x| x.inner.bitcoin_chain_tip);
        assert_eq!(gossiped_messages, signed_messages);
    }

    #[tokio::test]
    async fn swarm_rejects_connections_from_unknown_peers() {
        // In this test we create three swarms (simulating three signers). We
        // simulate that signers 1 & 2 are trusted peers, and that signer 3 is
        // an untrusted peer. We start the swarms and ensure that signers 1 & 2
        // can exchange messages, but that signer 3 is rejected by both signers.
        //
        // TODO: This test could be made much more efficient by emitting more
        // events from the swarms and checking that the expected events are
        // emitted.

        // PeerId = 16Uiu2HAm46BSFWYYWzMjhTRDRwXHpDWpQ32iu93nzDwd1F4Tt256
        let key1 = PrivateKey::from_str(
            "ab0893ecf683dc188c3fb219dd6489dc304bb5babb8151a41245a70e60cb7258",
        )
        .unwrap();
        // PeerId = 16Uiu2HAkuyB8ECXxACm8hzQj4vZ2iWrYMF3xcKNf1oJJ1NuQEMvQ
        let key2 = PrivateKey::from_str(
            "0dd4077c8bcec09c803f9ba23a0f5b56eba75769b2d1b96a33b579dbbe5055ce",
        )
        .unwrap();
        // PeerId = 16Uiu2HAkv4DBE9f9eg53RoRYsfuzJXdoAvRU91gb6oii5pTseo1j
        let key3 = PrivateKey::from_str(
            "bdbb219e045b12c12d99c86afd83764ea67a9e3c0127c0298d7c57b3597a4645",
        )
        .unwrap();

        // Create the context for signer1.
        let context1 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key1;
            })
            .build();
        // Add key2 to the known signers for signer1.
        context1
            .state()
            .current_signer_set()
            .add_signer(PublicKey::from_private_key(&key2));

        // Create the context for signer2.
        let context2 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key2;
            })
            .build();
        // Add key1 to the known signers for signer2.
        context2
            .state()
            .current_signer_set()
            .add_signer(PublicKey::from_private_key(&key1));

        // Create the context for signer3.
        let context3 = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key3;
            })
            .build();
        // Add key1 and key2 to the known signers for signer 3. This simulates
        // what an adversary signer might do, i.e. it would want to join with
        // the known signers.
        context3
            .state()
            .current_signer_set()
            .add_signer(PublicKey::from_private_key(&key1));
        context3
            .state()
            .current_signer_set()
            .add_signer(PublicKey::from_private_key(&key2));

        let swarm1_addr = Multiaddr::random_memory();
        let swarm2_addr = Multiaddr::random_memory();
        let swarm3_addr = Multiaddr::random_memory();

        // Create the two trusted swarms.
        let mut swarm1 = SignerSwarmBuilder::new(&key1)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm1_addr.clone())
            .add_seed_addrs(&[swarm2_addr.clone(), swarm3_addr.clone()])
            .build()
            .expect("Failed to build swarm 1");
        let mut swarm2 = SignerSwarmBuilder::new(&key2)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm2_addr.clone())
            .add_seed_addrs(&[swarm1_addr.clone(), swarm3_addr.clone()])
            .build()
            .expect("Failed to build swarm 2");
        // Create the adversarial swarm.
        let mut swarm3 = SignerSwarmBuilder::new(&key3)
            .enable_memory_transport(true)
            .add_listen_endpoint(swarm3_addr.clone())
            .add_seed_addrs(&[swarm1_addr, swarm2_addr])
            .build()
            .expect("Failed to build swarm 3");

        // Create the network liasons for the swarms (i.e. `MessageTransfer`
        // instances).
        let mut trusted1 = P2PNetwork::new(&context1);
        let mut trusted2 = P2PNetwork::new(&context2);
        let mut adversarial = P2PNetwork::new(&context3);

        // Start the swarms.
        let handle1 = tokio::spawn(async move {
            swarm1.start(&context1).await.unwrap();
        });
        let handle2 = tokio::spawn(async move {
            swarm2.start(&context2).await.unwrap();
        });
        let handle3 = tokio::spawn(async move {
            swarm3.start(&context3).await.unwrap();
        });

        // Give the swarms a bit of time to connect.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test that trusted 2 can send a message to trusted 1.
        let trusted_msg_from_2_to_1 = tokio::time::timeout(Duration::from_secs(1), async {
            trusted1.receive().await.unwrap();
        });
        let msg_from_2_to_adversarial = tokio::time::timeout(Duration::from_secs(1), async {
            adversarial.receive().await.unwrap();
        });
        trusted2
            .broadcast(Msg::random_with_private_key(&mut rand::thread_rng(), &key2))
            .await
            .unwrap();
        trusted_msg_from_2_to_1
            .await
            .expect("Failed to receive message from trusted 2 to trusted 1");
        msg_from_2_to_adversarial
            .await
            .expect_err("Adversarial should not receive messages");

        // Test that trusted 1 can send a message to trusted 2.
        let trusted_msg_from_1_to_2 = tokio::time::timeout(Duration::from_secs(1), async {
            trusted2.receive().await.unwrap();
        });
        let msg_from_1_to_adversarial = tokio::time::timeout(Duration::from_secs(1), async {
            adversarial.receive().await.unwrap();
        });
        trusted1
            .broadcast(Msg::random_with_private_key(&mut rand::thread_rng(), &key1))
            .await
            .unwrap();
        trusted_msg_from_1_to_2
            .await
            .expect("Failed to receive message from trusted 1 to trusted 2");
        msg_from_1_to_adversarial
            .await
            .expect_err("Adversarial should not receive messages");

        // Test that adversarial can't send a message to trusted 1.
        let adversarial_msg_to_1 = tokio::time::timeout(Duration::from_secs(1), async {
            trusted1.receive().await.unwrap();
        });
        adversarial
            .broadcast(Msg::random(&mut rand::thread_rng()))
            .await
            .unwrap();
        assert!(adversarial_msg_to_1.await.is_err());

        // Test that adversarial can't send a message to trusted 2.
        let adversarial_msg_to_2 = tokio::time::timeout(Duration::from_secs(1), async {
            trusted2.receive().await.unwrap();
        });
        adversarial
            .broadcast(Msg::random(&mut rand::thread_rng()))
            .await
            .unwrap();
        assert!(adversarial_msg_to_2.await.is_err());

        // Kill the swarms just to be sure.
        handle1.abort();
        handle2.abort();
        handle3.abort();
    }
}
