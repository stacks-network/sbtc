use std::sync::Arc;
use std::time::Duration;

use libp2p::swarm::SwarmEvent;
use libp2p::{autonat, gossipsub, identify, mdns, Swarm};
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio_stream::StreamExt as _;

use crate::codec::{Decode, Encode};
use crate::context::{P2PEvent, SignerCommand, SignerSignal, TerminationHandle};
use crate::network::Msg;

use super::swarm::{SignerBehavior, SignerBehaviorEvent};
use super::TOPIC;

#[tracing::instrument(skip_all, name = "p2p")]
pub async fn run(
    term: &mut TerminationHandle,
    swarm: Arc<Mutex<Swarm<SignerBehavior>>>,
    signal_tx: Sender<SignerSignal>,
    mut signal_rx: Receiver<SignerSignal>,
) {
    // Subscribe to the gossipsub topic.
    let topic = TOPIC.clone();
    swarm
        .lock()
        .await
        .behaviour_mut()
        .gossipsub
        .subscribe(&TOPIC)
        .expect("failed to subscribe to topic");

    // Here we create a future that listens for `P2PPublish` commands from the
    // app signalling channel and pushes them into the outbound message queue.
    // This queue is then polled by the `poll_swarm` event loop to publish the
    // messages to the network.
    let outbox = RwLock::new(Vec::<Msg>::new());
    let poll_outbound = async {
        tracing::debug!("P2P outbound message polling started");
        loop {
            let Ok(SignerSignal::Command(SignerCommand::P2PPublish(payload))) =
                signal_rx.recv().await
            else {
                continue;
            };

            outbox.write().await.push(payload);
        }
    };

    // Here we create a future that polls the libp2p swarm for events and also
    // publishes messages from the outbox to the network.
    let poll_swarm = async {
        tracing::debug!("P2P network polling started");
        
        loop {
            // Poll the libp2p swarm for events, waiting for a maximum of 5ms
            // so that we don't starve the outbox.
            let event =
                match tokio::time::timeout(Duration::from_millis(5), swarm.lock().await.next())
                    .await
                {
                    Ok(event) => event,
                    Err(_) => None,
                };

            // Handle the event if one was received.
            if let Some(event) = event {
                let swarm = &mut *swarm.lock().await;

                match event {
                    // mDNS autodiscovery events. These are used by the local
                    // peer to discover other peers on the local network.
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Mdns(event)) => {
                        handle_mdns_event(swarm, event)
                    }
                    // Identify protocol events. These are used by the relay to
                    // help determine/verify its own address.
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Identify(event)) => {
                        handle_identify_event(swarm, event)
                    }
                    // Gossipsub protocol events.
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Gossipsub(event)) => {
                        handle_gossipsub_event(swarm, event, &signal_tx)
                    }
                    // AutoNAT client protocol events.
                    SwarmEvent::Behaviour(SignerBehaviorEvent::AutonatClient(event)) => {
                        handle_autonat_client_event(swarm, event)
                    }
                    // AutoNAT server protocol events.
                    SwarmEvent::Behaviour(SignerBehaviorEvent::AutonatServer(event)) => {
                        handle_autonat_server_event(swarm, event)
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        tracing::info!(%address, "Listener started");
                    }
                    SwarmEvent::ExpiredListenAddr { address, .. } => {
                        tracing::debug!(%address, "Listener expired");
                    }
                    SwarmEvent::ListenerClosed { addresses, reason, .. } => {
                        tracing::info!(?addresses, ?reason, "Listener closed");
                    }
                    SwarmEvent::ListenerError { listener_id, error } => {
                        tracing::warn!(%listener_id, %error, "Listener error");
                    }
                    SwarmEvent::Dialing { peer_id, connection_id } => {
                        tracing::info!(peer_id = ?peer_id, %connection_id, "Dialing peer");
                    }
                    SwarmEvent::ConnectionEstablished { endpoint, peer_id, .. } => {
                        tracing::info!(%peer_id, ?endpoint, "Connected to peer");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        tracing::info!(%peer_id, ?cause, "Connection closed");
                    }
                    SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                        tracing::debug!(%local_addr, %send_back_addr, "Incoming connection");
                    }
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Ping(ping)) => {
                        tracing::trace!("ping received: {:?}", ping);
                    }
                    SwarmEvent::OutgoingConnectionError { connection_id, error, .. } => {
                        tracing::warn!(%connection_id, %error, "outgoing connection error");
                    }
                    SwarmEvent::IncomingConnectionError {
                        local_addr,
                        send_back_addr,
                        error,
                        ..
                    } => {
                        tracing::warn!(%local_addr, %send_back_addr, %error, "incoming connection error");
                    }
                    SwarmEvent::NewExternalAddrCandidate { address } => {
                        tracing::debug!(%address, "New external address candidate");
                    }
                    SwarmEvent::ExternalAddrConfirmed { address } => {
                        tracing::debug!(%address, "External address confirmed");
                    }
                    SwarmEvent::ExternalAddrExpired { address } => {
                        tracing::debug!(%address, "External address expired");
                    }
                    SwarmEvent::NewExternalAddrOfPeer { peer_id, address } => {
                        tracing::debug!(%peer_id, %address, "New external address of peer");
                    }
                    // The derived `SwarmEvent` is marked as #[non_exhaustive], so we must have a
                    // catch-all.
                    _ => tracing::trace!("unhandled swarm event"),
                }
            }

            // Drain the outbox and publish the messages to the network.
            let outbox = outbox.write().await.drain(..).collect::<Vec<_>>();
            for payload in outbox {
                tracing::info!("publishing message");
                let msg_id = payload.id();

                // Attempt to encode the message payload into bytes
                // using the signer codec.
                let encoded_msg = match payload.encode_to_vec() {
                    Ok(msg) => msg,
                    Err(error) => {
                        // An error occurred while encoding the message.
                        // Log the error and send a failure signal to the application
                        // so that it can handle the failure as needed.
                        tracing::warn!(%error, "Failed to encode message");
                        let _ = signal_tx.send(P2PEvent::PublishFailure(msg_id).into());
                        continue;
                    }
                };

                let _ = swarm
                    .lock()
                    .await
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), encoded_msg)
                    .map_err(|error| {
                        // An error occurred while attempting to publish.
                        // Log the error and send a failure signal to the application
                        // so that it can handle the failure as needed.
                        tracing::warn!(%error, ?msg_id, "Failed to publish message");
                        let _ = signal_tx.send(P2PEvent::PublishFailure(msg_id).into());
                    })
                    .map(|_| {
                        // The message was published successfully. Log the success
                        // and send a success signal to the application so that it can
                        // handle the success as needed.
                        tracing::trace!(?msg_id, "Message published successfully");
                        let _ = signal_tx.send(P2PEvent::PublishSuccess(msg_id).into());
                    });
            }
        }
    };

    tokio::select! {
        _ = term.wait_for_shutdown() => {
            tracing::info!("libp2p received a termination signal; stopping the libp2p swarm");
        },
        _ = poll_outbound => {},
        _ = poll_swarm => {},
    }

    tracing::info!("libp2p event loop terminated");
}

fn handle_autonat_client_event(_: &mut Swarm<SignerBehavior>, event: autonat::v2::client::Event) {
    use autonat::v2::client::Event;

    match event {
        //  Match on successful AutoNAT test event
        Event {
            server,
            tested_addr,
            bytes_sent,
            result: Ok(()),
        } => {
            tracing::trace!(%server, %tested_addr, %bytes_sent, "AutoNAT (client) test successful");
        }
        // Match on failed AutoNAT test event
        Event {
            server,
            tested_addr,
            bytes_sent,
            result: Err(e),
        } => {
            tracing::trace!(%server, %tested_addr, %bytes_sent, %e, "AutoNAT (client) test failed");
        }
    }
}

fn handle_autonat_server_event(_: &mut Swarm<SignerBehavior>, event: autonat::v2::server::Event) {
    use autonat::v2::server::Event;

    match event {
        Event {
            all_addrs,
            client,
            tested_addr,
            data_amount,
            result: Ok(()),
        } => {
            tracing::trace!(
                ?all_addrs, 
                %client, 
                %tested_addr, 
                %data_amount, 
                "AutoNAT (server) test successful");
        }
        Event {
            all_addrs,
            client,
            tested_addr,
            data_amount,
            result: Err(error),
        } => {
            tracing::warn!(
                ?all_addrs,
                %client,
                %tested_addr,
                %data_amount,
                %error,
                "AutoNAT (server) test failed");
        }
    }
}

fn handle_mdns_event(swarm: &mut Swarm<SignerBehavior>, event: mdns::Event) {
    use mdns::Event;

    match event {
        // A multicast-DNS event indicating that a new peer has been discovered.
        // mDNS can only be used to discover peers on the same local network,
        // so this will never be raised for WAN peers which must otherwise
        // be discovered via seed nodes.
        Event::Discovered(peers) => {
            for (peer_id, addr) in peers {
                tracing::info!(%peer_id, %addr, "Discovered peer via mDNS");
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
            }
        }
        // A multicast-DNS event indicating that a previously discovered peer
        // has expired. This is raised when the TTL of the autodiscovery has
        // expired and the peer's address has not been updated.
        Event::Expired(peers) => {
            for (peer_id, addr) in peers {
                tracing::info!(%peer_id, %addr, "Expired peer via mDNS");
            }
        }
    }
}

fn handle_identify_event(swarm: &mut Swarm<SignerBehavior>, event: identify::Event) {
    use identify::Event;

    match event {
        Event::Received { peer_id, info, .. } => {
            tracing::debug!(%peer_id, "Received identify message from peer; adding to confirmed external addresses");
            swarm.add_external_address(info.observed_addr.clone());
        }
        Event::Pushed { connection_id, peer_id, info } => {
            tracing::trace!(%connection_id, %peer_id, ?info, "Pushed identify message to peer");
        }
        Event::Error { connection_id, peer_id, error } => {
            tracing::warn!(%connection_id, %peer_id, %error, "Error handling identify message");
        }
        Event::Sent { connection_id, peer_id } => {
            tracing::trace!(%connection_id, %peer_id, "Sent identify message to peer");
        }
    }
}

fn handle_gossipsub_event(
    swarm: &mut Swarm<SignerBehavior>,
    event: gossipsub::Event,
    signal_tx: &Sender<SignerSignal>,
) {
    use gossipsub::Event;

    match event {
        Event::Message {
            propagation_source: peer_id,
            message_id: id,
            message,
        } => {
            tracing::trace!(local_peer_id = %swarm.local_peer_id(), %peer_id,
                "Got message: '{}' with id: {id} from peer: {peer_id}",
                String::from_utf8_lossy(&message.data),
            );

            Msg::decode(message.data.as_slice())
                .map(|msg| {
                    let _ = signal_tx
                        .send(P2PEvent::MessageReceived(msg).into())
                        .map_err(|error| {
                            tracing::debug!(%error, "Failed to send message to application; we are likely shutting down.");
                        });
                })
                .unwrap_or_else(|error| {
                    tracing::warn!(?peer_id, %error, "Failed to decode message");
                });
        }
        Event::Subscribed { peer_id, topic } => {
            tracing::info!(%peer_id, %topic, "Subscribed to topic");
        }
        Event::Unsubscribed { peer_id, topic } => {
            tracing::info!(%peer_id, %topic, "Unsubscribed from topic");
        }
        Event::GossipsubNotSupported { peer_id } => {
            tracing::warn!(%peer_id, "Peer does not support gossipsub");
        }
    }
}
