use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, identify, kad, mdns, Multiaddr, Swarm};
use tokio::sync::Mutex;

use crate::codec::{Decode, Encode};
use crate::context::{Context, P2PEvent, SignerCommand, SignerSignal};
use crate::network::Msg;

use super::swarm::{SignerBehavior, SignerBehaviorEvent};
use super::TOPIC;

#[tracing::instrument(skip_all, name = "p2p")]
pub async fn run(ctx: &impl Context, swarm: Arc<Mutex<Swarm<SignerBehavior>>>) {
    // Subscribe to the gossipsub topic.
    let topic = TOPIC.clone();
    swarm
        .lock()
        .await
        .behaviour_mut()
        .gossipsub
        .subscribe(&TOPIC)
        .expect("failed to subscribe to topic");

    let mut term = ctx.get_termination_handle();
    let mut signal_rx = ctx.get_signal_receiver();
    let signal_tx = ctx.get_signal_sender();

    // Here we create a future that listens for `P2PPublish` commands from the
    // app signalling channel and pushes them into the outbound message queue.
    // This queue is then polled by the `poll_swarm` event loop to publish the
    // messages to the network.
    let outbox = Mutex::new(Vec::<Msg>::new());
    let poll_outbound = async {
        tracing::debug!("P2P outbound message polling started");
        loop {
            let Ok(SignerSignal::Command(SignerCommand::P2PPublish(payload))) =
                signal_rx.recv().await
            else {
                continue;
            };

            outbox.lock().await.push(payload);
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
                let mut swarm = swarm.lock().await;

                match event {
                    // mDNS autodiscovery events. These are used by the local
                    // peer to discover other peers on the local network.
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Mdns(event)) => {
                        handle_mdns_event(&mut swarm, ctx, event)
                    }
                    // Identify protocol events. These are used by the relay to
                    // help determine/verify its own address.
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Identify(event)) => {
                        handle_identify_event(&mut swarm, ctx, event)
                    }
                    // Gossipsub protocol events.
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Gossipsub(event)) => {
                        handle_gossipsub_event(&mut swarm, ctx, event)
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
                        tracing::trace!(?peer_id, %connection_id, "Dialing peer");
                    }
                    SwarmEvent::ConnectionEstablished { endpoint, peer_id, .. } => {
                        if !ctx.state().current_signer_set().is_allowed_peer(&peer_id) {
                            tracing::warn!(%peer_id, ?endpoint, "Connected to peer, however it is not a known signer; disconnecting");
                            let _ = swarm.disconnect_peer_id(peer_id);
                            continue;
                        }
                        tracing::info!(%peer_id, ?endpoint, "Connected to peer");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, endpoint, .. } => {
                        tracing::trace!(%peer_id, ?cause, ?endpoint, "Connection closed");
                    }
                    SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                        tracing::trace!(%local_addr, %send_back_addr, "Incoming connection");
                    }
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Ping(ping)) => {
                        tracing::trace!("ping received: {:?}", ping);
                    }
                    SwarmEvent::OutgoingConnectionError { connection_id, error, peer_id } => {
                        tracing::trace!(%connection_id, %error, ?peer_id, "outgoing connection error");
                    }
                    SwarmEvent::IncomingConnectionError {
                        local_addr,
                        send_back_addr,
                        error,
                        ..
                    } => {
                        tracing::trace!(%local_addr, %send_back_addr, %error, "incoming connection error");
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
                        if swarm.listeners().any(|addr| addr == &address) {
                            tracing::debug!(%peer_id, %address, "ignoring our own external address");
                        } else {
                            tracing::debug!(%peer_id, %address, "New external address of peer");
                            let kad_addr = strip_peer_id(&address);
                            tracing::debug!(%peer_id, %kad_addr, "Adding address to kademlia");
                            swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, kad_addr);
                        }
                    }
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Kademlia(event)) => {
                        handle_kademlia_event(event);
                    }
                    SwarmEvent::Behaviour(SignerBehaviorEvent::AutonatClient(event)) => {
                        tracing::debug!(
                            tested_addr = ?event.tested_addr,
                            server = ?event.server,
                            result = ?event.result,
                            "autonat client event"
                        );
                    }
                    SwarmEvent::Behaviour(SignerBehaviorEvent::AutonatServer(event)) => {
                        tracing::debug!(
                            all_addrs = ?event.all_addrs,
                            tested_addr = ?event.tested_addr,
                            client = ?event.client,
                            result = ?event.result,
                            "autonat server event"
                        );
                    }
                    // The derived `SwarmEvent` is marked as #[non_exhaustive], so we must have a
                    // catch-all.
                    event => tracing::trace!(?event, "unhandled swarm event"),
                }
            }

            // Drain the outbox and publish the messages to the network.
            let outbox = outbox.lock().await.drain(..).collect::<Vec<_>>();
            for payload in outbox {
                let msg_id = payload.id();
                tracing::trace!(
                    message_id = hex::encode(msg_id),
                    msg = %payload,
                    "publishing message"
                );

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
                    .inspect_err(|error| {
                        // An error occurred while attempting to publish.
                        // Log the error and send a failure signal to the application
                        // so that it can handle the failure as needed.
                        tracing::warn!(%error, ?msg_id, "Failed to publish message");
                        let _ = signal_tx.send(P2PEvent::PublishFailure(msg_id).into());
                    })
                    .inspect(|_| {
                        // The message was published successfully. Log the success
                        // and send a success signal to the application so that it can
                        // handle the success as needed.
                        tracing::trace!(?msg_id, "Message published successfully");
                        let _ = signal_tx.send(P2PEvent::PublishSuccess(msg_id).into());
                    });
            }
        }
    };

    let log = async {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let swarm = swarm.lock().await;
            let peers = swarm.connected_peers().collect::<Vec<_>>();
            tracing::debug!(?peers, "connected peers");
        }
    };

    tokio::select! {
        _ = term.wait_for_shutdown() => {
            tracing::info!("libp2p received a termination signal; stopping the libp2p swarm");
        },
        _ = poll_outbound => {},
        _ = poll_swarm => {},
        _ = log => {},
    }

    tracing::info!("libp2p event loop terminated");
}

fn handle_kademlia_event(event: kad::Event) {
    match event {
        kad::Event::RoutingUpdated {
            peer,
            is_new_peer,
            addresses,
            bucket_range,
            old_peer,
        } => {
            tracing::debug!(
                %peer,
                is_new_peer,
                ?addresses,
                ?bucket_range,
                ?old_peer,
                "kademlia routing table updated"
            );
        }
        _ => tracing::trace!(?event, "kademlia event"),
    }
}

fn handle_mdns_event(swarm: &mut Swarm<SignerBehavior>, ctx: &impl Context, event: mdns::Event) {
    use mdns::Event;

    match event {
        // A multicast-DNS event indicating that a new peer has been discovered.
        // mDNS can only be used to discover peers on the same local network,
        // so this will never be raised for WAN peers which must otherwise
        // be discovered via seed nodes.
        Event::Discovered(peers) => {
            // If we have disabled mDNS, we should not process this event.
            if !ctx.config().signer.p2p.enable_mdns {
                return;
            }

            for (peer_id, addr) in peers {
                if !ctx.state().current_signer_set().is_allowed_peer(&peer_id) {
                    tracing::warn!(%peer_id, %addr, "Discovered peer via mDNS, however it is not a known signer; ignoring");
                    continue;
                }

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
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .remove_explicit_peer(&peer_id);
            }
        }
    }
}

fn handle_identify_event(
    swarm: &mut Swarm<SignerBehavior>,
    _: &impl Context,
    event: identify::Event,
) {
    use identify::Event;

    match event {
        Event::Received { peer_id, info, .. } => {
            tracing::debug!(%peer_id, ?info, "Received identify message from peer");
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, strip_peer_id(&info.observed_addr));
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
    ctx: &impl Context,
    event: gossipsub::Event,
) {
    use gossipsub::Event;

    match event {
        Event::Message {
            propagation_source: peer_id,
            message,
            ..
        } => {
            if !ctx.state().current_signer_set().is_allowed_peer(&peer_id) {
                tracing::warn!(%peer_id, "ignoring message from unknown peer");
                return;
            }

            Msg::decode(message.data.as_slice())
                .map(|msg| {
                    tracing::trace!(
                        local_peer_id = %swarm.local_peer_id(),
                        %peer_id,
                        message_id = hex::encode(msg.id()),
                        %msg,
                        "received message",
                    );

                    let _ = ctx.get_signal_sender()
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

/// For a multiaddr that ends with a peer id, this strips this suffix. Rust-libp2p
/// only supports dialing to an address without providing the peer id.
fn strip_peer_id(addr: &Multiaddr) -> Multiaddr {
    let mut new_addr = Multiaddr::empty();
    for protocol in addr.iter().take_while(|p| !matches!(p, Protocol::P2p(_))) {
        new_addr.push(protocol);
    }
    new_addr
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_strip_peer_id() {
        let endpoint =
            "/ip4/198.51.100.0/tcp/4242/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";
        let addr = Multiaddr::from_str(endpoint).unwrap();

        let stripped = strip_peer_id(&addr);

        let stripped_str = "/ip4/198.51.100.0/tcp/4242";
        assert_eq!(stripped.to_string(), stripped_str);
    }
}
