use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::kad::RoutingUpdate;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, identify, kad, mdns, Swarm};
use tokio::sync::Mutex;

use crate::codec::Encode;
use crate::context::{Context, P2PEvent, SignerCommand, SignerSignal};
use crate::error::Error;
use crate::network::Msg;

use super::swarm::{SignerBehavior, SignerBehaviorEvent};
use super::TOPIC;

#[tracing::instrument(skip_all, name = "swarm")]
pub async fn run(ctx: &impl Context, swarm: Arc<Mutex<Swarm<SignerBehavior>>>) {
    // Subscribe to the gossipsub topic.
    let topic = TOPIC.clone();
    swarm
        .lock()
        .await
        .behaviour_mut()
        .gossipsub
        .subscribe(&TOPIC)
        // If this doesn't succeed then nothing will work. It should never fail.
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
        tracing::debug!("p2p outbound message polling started");
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
        tracing::debug!("p2p network polling started");

        loop {
            // Poll the libp2p swarm for events, waiting for a maximum of 5ms
            // so that we don't starve the outbox.
            let event = tokio::time::timeout(Duration::from_millis(5), swarm.lock().await.next())
                .await
                .unwrap_or_default();

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
                        tracing::info!(%address, "listener started");
                    }
                    SwarmEvent::ExpiredListenAddr { address, .. } => {
                        tracing::debug!(%address, "listener expired");
                    }
                    SwarmEvent::ListenerClosed { addresses, reason, .. } => {
                        tracing::debug!(?addresses, ?reason, "listener closed");
                    }
                    SwarmEvent::ListenerError { listener_id, error } => {
                        tracing::warn!(%listener_id, %error, "listener error");
                    }
                    SwarmEvent::Dialing { peer_id, connection_id } => {
                        tracing::trace!(?peer_id, %connection_id, "dialing peer");
                    }
                    SwarmEvent::ConnectionEstablished {
                        connection_id,
                        endpoint,
                        peer_id,
                        ..
                    } => {
                        if !ctx.state().current_signer_set().is_allowed_peer(&peer_id) {
                            tracing::warn!(%connection_id, %peer_id, ?endpoint, "connected to peer, however it is not a known signer; disconnecting");
                            let _ = swarm.disconnect_peer_id(peer_id);
                        } else {
                            tracing::debug!(%peer_id, ?endpoint, "connected to peer");
                            if endpoint.is_dialer() {
                                let kad_addr = endpoint.get_remote_address();
                                tracing::debug!(%peer_id, %kad_addr, "adding address to kademlia");
                                swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .add_address(&peer_id, kad_addr.clone());
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, cause, endpoint, .. } => {
                        tracing::trace!(%peer_id, ?cause, ?endpoint, "connection closed");
                    }
                    SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                        tracing::trace!(%local_addr, %send_back_addr, "incoming connection");
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
                        tracing::debug!(%address, "new external address candidate (ours)");
                    }
                    SwarmEvent::ExternalAddrConfirmed { address } => {
                        tracing::debug!(%address, "external address confirmed (ours)");
                    }
                    SwarmEvent::ExternalAddrExpired { address } => {
                        tracing::debug!(%address, "external address expired (ours)");
                    }
                    SwarmEvent::NewExternalAddrOfPeer { peer_id, address } => {
                        if &peer_id == swarm.local_peer_id() {
                            tracing::debug!(%peer_id, %address, "ignoring our own external address");
                        } else {
                            tracing::debug!(%peer_id, %address, "new external address of peer");

                            let result = swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, address.clone());

                            match result {
                                RoutingUpdate::Success => {
                                    tracing::debug!(%peer_id, %address, "added peer address to kademlia");
                                }
                                RoutingUpdate::Failed => {
                                    tracing::warn!(%peer_id, %address, "failed to add peer address to kademlia");
                                }
                                RoutingUpdate::Pending => {
                                    tracing::debug!(%peer_id, %address, "request to add peer address to kademlia is pending");
                                }
                            }
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
                    SwarmEvent::Behaviour(SignerBehaviorEvent::Bootstrap(_)) => {}
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

                // Encode the message payload into bytes using the signer codec.
                let encoded_msg = payload.encode_to_vec();

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
                        tracing::warn!(%error, ?msg_id, "failed to publish message");
                        let _ = signal_tx.send(P2PEvent::PublishFailure(msg_id).into());
                    })
                    .inspect(|_| {
                        // The message was published successfully. Log the success
                        // and send a success signal to the application so that it can
                        // handle the success as needed.
                        tracing::trace!(?msg_id, "message published successfully");
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

#[tracing::instrument(skip_all, name = "kademlia")]
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

#[tracing::instrument(skip_all, name = "mdns")]
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
                    tracing::debug!(%peer_id, %addr, "discovered peer via mDNS, however it is not a known signer; ignoring");
                    continue;
                }

                tracing::debug!(%peer_id, %addr, "discovered peer via mDNS");
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
            }
        }
        // A multicast-DNS event indicating that a previously discovered peer
        // has expired. This is raised when the TTL of the autodiscovery has
        // expired and the peer's address has not been updated.
        Event::Expired(peers) => {
            for (peer_id, addr) in peers {
                tracing::debug!(%peer_id, %addr, "expired peer via mDNS");
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .remove_explicit_peer(&peer_id);
            }
        }
    }
}

#[tracing::instrument(skip_all, name = "identify")]
fn handle_identify_event(
    _swarm: &mut Swarm<SignerBehavior>,
    _: &impl Context,
    event: identify::Event,
) {
    use identify::Event;

    match event {
        Event::Received { peer_id, info, .. } => {
            tracing::debug!(%peer_id, ?info, "received identify message from peer");
        }
        Event::Pushed { connection_id, peer_id, info } => {
            tracing::debug!(%connection_id, %peer_id, ?info, "pushed identify message to peer");
        }
        Event::Error { connection_id, peer_id, error } => {
            tracing::warn!(%connection_id, %peer_id, %error, "error handling identify message");
        }
        Event::Sent { connection_id, peer_id } => {
            tracing::debug!(%connection_id, %peer_id, "sent identify message to peer");
        }
    }
}

#[tracing::instrument(skip_all, name = "gossipsub")]
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
            let current_signer_set = ctx.state().current_signer_set();
            // The following check should be unnecessary. In order to
            // receive a message the peer needs to establish a connection,
            // and in order to do that the peer needs to be in the current
            // signer set. When we implement the signing set changing code,
            // we should re-evaluate whether we should remove this check.
            if !current_signer_set.is_allowed_peer(&peer_id) {
                tracing::warn!(%peer_id, "ignoring message from unknown peer");
                return;
            }

            // The message may have originated from someone else, let's
            // check that peer ID too. If we haven't been told the source
            // then we distrust the message and ignore it.
            let Some(origin_peer_id) = message.source else {
                tracing::warn!(%peer_id, "origin peer id unknown, ignoring message");
                return;
            };

            if !current_signer_set.is_allowed_peer(&origin_peer_id) {
                tracing::warn!(%origin_peer_id, "ignoring message from unknown origin peer");
                return;
            }

            Msg::decode_with_digest(&message.data)
                .and_then(|(msg, digest)| {
                    tracing::trace!(
                        local_peer_id = %swarm.local_peer_id(),
                        %peer_id,
                        message_id = hex::encode(msg.id()),
                        %msg,
                        "received message",
                    );

                    if origin_peer_id != msg.signer_public_key.into() {
                        tracing::error!(%origin_peer_id, "connected peer sent an invalid message");
                        return Err(Error::InvalidSignature)
                    }

                    if let Err(error) = msg.verify_digest(digest) {
                        tracing::error!(%origin_peer_id, "connected peer sent an invalid signature");
                        return Err(error)
                    }

                    let _ = ctx.get_signal_sender()
                        .send(P2PEvent::MessageReceived(msg).into())
                        .inspect_err(|error| {
                            tracing::debug!(%error, "Failed to send message to application; we are likely shutting down.");
                        });

                    Ok(())
                })
                .unwrap_or_else(|error| {
                    tracing::warn!(%peer_id, %error, "Failed to decode message");
                });
        }
        Event::Subscribed { peer_id, topic } => {
            tracing::debug!(%peer_id, %topic, "subscribed to topic");
        }
        Event::Unsubscribed { peer_id, topic } => {
            tracing::debug!(%peer_id, %topic, "unsubscribed from topic");
        }
        Event::GossipsubNotSupported { peer_id } => {
            tracing::warn!(%peer_id, "peer does not support gossipsub");
        }
        Event::SlowPeer { peer_id, failed_messages } => {
            tracing::warn!(
                %peer_id,
                failed_publishes = %failed_messages.publish,
                failed_forwards = %failed_messages.forward,
                failed_priority = %failed_messages.priority,
                failed_non_priority = %failed_messages.non_priority,
                failed_timeout = %failed_messages.timeout,
                "peer has been flagged as slow"
            );
        }
    }
}
