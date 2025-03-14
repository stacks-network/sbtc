//! LibP2P behavior for bootstrapping the node against the network using
//! the known seed addresses.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    task::Poll,
    time::{Duration, Instant},
};

use libp2p::{
    core::{transport::PortUse, Endpoint},
    swarm::{
        dial_opts::DialOpts, dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour,
        THandler, THandlerInEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};

use super::MultiaddrExt;

#[derive(Clone, Debug)]
pub struct Config {
    local_peer_id: PeerId,
    seed_addresses: Vec<Multiaddr>,
    bootstrap_interval: Duration,
    initial_delay: Duration,
}

impl Config {
    /// Creates a new [`Config`] instance with the provided local peer ID.
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            local_peer_id,
            seed_addresses: Default::default(),
            bootstrap_interval: Duration::from_secs(60),
            initial_delay: Duration::ZERO,
        }
    }

    /// Adds seed addresses to the configuration.
    pub fn add_seed_addresses<T>(mut self, seed_addresses: T) -> Self
    where
        T: IntoIterator<Item = Multiaddr>,
    {
        self.seed_addresses.extend(seed_addresses);
        self
    }

    /// Sets the bootstrapping interval. This is the interval at which the
    /// behavior will attempt to bootstrap the network if no connections are
    /// established. The default is 60 seconds.
    #[allow(unused)]
    pub fn with_bootstrap_interval(mut self, interval: Duration) -> Self {
        self.bootstrap_interval = interval;
        self
    }

    /// Sets the initial delay before bootstrapping. This is the delay before
    /// the behavior will attempt to bootstrap the network upon startup. The
    /// default is 0 seconds.
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }
}

/// Events emitted by the bootstrapping behavior.
#[allow(unused)] // Due to currently unconsumed fields in event variants.
#[derive(Debug)]
pub enum BootstrapEvent {
    /// An event which is raised when the network has been bootstrapped, i.e.
    /// when the node has connected to at least one peer.
    Bootstrapped {
        connection_count: usize,
        connected_peers: Vec<PeerId>,
    },
    /// An event which is raised when the node has transitioned from
    /// [`BootstrapEvent::Bootstrapped`] to a state where no peers are connected.
    NoConnectedPeers,
    /// An event which is raised when the bootstrapping process has started.
    Started { seed_addresses: Vec<Multiaddr> },
    /// An event which is raised when the behavior is dialing a seed peer.
    DialingSeed {
        connection_id: ConnectionId,
        peer_id: Option<PeerId>,
        addresses: Vec<Multiaddr>,
    },
    /// An event which is raised when the behavior has connected to a seed peer.
    SeedConnected {
        connection_id: ConnectionId,
        peer_id: PeerId,
        address: Multiaddr,
    },
}

/// Struct to hold information about a peer.
#[derive(Debug, Clone)]
struct PeerInfo {
    is_seed: bool,
    connections: HashMap<ConnectionId, Multiaddr>,
}

impl PeerInfo {
    fn new(is_seed: bool) -> Self {
        Self {
            is_seed,
            connections: Default::default(),
        }
    }

    fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

pub struct Behavior {
    config: Config,
    pending_events: VecDeque<ToSwarm<BootstrapEvent, THandlerInEvent<Behavior>>>,
    connected_peers: HashMap<PeerId, PeerInfo>,
    pending_connections: HashSet<ConnectionId>,
    last_attempted_at: Option<Instant>,
    first_attempt_at: Option<Instant>,
    is_bootstrapped: bool,
}

impl Behavior {
    /// Creates a new [`Behavior`] instance with the provided configuration.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            pending_events: Default::default(),
            connected_peers: Default::default(),
            pending_connections: Default::default(),
            last_attempted_at: None,
            first_attempt_at: None,
            is_bootstrapped: false,
        }
    }

    /// Gets the local [`PeerId`].
    pub fn local_peer_id(&self) -> PeerId {
        self.config.local_peer_id
    }

    /// Gets the next pending event from the behavior, or [`Poll::Pending`] if
    /// there are none
    fn next_pending_event(&mut self) -> Poll<ToSwarm<BootstrapEvent, THandlerInEvent<Self>>> {
        self.pending_events
            .pop_front()
            .map(Poll::Ready)
            .unwrap_or(Poll::Pending)
    }

    /// Gets the total number of connected peers.
    pub fn connected_peer_count(&self) -> usize {
        self.connected_peers.len()
    }

    /// Gets all currently connected peers and the addresses they are connected
    /// on.
    pub fn connected_peers(&self) -> HashMap<PeerId, Vec<Multiaddr>> {
        self.connected_peers
            .iter()
            .map(|(peer_id, info)| {
                let addresses = info.connections.values().cloned().collect();
                (*peer_id, addresses)
            })
            .collect()
    }

    /// Gets the total number of connections across all connected peers.
    pub fn connection_count(&self) -> usize {
        self.connected_peers
            .values()
            .map(|info| info.connection_count())
            .sum()
    }

    /// Handles a peer connection event. Returns a reference to the [`PeerInfo`]
    /// instance for the connected peer.
    fn peer_connected(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        address: &Multiaddr,
    ) -> Option<&mut PeerInfo> {
        // If we've connected to ourselves then we don't want to count that as a
        // real peer connection. This might happen if a node has its own address
        // in the seed list or if listening on multiple interfaces and mDNS is
        // enabled.
        if peer_id == self.local_peer_id() {
            return None;
        }

        // We want to strip the p2p protocol from the address if it exists
        // before we use it in comparisons.
        let addr = address.without_p2p_protocol();

        // Determine if this is one of our seed addresses.
        let is_seed_addr = self.config.seed_addresses.iter().any(|seed| seed == &addr);

        // Get or create the peer info record for the connected peer.
        let peer_info = self
            .connected_peers
            .entry(peer_id)
            .or_insert_with(|| PeerInfo::new(is_seed_addr));

        // It's possible that we had an incoming connection from a seed using an
        // ephemeral port that doesn't match a known endpoint, but now we have
        // an outgoing connection to the peer's known seed endpoint and now
        // matched, so we update the info record to reflect that.
        if is_seed_addr {
            peer_info.is_seed = true;
        }

        // Update the peer info record with the connection and address.
        peer_info.connections.insert(connection_id, addr);

        Some(peer_info)
    }

    /// Handles a peer disconnection event. Returns [`Some<PeerInfo>`] if the
    /// peer was removed due to having no remaining connections, otherwise
    /// returns [`None`].
    fn peer_disconnected(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        _address: &Multiaddr,
    ) -> Option<PeerInfo> {
        // Get the peer info record for the disconnected peer and remove the
        // connection and address. If the peer wasn't found, we return `None`
        // immediately, otherwise we check if the peer has no remaining
        // connections.
        let remove_peer = {
            let peer_info = self.connected_peers.get_mut(&peer_id)?;
            peer_info.connections.remove(&connection_id);
            peer_info.connection_count() == 0
        };

        // If the peer has no remaining connections, we remove the peer from the
        // connected peers map and return the peer info record.
        if remove_peer {
            return self.connected_peers.remove(&peer_id);
        }

        // Otherwise we return `None` as the peer still has connections.
        None
    }
}

impl NetworkBehaviour for Behavior {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = BootstrapEvent;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.peer_connected(peer_id, connection_id, remote_addr);

        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        address: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.peer_connected(peer_id, connection_id, address);

        if self.pending_connections.remove(&connection_id) {
            tracing::debug!(%connection_id, %peer_id, %address, "successfully dialed seed peer");
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(BootstrapEvent::SeedConnected {
                    connection_id,
                    peer_id,
                    address: address.clone(),
                }));
        }

        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let addresses = addresses.to_vec();

        // If the connection ID is in the pending connections set, then we know
        // that this is a seed peer dial that we've initiated, so we publish
        // the `DialingSeed` event.
        if self.pending_connections.contains(&connection_id) {
            tracing::debug!(%connection_id, ?addresses, peer_id = ?maybe_peer, "attempting to dial seed peer");
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(BootstrapEvent::DialingSeed {
                    connection_id,
                    addresses: addresses.clone(),
                    peer_id: None,
                }));
        }

        // Return the addresses as-is.
        Ok(addresses)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(e) => {
                let (peer_id, connection_id, address) =
                    (e.peer_id, e.connection_id, e.endpoint.get_remote_address());
                self.peer_disconnected(peer_id, connection_id, address);
            }
            FromSwarm::DialFailure(e) => {
                let (connection_id, error, peer_id) = (e.connection_id, e.error, e.peer_id);
                if self.pending_connections.remove(&connection_id) {
                    tracing::debug!(
                        %connection_id,
                        ?peer_id,
                        %error,
                        "failed to dial seed peer"
                    );
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: libp2p::swarm::ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
    }

    #[tracing::instrument(skip_all)]
    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::swarm::ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>>
    {
        // If we have any pending events, we return them immediately.
        // Check for any existing events first
        if let Poll::Ready(event) = self.next_pending_event() {
            return Poll::Ready(event);
        }

        // If we have any connections, we consider ourselves bootstrapped.
        // Determine if there was a state change or not and return the correct
        // poll result.
        if self.connected_peer_count() >= 1 {
            return match self.is_bootstrapped {
                true => self.next_pending_event(),
                false => {
                    // We've just bootstrapped, so we flag our state as
                    // bootstrapped and emit an event to the swarm.
                    self.is_bootstrapped = true;
                    let connection_count = self.connection_count();
                    let connected_peers = self.connected_peers().keys().copied().collect();

                    tracing::info!(%connection_count, ?connected_peers, "network bootstrapping complete");
                    Poll::Ready(ToSwarm::GenerateEvent(BootstrapEvent::Bootstrapped {
                        connection_count,
                        connected_peers,
                    }))
                }
            };
        }

        // If we're here then we're not connected to any peers. If our current
        // state is bootstrapped, we need to re-bootstrap.
        if self.is_bootstrapped {
            tracing::info!(
                "state is bootstrapped but not connected to any peers; re-bootstrapping is needed"
            );
            self.is_bootstrapped = false;
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(BootstrapEvent::NoConnectedPeers));
        }

        // If we've attempted to bootstrap recently, we wait until the interval has passed.
        if let Some(last_bootstrap) = self.last_attempted_at {
            if last_bootstrap.elapsed() < self.config.bootstrap_interval {
                return self.next_pending_event();
            }
        }

        // If this is the first attempt, we wait for the initial delay.
        if let Some(first_attempt) = self.first_attempt_at {
            // If the initial delay has not elapsed, we continue waiting and
            // return the next pending event.
            if first_attempt.elapsed() < self.config.initial_delay {
                return self.next_pending_event();
            }
        } else if self.config.initial_delay > Duration::ZERO {
            // If we don't have a first attempt time and an initial delay is
            // configured, we set it and return the next pending event.
            tracing::info!(
                initial_delay = %self.config.initial_delay.as_secs(),
                "initial bootstrapping delay is configured; waiting before attempting to bootstrap"
            );
            self.first_attempt_at = Some(Instant::now());
            return self.next_pending_event();
        }

        // Queue the bootstrap started event.
        tracing::info!(addresses = ?self.config.seed_addresses, "initiating network bootstrapping from seed addresses");
        self.pending_events
            .push_back(ToSwarm::GenerateEvent(BootstrapEvent::Started {
                seed_addresses: self.config.seed_addresses.clone(),
            }));

        // Iterate over the seed addresses and queue dial events for each. Note
        // that we queue a dial event for each seed address, regardless of our
        // current connection count (which will then be propagated in subsequent
        // polls). This is to ensure the best chance of connecting to the
        // network.
        self.config.seed_addresses.iter().for_each(|addr| {
            // Construct the dialing options and `Dial` event which will be
            // sent to the swarm.
            let dial_opts = DialOpts::unknown_peer_id().address(addr.clone()).build();
            self.pending_connections.insert(dial_opts.connection_id());
            let event = ToSwarm::Dial { opts: dial_opts };

            // Queue the dial event.
            self.pending_events.push_back(event);
        });

        // Update the last bootstrap attempt time.
        self.last_attempted_at = Some(Instant::now());

        self.next_pending_event()
    }
}
