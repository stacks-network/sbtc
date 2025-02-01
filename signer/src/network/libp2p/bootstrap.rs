//! LibP2P behavior for bootstrapping the node against the network using
//! the known seed addresses.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    task::Poll,
    time::{Duration, Instant},
};

use libp2p::{
    multiaddr::Protocol,
    swarm::{dial_opts::DialOpts, FromSwarm, NetworkBehaviour, THandlerInEvent, ToSwarm},
    Multiaddr, PeerId,
};

#[derive(Clone, Debug)]
pub struct Config {
    local_peer_id: PeerId,
    seed_addresses: Vec<Multiaddr>,
    bootstrap_interval: Duration,
}

impl Config {
    /// Creates a new [`Config`] instance with the provided local peer ID.
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            local_peer_id,
            seed_addresses: Default::default(),
            bootstrap_interval: Duration::from_secs(60),
        }
    }

    /// Adds seed addresses to the configuration.
    #[allow(dead_code)]
    pub fn add_seed_addresses<T>(&mut self, seed_addresses: T) -> &mut Self
    where
        T: IntoIterator<Item = Multiaddr>,
    {
        self.seed_addresses.extend(seed_addresses);
        self
    }

    #[allow(dead_code)]
    pub fn with_bootstrap_interval(&mut self, interval: Duration) -> &mut Self {
        self.bootstrap_interval = interval;
        self
    }
}

#[derive(Debug)]
pub enum BootstrapEvent {
    Complete,
    Needed,
    Started { addresses: Vec<Multiaddr> },
}

pub struct Behavior {
    config: Config,
    pending_events: VecDeque<ToSwarm<BootstrapEvent, THandlerInEvent<Behavior>>>,
    connection_count: usize,
    connected_seeds: HashMap<PeerId, HashSet<Multiaddr>>,
    last_attempted_at: Option<Instant>,
    is_bootstrapped: bool,
}

impl Behavior {
    /// Creates a new [`Behavior`] instance with the provided configuration.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            pending_events: VecDeque::new(),
            connection_count: 0,
            connected_seeds: HashMap::new(),
            last_attempted_at: None,
            is_bootstrapped: false,
        }
    }

    /// Determines whether or not the provided address is one of the known
    /// seed addresses.
    fn is_seed_address(&self, addr: &Multiaddr) -> bool {
        let mut addr = addr.clone();

        // If the address ends with a p2p protocol, we need to remove it
        // before checking if it's a seed address.
        if let Some(Protocol::P2p(_)) = addr.iter().last() {
            addr.pop();
        }

        self.config.seed_addresses.iter().any(|seed| seed == &addr)
    }

    /// Gets the local [`PeerId`].
    fn local_peer_id(&self) -> PeerId {
        self.config.local_peer_id
    }

    /// Adds seed addresses to the behavior's configuration.
    pub fn add_seed_addresses<T>(&mut self, seed_addresses: T) -> &mut Self
    where
        T: IntoIterator<Item = Multiaddr>,
    {
        self.config.add_seed_addresses(seed_addresses);
        tracing::debug!(addresses = ?self.config.seed_addresses, "seed addresses added");
        self
    }

    /// Gets the next pending event from the behavior, or [`Poll::Pending`] if
    /// there are none
    fn next_pending_event(&mut self) -> Poll<ToSwarm<BootstrapEvent, THandlerInEvent<Self>>> {
        self.pending_events
            .pop_front()
            .map(Poll::Ready)
            .unwrap_or(Poll::Pending)
    }
}

impl NetworkBehaviour for Behavior {
    type ConnectionHandler = libp2p::swarm::dummy::ConnectionHandler;
    type ToSwarm = BootstrapEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: libp2p::core::Endpoint,
        _port_use: libp2p::core::transport::PortUse,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        Ok(libp2p::swarm::dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        _maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: libp2p::core::Endpoint,
    ) -> Result<Vec<Multiaddr>, libp2p::swarm::ConnectionDenied> {
        tracing::debug!(?addresses, "handling pending outbound connection");
        let addresses = addresses.to_vec();

        // We're only interested in our outbound dialing activity. This _can_ be
        // a listener if the swarm is attempting a hole-punch.
        if !effective_role.is_dialer() {
            return Ok(addresses);
        }

        for addr in &addresses {
            if self.is_seed_address(addr) {
                tracing::debug!(%addr, "attempting to dial seed address");
            }
        }

        // Return the addresses as-is.
        Ok(addresses)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                // We're only interested in our outbound activity.
                if !e.endpoint.is_dialer() {
                    return;
                }

                // If we've connected to ourselves, we don't need to do anything.
                // This might happen if a node has its own address in the seed list.
                if e.peer_id == self.local_peer_id() {
                    return;
                }

                // Increment our total connection count. We're not interested
                // in counting connections to ourselves.
                self.connection_count = self.connection_count.saturating_add(1);

                // Get the remote address, and remove the p2p protocol if it exists.
                let mut addr = e.endpoint.get_remote_address().clone();
                if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
                    addr.pop();
                }

                // Check if the address is a seed address. If it's not, then
                // we don't need to do anything so we return early.
                if self.is_seed_address(&addr) {
                    tracing::debug!(peer_id = %e.peer_id, %addr, "connected to seed");
                } else {
                    return;
                }

                // Update our connected seeds map.
                let entry_added = self
                    .connected_seeds
                    .entry(e.peer_id)
                    .or_default()
                    .insert(addr.clone());

                if entry_added {
                    tracing::trace!(peer_id = %e.peer_id, %addr, "added connected seed");
                }
            }
            FromSwarm::ConnectionClosed(e) => {
                // If this was a connection to ourselves then we don't need to do
                // anything.
                if e.peer_id == self.local_peer_id() {
                    return;
                }

                // Decrement our total connection count.
                self.connection_count = self.connection_count.saturating_sub(1);

                // Get the remote address, and remove the p2p protocol if it exists.
                let mut addr = e.endpoint.get_remote_address().clone();
                if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
                    addr.pop();
                }

                // Check if the address is a seed address. If it's not, then
                // we don't need to do anything so we return early.
                if self.is_seed_address(&addr) {
                    tracing::debug!(peer_id = %e.peer_id, %addr, "disconnected from seed");
                } else {
                    return;
                }

                // Update our connected seeds map.
                if let Some(set) = self.connected_seeds.get_mut(&e.peer_id) {
                    if set.remove(&addr) {
                        tracing::trace!(peer_id = %e.peer_id, %addr, "removed connected seed");
                    }
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
        if let Some(event) = self.pending_events.pop_front() {
            return Poll::Ready(event);
        }

        // If we have any connections, we consider ourselves bootstrapped.
        // Determine if there was a state change or not and return the correct
        // poll result.
        if self.connection_count >= 1 {
            return match self.is_bootstrapped {
                true => Poll::Pending,
                false => {
                    // We've just bootstrapped, so we generate an event to notify the
                    // swarm.
                    tracing::debug!(connection_count = %self.connection_count, "bootstrapping complete");
                    self.is_bootstrapped = true;
                    Poll::Ready(ToSwarm::GenerateEvent(BootstrapEvent::Complete))
                }
            };
        }

        // If we're here then we're not connected to any peers. If our current
        // state is bootstrapped, we need to re-bootstrap.
        if self.is_bootstrapped {
            tracing::debug!(
                "state is bootstrapped but not connected to any peers; re-bootstrapping is needed"
            );
            self.is_bootstrapped = false;
            self.pending_events
                .push_back(ToSwarm::GenerateEvent(BootstrapEvent::Needed));
        }

        // If we've attempted to bootstrap recently, we wait until the interval
        // has passed.
        if let Some(last_bootstrap) = self.last_attempted_at {
            if last_bootstrap.elapsed() < self.config.bootstrap_interval {
                return self.next_pending_event();
            }
        }

        // Queue the bootstrap started event.
        tracing::debug!(addresses = ?self.config.seed_addresses, "initiating network bootstrapping from seed addresses");
        self.pending_events
            .push_back(ToSwarm::GenerateEvent(BootstrapEvent::Started {
                addresses: self.config.seed_addresses.clone(),
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
            let event = ToSwarm::Dial { opts: dial_opts };

            // Queue the dial event.
            self.pending_events.push_back(event);
        });

        // Update the last bootstrap attempt time.
        self.last_attempted_at = Some(Instant::now());

        self.next_pending_event()
    }
}
