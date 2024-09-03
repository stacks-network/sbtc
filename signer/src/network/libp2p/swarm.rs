use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use crate::context::Context;
use crate::keys::PrivateKey;
use libp2p::autonat::v2::client::{
    Behaviour as AutoNatClientBehavior, Config as AutoNatClientConfig,
};
use libp2p::autonat::v2::server::Behaviour as AutoNatServerBehavior;
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    gossipsub, identify, kad, mdns, noise, ping, relay, tcp, yamux, Multiaddr, PeerId, Swarm,
    SwarmBuilder,
};
use rand::rngs::OsRng;
use tokio::sync::Mutex;

use super::errors::SignerSwarmError;
use super::event_loop;

/// Define the behaviors of the [`SignerSwarm`] libp2p network.
#[derive(NetworkBehaviour)]
pub struct SignerBehavior {
    pub gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    ping: ping::Behaviour,
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    autonat_server: AutoNatServerBehavior,
    autonat_client: AutoNatClientBehavior,
}

impl SignerBehavior {
    pub fn new(keypair: Keypair) -> Result<Self, SignerSwarmError> {
        let message_id_fn = |message: &gossipsub::Message| {
            let mut hasher = DefaultHasher::new();
            message.data.hash(&mut hasher);
            gossipsub::MessageId::from(hasher.finish().to_string())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?;

        Ok(Self {
            gossipsub: gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(keypair.clone()),
                gossipsub_config,
            )
            .map_err(SignerSwarmError::LibP2PMessage)?,
            mdns: mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                keypair.public().to_peer_id(),
            )
            .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?,
            kademlia: kad::Behaviour::new(
                keypair.public().to_peer_id(),
                MemoryStore::new(keypair.public().to_peer_id()),
            ),
            ping: ping::Behaviour::default(),
            relay: relay::Behaviour::new(keypair.public().to_peer_id(), Default::default()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/sbtc-signer/1.0.0".into(),
                keypair.public(),
            )),
            autonat_server: AutoNatServerBehavior::new(OsRng),
            autonat_client: AutoNatClientBehavior::new(
                OsRng,
                AutoNatClientConfig::default().with_probe_interval(Duration::from_secs(2)),
            ),
        })
    }
}

/// Builder for the [`SignerSwarm`] libp2p network.
pub struct SignerSwarmBuilder<'a> {
    private_key: &'a PrivateKey,
    listen_on: Vec<Multiaddr>,
    seed_addrs: Vec<Multiaddr>,
}

impl<'a> SignerSwarmBuilder<'a> {
    /// Create a new [`SignerSwarmBuilder`] with the given private key.
    pub fn new(private_key: &'a PrivateKey) -> Self {
        Self {
            private_key,
            listen_on: Vec::new(),
            seed_addrs: Vec::new(),
        }
    }

    /// Add a listen endpoint to the builder.
    #[allow(dead_code)]
    pub fn add_listen_endpoint(mut self, addr: Multiaddr) -> Self {
        if !self.listen_on.contains(&addr) {
            self.listen_on.push(addr);
        }
        self
    }

    /// Add multiple listen endpoints to the builder.
    #[allow(dead_code)]
    pub fn add_listen_endpoints(mut self, addrs: &[Multiaddr]) -> Self {
        for addr in addrs {
            if !self.listen_on.contains(addr) {
                self.listen_on.push(addr.clone());
            }
        }
        self
    }

    /// Add a seed address to the builder.
    #[allow(dead_code)]
    pub fn add_seed_addr(mut self, addr: Multiaddr) -> Self {
        if !self.seed_addrs.contains(&addr) {
            self.seed_addrs.push(addr);
        }
        self
    }

    /// Add multiple seed addresses to the builder.
    #[allow(dead_code)]
    pub fn add_seed_addrs(mut self, addrs: &[Multiaddr]) -> Self {
        for addr in addrs {
            if !self.seed_addrs.contains(addr) {
                self.seed_addrs.push(addr.clone());
            }
        }
        self
    }

    /// Build the [`SignerSwarm`], consuming the builder.
    pub fn build(self) -> Result<SignerSwarm, SignerSwarmError> {
        let keypair = Keypair::ed25519_from_bytes(self.private_key.to_bytes())?;

        let behavior = SignerBehavior::new(keypair.clone())?;

        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?
            .with_quic()
            .with_dns()
            .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?
            .with_behaviour(|_| behavior)
            .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        Ok(SignerSwarm {
            swarm: Arc::new(Mutex::new(swarm)),
            listen_addrs: self.listen_on,
            seed_addrs: self.seed_addrs,
        })
    }
}

pub struct SignerSwarm {
    swarm: Arc<Mutex<Swarm<SignerBehavior>>>,
    listen_addrs: Vec<Multiaddr>,
    seed_addrs: Vec<Multiaddr>,
}

impl SignerSwarm {
    /// Retrieves the local peer ID of the swarm.
    pub async fn local_peer_id(&self) -> PeerId {
        *self.swarm.lock().await.local_peer_id()
    }

    /// Start the [`SignerSwarm`] and run the event loop. This function will block until the
    /// swarm is stopped (either by receiving a shutdown signal or an unrecoverable error).
    pub async fn start(&mut self, ctx: &impl Context) -> Result<(), SignerSwarmError> {
        let local_peer_id = self.local_peer_id().await;
        tracing::info!("Starting SignerSwarm with peer ID: {}", local_peer_id);

        // Start listening on the listen addresses.
        for addr in self.listen_addrs.iter() {
            self.swarm
                .lock()
                .await
                .listen_on(addr.clone())
                .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?;
        }

        // Dial the seed addresses.
        for addr in self.seed_addrs.iter() {
            self.swarm
                .lock()
                .await
                .dial(addr.clone())
                .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?;
        }

        // Get our signal channel sender/receiver.
        let signal_tx = ctx.get_signal_sender();
        let signal_rx = ctx.get_signal_receiver();
        let mut term = ctx.get_termination_handle();

        // Run the event loop, blocking until its completion.
        event_loop::run(&mut term, Arc::clone(&self.swarm), signal_tx, signal_rx).await;

        Ok(())
    }
}
