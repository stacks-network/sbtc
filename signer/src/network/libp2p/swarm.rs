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

        let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
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
            keypair,
            swarm: Arc::new(Mutex::new(swarm)),
            listen_addrs: self.listen_on,
            seed_addrs: self.seed_addrs,
        })
    }
}

pub struct SignerSwarm {
    keypair: Keypair,
    swarm: Arc<Mutex<Swarm<SignerBehavior>>>,
    listen_addrs: Vec<Multiaddr>,
    seed_addrs: Vec<Multiaddr>,
}

impl SignerSwarm {
    /// Get the local peer ID of the signer.
    pub fn local_peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.keypair.public())
    }

    /// Start the [`SignerSwarm`] and run the event loop. This function will block until the
    /// swarm is stopped (either by receiving a shutdown signal or an unrecoverable error).
    pub async fn start(&mut self, ctx: &impl Context) -> Result<(), SignerSwarmError> {
        let local_peer_id = *self.swarm.lock().await.local_peer_id();
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

#[cfg(test)]
mod tests {
    use crate::{config::Settings, context::SignerContext};

    use super::*;

    #[tokio::test]
    async fn test_signer_swarm_builder() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let keypair = Keypair::ed25519_from_bytes(private_key.to_bytes()).unwrap();
        let builder = SignerSwarmBuilder::new(&private_key)
            .add_listen_endpoint(addr.clone())
            .add_seed_addr(addr.clone());
        let swarm = builder.build().unwrap();

        assert!(swarm.listen_addrs.contains(&addr));
        assert!(swarm.seed_addrs.contains(&addr));
        assert_eq!(
            swarm.swarm.lock().await.local_peer_id(),
            &PeerId::from_public_key(&keypair.public())
        );
    }

    #[tokio::test]
    async fn swarm_shuts_down_on_shutdown_signal() {
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let builder = SignerSwarmBuilder::new(&private_key);
        let mut swarm = builder.build().unwrap();

        let settings = Settings::new_from_default_config().unwrap();
        let ctx = SignerContext::init(settings).unwrap();
        let term = ctx.get_termination_handle();

        let timeout = tokio::time::timeout(Duration::from_secs(10), async {
            let swarm_task = tokio::spawn(async move {
                swarm.start(&ctx).await.unwrap();
            });

            // A small pause to ensure that the swarm's event loop has started
            // and that it is awaiting the shutdown signal.
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Send a termination signal.
            term.signal_shutdown();

            // Wait for the swarm to shut down.
            swarm_task.await.unwrap();
        });

        match timeout.await {
            Ok(_) => (),
            Err(_) => panic!("Swarm did not shut down within the timeout"),
        }
    }
}
