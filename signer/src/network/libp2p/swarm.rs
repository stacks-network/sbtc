use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use crate::context::Context;
use crate::keys::PrivateKey;
use libp2p::identity::Keypair;
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    autonat, gossipsub, identify, kad, mdns, noise, ping, tcp, yamux, Multiaddr, PeerId, Swarm,
    SwarmBuilder,
};
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use tokio::sync::Mutex;

use super::errors::SignerSwarmError;
use super::event_loop;

/// Define the behaviors of the [`SignerSwarm`] libp2p network.
#[derive(NetworkBehaviour)]
pub struct SignerBehavior {
    pub gossipsub: gossipsub::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    pub kademlia: kad::Behaviour<MemoryStore>,
    ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub autonat_client: autonat::v2::client::Behaviour<StdRng>,
    pub autonat_server: autonat::v2::server::Behaviour<StdRng>,
}

impl SignerBehavior {
    pub fn new(keypair: Keypair, enable_mdns: bool) -> Result<Self, SignerSwarmError> {
        let local_peer_id = keypair.public().to_peer_id();

        let mdns = if enable_mdns {
            Some(
                mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                    .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?,
            )
        } else {
            None
        }
        .into();

        let autonat_client = autonat::v2::client::Behaviour::new(
            rand::rngs::StdRng::from_entropy(),
            autonat::v2::client::Config::default(),
        );

        let autonat_server =
            autonat::v2::server::Behaviour::new(rand::rngs::StdRng::from_entropy());

        let identify = identify::Behaviour::new(identify::Config::new(
            identify::PUSH_PROTOCOL_NAME.to_string(),
            keypair.public(),
        ));

        Ok(Self {
            gossipsub: Self::gossipsub(&keypair)?,
            mdns,
            kademlia: Self::kademlia(&local_peer_id),
            ping: Default::default(),
            identify,
            autonat_client,
            autonat_server,
        })
    }

    /// Create a new gossipsub behavior.
    fn gossipsub(keypair: &Keypair) -> Result<gossipsub::Behaviour, SignerSwarmError> {
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

        gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(SignerSwarmError::LibP2PMessage)
    }

    /// Create a new kademlia behavior.
    fn kademlia(peer_id: &PeerId) -> kad::Behaviour<MemoryStore> {
        let config = kad::Config::new(kad::PROTOCOL_NAME)
            .disjoint_query_paths(true)
            .to_owned();

        let mut kademlia =
            kad::Behaviour::with_config(*peer_id, MemoryStore::new(*peer_id), config);
        kademlia.set_mode(Some(kad::Mode::Server));
        kademlia
    }
}

/// Builder for the [`SignerSwarm`] libp2p network.
pub struct SignerSwarmBuilder<'a> {
    private_key: &'a PrivateKey,
    listen_on: Vec<Multiaddr>,
    seed_addrs: Vec<Multiaddr>,
    external_addresses: Vec<Multiaddr>,
    use_mdns: bool,
}

impl<'a> SignerSwarmBuilder<'a> {
    /// Create a new [`SignerSwarmBuilder`] with the given private key.
    pub fn new(private_key: &'a PrivateKey, use_mdns: bool) -> Self {
        Self {
            private_key,
            listen_on: Vec::new(),
            seed_addrs: Vec::new(),
            external_addresses: Vec::new(),
            use_mdns,
        }
    }

    /// Sets whether or not this swarm should use mdns.
    pub fn use_mdns(mut self, use_mdns: bool) -> Self {
        self.use_mdns = use_mdns;
        self
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

    /// Add an external address to the builder.
    pub fn add_external_address(mut self, addr: Multiaddr) -> Self {
        if !self.external_addresses.contains(&addr) {
            self.external_addresses.push(addr);
        }
        self
    }

    /// Add multiple external addresses to the builder.
    pub fn add_external_addresses(mut self, addrs: &[Multiaddr]) -> Self {
        for addr in addrs {
            if !self.external_addresses.contains(addr) {
                self.external_addresses.push(addr.clone());
            }
        }
        self
    }

    /// Build the [`SignerSwarm`], consuming the builder.
    pub fn build(self) -> Result<SignerSwarm, SignerSwarmError> {
        let keypair: Keypair = (*self.private_key).into();
        let behavior = SignerBehavior::new(keypair.clone(), self.use_mdns)?;

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
            external_addresses: self.external_addresses,
        })
    }
}

pub struct SignerSwarm {
    keypair: Keypair,
    swarm: Arc<Mutex<Swarm<SignerBehavior>>>,
    listen_addrs: Vec<Multiaddr>,
    seed_addrs: Vec<Multiaddr>,
    external_addresses: Vec<Multiaddr>,
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
        tracing::info!(%local_peer_id, "starting signer swarm");

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

        for addr in self.external_addresses.iter() {
            self.swarm
                .lock()
                .await
                .dial(addr.clone())
                .map_err(|e| SignerSwarmError::LibP2P(Box::new(e)))?;
        }

        // Run the event loop, blocking until its completion.
        event_loop::run(ctx, Arc::clone(&self.swarm)).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::context::*;

    use super::*;

    #[tokio::test]
    async fn test_signer_swarm_builder() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let private_key = PrivateKey::new(&mut rand::thread_rng());
        let keypair: Keypair = private_key.into();
        let builder = SignerSwarmBuilder::new(&private_key, true)
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
        let builder = SignerSwarmBuilder::new(&private_key, true);
        let mut swarm = builder.build().unwrap();

        let ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

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
