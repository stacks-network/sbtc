//! Tests for how the signers communicate with one another.

use std::collections::BTreeSet;
use std::time::Duration;

use libp2p::Multiaddr;
use signer::context::Context as _;
use signer::context::P2PEvent;
use signer::context::SignerEvent;
use signer::context::SignerSignal;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::network::P2PNetwork;
use signer::network::libp2p::SignerSwarmBuilder;
use signer::testing::context::TestContext;
use signer::testing::context::*;
use test_case::test_case;
use tokio_stream::StreamExt;

#[test_case("/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/tcp/0"; "tcp")]
#[test_case("/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/udp/0/quic-v1"; "quic-v1")]
#[tokio::test]
async fn libp2p_clients_can_exchange_messages_given_real_network(addr1: &str, addr2: &str) {
    let swarm1_addr: Multiaddr = addr1.parse().expect("Failed to parse swarm1 address");
    let swarm2_addr: Multiaddr = addr2.parse().expect("Failed to parse swarm2 address");

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

    let swarm1 = SignerSwarmBuilder::new(&key1)
        .enable_mdns(false)
        .enable_kademlia(false)
        .enable_autonat(false)
        .enable_quic_transport(true)
        .add_listen_endpoint(swarm1_addr.clone())
        .build()
        .expect("Failed to build swarm 1");

    let swarm2 = SignerSwarmBuilder::new(&key2)
        .enable_mdns(false)
        .enable_kademlia(false)
        .enable_autonat(false)
        .enable_quic_transport(true)
        .add_listen_endpoint(swarm2_addr)
        .build()
        .expect("Failed to build swarm 2");

    let network1 = P2PNetwork::new(&context1);
    let network2 = P2PNetwork::new(&context2);

    // Start the two swarms.
    let mut swarm1_clone = swarm1.clone();
    let handle1 = tokio::spawn(async move {
        swarm1_clone.start(&context1).await.unwrap();
    });

    let mut swarm2_clone = swarm2.clone();
    let handle2 = tokio::spawn(async move {
        swarm2_clone.start(&context2).await.unwrap();
    });

    // Wait for the swarms to start.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let swarm1_addr = swarm1.listen_addrs().await.pop().unwrap();
    let swarm2_addr = swarm2.listen_addrs().await.pop().unwrap();

    swarm1.dial(swarm2_addr).await.unwrap();
    swarm2.dial(swarm1_addr).await.unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Run the test with a 10-second timeout for the swarms to exchange messages.
    if let Err(_) = tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        signer::testing::network::assert_clients_can_exchange_messages(
            network1, network2, key1, key2,
        ),
    )
    .await
    {
        handle1.abort();
        handle2.abort();
        panic!(
            r#"Test timed out, we waited for 10 seconds but this usually takes around 5 seconds.
        This is generally due to connectivity issues between the two swarms."#
        );
    }

    // Ensure we're shutting down
    term1.signal_shutdown();
    term2.signal_shutdown();
}

#[test_log::test(tokio::test)]
async fn libp2p_limits_max_established_connections() -> Result<(), Box<dyn std::error::Error>> {
    // Create 10 keys (main swarm + 9 peers)
    let keys = (0..10)
        .map(|_| PrivateKey::new(&mut rand::thread_rng()))
        .collect::<Vec<_>>();
    let public_keys = keys
        .iter()
        .map(|key| PublicKey::from_private_key(key))
        .collect::<BTreeSet<_>>();

    let mut handles = Vec::new();
    let mut contexts = Vec::new();
    let mut swarms = Vec::new();

    // Create the main swarm with connection limits
    let swarm1 = SignerSwarmBuilder::new(&keys[0])
        .enable_mdns(false)
        .enable_kademlia(false)
        .enable_autonat(false)
        .with_initial_bootstrap_delay(Duration::MAX)
        .add_listen_endpoint("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .with_num_signers(2) // Sets max_established = 3*2 = 6
        .build()?;

    let context1 = TestContext::builder()
        .with_in_memory_storage()
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.private_key = keys[0].clone();
        })
        .build();
    context1
        .state()
        .update_current_signer_set(public_keys.clone());
    contexts.push(context1.clone());

    // Start the main swarm
    let mut event_receiver = context1.as_signal_stream(|signal| {
        matches!(
            signal,
            SignerSignal::Event(SignerEvent::P2P(P2PEvent::EventLoopStarted))
        )
    });

    let mut swarm1_clone = swarm1.clone();
    handles.push(tokio::spawn(async move {
        if let Err(e) = swarm1_clone.start(&context1).await {
            tracing::error!("target swarm error: {}", e);
        }
    }));

    // Wait for the swarm event loop start signal
    tokio::time::timeout(Duration::from_secs(1), async {
        event_receiver.next().await;
    })
    .await
    .unwrap_or_else(|_| {
        panic!("timeout waiting for target swarm to start");
    });

    let swarm1_addr = swarm1
        .listen_addrs()
        .await
        .pop()
        .ok_or("target swarm failed to start with a listening address")?;

    // Create dedicated ping swarms that just keep connections alive
    for i in 0..6 {
        let key = &keys[i + 1]; // Use first 6 peer keys

        let peer_swarm = SignerSwarmBuilder::new(key)
            .enable_mdns(false)
            .enable_kademlia(false)
            .enable_autonat(false)
            .with_initial_bootstrap_delay(Duration::MAX)
            .build()?;

        let peer_context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.private_key = key.clone();
            })
            .build();
        peer_context
            .state()
            .update_current_signer_set(public_keys.clone());

        // Start the peer swarm
        let mut peer_event_receiver = peer_context.as_signal_stream(|signal| {
            matches!(
                signal,
                SignerSignal::Event(SignerEvent::P2P(P2PEvent::EventLoopStarted))
            )
        });

        let mut peer_swarm_clone = peer_swarm.clone();
        let peer_context_clone = peer_context.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = peer_swarm_clone.start(&peer_context_clone).await {
                tracing::error!("peer {} swarm error: {}", i, e);
            }
        }));

        tokio::time::timeout(Duration::from_secs(1), async {
            peer_event_receiver.next().await;
        })
        .await
        .unwrap_or_else(|_| {
            panic!("timeout waiting for peer {}'s swarm to start", i);
        });

        // Create a dedicated reconnect loop to keep connection alive
        let peer_swarm_ping = peer_swarm.clone();
        let peer_dial_addr = swarm1_addr.clone();
        handles.push(tokio::spawn(async move {
            loop {
                let peer_dial_addr = peer_dial_addr.clone();
                // Continually try to keep connection alive
                if let Err(e) = peer_swarm_ping.dial(peer_dial_addr).await {
                    tracing::warn!("reconnection for peer {} failed: {}", i, e);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }));

        // Store the swarm and context to prevent dropping
        swarms.push(peer_swarm);
        contexts.push(peer_context);
    }

    // Create a few more connections that may get rejected due to limits
    for i in 6..9 {
        let key = &keys[i + 1];

        let peer_swarm = SignerSwarmBuilder::new(key)
            .enable_mdns(false)
            .enable_kademlia(false)
            .enable_autonat(false)
            .with_initial_bootstrap_delay(Duration::MAX)
            .build()?;

        // Just dial without starting the swarm
        if let Err(e) = peer_swarm.dial(swarm1_addr.clone()).await {
            tracing::info!("extra peer {} rejected as expected: {}", i, e);
        } else {
            tracing::info!("extra peer {} connected", i);
        }

        swarms.push(peer_swarm);
    }

    // Wait for final connection count to stabilize
    tokio::time::sleep(Duration::from_secs(1)).await;

    let counters = swarm1.connection_counters().await;
    tracing::info!("final connection count: {}", counters.num_established());

    // Verify connection count is at least 4 and at most 6
    // The exact number might fluctuate due to connection stability issues
    assert!(
        counters.num_established() >= 4 && counters.num_established() <= 6,
        "expected 4-6 connections, got {}",
        counters.num_established()
    );

    // Clean up
    for handle in handles {
        handle.abort();
    }

    Ok(())
}
