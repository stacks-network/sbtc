//! Tests for how the signers communicate with one another.
//!

use libp2p::Multiaddr;
use signer::context::Context as _;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::network::libp2p::SignerSwarmBuilder;
use signer::network::P2PNetwork;
use signer::testing::context::TestContext;
use signer::testing::context::*;
use test_case::test_case;

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
        .enable_quic_transport(true)
        .add_listen_endpoint(swarm1_addr.clone())
        .build()
        .expect("Failed to build swarm 1");

    let swarm2 = SignerSwarmBuilder::new(&key2)
        .enable_mdns(false)
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
