//! Tests for how the signers communicate with one another.
//!

use std::str::FromStr as _;
use std::time::Duration;

use signer::context::Context as _;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::network::libp2p::SignerSwarmBuilder;
use signer::network::MessageTransfer as _;
use signer::network::Msg;
use signer::network::P2PNetwork;
use signer::testing::context::TestContext;
use signer::testing::context::*;

#[tokio::test]
async fn swarm_rejects_connections_from_unknown_peers() {
    // In this test we create three swarms (simulating three signers). We
    // simulate that signers 1 & 2 are trusted peers, and that signer 3 is
    // an untrusted peer. We start the swarms and ensure that signers 1 & 2
    // can exchange messages, but that signer 3 is rejected by both signers.
    //
    // TODO: This test could be made much more efficient by emitting more
    // events from the swarms and checking that the expected events are
    // emitted.

    // PeerId = 16Uiu2HAm46BSFWYYWzMjhTRDRwXHpDWpQ32iu93nzDwd1F4Tt256
    let key1 =
        PrivateKey::from_str("ab0893ecf683dc188c3fb219dd6489dc304bb5babb8151a41245a70e60cb7258")
            .unwrap();
    // PeerId = 16Uiu2HAkuyB8ECXxACm8hzQj4vZ2iWrYMF3xcKNf1oJJ1NuQEMvQ
    let key2 =
        PrivateKey::from_str("0dd4077c8bcec09c803f9ba23a0f5b56eba75769b2d1b96a33b579dbbe5055ce")
            .unwrap();
    // PeerId = 16Uiu2HAkv4DBE9f9eg53RoRYsfuzJXdoAvRU91gb6oii5pTseo1j
    let key3 =
        PrivateKey::from_str("bdbb219e045b12c12d99c86afd83764ea67a9e3c0127c0298d7c57b3597a4645")
            .unwrap();

    // Create the context for signer1.
    let context1 = TestContext::builder()
        .with_in_memory_storage()
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.private_key = key1;
        })
        .build();
    // Add key2 to the known signers for signer1.
    context1
        .state()
        .current_signer_set()
        .add_signer(PublicKey::from_private_key(&key2));

    // Create the context for signer2.
    let context2 = TestContext::builder()
        .with_in_memory_storage()
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.private_key = key2;
        })
        .build();
    // Add key1 to the known signers for signer2.
    context2
        .state()
        .current_signer_set()
        .add_signer(PublicKey::from_private_key(&key1));

    // Add key2 to the known signers for signer1.
    context1
        .state()
        .current_signer_set()
        .add_signer(PublicKey::from_private_key(&key2));

    // Create the context for signer2.
    let context3 = TestContext::builder()
        .with_in_memory_storage()
        .with_mocked_clients()
        .modify_settings(|settings| {
            settings.signer.private_key = key3;
        })
        .build();
    // Add key1 and key2 to the known signers for signer 3. This simulates
    // what an adversary signer might do, i.e. it would want to join with
    // the known signers.
    context3
        .state()
        .current_signer_set()
        .add_signer(PublicKey::from_private_key(&key1));
    context3
        .state()
        .current_signer_set()
        .add_signer(PublicKey::from_private_key(&key2));

    // Create the two trusted swarms.
    let mut swarm1 = SignerSwarmBuilder::new(&key1, true)
        .add_listen_endpoint("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .build()
        .expect("Failed to build swarm 1");
    let mut swarm2 = SignerSwarmBuilder::new(&key2, true)
        .add_listen_endpoint("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .build()
        .expect("Failed to build swarm 2");
    // Create the adversarial swarm.
    let mut swarm3 = SignerSwarmBuilder::new(&key3, true)
        .add_listen_endpoint("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .build()
        .expect("Failed to build swarm 3");

    // Create the network liasons for the swarms (i.e. `MessageTransfer`
    // instances).
    let mut trusted1 = P2PNetwork::new(&context1);
    let mut trusted2 = P2PNetwork::new(&context2);
    let mut adversarial = P2PNetwork::new(&context3);

    // Start the swarms.
    let handle1 = tokio::spawn(async move {
        swarm1.start(&context1).await.unwrap();
    });
    let handle2 = tokio::spawn(async move {
        swarm2.start(&context2).await.unwrap();
    });
    let handle3 = tokio::spawn(async move {
        swarm3.start(&context3).await.unwrap();
    });

    // The swarms are discovering themselves via mDNS, so we need to give
    // them a bit of time to connect. 2 seconds seems to be enough to
    // allow the swarms to consistently connect; 1 second is too little.
    // TODO: This is a bit of a hack, we should probably keep a count
    // of connected peers and wait until we have the expected number.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Test that trusted 2 can send a message to trusted 1.
    let trusted_msg_from_2_to_1 = tokio::time::timeout(Duration::from_secs(1), async {
        trusted1.receive().await.unwrap();
    });
    trusted2
        .broadcast(Msg::random_with_private_key(&mut rand::thread_rng(), &key2))
        .await
        .unwrap();
    trusted_msg_from_2_to_1
        .await
        .expect("Failed to receive message from trusted 2 to trusted 1");

    // Test that trusted 1 can send a message to trusted 2.
    let trusted_msg_from_1_to_2 = tokio::time::timeout(Duration::from_secs(1), async {
        trusted2.receive().await.unwrap();
    });
    trusted1
        .broadcast(Msg::random_with_private_key(&mut rand::thread_rng(), &key1))
        .await
        .unwrap();
    trusted_msg_from_1_to_2
        .await
        .expect("Failed to receive message from trusted 1 to trusted 2");

    // Test that adversarial can't send a message to trusted 1.
    let adversarial_msg_to_1 = tokio::time::timeout(Duration::from_secs(1), async {
        trusted1.receive().await.unwrap();
    });
    adversarial
        .broadcast(Msg::random(&mut rand::thread_rng()))
        .await
        .unwrap();
    assert!(adversarial_msg_to_1.await.is_err());

    // Test that adversarial can't send a message to trusted 2.
    let adversarial_msg_to_2 = tokio::time::timeout(Duration::from_secs(1), async {
        trusted2.receive().await.unwrap();
    });
    adversarial
        .broadcast(Msg::random(&mut rand::thread_rng()))
        .await
        .unwrap();
    assert!(adversarial_msg_to_2.await.is_err());

    // Kill the swarms just to be sure.
    handle1.abort();
    handle2.abort();
    handle3.abort();
}
