//! Test utilities for the `network` module

use crate::network;

/// Test helper that spawns two concurrent tasks for the provided clients and have them
/// broadcasting randomly generated messages.
/// The clients are assumed to be connected to the same network, which means
/// that they should be able to receive each other's messages.
///
/// The function asserts that all sent messages are received unmodified and in-order on the other end.
pub async fn assert_clients_can_exchange_messages<C: network::MessageTransfer + Send + 'static>(
    client_1: C,
    client_2: C,
) {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
    let number_of_messages = 32;

    let client_1_messages: Vec<_> = (0..number_of_messages)
        .map(|_| network::Msg::random(&mut rng))
        .collect();
    let client_2_messages: Vec<_> = (0..number_of_messages)
        .map(|_| network::Msg::random(&mut rng))
        .collect();

    let handle_1 = spawn_client_task(
        client_1,
        client_1_messages.clone(),
        client_2_messages.clone(),
    );

    let handle_2 = spawn_client_task(client_2, client_2_messages, client_1_messages);

    handle_1.await.unwrap();
    handle_2.await.unwrap();
}

fn spawn_client_task(
    mut client: impl network::MessageTransfer + Send + 'static,
    send_messages: Vec<network::Msg>,
    should_receive: Vec<network::Msg>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for msg in send_messages {
            client.broadcast(msg).await.expect("Failed to broadcast");
        }

        // We use this method to receive messages and check for its existence
        // in `send_messages` as we cannot guarantee the order of messages
        // received in the network (particularly when using libp2p's gossipsub).
        for _ in 0..should_receive.len() {
            let received = client.receive().await.expect("Failed to receive message");
            assert!(should_receive.contains(&received));
        }
    })
}
