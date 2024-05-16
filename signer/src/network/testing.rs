use crate::ecdsa;
use crate::message;

pub type Msg = ecdsa::Signed<message::SignerMessage>;

pub async fn assert_clients_can_exchange_messages<C: super::MessageTransfer + Send + 'static>(
    mut client_1: C,
    mut client_2: C,
) {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(1337);
    let number_of_messages = 32;

    let client_1_messages: Vec<_> = (0..number_of_messages)
        .map(|_| Msg::random(&mut rng))
        .collect();
    let client_2_messages: Vec<_> = (0..number_of_messages)
        .map(|_| Msg::random(&mut rng))
        .collect();

    let client_1_expected_received_messages = client_2_messages.clone();
    let client_2_expected_received_messages = client_1_messages.clone();

    let handle_1 = tokio::spawn(async move {
        for msg in client_1_messages {
            client_1.broadcast(msg).await.expect("Failed to broadcast");
        }

        for msg in client_1_expected_received_messages {
            let received = client_1.receive().await.expect("Failed to receive message");
            assert_eq!(received, msg);
        }
    });

    let handle_2 = tokio::spawn(async move {
        for msg in client_2_messages {
            client_2.broadcast(msg).await.expect("Failed to broadcast");
        }

        for msg in client_2_expected_received_messages {
            let received = client_2.receive().await.expect("Failed to receive message");
            assert_eq!(received, msg);
        }
    });

    handle_1.await.unwrap();
    handle_2.await.unwrap();
}
