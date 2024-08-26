#[cfg(feature = "testing")]
use clap::Parser;

use rand::rngs::OsRng;
use signer::ecdsa;
use signer::keys::PrivateKey;
use signer::keys::PublicKey;
use signer::message;
use signer::network::grpc_relay;

use signer::network::MessageTransfer;

type Msg = ecdsa::Signed<message::SignerMessage>;

/// Relay client example for sBTC v1.
///
/// This example shows how to connect to a relay server
/// and send/receive messages from it. In particular,
/// this binary will send random messages on a regular
/// interval to the relay server and display any
/// incoming messages.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = String::from("127.0.0.1"), env = "SBTC_RELAY_HOST")]
    host: String,

    #[arg(long, default_value_t = 50042, env = "SBTC_RELAY_PORT")]
    port: u16,

    #[arg(long, default_value_t = true, env = "SBTC_LOG_PRETTY")]
    pretty_logs: bool,

    #[arg(
        short,
        long,
        default_value_t = 2,
        env = "SBTC_EXAMPLE_RELAY_CLIENT_PERIOD"
    )]
    send_period_seconds: u64,
}

impl Args {
    fn address(&self) -> String {
        let Self { host, port, .. } = self;
        format!("http://{host}:{port}")
    }

    fn send_period(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.send_period_seconds)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    sbtc::logging::setup_logging("info,signer=debug,relay-client=debug", args.pretty_logs);

    let mut client = grpc_relay::RelayClient::connect(args.address())
        .await
        .expect("Failed to connect");

    let private_key = setup_keypair();
    let mut message_source = spawn_message_source(private_key, args.send_period());

    loop {
        tokio::select! {
            msg_result = client.receive() => {
                match msg_result {
                    Ok(msg) => tracing::info!(?msg.signer_pub_key, "received message"),
                    Err(_) => client = grpc_relay::RelayClient::connect(args.address())
                                .await.expect("Failed to connect"),
                }
            }

            Some(msg) = message_source.recv() => {
                tracing::info!("sent message");
                client.broadcast(msg).await.expect("Failed to send message");
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C signal - exiting");
                break;
            }
        }
    }
}

fn setup_keypair() -> PrivateKey {
    let private_key = PrivateKey::new(&mut OsRng);
    let public_key = PublicKey::from_private_key(&private_key);

    tracing::info!(%public_key, "generated key pair");
    private_key
}

fn spawn_message_source(
    private_key: PrivateKey,
    send_period: std::time::Duration,
) -> tokio::sync::mpsc::Receiver<Msg> {
    let (heartbeat_tx, heartbeat_rx) = tokio::sync::mpsc::channel(128);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(send_period).await;
            let msg = Msg::random_with_private_key(&mut OsRng, &private_key);
            if heartbeat_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    heartbeat_rx
}
