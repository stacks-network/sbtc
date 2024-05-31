//! This module provides functionality for notifying about new blocks using the Electrum client.

use crate::config::{BlockNotifierConfig, SETTINGS};
use electrum_client::bitcoin::BlockHash;
use electrum_client::{
    Client, ConfigBuilder, ElectrumApi, Error as ElectrumError, HeaderNotification,
};
use futures::stream::{Stream, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::{interval, sleep, Duration};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, error};

/// Block Notifier Errors
#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
    /// Electrum error
    #[error("electrum error: {0}")]
    Electrum(Arc<electrum_client::Error>),
    /// Lagged
    #[error("BroadcastStream")]
    BroadcastStream,
}

/// The `BlockNotifier` trait defines a method for subscribing to a stream of block headers.
pub trait BlockNotifier {
    /// Errors occurring during subscription or running the notifier.
    type Error: std::error::Error;

    /// Returns a stream of block headers.
    fn subscribe(&self) -> impl Stream<Item = Result<BlockHash, Self::Error>> + Send;
}

/// A struct for polling Block Headers from Electrum client.
pub struct ElectrumBlockNotifier {
    client: Arc<Mutex<Client>>,
    retry_interval: Duration,
    max_retry_attempts: u32,
    ping_interval: Duration,
    subscribe_interval: Duration,
}

impl ElectrumBlockNotifier {
    /// Creates a new instance of `ElectrumBlockNotifier` from config.
    ///
    /// # Returns
    ///
    /// A new instance of `ElectrumBlockNotifier`.
    pub fn from_config(config: &BlockNotifierConfig) -> Result<Self, ElectrumError> {
        let server = &config.server;
        let client_config = ConfigBuilder::new().build();
        let client = Arc::new(Mutex::new(Client::from_config(server, client_config)?));
        let retry_interval = Duration::from_secs(config.retry_interval);
        let max_retry_attempts = config.max_retry_attempts;
        let ping_interval = Duration::from_secs(config.ping_interval);
        let subscribe_interval = Duration::from_secs(config.subscribe_interval);
        Ok(ElectrumBlockNotifier {
            client,
            retry_interval,
            max_retry_attempts,
            ping_interval,
            subscribe_interval,
        })
    }

    /// Creates a new instance of `ElectrumBlockNotifier` from system config.
    ///
    /// # Returns
    ///
    /// A new instance of `ElectrumBlockNotifier`.
    pub fn new() -> Result<Self, ElectrumError> {
        Self::from_config(&SETTINGS.block_notifier)
    }

    /// The notify loop that handles block header notifications and sends them to the broadcast channel.
    async fn notify_loop(
        client: Arc<Mutex<Client>>,
        retry_interval: Duration,
        max_retry_attempts: u32,
        ping_interval: Duration,
        subscribe_interval: Duration,
        sender: Sender<Result<BlockHash, Error>>,
    ) {
        let mut retry_attempts = 0;
        let mut ping_interval = interval(ping_interval);
        let mut subscribe_interval = interval(subscribe_interval);
        let mut continue_loop = true;

        debug!("Beginning to poll for block headers");

        while continue_loop {
            tokio::select! {
                // Concurrent keep-alive check
                _ = ping_interval.tick() => {
                    if client.lock().await.ping().is_err() {
                        error!("Ping failed, attempting to reconnect...");
                        retry_attempts += 1;
                        if retry_attempts >= max_retry_attempts {
                            error!("Max retry attempts reached, giving up.");
                            continue_loop = false;
                        }
                    } else {
                        retry_attempts = 0; // Reset retry attempts on successful ping
                    }
                }
                // Periodic block header subscription
                _ = subscribe_interval.tick() => {
                    let client_clone = Arc::clone(&client);
                    let sender_clone = sender.clone();

                    task::spawn_blocking(move || {
                        match client_clone.blocking_lock().block_headers_subscribe() {
                            Ok(HeaderNotification { header, .. }) => {
                                let block_hash = header.block_hash();
                                let _ = sender_clone.send(Ok(block_hash));
                            }
                            Err(e) => {
                                let _ = sender_clone.send(Err(Error::Electrum(Arc::new(e))));
                            }
                        }
                    });
                }
            }
            sleep(retry_interval).await;
        }
    }

    /// Starts the notification loop in a new task.
    ///
    /// # Returns
    ///
    /// A new instance of `ElectrumBlockReceiver`.
    pub fn run(&self) -> ElectrumBlockReceiver {
        let (sender, receiver) = broadcast::channel(100); // Bounded channel to control memory usage
        let client = Arc::clone(&self.client);
        let retry_interval = self.retry_interval;
        let max_retry_attempts = self.max_retry_attempts;
        let ping_interval = self.ping_interval;
        let subscribe_interval = self.subscribe_interval;

        task::spawn(Self::notify_loop(
            client,
            retry_interval,
            max_retry_attempts,
            ping_interval,
            subscribe_interval,
            sender,
        ));

        ElectrumBlockReceiver { receiver }
    }
}

/// A struct implementing the `BlockNotifier` trait, wrapping a broadcast receiver.
pub struct ElectrumBlockReceiver {
    receiver: Receiver<Result<BlockHash, Error>>,
}

impl BlockNotifier for ElectrumBlockReceiver {
    type Error = Error;

    /// Subscribes to a stream of block headers.
    ///
    /// # Returns
    ///
    /// A stream of block headers.
    fn subscribe(&self) -> impl Stream<Item = Result<BlockHash, Self::Error>> + Send {
        // Call resubscribe to create a new Receiver for the broadcast channel
        let receiver = self.receiver.resubscribe();
        BroadcastStream::new(receiver)
            .map(|result| result.unwrap_or_else(|_| Err(Error::BroadcastStream)))
    }
}
