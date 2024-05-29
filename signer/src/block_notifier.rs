//! This module provides functionality for notifying about new blocks using the Electrum client.

use crate::config::SETTINGS;
use electrum_client::bitcoin::BlockHash;
use electrum_client::{
    Client, ConfigBuilder, ElectrumApi, Error as ElectrumError, HeaderNotification,
};
use futures::stream::Stream;
use std::error::Error;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Sender};
use tokio::task;
use tokio::time::{interval, sleep, Duration};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info, warn};

/// The `BlockNotifier` trait defines a method for subscribing to a stream of block headers.
pub trait BlockNotifier {
    /// Errors occurring during subscription or running the notifier.
    type Error: Error;

    /// Returns a stream of block headers.
    fn subscribe(&self) -> Pin<Box<dyn Stream<Item = Result<BlockHash, Self::Error>> + Send>>;
}

/// A struct implementing the `BlockNotifier` trait using Electrum client.
pub struct ElectrumBlockNotifier {
    client: Arc<Client>,
    retry_interval: Duration,
    max_retry_attempts: u32,
    ping_interval: Duration,
    subscribe_interval: Duration,
}

impl ElectrumBlockNotifier {
    /// Creates a new instance of `ElectrumBlockNotifier` from config settings.
    ///
    /// # Returns
    ///
    /// A new instance of `ElectrumBlockNotifier`.
    pub fn from_config() -> Result<Self, ElectrumError> {
        let server = &SETTINGS.block_notifier.server;
        let config = ConfigBuilder::new().build();
        let client = Arc::new(Client::from_config(server, config)?);
        let retry_interval = Duration::from_secs(SETTINGS.block_notifier.retry_interval);
        let max_retry_attempts = SETTINGS.block_notifier.max_retry_attempts;
        let ping_interval = Duration::from_secs(SETTINGS.block_notifier.ping_interval);
        let subscribe_interval = Duration::from_secs(SETTINGS.block_notifier.subscribe_interval);
        Ok(ElectrumBlockNotifier {
            client,
            retry_interval,
            max_retry_attempts,
            ping_interval,
            subscribe_interval,
        })
    }

    /// The notify loop that handles block header notifications and sends them to the receiver.
    async fn notify_loop(
        client: Arc<Client>,
        retry_interval: Duration,
        max_retry_attempts: u32,
        ping_interval: Duration,
        subscribe_interval: Duration,
        sender: Sender<Result<BlockHash, ElectrumError>>,
    ) {
        let mut retry_attempts = 0;
        let mut ping_interval = interval(ping_interval);
        let mut subscribe_interval = interval(subscribe_interval);
        let mut continue_loop = true;

        while continue_loop {
            tokio::select! {
                // Concurrent keep-alive check
                _ = ping_interval.tick() => {
                    if client.ping().is_err() {
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
                    match client.block_headers_subscribe() {
                        Ok(HeaderNotification { header, .. }) => {
                            let block_hash = header.block_hash();

                            if sender.send(Ok(block_hash)).await.is_err() {
                                warn!("Receiver dropped, stopping notify loop.");
                                continue_loop = false;
                            }
                        }
                        Err(e) => {
                            error!("Error subscribing to block headers: {}", e);
                            retry_attempts += 1;
                            if retry_attempts >= max_retry_attempts {
                                error!("Max retry attempts reached, giving up.");
                                continue_loop = false;
                            }
                        }
                    }
                }
            }
            sleep(retry_interval).await;
        }
    }

    /// Starts the notification loop in a new task.
    ///
    /// # Arguments
    ///
    /// * `sender` - The sender to which block headers will be sent.
    fn start_notifying(&self, sender: Sender<Result<BlockHash, ElectrumError>>) {
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
    }
}

impl BlockNotifier for ElectrumBlockNotifier {
    type Error = ElectrumError;

    /// Subscribes to a stream of block headers.
    ///
    /// # Returns
    ///
    /// A pinned boxed stream of block headers.
    fn subscribe(&self) -> Pin<Box<dyn Stream<Item = Result<BlockHash, Self::Error>> + Send>> {
        let (sender, receiver) = channel(100); // Bounded channel to control memory usage
        self.start_notifying(sender);
        Box::pin(ReceiverStream::new(receiver))
    }
}
