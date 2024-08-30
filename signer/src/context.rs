//! Context module for the signer binary.

use std::path::Path;

use tokio::sync::broadcast::Sender;

use crate::{config::Settings, error::Error};

/// Context trait that is implemented by the [`SignerContext`].
pub trait Context {
    /// Initialize a new signer context.
    fn init(config_path: Option<impl AsRef<Path>>) -> Result<Self, crate::error::Error>
    where
        Self: Sized;
    /// Get the current configuration for the signer.
    fn config(&self) -> &Settings;
    /// Subscribe to the application signalling channel, returning a receiver
    /// which can be used to listen for events.
    fn get_signal_receiver(&self) -> tokio::sync::broadcast::Receiver<SignerSignal>;
    /// Get an owned application signalling channel sender.
    fn get_signal_sender(&self) -> tokio::sync::broadcast::Sender<SignerSignal>;
    /// Send a signal to the application signalling channel.
    fn signal(&self, signal: SignerSignal) -> Result<usize, crate::error::Error>;
}

/// Signer context which is passed to different components within the
/// signer binary.
pub struct SignerContext {
    config: Settings,
    signal_tx: Sender<SignerSignal>,
    // Would be used if we wanted to listen for any events in the context,
    // for example if we wanted a subroutine to be able to trigger a config
    // refresh:
    // signal_rx: Receiver<SignerSignal>,

    // Example if we wanted to have a database pool in the context:
    // db_pool: sqlx::PgPool,
}

/// Signals that can be sent within the signer binary.
#[derive(Debug, Clone)]
pub enum SignerSignal {
    /// Signals to the application to shut down.
    Shutdown,
    /// Signals to the application to publish a message to the P2P network.
    P2PPublish(crate::network::Msg),
    /// Signals to the application that the P2P publish failed for the given message.
    P2PPublishFailure(crate::network::Msg),
    /// Signals to the application that a message was received from the P2P network.
    P2PMessage(crate::network::Msg),
}

impl Context for SignerContext {
    /// Create a new signer context.
    fn init(config_path: Option<impl AsRef<Path>>) -> Result<Self, Error> {
        let config = Settings::new(config_path).map_err(Error::SignerConfig)?;

        let (signal_tx, _) = tokio::sync::broadcast::channel(10);

        Ok(Self { config, signal_tx })
    }

    fn config(&self) -> &Settings {
        &self.config
    }

    fn get_signal_receiver(&self) -> tokio::sync::broadcast::Receiver<SignerSignal> {
        self.signal_tx.subscribe()
    }

    fn get_signal_sender(&self) -> tokio::sync::broadcast::Sender<SignerSignal> {
        self.signal_tx.clone()
    }

    /// Send a signal to the application signalling channel.
    fn signal(&self, signal: SignerSignal) -> Result<usize, Error> {
        self.signal_tx
            .send(signal)
            .map_err(Error::ApplicationSignal)
    }
}
