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
#[derive(Debug, Clone, Copy)]
pub enum SignerSignal {
    /// Signals to the application to shut down.
    Shutdown,
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

    /// Send a signal to the application signalling channel.
    fn signal(&self, signal: SignerSignal) -> Result<usize, Error> {
        self.signal_tx
            .send(signal)
            .map_err(Error::ApplicationSignal)
    }
}
