//! Context module for the signer binary.

use std::sync::Arc;
use tokio::sync::broadcast::Sender;

use crate::{config::Settings, error::Error, storage::{in_memory::Store, postgres::PgStore, DbRead, DbReadWrite}};

/// Context trait that is implemented by the [`SignerContext`].
pub trait Context {
    /// Get the current configuration for the signer.
    fn config(&self) -> &Settings;
    /// Subscribe to the application signalling channel, returning a receiver
    /// which can be used to listen for events.
    fn get_signal_receiver(&self) -> tokio::sync::broadcast::Receiver<SignerSignal>;
    /// Send a signal to the application signalling channel.
    fn signal(&self, signal: SignerSignal) -> Result<usize, crate::error::Error>;
    /// Retrieve a read-only storage connection.
    fn get_storage(&self) -> Arc<dyn DbRead>;
    /// Retrieve a mutable (read+write) storage connection.
    fn get_storage_mut(&self) -> Arc<dyn DbReadWrite>;
}

/// Signer context which is passed to different components within the
/// signer binary.
pub struct SignerContext {
    config: Settings,
    signal_tx: Sender<SignerSignal>,
    db: Arc<dyn DbReadWrite>,
    // Would be used if we wanted to listen for any events in the context,
    // for example if we wanted a subroutine to be able to trigger a config
    // refresh:
    // signal_rx: Receiver<SignerSignal>,

    // Example if we wanted to have a database pool in the context:
    // db_pool: sqlx::PgPool,
}

impl SignerContext
{
    /// Create a new signer context.
    pub async fn init(
        config: Settings,
    ) -> Result<Self, Error> {
        // Create a channel for signalling within the application.
        let (signal_tx, _) = tokio::sync::broadcast::channel(128);

        // Create a database connection.
        let db: Arc<dyn DbReadWrite> = match config.signer.db_endpoint.scheme() {
            "postgres" => {
                Arc::new(PgStore::connect(config.signer.db_endpoint.as_str()).await?)
            }
            "memory" => {
                Arc::new(Store::new_shared())
            }
            _ => {
                return Err(Error::SqlxUnsupportedDatabase(config.signer.db_endpoint.scheme().to_string()));
            }
        };

        Ok(SignerContext {
            config,
            signal_tx,
            db
        })
    }
}

/// Signals that can be sent within the signer binary.
#[derive(Debug, Clone, Copy)]
pub enum SignerSignal {
    /// Signals to the application to shut down.
    Shutdown,
}

impl Context for SignerContext {
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

    fn get_storage(&self) -> Arc<(dyn DbRead)> {
        Arc::clone(&self.db).as_read()
    }

    fn get_storage_mut(&self) -> Arc<dyn DbReadWrite> {
        Arc::clone(&self.db)
    }
}
