//! Context module for the signer binary.

use std::sync::Arc;
use tokio::sync::broadcast::Sender;

use crate::{config::Settings, error::Error, storage::{postgres::PgStore, DbRead, DbReadWrite}};

// TODO: This should be read from configuration
const DATABASE_URL: &str = "postgres://user:password@localhost:5432/signer";

// TODO: Should this be part of the SignerContext?
// fn get_connection_pool() -> sqlx::PgPool {
//     sqlx::postgres::PgPoolOptions::new()
//         .connect_lazy(DATABASE_URL)
//         .unwrap()
// }

/// Context trait that is implemented by the [`SignerContext`].
pub trait Context<'a> {
    /// Get the current configuration for the signer.
    fn config(&self) -> &Settings;
    /// Subscribe to the application signalling channel, returning a receiver
    /// which can be used to listen for events.
    fn get_signal_receiver(&self) -> tokio::sync::broadcast::Receiver<SignerSignal>;
    /// Send a signal to the application signalling channel.
    fn signal(&self, signal: SignerSignal) -> Result<usize, crate::error::Error>;
    /// Retrieve a read-only storage connection.
    fn get_storage(&'a self) -> Arc<dyn DbRead + 'static>;
    /// Retrieve a mutable (read+write) storage connection.
    fn get_storage_mut(&'a self) -> Arc<dyn DbReadWrite + 'a>;
}

/// Signer context which is passed to different components within the
/// signer binary.
pub struct SignerContext<'a> {
    config: Settings,
    signal_tx: Sender<SignerSignal>,
    db: Arc<dyn DbReadWrite + 'a>,
    // Would be used if we wanted to listen for any events in the context,
    // for example if we wanted a subroutine to be able to trigger a config
    // refresh:
    // signal_rx: Receiver<SignerSignal>,

    // Example if we wanted to have a database pool in the context:
    // db_pool: sqlx::PgPool,
}

impl SignerContext<'_>
{
    /// Create a new signer context.
    pub async fn init(
        config: Settings,
    ) -> Result<Self, Error> {
        let (signal_tx, _) = tokio::sync::broadcast::channel(128);

        let db: Arc<dyn DbReadWrite> = Arc::new(PgStore::connect(DATABASE_URL).await?);

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

impl<'a> Context<'a> for SignerContext<'a> {
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

    fn get_storage(&self) -> Arc<(dyn DbRead + 'static)> {
        Arc::clone(&self.db).as_read()
    }

    fn get_storage_mut(&'a self) -> Arc<dyn DbReadWrite + 'a> {
        Arc::clone(&self.db)
    }
}
