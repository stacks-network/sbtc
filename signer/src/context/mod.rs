//! Context module for the signer binary.

pub mod messaging;
pub mod termination;

use tokio::sync::broadcast::Sender;
use url::Url;

use crate::bitcoin::BitcoinInteract;
use crate::config::Settings;
use crate::error::Error;
use crate::storage::DbRead;
use crate::storage::DbWrite;
pub use messaging::*;
pub use termination::*;

/// Context trait that is implemented by the [`SignerContext`].
pub trait Context: Clone + Sync + Send {
    /// Get the current configuration for the signer.
    fn config(&self) -> &Settings;
    /// Subscribe to the application signalling channel, returning a receiver
    /// which can be used to listen for events.
    fn get_signal_receiver(&self) -> tokio::sync::broadcast::Receiver<SignerSignal>;
    /// Get an owned application signalling channel sender.
    fn get_signal_sender(&self) -> tokio::sync::broadcast::Sender<SignerSignal>;
    /// Send a signal to the application signalling channel.
    fn signal(&self, signal: SignerSignal) -> Result<(), Error>;
    /// Returns a handle to the application's termination signal.
    fn get_termination_handle(&self) -> TerminationHandle;
    /// Get a read-only handle to the signer storage.
    fn get_storage(&self) -> impl DbRead + Clone + Sync + Send;
    /// Get a read-write handle to the signer storage.
    fn get_storage_mut(&self) -> impl DbRead + DbWrite + Clone + Sync + Send;
    /// Get a handle to a Bitcoin client.
    fn get_bitcoin_client(&self) -> impl BitcoinInteract + Clone;
}

/// Signer context which is passed to different components within the
/// signer binary.
#[derive(Debug, Clone)]
pub struct SignerContext<S, BC> {
    config: Settings,
    // Handle to the app signalling channel. This keeps the channel alive
    // for the duration of the program and is used both to send messages
    // and to hand out new receivers.
    signal_tx: Sender<SignerSignal>,
    /// Handle to the app termination channel. This keeps the channel alive
    /// for the duration of the program and is used to provide new senders
    /// and receivers for a [`TerminationHandle`].
    term_tx: tokio::sync::watch::Sender<bool>,
    /// Handle to the signer storage.
    storage: S,
    /// Handle to a Bitcoin-RPC fallback-client.
    bitcoin_client: BC,
    // TODO: Additional clients to be added in future PRs. We may want
    // to break the clients out into a separate struct to keep the field
    // count down.
    // /// Handle to a Stacks-RPC fallback-client.
    //stacks_client: ApiFallbackClient<ST>,
    // /// Handle to a Emily-API fallback-client.
    //emily_client: ApiFallbackClient<EM>,
    // /// Handle to a Blocklist-API fallback-client.
    //blocklist_client: ApiFallbackClient<BL>,
}

impl<S, BC> SignerContext<S, BC>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: for<'a> TryFrom<&'a [Url]> + BitcoinInteract + Clone + Sync + Send + 'static,
    Error: for<'a> From<<BC as TryFrom<&'a [Url]>>::Error>,
{
    /// Initializes a new [`SignerContext`], automatically creating clients
    /// based on the provided types.
    pub fn init(config: Settings, db: S) -> Result<Self, Error> {
        let bc = BC::try_from(&config.bitcoin.endpoints)?;

        Ok(Self::new(config, db, bc))
    }
}

impl<S, BC> SignerContext<S, BC>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: BitcoinInteract + Clone + Sync + Send,
{
    /// Create a new signer context.
    pub fn new(config: Settings, db: S, bitcoin_client: BC) -> Self {
        // TODO: Decide on the channel capacity and how we should handle slow consumers.
        // NOTE: Ideally consumers which require processing time should pull the relevent
        // messages into a local VecDequeue and process them in their own time.
        let (signal_tx, _) = tokio::sync::broadcast::channel(128);
        let (term_tx, _) = tokio::sync::watch::channel(false);

        Self {
            config,
            signal_tx,
            term_tx,
            storage: db,
            bitcoin_client,
        }
    }
}

impl<S, BC> Context for SignerContext<S, BC>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: BitcoinInteract + Clone + Sync + Send,
{
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
    fn signal(&self, signal: SignerSignal) -> Result<(), Error> {
        self.signal_tx
            .send(signal)
            .map_err(|_| {
                // This realistically shouldn't ever happen
                tracing::warn!("failed to send signal to the application, no receivers present.");
                // Send a shutdown signal, just in-case.
                self.get_termination_handle().signal_shutdown();
                Error::SignerShutdown
            })
            .map(|_| ())
    }

    fn get_termination_handle(&self) -> TerminationHandle {
        TerminationHandle::new(self.term_tx.clone(), self.term_tx.subscribe())
    }

    fn get_storage(&self) -> impl DbRead + Clone + Sync + Send {
        self.storage.clone()
    }

    fn get_storage_mut(&self) -> impl DbRead + DbWrite + Clone + Sync + Send {
        self.storage.clone()
    }

    fn get_bitcoin_client(&self) -> impl BitcoinInteract + Clone {
        self.bitcoin_client.clone()
    }
}
