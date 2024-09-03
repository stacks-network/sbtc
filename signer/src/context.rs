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
    /// Returns a handle to the application's termination signal.
    fn get_termination_handle(&self) -> TerminationHandle;
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
    term_tx: tokio::sync::watch::Sender<bool>,
}

/// Signals that can be sent within the signer binary.
#[derive(Debug, Clone)]
pub enum SignerSignal {
    /// Send a command to the application.
    Command(SignerCommand),
    /// Signal an event to the application.
    Event(SignerEvent),
}

/// Commands that can be sent on the signalling channel.
#[derive(Debug, Clone)]
pub enum SignerCommand {
    /// Signals to the application to publish a message to the P2P network.
    P2PPublish(crate::network::Msg),
}

/// Events that can be received on the signalling channel.
#[derive(Debug, Clone)]
pub enum SignerEvent {
    /// Signals to the application that the P2P publish failed for the given message.
    P2PPublishFailure(crate::network::MsgId),
    /// Signals to the application that the P2P publish for the given message id
    /// was successful.
    P2PPublishSuccess(crate::network::MsgId),
    /// Signals to the application that a message was received from the P2P network.
    P2PMessageReceived(crate::network::Msg),
}

/// Handle to the termination signal. This can be used to signal the application
/// to shutdown or to wait for a shutdown signal.
pub struct TerminationHandle(
    tokio::sync::watch::Sender<bool>,
    tokio::sync::watch::Receiver<bool>,
);

impl TerminationHandle {
    /// Signal the application to shutdown.
    pub fn signal_shutdown(&self) -> Result<(), Error> {
        self.0.send(true).map_err(Error::TerminationSendError)
    }
    /// Blocks until a shutdown signal is received.
    pub async fn wait_for_shutdown(&mut self) -> Result<(), Error> {
        loop {
            self.1
                .changed()
                .await
                .map_err(Error::TerminationRecvError)?;
            if *self.1.borrow_and_update() {
                return Ok(());
            }
        }
    }
}

impl Context for SignerContext {
    /// Create a new signer context.
    fn init(config_path: Option<impl AsRef<Path>>) -> Result<Self, Error> {
        let config = Settings::new(config_path).map_err(Error::SignerConfig)?;

        // TODO: Decide on the channel capacity and how we should handle slow consumers.
        // NOTE: Ideally consumers which require processing time should pull the relevent
        // messages into a local VecDequeue and process them in their own time.
        let (signal_tx, _) = tokio::sync::broadcast::channel(128);
        let (term_tx, _) = tokio::sync::watch::channel(false);

        Ok(Self { config, signal_tx, term_tx })
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
            .map_err(Error::BroadcastSendError)
    }

    fn get_termination_handle(&self) -> TerminationHandle {
        TerminationHandle(self.term_tx.clone(), self.term_tx.subscribe())
    }
}
