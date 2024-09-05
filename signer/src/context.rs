//! Context module for the signer binary.

use std::sync::Arc;

use tokio::sync::broadcast::Sender;

use crate::{config::Settings, error::Error};

/// Context trait that is implemented by the [`SignerContext`].
pub trait Context {
    /// Initialize a new signer context.
    fn init(config: Settings) -> Result<Self, crate::error::Error>
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
    fn signal(&self, signal: SignerSignal) -> Result<(), Error>;
    /// Returns a handle to the application's termination signal.
    fn get_termination_handle(&self) -> TerminationHandle;
}

/// Signer context which is passed to different components within the
/// signer binary.
pub struct SignerContext {
    inner: Arc<InnerSignerContext>,
}

impl std::ops::Deref for SignerContext {
    type Target = InnerSignerContext;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Inner signer context which holds the configuration and signalling channels.
pub struct InnerSignerContext {
    config: Settings,
    // Handle to the app signalling channel. This keeps the channel alive
    // for the duration of the program and is used both to send messages
    // and to hand out new receivers.
    signal_tx: Sender<SignerSignal>,
    /// Handle to the app termination channel. This keeps the channel alive
    /// for the duration of the program and is used to provide new senders
    /// and receivers for a [`TerminationHandle`].
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
    /// Signals to the application that a new peer has connected to the P2P network.
    P2PPeerConnected(libp2p::PeerId),
}

/// Handle to the termination signal. This can be used to signal the application
/// to shutdown or to wait for a shutdown signal.
pub struct TerminationHandle(
    tokio::sync::watch::Sender<bool>,
    tokio::sync::watch::Receiver<bool>,
);

impl TerminationHandle {
    /// Signal the application to shutdown.
    pub fn signal_shutdown(&self) {
        // We ignore the result here, as if all receivers have been dropped,
        // we're on our way down anyway.
        self.0.send_if_modified(|x| {
            if !(*x) {
                *x = true;
                true
            } else {
                false
            }
        });
    }
    /// Blocks until a shutdown signal is received.
    pub async fn wait_for_shutdown(&mut self) {
        loop {
            // Wait for the termination channel to be updated. If it's updated
            // and the value is true, we break out of the loop.
            // We ignore the result here because it's impossible for the sender
            // to be dropped while this instance is alive (it holds its own sender).
            let _ = self.1.changed().await;
            if *self.1.borrow_and_update() {
                break;
            }
        }
    }
}

impl Context for SignerContext {
    /// Create a new signer context.
    fn init(config: Settings) -> Result<Self, Error> {
        // TODO: Decide on the channel capacity and how we should handle slow consumers.
        // NOTE: Ideally consumers which require processing time should pull the relevent
        // messages into a local VecDequeue and process them in their own time.
        let (signal_tx, _) = tokio::sync::broadcast::channel(128);
        let (term_tx, _) = tokio::sync::watch::channel(false);

        Ok(Self {
            inner: Arc::new(InnerSignerContext { config, signal_tx, term_tx }),
        })
    }

    fn config(&self) -> &Settings {
        &self.config
    }

    fn get_signal_receiver(&self) -> tokio::sync::broadcast::Receiver<SignerSignal> {
        self.signal_tx.subscribe()
    }

    fn get_signal_sender(&self) -> tokio::sync::broadcast::Sender<SignerSignal> {
        self.inner.signal_tx.clone()
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
        TerminationHandle(self.term_tx.clone(), self.term_tx.subscribe())
    }
}
