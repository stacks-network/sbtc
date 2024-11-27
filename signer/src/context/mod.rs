//! Context module for the signer binary.

mod messaging;
mod signer_context;
mod signer_state;
mod termination;

use tokio::sync::broadcast::error::RecvError;
use tokio_stream::wrappers::ReceiverStream;

use crate::bitcoin::BitcoinInteract;
use crate::config::Settings;
use crate::emily_client::EmilyInteract;
use crate::error::Error;
use crate::stacks::api::StacksInteract;
use crate::storage::DbRead;
use crate::storage::DbWrite;
use crate::SIGNER_CHANNEL_CAPACITY;

pub use messaging::*;
pub use signer_context::SignerContext;
pub use signer_state::*;
pub use termination::*;

/// Context trait that is implemented by the [`SignerContext`].
pub trait Context: Clone + Sync + Send {
    /// Get the current configuration for the signer.
    fn config(&self) -> &Settings;
    /// Get the current state for the signer.
    fn state(&self) -> &SignerState;
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
    fn get_storage(&self) -> impl DbRead + Clone + Sync + Send + 'static;
    /// Get a read-write handle to the signer storage.
    fn get_storage_mut(&self) -> impl DbRead + DbWrite + Clone + Sync + Send + 'static;
    /// Get a handle to a Bitcoin client.
    fn get_bitcoin_client(&self) -> impl BitcoinInteract + Clone + 'static;
    /// Get a handler to the Stacks client.
    fn get_stacks_client(&self) -> impl StacksInteract + Clone + 'static;
    /// Get a handle to an Emily client.
    fn get_emily_client(&self) -> impl EmilyInteract + Clone + 'static;
    /// Create a new signal stream containing signer messages from:
    /// 1. The signer network, as defined by the given network object
    ///    implementing [`MessageTransfer`].
    /// 2. The termination handled. This should only ever return one item.
    /// 3. All messages over the signers' internal channel.
    ///
    /// Messages are returned as they become ready. Note that the returned
    /// stream is not "fused", so [`StreamExt::next`] can return `None` and
    /// later return `Some(_)`. But if [`StreamExt::next`] yields `None`
    /// three times then the stream is "fused" and will return `None`
    /// forever after.
    fn as_signal_stream<F>(&self, predicate: F) -> ReceiverStream<SignerSignal>
    where
        F: Fn(&SignerSignal) -> bool + Send + Sync + 'static,
    {
        let (sender, receiver) = tokio::sync::mpsc::channel(SIGNER_CHANNEL_CAPACITY);

        let mut watch_receiver = self.get_termination_handle();
        let mut signal_stream = self.get_signal_receiver();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = watch_receiver.wait_for_shutdown() => {
                        let signal = SignerSignal::Command(SignerCommand::Shutdown);
                        // An error means that the channel has been closed.
                        // This is most likely due to the receiver being
                        // closed so we can bail.
                        if sender.send(signal).await.is_err() {
                            break;
                        }
                    }
                    item = signal_stream.recv() => {
                        match item {
                            Ok(signal) if predicate(&signal) => {
                                // See comment above, we can bail.
                                if sender.send(signal).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => continue,
                            Err(RecvError::Closed) => {
                                tracing::warn!("internal signal stream closed");
                                break;
                            }
                            Err(error @ RecvError::Lagged(_)) => {
                                tracing::warn!(%error, "internal signal stream lagging");
                                continue
                            }
                        }
                    }
                }
            }
        });
        ReceiverStream::new(receiver)
    }
}
