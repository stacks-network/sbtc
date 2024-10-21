//! Context module for the signer binary.

mod messaging;
mod signer_context;
mod signer_state;
mod termination;

use crate::bitcoin::BitcoinInteract;
use crate::config::Settings;
use crate::emily_client::EmilyInteract;
use crate::error::Error;
use crate::stacks::api::StacksInteract;
use crate::storage::DbRead;
use crate::storage::DbWrite;

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
    /// Get a handle to a Emily client.
    fn get_emily_client(&self) -> impl EmilyInteract + Clone + 'static;
}
