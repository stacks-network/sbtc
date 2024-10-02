//! Context module for the signer binary.

pub mod messaging;
pub mod termination;

use tokio::sync::broadcast::Sender;
use url::Url;

use crate::bitcoin::BitcoinInteract;
use crate::config::Settings;
use crate::error::Error;
use crate::stacks::api::StacksInteract;
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
    /// Get a handler to the Stacks client.
    fn get_stacks_client(&self) -> impl StacksInteract + Clone;
}

/// Signer context which is passed to different components within the
/// signer binary.
#[derive(Debug, Clone)]
pub struct SignerContext<S, BC, ST> {
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
    /// Handle to a Stacks-RPC fallback-client.
    stacks_client: ST,
    // /// Handle to a Emily-API fallback-client.
    //emily_client: ApiFallbackClient<EM>,
    // /// Handle to a Blocklist-API fallback-client.
    //blocklist_client: ApiFallbackClient<BL>,
}

impl<S, BC, ST> SignerContext<S, BC, ST>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: for<'a> TryFrom<&'a [Url]> + BitcoinInteract + Clone + 'static,
    ST: for<'a> TryFrom<&'a Settings> + StacksInteract + Clone + Sync + Send + 'static,
    Error: for<'a> From<<BC as TryFrom<&'a [Url]>>::Error>,
    Error: for<'a> From<<ST as TryFrom<&'a Settings>>::Error>,
{
    /// Initializes a new [`SignerContext`], automatically creating clients
    /// based on the provided types.
    pub fn init(config: Settings, db: S) -> Result<Self, Error> {
        let bc = BC::try_from(&config.bitcoin.rpc_endpoints)?;
        let st = ST::try_from(&config)?;

        Ok(Self::new(config, db, bc, st))
    }
}

impl<S, BC, ST> SignerContext<S, BC, ST>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: BitcoinInteract + Clone,
    ST: StacksInteract + Clone + Sync + Send,
{
    /// Create a new signer context.
    pub fn new(config: Settings, db: S, bitcoin_client: BC, stacks_client: ST) -> Self {
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
            stacks_client,
        }
    }
}

impl<S, BC, ST> Context for SignerContext<S, BC, ST>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: BitcoinInteract + Clone,
    ST: StacksInteract + Clone + Sync + Send,
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

    fn get_stacks_client(&self) -> impl StacksInteract + Clone {
        self.stacks_client.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    };

    use tokio::sync::Notify;

    use crate::{
        config::Settings,
        context::{Context as _, SignerEvent, SignerSignal},
        storage::in_memory::Store,
        testing::NoopSignerContext,
    };

    /// This test shows that cloning a context and signalling on the original
    /// context will also signal on the cloned context. But it also demonstrates
    /// that there can be timing issues (particularly in tests) when signalling
    /// across threads/clones, and shows how to handle that.
    #[tokio::test]
    async fn context_clone_signalling_works() {
        // Create a context.
        let context = NoopSignerContext::init(
            Settings::new_from_default_config().unwrap(),
            Store::new_shared(),
        )
        .unwrap();

        // Clone the context.
        let context_clone = context.clone();

        // Get the receiver from the cloned context.
        let mut cloned_receiver = context_clone.get_signal_receiver();

        // Create a counter to track how many signals are received and some
        // Notify channels so that we ensure we don't hit timing issues.
        let recv_count = Arc::new(AtomicU8::new(0));
        let task_started = Arc::new(Notify::new());
        let task_completed = Arc::new(Notify::new());

        // Spawn a task that will receive a signal (and clone values that will
        // be used in the `move` closure). We will receive on the cloned context.
        let task_started_clone = Arc::clone(&task_started);
        let task_completed_clone = Arc::clone(&task_completed);
        let recv_count_clone = Arc::clone(&recv_count);
        tokio::spawn(async move {
            task_started_clone.notify_one();
            let signal = cloned_receiver.recv().await.unwrap();

            assert_eq!(
                signal,
                SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
            );

            recv_count_clone.fetch_add(1, Ordering::Relaxed);
            task_completed_clone.notify_one();
        });

        // This wait is needed to ensure that the `recv_task` is started and
        // the receiver subscribed before we send the signal. Otherwise, the
        // signal may be sent before the receiver is ready to receive it,
        // failing the test.
        task_started.notified().await;

        // Signal the original context.
        context
            .signal(SignerEvent::BitcoinBlockObserved.into())
            .unwrap();

        // This wait is needed to ensure that the below `abort()` doesn't
        // kill the task before it has a chance to update `recv_count`.
        task_completed.notified().await;

        // Ensure that the signal was received.
        assert_eq!(recv_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
