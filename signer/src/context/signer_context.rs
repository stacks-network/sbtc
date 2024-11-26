use std::sync::Arc;

use tokio::sync::broadcast::Sender;
use url::Url;

use crate::{
    bitcoin::BitcoinInteract,
    config::{EmilyClientConfig, Settings},
    emily_client::EmilyInteract,
    error::Error,
    stacks::api::StacksInteract,
    storage::{DbRead, DbWrite},
    SIGNER_CHANNEL_CAPACITY,
};

use super::{Context, SignerSignal, SignerState, TerminationHandle};

/// Signer context which is passed to different components within the
/// signer binary.
#[derive(Debug, Clone)]
pub struct SignerContext<S, BC, ST, EM> {
    config: Settings,
    // Handle to the app signalling channel. This keeps the channel alive
    // for the duration of the program and is used both to send messages
    // and to hand out new receivers.
    signal_tx: Sender<SignerSignal>,
    /// The internal state of the signer.
    state: Arc<SignerState>,
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
    /// Handle to a Emily-API fallback-client.
    emily_client: EM,
    // /// Handle to a Blocklist-API fallback-client.
    //blocklist_client: ApiFallbackClient<BL>,
}

impl<S, BC, ST, EM> SignerContext<S, BC, ST, EM>
where
    S: DbRead + DbWrite + Clone + Sync + Send + 'static,
    BC: for<'a> TryFrom<&'a [Url]> + BitcoinInteract + Clone + 'static,
    ST: for<'a> TryFrom<&'a Settings> + StacksInteract + Clone + Sync + Send + 'static,
    EM: for<'a> TryFrom<&'a EmilyClientConfig> + EmilyInteract + Clone + Sync + Send + 'static,
    Error: for<'a> From<<BC as TryFrom<&'a [Url]>>::Error>,
    Error: for<'a> From<<ST as TryFrom<&'a Settings>>::Error>,
    Error: for<'a> From<<EM as TryFrom<&'a EmilyClientConfig>>::Error>,
{
    /// Initializes a new [`SignerContext`], automatically creating clients
    /// based on the provided types.
    pub fn init(config: Settings, db: S) -> Result<Self, Error> {
        let bc = BC::try_from(&config.bitcoin.rpc_endpoints)?;
        let st = ST::try_from(&config)?;
        let em = EM::try_from(&config.emily)?;

        Ok(Self::new(config, db, bc, st, em))
    }
}

impl<S, BC, ST, EM> SignerContext<S, BC, ST, EM>
where
    S: DbRead + DbWrite + Clone + Sync + Send,
    BC: BitcoinInteract + Clone,
    ST: StacksInteract + Clone + Sync + Send,
    EM: EmilyInteract + Clone + Sync + Send,
{
    /// Create a new signer context.
    pub fn new(
        config: Settings,
        db: S,
        bitcoin_client: BC,
        stacks_client: ST,
        emily_client: EM,
    ) -> Self {
        // TODO: Decide on the channel capacity and how we should handle slow consumers.
        // NOTE: Ideally consumers which require processing time should pull the relevent
        // messages into a local VecDequeue and process them in their own time.
        let (signal_tx, _) = tokio::sync::broadcast::channel(SIGNER_CHANNEL_CAPACITY);
        let (term_tx, _) = tokio::sync::watch::channel(false);

        Self {
            config,
            state: Default::default(),
            signal_tx,
            term_tx,
            storage: db,
            bitcoin_client,
            stacks_client,
            emily_client,
        }
    }
}

impl<S, BC, ST, EM> Context for SignerContext<S, BC, ST, EM>
where
    S: DbRead + DbWrite + Clone + Sync + Send + 'static,
    BC: BitcoinInteract + Clone + 'static,
    ST: StacksInteract + Clone + Sync + Send + 'static,
    EM: EmilyInteract + Clone + Sync + Send + 'static,
{
    fn config(&self) -> &Settings {
        &self.config
    }

    fn state(&self) -> &SignerState {
        &self.state
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

    fn get_storage(&self) -> impl DbRead + Clone + Sync + Send + 'static {
        self.storage.clone()
    }

    fn get_storage_mut(&self) -> impl DbRead + DbWrite + Clone + Sync + Send + 'static {
        self.storage.clone()
    }

    fn get_bitcoin_client(&self) -> impl BitcoinInteract + Clone + 'static {
        self.bitcoin_client.clone()
    }

    fn get_stacks_client(&self) -> impl StacksInteract + Clone + 'static {
        self.stacks_client.clone()
    }

    fn get_emily_client(&self) -> impl EmilyInteract + Clone + 'static {
        self.emily_client.clone()
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
        context::{Context as _, SignerEvent, SignerSignal},
        testing::context::*,
    };

    /// This test shows that cloning a context and signalling on the original
    /// context will also signal on the cloned context. But it also demonstrates
    /// that there can be timing issues (particularly in tests) when signalling
    /// across threads/clones, and shows how to handle that.
    #[tokio::test]
    async fn context_clone_signalling_works() {
        // Create a context.
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

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
