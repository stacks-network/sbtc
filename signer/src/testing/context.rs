//! Test Context implementation

use std::{ops::Deref, sync::Arc};

use bitcoin::Txid;
use tokio::sync::Mutex;

use crate::{
    bitcoin::{rpc::GetTxResponse, BitcoinInteract, MockBitcoinInteract},
    config::Settings,
    context::{Context, SignerContext},
    error::Error,
    storage::in_memory::{SharedStore, Store},
};

/// A [`Context`] which can be used for testing.
///
/// This context is opinionated and uses a shared in-memory store and mocked
/// clients, which can be used to simulate different scenarios.
///
/// This context also provides you raw access to both the inner [`SignerContext`]
/// as well as the different mocked clients, so you can modify their behavior as
/// needed.
#[derive(Clone)]
pub struct TestContext<BC> {
    /// The inner [`SignerContext`] which this context wraps.
    pub inner: SignerContext<SharedStore, BC>,

    /// The mocked bitcoin client.
    pub bitcoin_client: BC,
}

impl<BC> TestContext<BC>
where
    BC: BitcoinInteract + Clone + Send + Sync,
{
    /// Create a new test context.
    pub fn new(bitcoin_client: BC) -> Self {
        let settings = Settings::new_from_default_config().unwrap();
        let store = Store::new_shared();

        let context = SignerContext::new(settings, store, bitcoin_client.clone());

        Self { inner: context, bitcoin_client }
    }

    /// Get an instance of the inner bitcoin client. This will be a clone of the
    ///
    pub fn inner_bitcoin_client(&self) -> BC {
        self.bitcoin_client.clone()
    }
}

impl TestContext<WrappedMock<MockBitcoinInteract>> {
    /// Execute a closure with a mutable reference to the inner mocked
    /// bitcoin client.
    pub async fn with_bitcoin_client<F>(&mut self, f: F)
    where
        F: FnOnce(&mut MockBitcoinInteract),
    {
        let mut client = self.bitcoin_client.lock().await;
        f(&mut client);
    }
}

impl<BC> Context for TestContext<BC>
where
    BC: BitcoinInteract + Clone + Send + Sync,
{
    fn config(&self) -> &Settings {
        self.inner.config()
    }

    fn get_signal_receiver(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::context::SignerSignal> {
        self.inner.get_signal_receiver()
    }

    fn get_signal_sender(&self) -> tokio::sync::broadcast::Sender<crate::context::SignerSignal> {
        self.inner.get_signal_sender()
    }

    fn signal(&self, signal: crate::context::SignerSignal) -> Result<(), Error> {
        self.inner.signal(signal)
    }

    fn get_termination_handle(&self) -> crate::context::TerminationHandle {
        self.inner.get_termination_handle()
    }

    fn get_storage(&self) -> impl crate::storage::DbRead + Clone + Sync + Send {
        self.inner.get_storage()
    }

    fn get_storage_mut(
        &self,
    ) -> impl crate::storage::DbRead + crate::storage::DbWrite + Clone + Sync + Send {
        self.inner.get_storage_mut()
    }

    fn get_bitcoin_client(&self) -> impl BitcoinInteract + Clone {
        self.inner.get_bitcoin_client()
    }
}

/// A wrapper around a mock which can be cloned and shared between threads.
pub struct WrappedMock<T> {
    inner: Arc<Mutex<T>>,
}

impl<T> Clone for WrappedMock<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T> WrappedMock<T> {
    /// Create a new wrapped mock.
    pub fn new(mock: T) -> Self {
        Self {
            inner: Arc::new(Mutex::new(mock)),
        }
    }
}

impl<T> Deref for WrappedMock<T> {
    type Target = Mutex<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> Default for WrappedMock<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl BitcoinInteract for WrappedMock<MockBitcoinInteract> {
    async fn get_block(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<Option<bitcoin::Block>, Error> {
        self.inner.lock().await.get_block(block_hash).await
    }

    async fn get_tx(&self, txid: &Txid) -> Result<Option<GetTxResponse>, Error> {
        self.inner.lock().await.get_tx(txid).await
    }

    async fn get_tx_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<Option<crate::bitcoin::rpc::BitcoinTxInfo>, Error> {
        self.inner.lock().await.get_tx_info(txid, block_hash).await
    }

    async fn estimate_fee_rate(&self) -> Result<f64, Error> {
        self.inner.lock().await.estimate_fee_rate().await
    }

    async fn get_last_fee(
        &self,
        utxo: bitcoin::OutPoint,
    ) -> Result<Option<crate::bitcoin::utxo::Fees>, Error> {
        self.inner.lock().await.get_last_fee(utxo).await
    }

    async fn broadcast_transaction(&self, tx: &bitcoin::Transaction) -> Result<(), Error> {
        self.inner.lock().await.broadcast_transaction(tx).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicU8, Ordering},
            Arc,
        },
        time::Duration,
    };

    use tokio::sync::Notify;

    use crate::{
        bitcoin::MockBitcoinInteract,
        context::{Context as _, SignerEvent, SignerSignal},
        testing::context::{TestContext, WrappedMock},
    };

    /// This test ensures that the context can be cloned and signals can be sent
    /// to both clones.
    #[tokio::test]
    async fn context_clone_signalling_works() {
        let context = Arc::new(TestContext::new(
            WrappedMock::<MockBitcoinInteract>::default(),
        ));
        let mut recv = context.get_signal_receiver();
        let recv_count = Arc::new(AtomicU8::new(0));

        let recv1 = tokio::spawn(async move {
            let signal = recv.recv().await.unwrap();
            assert_eq!(
                signal,
                SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
            );
            dbg!(&signal);
            signal
        });

        let context_clone = Arc::clone(&context);
        let recv_count_clone = Arc::clone(&recv_count);
        let recv_task_started = Arc::new(AtomicBool::new(false));
        let recv_task_started_clone = Arc::clone(&recv_task_started);
        let recv_signal_received = Arc::new(AtomicBool::new(false));
        let recv_signal_received_clone = Arc::clone(&recv_signal_received);

        let recv_task = tokio::spawn(async move {
            let mut cloned_receiver = context_clone.get_signal_receiver();
            recv_task_started_clone.store(true, Ordering::Relaxed);
            let signal = cloned_receiver.recv().await.unwrap();
            assert_eq!(
                signal,
                SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
            );
            recv_count_clone.fetch_add(1, Ordering::Relaxed);
            recv_signal_received_clone.store(true, Ordering::Relaxed);
            signal
        });

        while !recv_task_started.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        context
            .signal(SignerEvent::BitcoinBlockObserved.into())
            .unwrap();

        while !recv_signal_received.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        recv_task.abort();
        recv1.abort();

        assert_eq!(recv_count.load(Ordering::Relaxed), 1);
    }

    /// This test demonstrates that cloning a broadcast channel and subscribing to
    /// it from multiple tasks works as expected (as according to the docs, but
    /// there were some weird issues in some tests that behaved as-if the cloning
    /// wasn't working as expected).
    #[tokio::test]
    async fn test_tokio_broadcast_clone_assumptions() {
        let (tx1, mut rx1) = tokio::sync::broadcast::channel(100);
        let tx2 = tx1.clone();
        let mut rx2 = tx2.subscribe();

        assert_eq!(tx1.receiver_count(), 2);

        let count = Arc::new(AtomicU8::new(0));
        let count1 = Arc::clone(&count);
        let count2 = Arc::clone(&count);

        let task1_started = Arc::new(Notify::new());
        let task1_started_clone = Arc::clone(&task1_started);

        let task1 = tokio::spawn(async move {
            task1_started_clone.notify_one();

            while let Ok(_) = rx2.recv().await {
                count1.fetch_add(1, Ordering::Relaxed);
            }
        });

        task1_started.notified().await;

        tx1.send(1).unwrap();

        let task2_started = Arc::new(Notify::new());
        let task2_started_clone = Arc::clone(&task2_started);

        let task2 = tokio::spawn(async move {
            task2_started_clone.notify_one();

            while let Ok(_) = rx1.recv().await {
                count2.fetch_add(1, Ordering::Relaxed);
            }
        });

        task2_started.notified().await;

        tx2.send(2).unwrap();
        tx1.send(3).unwrap();
        tx1.send(4).unwrap();

        // Just to ensure that the tasks have a chance to process the messages.
        tokio::time::sleep(Duration::from_millis(100)).await;

        task1.abort();
        task2.abort();

        // You might expect this to be 7 since we start the 2nd event loop
        // after the first send, but the subscriptions are created at the
        // beginning of this test, so the messages are buffered in the channel.
        assert_eq!(count.load(Ordering::Relaxed), 8);
    }
}
