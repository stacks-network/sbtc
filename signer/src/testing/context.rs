//! Test Context implementation

use std::{ops::Deref, sync::Arc};

use bitcoin::Txid;
use blockstack_lib::{
    chainstate::{nakamoto::NakamotoBlock, stacks::StacksTransaction},
    net::api::gettenureinfo::RPCGetTenureInfo,
};
use clarity::types::chainstate::{StacksAddress, StacksBlockId};
use tokio::sync::Mutex;

use crate::{
    bitcoin::{rpc::GetTxResponse, BitcoinInteract, MockBitcoinInteract},
    config::Settings,
    context::{Context, SignerContext},
    emily_client::{EmilyInteract, MockEmilyInteract},
    error::Error,
    keys::PublicKey,
    stacks::{
        api::{AccountInfo, FeePriority, MockStacksInteract, StacksInteract, SubmitTxResponse},
        contracts::AsTxPayload,
    },
    storage::{
        in_memory::{SharedStore, Store},
        DbRead, DbWrite,
    },
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
pub struct TestContext<Storage, Bitcoin, Stacks, Emily> {
    /// The inner [`SignerContext`] which this context wraps.
    pub inner: SignerContext<Storage, Bitcoin, Stacks, Emily>,

    /// The raw inner storage implementation.
    pub storage: Storage,

    /// The raw inner Bitcoin client.
    pub bitcoin_client: Bitcoin,

    /// The raw inner Stacks client.
    pub stacks_client: Stacks,

    /// The raw inner Emily client.
    pub emily_client: Emily,
}

impl<Storage, Bitcoin, Stacks, Emily> TestContext<Storage, Bitcoin, Stacks, Emily>
where
    Storage: DbRead + DbWrite + Clone + Sync + Send,
    Bitcoin: BitcoinInteract + Clone + Send + Sync,
    Stacks: StacksInteract + Clone + Send + Sync,
    Emily: EmilyInteract + Clone + Send + Sync,
{
    /// Create a new test context.
    pub fn new(
        settings: Settings,
        storage: Storage,
        bitcoin_client: Bitcoin,
        stacks_client: Stacks,
        emily_client: Emily,
    ) -> Self {
        let context = SignerContext::new(
            settings,
            storage.clone(),
            bitcoin_client.clone(),
            stacks_client.clone(),
            emily_client.clone(),
        );

        Self {
            inner: context,
            storage,
            bitcoin_client,
            stacks_client,
            emily_client,
        }
    }

    /// Get an instance of the raw storage implementation.
    pub fn inner_storage(&self) -> Storage {
        self.storage.clone()
    }

    /// Get an instance of the raw inner Bitcoin client.
    pub fn inner_bitcoin_client(&self) -> Bitcoin {
        self.bitcoin_client.clone()
    }

    /// Get an instance of the raw inner Stacks client.
    pub fn inner_stacks_client(&self) -> Stacks {
        self.stacks_client.clone()
    }

    /// Get an instance of the raw inner Emily client.
    pub fn inner_emily_client(&self) -> Emily {
        self.emily_client.clone()
    }
}

impl TestContext<(), (), (), ()> {
    /// Returns a builder for creating a new [`TestContext`]. The builder will
    /// be initialized with settings from the default configuration file; use
    /// the [`ContextBuilder::with_settings`] method to override these settings.
    pub fn builder() -> ContextBuilder<(), (), (), ()> {
        Default::default()
    }
}

/// Provide extra methods for when using a mocked bitcoin client.
impl<Storage, Stacks, Emily> TestContext<Storage, WrappedMock<MockBitcoinInteract>, Stacks, Emily> {
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

/// Provide extra methods for when using a mocked stacks client.
impl<Storage, Bitcoin, Emily>
    TestContext<Storage, Bitcoin, WrappedMock<MockStacksInteract>, Emily>
{
    /// Execute a closure with a mutable reference to the inner mocked
    /// stacks client.
    pub async fn with_stacks_client<F>(&mut self, f: F)
    where
        F: FnOnce(&mut MockStacksInteract),
    {
        let mut client = self.stacks_client.lock().await;
        f(&mut client);
    }
}

/// Provide extra methods for when using a mocked emily client.
impl<Storage, Bitcoin, Stacks>
    TestContext<Storage, Bitcoin, Stacks, WrappedMock<MockEmilyInteract>>
{
    /// Execute a closure with a mutable reference to the inner mocked
    /// emily client.
    pub async fn with_emily_client<F>(&mut self, f: F)
    where
        F: FnOnce(&mut MockEmilyInteract),
    {
        let mut client = self.emily_client.lock().await;
        f(&mut client);
    }
}

impl<Storage, Bitcoin, Stacks, Emily> Context for TestContext<Storage, Bitcoin, Stacks, Emily>
where
    Storage: DbRead + DbWrite + Clone + Sync + Send,
    Bitcoin: BitcoinInteract + Clone + Send + Sync,
    Stacks: StacksInteract + Clone + Send + Sync,
    Emily: EmilyInteract + Clone + Send + Sync,
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

    fn get_stacks_client(&self) -> impl StacksInteract + Clone {
        self.inner.get_stacks_client()
    }

    fn get_emily_client(&self) -> impl EmilyInteract + Clone {
        self.inner.get_emily_client()
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

impl StacksInteract for WrappedMock<MockStacksInteract> {
    async fn get_current_signer_set(
        &self,
        contract_principal: &StacksAddress,
    ) -> Result<Vec<PublicKey>, Error> {
        self.inner
            .lock()
            .await
            .get_current_signer_set(contract_principal)
            .await
    }

    async fn get_account(&self, address: &StacksAddress) -> Result<AccountInfo, Error> {
        self.inner.lock().await.get_account(address).await
    }

    async fn submit_tx(&self, tx: &StacksTransaction) -> Result<SubmitTxResponse, Error> {
        self.inner.lock().await.submit_tx(tx).await
    }

    async fn get_block(&self, block_id: StacksBlockId) -> Result<NakamotoBlock, Error> {
        self.inner.lock().await.get_block(block_id).await
    }

    async fn get_tenure(&self, block_id: StacksBlockId) -> Result<Vec<NakamotoBlock>, Error> {
        self.inner.lock().await.get_tenure(block_id).await
    }

    async fn get_tenure_info(&self) -> Result<RPCGetTenureInfo, Error> {
        self.inner.lock().await.get_tenure_info().await
    }

    async fn estimate_fees<T>(&self, payload: &T, priority: FeePriority) -> Result<u64, Error>
    where
        T: AsTxPayload + Send + Sync,
    {
        self.inner
            .lock()
            .await
            .estimate_fees(payload, priority)
            .await
    }

    fn nakamoto_start_height(&self) -> u64 {
        tokio::runtime::Handle::current().block_on(async move {
            let inner = self.inner.lock().await;
            inner.nakamoto_start_height()
        })
    }
}

impl EmilyInteract for WrappedMock<MockEmilyInteract> {
    async fn get_deposits(&self) -> Result<Vec<sbtc::deposits::CreateDepositRequest>, Error> {
        self.inner.lock().await.get_deposits().await
    }
}

/// Struct which holds the current configuration of the context builder.
pub struct ContextConfig<Storage, Bitcoin, Stacks, Emily> {
    settings: crate::config::Settings,
    storage: Storage,
    bitcoin: Bitcoin,
    stacks: Stacks,
    emily: Emily,
}

impl Default for ContextConfig<(), (), (), ()> {
    fn default() -> Self {
        Self {
            settings: Settings::new_from_default_config().expect("failed to load default config"),
            storage: (),
            bitcoin: (),
            stacks: (),
            emily: (),
        }
    }
}

/// State for the builder pattern.
pub trait BuilderState<Storage, Bitcoin, Stacks, Emily> {
    /// Consumes the builder, returning its current internal configuration.
    fn get_config(self) -> ContextConfig<Storage, Bitcoin, Stacks, Emily>;
}

/// A builder for creating a [`TestContext`].
pub struct ContextBuilder<Storage, Bitcoin, Stacks, Emily> {
    config: ContextConfig<Storage, Bitcoin, Stacks, Emily>,
}

impl ContextBuilder<(), (), (), ()> {
    /// Create a new context builder.
    pub fn new() -> Self {
        Self { config: Default::default() }
    }
}

impl Default for ContextBuilder<(), (), (), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Storage, Bitcoin, Stacks, Emily> BuilderState<Storage, Bitcoin, Stacks, Emily>
    for ContextBuilder<Storage, Bitcoin, Stacks, Emily>
{
    fn get_config(self) -> ContextConfig<Storage, Bitcoin, Stacks, Emily> {
        self.config
    }
}

/// Trait for configuring the settings. These methods are always available.
pub trait ConfigureSettings<Storage, Bitcoin, Stacks, Emily>
where
    Self: Sized + BuilderState<Storage, Bitcoin, Stacks, Emily>,
{
    /// Configure the context with the specified settings.
    fn with_settings(self, settings: Settings) -> ContextBuilder<Storage, Bitcoin, Stacks, Emily> {
        let config = self.get_config();
        ContextBuilder {
            config: ContextConfig { settings, ..config },
        }
    }
}

impl<Storage, Bitcoin, Stacks, Emily> ConfigureSettings<Storage, Bitcoin, Stacks, Emily>
    for ContextBuilder<Storage, Bitcoin, Stacks, Emily>
where
    Self: BuilderState<Storage, Bitcoin, Stacks, Emily>,
{
}

/// Trait for configuring the storage implementation. These methods are available
/// when the storage implementation has not been set yet.
pub trait ConfigureStorage<Bitcoin, Stacks, Emily>
where
    Self: Sized + BuilderState<(), Bitcoin, Stacks, Emily>,
{
    /// Configure the context with an in-memory storage implementation.
    fn with_in_memory_storage(self) -> ContextBuilder<SharedStore, Bitcoin, Stacks, Emily> {
        let config = self.get_config();
        ContextBuilder {
            config: ContextConfig {
                settings: config.settings,
                storage: Store::new_shared(),
                bitcoin: config.bitcoin,
                stacks: config.stacks,
                emily: config.emily,
            },
        }
    }

    /// Configure the context with the specified storage implementation.
    fn with_storage<Storage: DbRead + DbWrite + Clone + Send + Sync>(
        self,
        storage: Storage,
    ) -> ContextBuilder<Storage, Bitcoin, Stacks, Emily> {
        let config = self.get_config();
        ContextBuilder {
            config: ContextConfig {
                settings: config.settings,
                storage,
                bitcoin: config.bitcoin,
                stacks: config.stacks,
                emily: config.emily,
            },
        }
    }
}

impl<Bitcoin, Stacks, Emily> ConfigureStorage<Bitcoin, Stacks, Emily>
    for ContextBuilder<(), Bitcoin, Stacks, Emily>
where
    Self: BuilderState<(), Bitcoin, Stacks, Emily>,
{
}

/// Trait for configuring the Bitcoin client implementation. These methods are
/// available when the Bitcoin client implementation has not been set yet.
pub trait ConfigureBitcoinClient<Storage, Stacks, Emily>
where
    Self: Sized + BuilderState<Storage, (), Stacks, Emily>,
{
    /// Configure the context with the specified Bitcoin client implementation.
    fn with_bitcoin_client<Bitcoin: BitcoinInteract + Clone + Send + Sync>(
        self,
        bitcoin_client: Bitcoin,
    ) -> ContextBuilder<Storage, Bitcoin, Stacks, Emily> {
        let config = self.get_config();
        ContextBuilder {
            config: ContextConfig {
                settings: config.settings,
                storage: config.storage,
                bitcoin: bitcoin_client,
                stacks: config.stacks,
                emily: config.emily,
            },
        }
    }

    /// Configure the context to use a [`BitcoinCoreClient`](crate::bitcoin::rpc::BitcoinCoreClient)
    /// with the first RPC endpoint from the settings.
    fn with_first_bitcoin_core_client(
        self,
    ) -> ContextBuilder<Storage, crate::bitcoin::rpc::BitcoinCoreClient, Stacks, Emily> {
        let config = self.get_config();
        let url = config.settings.bitcoin.rpc_endpoints.first().unwrap();
        let bitcoin_client = crate::bitcoin::rpc::BitcoinCoreClient::try_from(url).unwrap();
        ContextBuilder {
            config: ContextConfig {
                settings: config.settings,
                storage: config.storage,
                bitcoin: bitcoin_client,
                stacks: config.stacks,
                emily: config.emily,
            },
        }
    }

    /// Configure the context with a mocked Bitcoin client.
    fn with_mocked_bitcoin_client(
        self,
    ) -> ContextBuilder<Storage, WrappedMock<MockBitcoinInteract>, Stacks, Emily> {
        self.with_bitcoin_client(WrappedMock::default())
    }
}

impl<Storage, Stacks, Emily> ConfigureBitcoinClient<Storage, Stacks, Emily>
    for ContextBuilder<Storage, (), Stacks, Emily>
where
    Self: Sized + BuilderState<Storage, (), Stacks, Emily>,
{
}

/// Trait for configuring the Stacks client implementation. These methods are
/// available when the Stacks client implementation has not been set yet.
pub trait ConfigureStacksClient<Storage, Bitcoin, Emily>
where
    Self: Sized + BuilderState<Storage, Bitcoin, (), Emily>,
{
    /// Configure the context with the specified Stacks client implementation.
    fn with_stacks_client<Stacks: StacksInteract + Clone + Send + Sync>(
        self,
        stacks_client: Stacks,
    ) -> ContextBuilder<Storage, Bitcoin, Stacks, Emily> {
        let config = self.get_config();
        ContextBuilder {
            config: ContextConfig {
                settings: config.settings,
                storage: config.storage,
                bitcoin: config.bitcoin,
                stacks: stacks_client,
                emily: config.emily,
            },
        }
    }

    /// Configure the context with a mocked stacks client.
    fn with_mocked_stacks_client(
        self,
    ) -> ContextBuilder<Storage, Bitcoin, WrappedMock<MockStacksInteract>, Emily> {
        self.with_stacks_client(WrappedMock::default())
    }
}

impl<Storage, Bitcoin, Emily> ConfigureStacksClient<Storage, Bitcoin, Emily>
    for ContextBuilder<Storage, Bitcoin, (), Emily>
where
    Self: Sized + BuilderState<Storage, Bitcoin, (), Emily>,
{
}

/// Trait for configuring the Emily client implementation. These methods are
/// available when the Emily client implementation has not been set yet.
pub trait ConfigureEmilyClient<Storage, Bitcoin, Stacks>
where
    Self: Sized + BuilderState<Storage, Bitcoin, Stacks, ()>,
{
    /// Configure the context with the specified Emily client implementation.
    fn with_emily_client<Emily: EmilyInteract + Clone + Send + Sync>(
        self,
        emily_client: Emily,
    ) -> ContextBuilder<Storage, Bitcoin, Stacks, Emily> {
        let config = self.get_config();
        ContextBuilder {
            config: ContextConfig {
                settings: config.settings,
                storage: config.storage,
                bitcoin: config.bitcoin,
                stacks: config.stacks,
                emily: emily_client,
            },
        }
    }

    /// Configure the context with a mocked Emily client.
    fn with_mocked_emily_client(
        self,
    ) -> ContextBuilder<Storage, Bitcoin, Stacks, WrappedMock<MockEmilyInteract>> {
        self.with_emily_client(WrappedMock::default())
    }
}

impl<Storage, Bitcoin, Stacks> ConfigureEmilyClient<Storage, Bitcoin, Stacks>
    for ContextBuilder<Storage, Bitcoin, Stacks, ()>
where
    Self: Sized + BuilderState<Storage, Bitcoin, Stacks, ()>,
{
}

/// Trait for configuring the context with mocked clients. These methods are
/// available when no clients have been configured yet.
pub trait ConfigureMockedClients<Storage>
where
    Self: Sized + BuilderState<Storage, (), (), ()>,
{
    /// Configure the context to use mocks for all client implementations.
    fn with_mocked_clients(
        self,
    ) -> ContextBuilder<
        Storage,
        WrappedMock<MockBitcoinInteract>,
        WrappedMock<MockStacksInteract>,
        WrappedMock<MockEmilyInteract>,
    > {
        let config = self.get_config();
        ContextBuilder {
            config: ContextConfig {
                settings: config.settings,
                storage: config.storage,
                bitcoin: WrappedMock::default(),
                stacks: WrappedMock::default(),
                emily: WrappedMock::default(),
            },
        }
    }
}

impl<Storage> ConfigureMockedClients<Storage> for ContextBuilder<Storage, (), (), ()> where
    Self: Sized + BuilderState<Storage, (), (), ()>
{
}

/// Trait for building a [`TestContext`]. The [`BuildContext::build`] method
/// consumes the builder and returns a new [`TestContext`]. The method is only
/// available when all required components have been configured.
pub trait BuildContext<Storage, Bitcoin, Stacks, Emily>
where
    Self: Sized + BuilderState<Storage, Bitcoin, Stacks, Emily>,
{
    /// Consume the builder and return a new [`TestContext`].
    fn build(self) -> TestContext<Storage, Bitcoin, Stacks, Emily>;
}

// TODO: We could probably move the entire builder and use it for the `SignerContext`
// as well with a separate `SignerContextBuilder` trait.
impl<Storage, Bitcoin, Stacks, Emily> BuildContext<Storage, Bitcoin, Stacks, Emily>
    for ContextBuilder<Storage, Bitcoin, Stacks, Emily>
where
    Self: BuilderState<Storage, Bitcoin, Stacks, Emily>,
    Storage: DbRead + DbWrite + Clone + Sync + Send,
    Bitcoin: BitcoinInteract + Clone + Send + Sync,
    Stacks: StacksInteract + Clone + Send + Sync,
    Emily: EmilyInteract + Clone + Send + Sync,
{
    fn build(self) -> TestContext<Storage, Bitcoin, Stacks, Emily> {
        let config = self.get_config();
        TestContext::new(
            config.settings,
            config.storage,
            config.bitcoin,
            config.stacks,
            config.emily,
        )
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
        context::{Context as _, SignerEvent, SignerSignal},
        testing::context::*,
    };

    #[test]
    fn can_build() {
        let _builder = ContextBuilder::new()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();
    }

    /// This test ensures that the context can be cloned and signals can be sent
    /// to both clones.
    #[tokio::test]
    async fn context_clone_signalling_works() {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let context = Arc::new(context);
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

        let context_clone = context.clone();
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
