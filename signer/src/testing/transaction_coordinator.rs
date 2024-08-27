//! Test utilities for the transaction coordinator

use crate::bitcoin::utxo;
use crate::error;
use crate::keys::PrivateKey;
use crate::network;
use crate::storage;
use crate::testing;
use crate::transaction_coordinator;

use bitcoin::hashes::Hash as _;
use rand::SeedableRng as _;
use sha2::Digest as _;

struct EventLoopHarness<S, C> {
    event_loop: EventLoop<S, C>,
    block_observer_notification_tx: tokio::sync::watch::Sender<()>,
    storage: S,
}

impl<S, C> EventLoopHarness<S, C>
where
    S: storage::DbRead + storage::DbWrite + Clone + Send + 'static,
    error::Error: From<<S as storage::DbRead>::Error>,
    error::Error: From<<S as storage::DbWrite>::Error>,
    C: crate::bitcoin::BitcoinInteract + Send + 'static,
    error::Error: From<C::Error>,
{
    fn create(
        network: network::in_memory::MpmcBroadcaster,
        storage: S,
        bitcoin_client: C,
        context_window: usize,
        private_key: PrivateKey,
        threshold: u16,
    ) -> Self {
        let (block_observer_notification_tx, block_observer_notifications) =
            tokio::sync::watch::channel(());

        Self {
            event_loop: transaction_coordinator::TxCoordinatorEventLoop {
                storage: storage.clone(),
                network,
                block_observer_notifications,
                private_key,
                context_window,
                threshold,
                bitcoin_client,
                bitcoin_network: bitcoin::Network::Testnet,
            },
            block_observer_notification_tx,
            storage,
        }
    }

    pub fn start(self) -> RunningEventLoopHandle<S> {
        let block_observer_notification_tx = self.block_observer_notification_tx;
        let join_handle = tokio::spawn(async { dbg!(self.event_loop.run().await) });
        let storage = self.storage;

        RunningEventLoopHandle {
            join_handle,
            block_observer_notification_tx,
            storage,
        }
    }
}

type EventLoop<S, C> =
    transaction_coordinator::TxCoordinatorEventLoop<network::in_memory::MpmcBroadcaster, S, C>;

struct RunningEventLoopHandle<S> {
    join_handle: tokio::task::JoinHandle<Result<(), error::Error>>,
    block_observer_notification_tx: tokio::sync::watch::Sender<()>,
    storage: S,
}

impl<S> RunningEventLoopHandle<S> {
    /// Stop event loop
    pub async fn stop_event_loop(self) -> S {
        // While this explicit drop isn't strictly necessary, it serves to clarify our intention.
        drop(self.block_observer_notification_tx);

        self.join_handle
            .await
            .expect("joining event loop failed")
            .expect("event loop returned error");

        self.storage
    }
}

/// Test environment.
pub struct TestEnvironment<C> {
    /// Function to construct a storage instance
    pub storage_constructor: C,
    /// Bitcoin context window
    pub context_window: usize,
    /// Num signers
    pub num_signers: usize,
    /// Signing threshold
    pub signing_threshold: u16,
    /// Test model parameters
    pub test_model_parameters: testing::storage::model::Params,
}

impl<C, S> TestEnvironment<C>
where
    C: FnMut() -> S,
    S: storage::DbRead + storage::DbWrite + Clone + Send + 'static,
    error::Error: From<<S as storage::DbRead>::Error>,
    error::Error: From<<S as storage::DbWrite>::Error>,
{
    /// Assert that a coordinator should be able to coordiante a signing round
    pub async fn assert_should_be_able_to_coordinate_signing_rounds(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let placeholder_bitcoin_client = crate::bitcoin::MockBitcoinInteract::new();

        let mut event_loop_harness = EventLoopHarness::create(
            network.connect(),
            (self.storage_constructor)(),
            placeholder_bitcoin_client,
            self.context_window,
            signer_info.first().cloned().unwrap().signer_private_key,
            self.signing_threshold,
        );

        let test_data = self.generate_test_data(&mut rng);
        Self::write_test_data(&test_data, &mut event_loop_harness.storage).await;

        let mut testing_signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        // Run dkg and store result
        let chain_tip = event_loop_harness
            .storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage error")
            .expect("no chain tip");

        let dkg_txid = testing::dummy::txid(&fake::Faker, &mut rng);
        let bitcoin_chain_tip = bitcoin::BlockHash::from_byte_array(
            chain_tip.clone().try_into().expect("conversion failed"),
        );
        let (aggregate_key, all_dkg_shares) = testing_signer_set
            .run_dkg(bitcoin_chain_tip, dkg_txid, &mut rng)
            .await;

        testing_signer_set
            .write_as_rotate_keys_tx(
                &mut event_loop_harness.storage,
                &chain_tip,
                aggregate_key,
                &mut rng,
            )
            .await;

        let encrypted_dkg_shares = all_dkg_shares.first().unwrap();

        event_loop_harness
            .storage
            .write_encrypted_dkg_shares(encrypted_dkg_shares)
            .await
            .expect("failed to write encrypted shares");

        // Mock stuff -----------
        let public_key = bitcoin::XOnlyPublicKey::from(&aggregate_key);
        let outpoint = bitcoin::OutPoint {
            txid: testing::dummy::txid(&fake::Faker, &mut rng),
            vout: 3,
        };

        let signer_utxo = utxo::SignerUtxo {
            outpoint,
            amount: 1_337_000_000,
            public_key,
        };

        let mut mock_bitcoin_client = crate::bitcoin::MockBitcoinInteract::new();

        mock_bitcoin_client
            .expect_estimate_fee_rate()
            .times(1)
            .returning(|| Box::pin(async { Ok(1.3) }));

        mock_bitcoin_client
            .expect_get_signer_utxo()
            .once()
            .returning(move |_| Box::pin(async move { Ok(Some(signer_utxo)) }));

        mock_bitcoin_client
            .expect_get_last_fee()
            .once()
            .returning(|_| Box::pin(async { Ok(None) }));

        let (broadcasted_tx_sender, mut broadcasted_tx_receiver) = tokio::sync::mpsc::channel(1);

        mock_bitcoin_client
            .expect_broadcast_transaction()
            .once()
            .returning(move |tx| {
                let tx = tx.clone();
                let broadcasted_tx_sender = broadcasted_tx_sender.clone();
                Box::pin(async move {
                    broadcasted_tx_sender
                        .send(tx)
                        .await
                        .expect("Failed to send result");
                    Ok(())
                })
            });

        // Coordinator selection
        let mut hasher = sha2::Sha256::new();
        hasher.update(bitcoin_chain_tip);
        let digest = hasher.finalize();
        let index = usize::from_be_bytes(*digest.first_chunk().expect("unexpected digest size"));
        let private_key = signer_info
            .get(index % signer_info.len())
            .expect("missing signer info")
            .signer_private_key;

        // TODO: It's getting pretty clear that we should construct the event loop here
        event_loop_harness.event_loop.bitcoin_client = mock_bitcoin_client;
        event_loop_harness.event_loop.network = network.connect();
        event_loop_harness.event_loop.private_key = private_key;

        let handle = event_loop_harness.start();

        let _signers_handle = tokio::spawn(async move {
            testing_signer_set
                .participate_in_signing_rounds_forever()
                .await
        });

        handle
            .block_observer_notification_tx
            .send(())
            .expect("failed to send notification");

        let broadcasted_tx = broadcasted_tx_receiver.recv().await.unwrap();
        println!("Broadcasted tx: {:?}", broadcasted_tx);

        //signers_handle.await.expect("signers crashed");

        handle.stop_event_loop().await;
    }

    async fn write_test_data(test_data: &testing::storage::model::TestData, storage: &mut S) {
        test_data.write_to(storage).await;
    }

    fn generate_test_data(
        &self,
        rng: &mut impl rand::RngCore,
    ) -> testing::storage::model::TestData {
        testing::storage::model::TestData::generate(rng, &self.test_model_parameters)
    }
}
