//! Test utilities for the transaction coordinator

use std::time::Duration;

use crate::bitcoin::utxo;
use crate::error;
use crate::keys;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey;
use crate::network;
use crate::storage;
use crate::storage::model;
use crate::testing;
use crate::testing::storage::model::TestData;
use crate::testing::wsts::SignerSet;
use crate::transaction_coordinator;

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
                signing_round_max_duration: Duration::from_secs(10),
            },
            block_observer_notification_tx,
            storage,
        }
    }

    pub fn start(self) -> RunningEventLoopHandle<S> {
        let block_observer_notification_tx = self.block_observer_notification_tx;
        let join_handle = tokio::spawn(async { self.event_loop.run().await });
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

        tokio::time::timeout(Duration::from_secs(10), self.join_handle)
            .await
            .unwrap()
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
        let mut storage = (self.storage_constructor)();

        let mut testing_signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip) = self
            .prepare_database_and_run_dkg(&mut storage, &mut rng, &mut testing_signer_set)
            .await;

        let public_key = bitcoin::XOnlyPublicKey::from(&aggregate_key);
        let outpoint = bitcoin::OutPoint {
            txid: testing::dummy::txid(&fake::Faker, &mut rng),
            vout: 3,
        };

        let signer_utxo = utxo::SignerUtxo {
            outpoint,
            amount: 1_337_000_000_000,
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

        // TODO: multiple transactions can be generated and keeping this
        // too low will cause issues. Figure out why.
        let (broadcasted_tx_sender, mut broadcasted_tx_receiver) = tokio::sync::mpsc::channel(100);

        mock_bitcoin_client
            .expect_broadcast_transaction()
            .times(1..)
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

        let private_key = Self::select_coordinator(&bitcoin_chain_tip, &signer_info);

        let event_loop_harness = EventLoopHarness::create(
            network.connect(),
            storage,
            mock_bitcoin_client,
            self.context_window,
            private_key,
            self.signing_threshold,
        );

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

        let future = broadcasted_tx_receiver.recv();
        let broadcasted_tx = tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap()
            .unwrap();

        let first_script_pubkey = broadcasted_tx
            .tx_out(0)
            .expect("missing tx output")
            .script_pubkey
            .clone();

        handle.stop_event_loop().await;

        assert_eq!(first_script_pubkey, aggregate_key.signers_script_pubkey());
    }

    async fn prepare_database_and_run_dkg<Rng>(
        &mut self,
        storage: &mut S,
        rng: &mut Rng,
        signer_set: &mut SignerSet,
    ) -> (keys::PublicKey, model::BitcoinBlockHash)
    where
        Rng: rand::CryptoRng + rand::RngCore,
    {
        let signer_keys = signer_set.signer_keys();
        let test_data = self.generate_test_data(rng, signer_keys);
        Self::write_test_data(&test_data, storage).await;

        let bitcoin_chain_tip = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage error")
            .expect("no chain tip");

        let dkg_txid = testing::dummy::txid(&fake::Faker, rng);
        let (aggregate_key, all_dkg_shares) =
            signer_set.run_dkg(bitcoin_chain_tip, dkg_txid, rng).await;

        signer_set
            .write_as_rotate_keys_tx(storage, &bitcoin_chain_tip, aggregate_key, rng)
            .await;

        let encrypted_dkg_shares = all_dkg_shares.first().unwrap();

        storage
            .write_encrypted_dkg_shares(encrypted_dkg_shares)
            .await
            .expect("failed to write encrypted shares");

        (aggregate_key, bitcoin_chain_tip)
    }

    async fn write_test_data(test_data: &TestData, storage: &mut S) {
        test_data.write_to(storage).await;
    }

    fn generate_test_data<R>(&self, rng: &mut R, signer_keys: Vec<PublicKey>) -> TestData
    where
        R: rand::RngCore,
    {
        TestData::generate(rng, &signer_keys, &self.test_model_parameters)
    }

    fn select_coordinator(
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        signer_info: &[testing::wsts::SignerInfo],
    ) -> keys::PrivateKey {
        let mut hasher = sha2::Sha256::new();
        hasher.update(bitcoin_chain_tip.into_bytes());
        let digest = hasher.finalize();
        let index = usize::from_be_bytes(*digest.first_chunk().expect("unexpected digest size"));
        signer_info
            .get(index % signer_info.len())
            .expect("missing signer info")
            .signer_private_key
    }
}
