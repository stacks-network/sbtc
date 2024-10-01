//! Test utilities for the transaction coordinator

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::bitcoin::utxo;
use crate::bitcoin::MockBitcoinInteract;
use crate::context::Context;
use crate::context::SignerEvent;
use crate::error;
use crate::keys;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey;
use crate::network;
use crate::storage::model;
use crate::storage::DbRead as _;
use crate::storage::DbWrite;
use crate::testing;
use crate::testing::storage::model::TestData;
use crate::testing::wsts::SignerSet;
use crate::transaction_coordinator;

use rand::SeedableRng as _;
use sha2::Digest as _;

use super::context::TestContext;
use super::context::WrappedMock;

struct EventLoopHarness<C> {
    event_loop: EventLoop<C>,
    context: C,
    is_started: Arc<AtomicBool>,
}

impl<C> EventLoopHarness<C>
where
    C: Context + 'static,
{
    fn create(
        context: C,
        network: network::in_memory::MpmcBroadcaster,
        context_window: usize,
        private_key: PrivateKey,
        threshold: u16,
    ) -> Self {
        Self {
            event_loop: transaction_coordinator::TxCoordinatorEventLoop {
                context: context.clone(),
                network,
                private_key,
                context_window,
                threshold,
                bitcoin_network: bitcoin::Network::Testnet,
                signing_round_max_duration: Duration::from_secs(10),
            },
            context,
            is_started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start(self) -> RunningEventLoopHandle<C> {
        let is_started = self.is_started.clone();
        let join_handle = tokio::spawn(async move {
            is_started.store(true, Ordering::SeqCst);
            self.event_loop.run().await
        });

        while !self.is_started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        RunningEventLoopHandle {
            context: self.context.clone(),
            join_handle,
        }
    }
}

type EventLoop<C> =
    transaction_coordinator::TxCoordinatorEventLoop<C, network::in_memory::MpmcBroadcaster>;

struct RunningEventLoopHandle<C> {
    context: C,
    join_handle: tokio::task::JoinHandle<Result<(), error::Error>>,
}

/// Test environment.
pub struct TestEnvironment<Context> {
    /// Signer context
    pub context: Context,
    /// Bitcoin context window
    pub context_window: usize,
    /// Num signers
    pub num_signers: usize,
    /// Signing threshold
    pub signing_threshold: u16,
    /// Test model parameters
    pub test_model_parameters: testing::storage::model::Params,
}

impl TestEnvironment<TestContext<WrappedMock<MockBitcoinInteract>>> {
    /// Assert that a coordinator should be able to coordiante a signing round
    pub async fn assert_should_be_able_to_coordinate_signing_rounds(mut self) {
        // Get a handle to our mocked bitcoin client.
        let mock_bitcoin_client = self.context.inner_bitcoin_client();

        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);

        let mut testing_signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip) = self
            .prepare_database_and_run_dkg(&mut rng, &mut testing_signer_set)
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

        self.context
            .with_bitcoin_client(|client| {
                client
                    .expect_estimate_fee_rate()
                    .times(1)
                    .returning(|| Box::pin(async { Ok(1.3) }));

                client
                    .expect_get_signer_utxo()
                    .once()
                    .returning(move |_| Box::pin(async move { Ok(Some(signer_utxo)) }));

                client
                    .expect_get_last_fee()
                    .once()
                    .returning(|_| Box::pin(async { Ok(None) }));
            })
            .await;

        // Create a channel to log all transactions broadcasted by the coordinator.
        // The receiver is created by this method but not used as it is held as a
        // handle to ensure that the channel is alive until the end of the test.
        // This is because the coordinator will produce multiple transactions after
        // the first, and it will panic trying to send to the channel if it is closed
        // (even though we don't use those transactions).
        let (broadcasted_transaction_tx, _broadcasted_transaction_rxeiver) =
            tokio::sync::broadcast::channel(1);

        // This task logs all transactions broadcasted by the coordinator.
        let mut wait_for_transaction_rx = broadcasted_transaction_tx.subscribe();
        let wait_for_transaction_task =
            tokio::spawn(async move { wait_for_transaction_rx.recv().await });

        // Setup the bitcoin client mock to broadcast the transaction to our
        // channel.
        mock_bitcoin_client
            .lock()
            .await
            .expect_broadcast_transaction()
            .times(1..)
            .returning(move |tx| {
                let tx = tx.clone();
                let broadcasted_transaction_tx = broadcasted_transaction_tx.clone();
                Box::pin(async move {
                    broadcasted_transaction_tx
                        .send(tx)
                        .expect("Failed to send result");
                    Ok(())
                })
            });

        // Get the private key of the coordinator of the signer set.
        let private_key = Self::select_coordinator(&bitcoin_chain_tip, &signer_info);

        // Bootstrap the tx coordinator within an event loop harness.
        let event_loop_harness = EventLoopHarness::create(
            self.context.clone(),
            network.connect(),
            self.context_window,
            private_key,
            self.signing_threshold,
        );

        // Start the tx coordinator run loop.
        let handle = event_loop_harness.start().await;

        // Start the in-memory signer set.
        let _signers_handle = tokio::spawn(async move {
            testing_signer_set
                .participate_in_signing_rounds_forever()
                .await
        });

        // Signal `BitcoinBlockObserved` to trigger the coordinator.
        handle
            .context
            .signal(SignerEvent::BitcoinBlockObserved.into())
            .expect("failed to signal");

        // Await the `wait_for_tx_task` to receive the first transaction broadcasted.
        let broadcasted_tx = wait_for_transaction_task
            .await
            .expect("failed to receive message")
            .expect("no message received");

        // Extract the first script pubkey from the broadcasted transaction.
        let first_script_pubkey = broadcasted_tx
            .tx_out(0)
            .expect("missing tx output")
            .script_pubkey
            .clone();

        // Stop the event loop
        handle.join_handle.abort();

        // Perform assertions
        assert_eq!(first_script_pubkey, aggregate_key.signers_script_pubkey());
    }

    async fn prepare_database_and_run_dkg<Rng>(
        &mut self,
        rng: &mut Rng,
        signer_set: &mut SignerSet,
    ) -> (keys::PublicKey, model::BitcoinBlockHash)
    where
        Rng: rand::CryptoRng + rand::RngCore,
    {
        let storage = self.context.get_storage_mut();

        let signer_keys = signer_set.signer_keys();
        let test_data = self.generate_test_data(rng, signer_keys);
        self.write_test_data(&test_data).await;

        let bitcoin_chain_tip = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage error")
            .expect("no chain tip");

        let dkg_txid = testing::dummy::txid(&fake::Faker, rng);
        let (aggregate_key, all_dkg_shares) =
            signer_set.run_dkg(bitcoin_chain_tip, dkg_txid, rng).await;

        signer_set
            .write_as_rotate_keys_tx(
                &self.context.get_storage_mut(),
                &bitcoin_chain_tip,
                aggregate_key,
                rng,
            )
            .await;

        let encrypted_dkg_shares = all_dkg_shares.first().unwrap();

        storage
            .write_encrypted_dkg_shares(encrypted_dkg_shares)
            .await
            .expect("failed to write encrypted shares");

        (aggregate_key, bitcoin_chain_tip)
    }

    async fn write_test_data(&self, test_data: &TestData) {
        test_data.write_to(&self.context.get_storage_mut()).await;
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
