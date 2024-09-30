//! Test utilities for the transaction coordinator

use std::cell::RefCell;
use std::time::Duration;

use crate::bitcoin::utxo::SignerUtxo;
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

const EMPTY_BITCOIN_TX: bitcoin::Transaction = bitcoin::Transaction {
    version: bitcoin::transaction::Version::ONE,
    lock_time: bitcoin::absolute::LockTime::ZERO,
    input: vec![],
    output: vec![],
};

struct EventLoopHarness<S, C> {
    event_loop: EventLoop<S, C>,
    block_observer_notification_tx: tokio::sync::watch::Sender<()>,
    storage: S,
}

impl<S, C> EventLoopHarness<S, C>
where
    S: storage::DbRead + storage::DbWrite + Clone + Send + 'static,
    C: crate::bitcoin::BitcoinInteract + Send + 'static,
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

        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut storage, &mut rng, &mut testing_signer_set)
            .await;

        let original_test_data = test_data.clone();

        let tx_1 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_337_000_000_000),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        test_data.push_sbtc_txs(&bitcoin_chain_tip, vec![tx_1.clone()]);

        test_data.remove(original_test_data);
        Self::write_test_data(&test_data, &mut storage).await;

        let mut mock_bitcoin_client = crate::bitcoin::MockBitcoinInteract::new();

        mock_bitcoin_client
            .expect_estimate_fee_rate()
            .times(1)
            .returning(|| Box::pin(async { Ok(1.3) }));

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

        let private_key = Self::select_coordinator(&bitcoin_chain_tip.block_hash, &signer_info);

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

    /// Assert we get the correct UTXO in a simple case
    pub async fn assert_get_signer_utxo_simple(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let mut storage = (self.storage_constructor)();

        let mut signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut storage, &mut rng, &mut signer_set)
            .await;

        let original_test_data = test_data.clone();

        let tx = bitcoin::Transaction {
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(42),
                    script_pubkey: aggregate_key.signers_script_pubkey(),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(123),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
            ],
            ..EMPTY_BITCOIN_TX
        };

        let (block, block_ref) = test_data.new_block(
            &mut rng,
            &signer_set.signer_keys(),
            &self.test_model_parameters,
            Some(&bitcoin_chain_tip),
        );
        test_data.push(block);
        test_data.push_sbtc_txs(&block_ref, vec![tx.clone()]);

        let expected = SignerUtxo {
            outpoint: bitcoin::OutPoint::new(tx.compute_txid(), 0),
            amount: 42,
            public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
        };

        test_data.remove(original_test_data);
        Self::write_test_data(&test_data, &mut storage).await;

        let chain_tip = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage failure")
            .expect("missing block");
        assert_eq!(chain_tip, block_ref.block_hash);

        let signer_utxo = storage
            .get_signer_utxo(&chain_tip, &aggregate_key)
            .await
            .unwrap()
            .expect("no signer utxo");

        assert_eq!(signer_utxo, expected);
    }

    /// Assert we get the correct UTXO in a fork
    pub async fn assert_get_signer_utxo_fork(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let mut storage = (self.storage_constructor)();

        let mut signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, test_data) = self
            .prepare_database_and_run_dkg(&mut storage, &mut rng, &mut signer_set)
            .await;

        let original_test_data = test_data.clone();

        let test_data_rc = RefCell::new(test_data);
        let mut push_block = |parent| {
            let (block, block_ref) = test_data_rc.borrow_mut().new_block(
                &mut rng,
                &signer_set.signer_keys(),
                &self.test_model_parameters,
                Some(parent),
            );
            test_data_rc.borrow_mut().push(block);
            block_ref
        };
        let push_utxo = |block_ref, sat_amt| {
            let tx = bitcoin::Transaction {
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(sat_amt),
                    script_pubkey: aggregate_key.signers_script_pubkey(),
                }],
                ..EMPTY_BITCOIN_TX
            };
            test_data_rc
                .borrow_mut()
                .push_sbtc_txs(block_ref, vec![tx.clone()]);
            tx
        };

        // The scenario is: (* = no utxo)
        // [bitcoin_chain_tip] +- [block a1] - [block a2] - [block a3*]
        //                     +- [block b1] - [block b2] - [block b3*]
        //                     +- [block c1] - [block c2*]

        let block_a1 = push_block(&bitcoin_chain_tip);
        let tx_a1 = push_utxo(&block_a1, 0xA1);

        let block_a2 = push_block(&block_a1);
        let tx_a2 = push_utxo(&block_a2, 0xA2);

        let block_a3 = push_block(&block_a2);

        let block_b1 = push_block(&bitcoin_chain_tip);
        let tx_b1 = push_utxo(&block_b1, 0xB1);

        let block_b2 = push_block(&block_b1);
        let tx_b2 = push_utxo(&block_b2, 0xB2);

        let block_b3 = push_block(&block_b2);

        let block_c1 = push_block(&bitcoin_chain_tip);
        let tx_c1 = push_utxo(&block_c1, 0xC1);

        let block_c2 = push_block(&block_c1);

        let mut test_data = test_data_rc.into_inner();
        test_data.remove(original_test_data);
        Self::write_test_data(&test_data, &mut storage).await;

        for (chain_tip, tx, amt) in [
            (&block_a1, &tx_a1, 0xA1),
            (&block_a2, &tx_a2, 0xA2),
            (&block_a3, &tx_a2, 0xA2),
            (&block_b1, &tx_b1, 0xB1),
            (&block_b2, &tx_b2, 0xB2),
            (&block_b3, &tx_b2, 0xB2),
            (&block_c1, &tx_c1, 0xC1),
            (&block_c2, &tx_c1, 0xC1),
        ] {
            let expected = SignerUtxo {
                outpoint: bitcoin::OutPoint::new(tx.compute_txid(), 0),
                amount: amt,
                public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
            };
            let signer_utxo = storage
                .get_signer_utxo(&chain_tip.block_hash, &aggregate_key)
                .await
                .unwrap()
                .expect("no signer utxo");
            assert_eq!(signer_utxo, expected);
        }
    }

    /// Assert we get the correct UTXO with a spending chain in a block
    pub async fn assert_get_signer_utxo_unspent(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let mut storage = (self.storage_constructor)();

        let mut signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut storage, &mut rng, &mut signer_set)
            .await;

        let original_test_data = test_data.clone();

        let tx_1 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        let tx_2 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(2),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        let tx_3 = bitcoin::Transaction {
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: tx_1.compute_txid(),
                        vout: 0,
                    },
                    ..Default::default()
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: tx_2.compute_txid(),
                        vout: 0,
                    },
                    ..Default::default()
                },
            ],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(3),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        let (block, block_ref) = test_data.new_block(
            &mut rng,
            &signer_set.signer_keys(),
            &self.test_model_parameters,
            Some(&bitcoin_chain_tip),
        );
        test_data.push(block);
        test_data.push_sbtc_txs(&block_ref, vec![tx_1.clone(), tx_3.clone(), tx_2.clone()]);

        let expected = SignerUtxo {
            outpoint: bitcoin::OutPoint::new(tx_3.compute_txid(), 0),
            amount: 3,
            public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
        };

        test_data.remove(original_test_data);
        Self::write_test_data(&test_data, &mut storage).await;

        let chain_tip = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage failure")
            .expect("missing block");
        assert_eq!(chain_tip, block_ref.block_hash);

        let signer_utxo = storage
            .get_signer_utxo(&chain_tip, &aggregate_key)
            .await
            .unwrap()
            .expect("no signer utxo");

        assert_eq!(signer_utxo, expected);
    }

    async fn prepare_database_and_run_dkg<Rng>(
        &mut self,
        storage: &mut S,
        rng: &mut Rng,
        signer_set: &mut SignerSet,
    ) -> (keys::PublicKey, model::BitcoinBlockRef, TestData)
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

        let bitcoin_chain_tip_ref = storage
            .get_bitcoin_block(&bitcoin_chain_tip)
            .await
            .expect("storage failure")
            .expect("missing block")
            .into();

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

        (aggregate_key, bitcoin_chain_tip_ref, test_data)
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
