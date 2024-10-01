//! Test utilities for the transaction signer

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::time::Duration;

use crate::blocklist_client;
use crate::error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey as _;
use crate::message;
use crate::network;
use crate::storage;
use crate::storage::model;
use crate::testing;
use crate::testing::storage::model::TestData;
use crate::transaction_coordinator;
use crate::transaction_signer;
use crate::transaction_signer::TxSignerEvent;

use crate::ecdsa::SignEcdsa as _;
use crate::network::MessageTransfer as _;

use futures::StreamExt as _;
use rand::SeedableRng as _;
use sha2::Digest as _;

struct EventLoopHarness<S, Rng> {
    event_loop: EventLoop<S, Rng>,
    block_observer_notification_tx: tokio::sync::watch::Sender<()>,
    test_observer_rx: tokio::sync::mpsc::Receiver<transaction_signer::TxSignerEvent>,
    storage: S,
}

impl<S, Rng> EventLoopHarness<S, Rng>
where
    S: storage::DbRead + storage::DbWrite + Clone + Send + Sync + 'static,
    Rng: rand::RngCore + rand::CryptoRng + Send + Sync + 'static,
{
    fn create(
        network: network::in_memory::MpmcBroadcaster,
        storage: S,
        context_window: u16,
        signer_private_key: PrivateKey,
        threshold: u32,
        rng: Rng,
    ) -> Self {
        let (block_observer_notification_tx, block_observer_notifications) =
            tokio::sync::watch::channel(());

        let (test_observer_tx, test_observer_rx) = tokio::sync::mpsc::channel(128);

        Self {
            event_loop: transaction_signer::TxSignerEventLoop {
                storage: storage.clone(),
                network,
                blocklist_checker: Some(()),
                block_observer_notifications,
                signer_private_key,
                context_window,
                wsts_state_machines: HashMap::new(),
                threshold,
                network_kind: bitcoin::Network::Regtest,
                rng,
                test_observer_tx: Some(test_observer_tx),
            },
            block_observer_notification_tx,
            test_observer_rx,
            storage,
        }
    }

    pub fn start(self) -> RunningEventLoopHandle<S> {
        let block_observer_notification_tx = self.block_observer_notification_tx;
        let test_observer_rx = self.test_observer_rx;
        let join_handle = tokio::spawn(async { self.event_loop.run().await });
        let storage = self.storage;

        RunningEventLoopHandle {
            join_handle,
            block_observer_notification_tx,
            test_observer_rx,
            storage,
        }
    }
}

struct RunningEventLoopHandle<S> {
    join_handle: tokio::task::JoinHandle<Result<(), error::Error>>,
    block_observer_notification_tx: tokio::sync::watch::Sender<()>,
    test_observer_rx: tokio::sync::mpsc::Receiver<transaction_signer::TxSignerEvent>,
    storage: S,
}

impl<S> RunningEventLoopHandle<S> {
    /// Stop event loop
    pub async fn stop_event_loop(self) -> S {
        // While this explicit drop isn't strictly necessary, it serves to clarify our intention.
        drop(self.block_observer_notification_tx);

        let future = self.join_handle;
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap()
            .expect("joining event loop failed")
            .expect("event loop returned error");

        self.storage
    }

    /// Wait for N instances of the given event
    pub async fn wait_for_events(&mut self, msg: transaction_signer::TxSignerEvent, mut n: u16) {
        while let Some(event) = self.test_observer_rx.recv().await {
            if event == msg {
                n -= 1;
            }

            if n == 0 {
                return;
            }
        }
    }
}

type EventLoop<S, Rng> =
    transaction_signer::TxSignerEventLoop<network::in_memory::MpmcBroadcaster, S, (), Rng>;

impl blocklist_client::BlocklistChecker for () {
    async fn can_accept(
        &self,
        _address: &str,
    ) -> Result<bool, blocklist_api::apis::Error<blocklist_api::apis::address_api::CheckAddressError>>
    {
        Ok(true)
    }
}

/// Test environment.
pub struct TestEnvironment<C> {
    /// Function to construct a storage instance
    pub storage_constructor: C,
    /// Bitcoin context window
    pub context_window: u16,
    /// Num signers
    pub num_signers: usize,
    /// Signing threshold
    pub signing_threshold: u32,
    /// Test model parameters
    pub test_model_parameters: testing::storage::model::Params,
}

impl<C, S> TestEnvironment<C>
where
    C: FnMut() -> S,
    S: storage::DbRead + storage::DbWrite + Clone + Send + Sync + 'static,
{
    /// Assert that the transaction signer will make and store decisions
    /// for pending deposit requests.
    pub async fn assert_should_store_decisions_for_pending_deposit_requests(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = &signer_info.first().cloned().unwrap();

        let event_loop_harness = EventLoopHarness::create(
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
            coordinator_signer_info.signer_private_key,
            self.signing_threshold,
            rng.clone(),
        );

        let mut handle = event_loop_harness.start();

        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        Self::write_test_data(&test_data, &mut handle.storage).await;

        handle
            .block_observer_notification_tx
            .send(())
            .expect("failed to send notification");

        let storage = handle.stop_event_loop().await;

        Self::assert_only_deposit_requests_in_context_window_has_decisions(
            &storage,
            self.context_window,
            &test_data.deposit_requests,
            1,
        )
        .await;
    }

    /// Assert that the transaction signer will make and store decisions
    /// for pending withdraw requests.
    pub async fn assert_should_store_decisions_for_pending_withdraw_requests(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = signer_info.first().cloned().unwrap();

        let event_loop_harness = EventLoopHarness::create(
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
            coordinator_signer_info.signer_private_key,
            self.signing_threshold,
            rng.clone(),
        );

        let mut handle = event_loop_harness.start();

        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        Self::write_test_data(&test_data, &mut handle.storage).await;

        handle
            .block_observer_notification_tx
            .send(())
            .expect("failed to send notification");

        let storage = handle.stop_event_loop().await;

        Self::assert_only_withdraw_requests_in_context_window_has_decisions(
            &storage,
            self.context_window,
            &test_data.withdraw_requests,
            1,
        )
        .await;
    }

    /// Assert that the transaction signer will make and store decisions
    /// received from other signers.
    pub async fn assert_should_store_decisions_received_from_other_signers(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = signer_info.first().cloned().unwrap();

        let mut event_loop_handles: Vec<_> = signer_info
            .into_iter()
            .map(|signer_info| {
                let event_loop_harness = EventLoopHarness::create(
                    network.connect(),
                    (self.storage_constructor)(),
                    self.context_window,
                    signer_info.signer_private_key,
                    self.signing_threshold,
                    rng.clone(),
                );

                event_loop_harness.start()
            })
            .collect();

        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        for handle in event_loop_handles.iter_mut() {
            Self::write_test_data(&test_data, &mut handle.storage).await;
        }

        for handle in event_loop_handles.iter() {
            handle
                .block_observer_notification_tx
                .send(())
                .expect("failed to send notification");
        }

        let num_expected_decisions = (self.num_signers - 1) as u16
            * self.context_window
            * self.test_model_parameters.num_deposit_requests_per_block as u16;

        for handle in event_loop_handles.iter_mut() {
            let msg = TxSignerEvent::ReceivedDepositDecision;
            let future = handle.wait_for_events(msg, num_expected_decisions);
            tokio::time::timeout(Duration::from_secs(10), future)
                .await
                .unwrap();
        }

        for handle in event_loop_handles {
            let storage = handle.stop_event_loop().await;

            Self::assert_only_deposit_requests_in_context_window_has_decisions(
                &storage,
                self.context_window,
                &test_data.deposit_requests,
                self.num_signers,
            )
            .await;
        }
    }

    /// Assert that the transaction signer will respond to bitcoin transaction sign requests
    /// with an acknowledge message. Errors after 10 seconds.
    pub async fn assert_should_respond_to_bitcoin_transaction_sign_requests(self) {
        let future = self.assert_should_respond_to_bitcoin_transaction_sign_requests_impl();
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap()
    }

    /// Assert that the transaction signer will respond to bitcoin transaction sign requests
    /// with an acknowledge message
    pub async fn assert_should_respond_to_bitcoin_transaction_sign_requests_impl(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = &signer_info.first().cloned().unwrap();

        let event_loop_harness = EventLoopHarness::create(
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
            coordinator_signer_info.signer_private_key,
            self.signing_threshold,
            rng.clone(),
        );

        let mut handle = event_loop_harness.start();

        let signer_private_key = signer_info.first().unwrap().signer_private_key.to_bytes();
        let dummy_aggregate_key = PublicKey::from_private_key(&PrivateKey::new(&mut rng));

        store_dummy_dkg_shares(
            &mut rng,
            &signer_private_key,
            &mut handle.storage,
            dummy_aggregate_key,
        )
        .await;

        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        Self::write_test_data(&test_data, &mut handle.storage).await;

        let bitcoin_chain_tip = handle
            .storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage failure")
            .expect("no chain tip");

        let coordinator_public_key = transaction_coordinator::coordinator_public_key(
            &bitcoin_chain_tip,
            &signer_info.first().unwrap().signer_public_keys,
        )
        .expect("failed to compute coordinator public key")
        .unwrap();

        let coordinator_private_key = signer_info
            .iter()
            .find(|signer_info| {
                PublicKey::from_private_key(&signer_info.signer_private_key)
                    == coordinator_public_key
            })
            .unwrap()
            .signer_private_key;

        let transaction_sign_request = message::BitcoinTransactionSignRequest {
            tx: testing::dummy::tx(&fake::Faker, &mut rng),
            aggregate_key: dummy_aggregate_key,
        };

        run_dkg_and_store_results_for_signers(
            &signer_info,
            &bitcoin_chain_tip,
            self.signing_threshold,
            [&mut handle.storage],
            &mut rng,
        )
        .await;

        let mut network_handle = network.connect();

        let transaction_sign_request_payload: message::Payload = transaction_sign_request.into();

        network_handle
            .broadcast(
                transaction_sign_request_payload
                    .to_message(bitcoin_chain_tip)
                    .sign_ecdsa(&coordinator_private_key)
                    .expect("failed to sign"),
            )
            .await
            .expect("broadcast failed");

        let msg = network_handle
            .receive()
            .await
            .expect("failed to receive message");

        assert!(msg.verify());

        assert!(matches!(
            msg.payload,
            message::Payload::BitcoinTransactionSignAck(_)
        ));

        handle.stop_event_loop().await;
    }

    /// Assert that a group of transaction signers together can
    /// participate successfully in a DKG round
    pub async fn assert_should_be_able_to_participate_in_dkg(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = signer_info.first().unwrap().clone();

        let mut event_loop_handles: Vec<_> = signer_info
            .clone()
            .into_iter()
            .map(|signer_info| {
                let event_loop_harness = EventLoopHarness::create(
                    network.connect(),
                    (self.storage_constructor)(),
                    self.context_window,
                    signer_info.signer_private_key,
                    self.signing_threshold,
                    rng.clone(),
                );

                event_loop_harness.start()
            })
            .collect();

        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        for handle in event_loop_handles.iter_mut() {
            Self::write_test_data(&test_data, &mut handle.storage).await;
        }

        let bitcoin_chain_tip = event_loop_handles
            .first()
            .unwrap()
            .storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage error")
            .expect("no chain tip");

        run_dkg_and_store_results_for_signers(
            &signer_info,
            &bitcoin_chain_tip,
            self.signing_threshold,
            event_loop_handles
                .iter_mut()
                .map(|handle| &mut handle.storage),
            &mut rng,
        )
        .await;

        let dummy_txid = testing::dummy::txid(&fake::Faker, &mut rng);

        let mut coordinator = testing::wsts::Coordinator::new(
            network.connect(),
            coordinator_signer_info,
            self.signing_threshold,
        );
        let aggregate_key = coordinator.run_dkg(bitcoin_chain_tip, dummy_txid).await;

        for handle in event_loop_handles.into_iter() {
            let storage = handle.stop_event_loop().await;
            assert!(storage
                .get_encrypted_dkg_shares(&aggregate_key)
                .await
                .expect("storage error")
                .is_some());
        }
    }

    /// Assert that a group of transaction signers together can
    /// participate successfully in a signing roundd
    pub async fn assert_should_be_able_to_participate_in_signing_round(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = signer_info.first().unwrap().clone();

        let mut event_loop_handles: Vec<_> = signer_info
            .clone()
            .into_iter()
            .map(|signer_info| {
                let event_loop_harness = EventLoopHarness::create(
                    network.connect(),
                    (self.storage_constructor)(),
                    self.context_window,
                    signer_info.signer_private_key,
                    self.signing_threshold,
                    rng.clone(),
                );

                event_loop_harness.start()
            })
            .collect();

        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        for handle in event_loop_handles.iter_mut() {
            Self::write_test_data(&test_data, &mut handle.storage).await;
        }

        let bitcoin_chain_tip = event_loop_handles
            .first()
            .unwrap()
            .storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage error")
            .expect("no chain tip");

        run_dkg_and_store_results_for_signers(
            &signer_info,
            &bitcoin_chain_tip,
            self.signing_threshold,
            event_loop_handles
                .iter_mut()
                .map(|handle| &mut handle.storage),
            &mut rng,
        )
        .await;

        let coordinator_public_key = transaction_coordinator::coordinator_public_key(
            &bitcoin_chain_tip,
            &signer_info.first().unwrap().signer_public_keys,
        )
        .unwrap()
        .unwrap();

        let coordinator_signer_info = signer_info
            .iter()
            .find(|signer_info| {
                PublicKey::from_private_key(&signer_info.signer_private_key)
                    == coordinator_public_key
            })
            .unwrap()
            .clone();

        let dummy_txid = testing::dummy::txid(&fake::Faker, &mut rng);

        let mut coordinator = testing::wsts::Coordinator::new(
            network.connect(),
            coordinator_signer_info,
            self.signing_threshold,
        );
        let aggregate_key = coordinator.run_dkg(bitcoin_chain_tip, dummy_txid).await;

        let tx = testing::dummy::tx(&fake::Faker, &mut rng);
        let txid = tx.compute_txid();

        let mut hasher = sha2::Sha256::new();
        hasher.update("sign here please");
        let msg: [u8; 32] = hasher.finalize().into(); // TODO(296): Compute proper sighash from transaction

        coordinator
            .request_sign_transaction(bitcoin_chain_tip, tx, aggregate_key)
            .await;

        let signature = coordinator
            .run_signing_round(bitcoin_chain_tip, txid, &msg)
            .await;

        // Let's check the signature using the secp256k1 types.
        let sig = secp256k1::schnorr::Signature::from_slice(&signature.to_bytes()).unwrap();
        let msg_digest = secp256k1::Message::from_digest(msg);
        let pk = aggregate_key.signers_tweaked_pubkey().unwrap();
        let x_only_pk = secp256k1::XOnlyPublicKey::from(&pk);
        sig.verify(&msg_digest, &x_only_pk).unwrap();

        // Let's check using the p256k1 types
        let tweaked_aggregate_key = wsts::compute::tweaked_public_key(&aggregate_key.into(), None);
        assert!(signature.verify(&tweaked_aggregate_key.x(), &msg));
    }

    async fn write_test_data(test_data: &TestData, storage: &mut S) {
        test_data.write_to(storage).await;
    }

    async fn extract_context_window_block_hashes(
        context_window: u16,
        storage: &S,
    ) -> Vec<model::BitcoinBlockHash> {
        let mut context_window_block_hashes = Vec::new();
        let mut block_hash = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .unwrap()
            .expect("found no canonical chain tip");

        for _ in 0..context_window {
            context_window_block_hashes.push(block_hash);
            let Some(block) = storage.get_bitcoin_block(&block_hash).await.unwrap() else {
                break;
            };
            block_hash = block.parent_hash;
        }

        context_window_block_hashes
    }

    async fn extract_stacks_context_window_block_hashes(
        context_window: u16,
        storage: &S,
    ) -> Vec<model::StacksBlockHash> {
        let canoncial_tip_block_hash = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage failure")
            .expect("found no canonical chain tip");

        let chain_tip = storage
            .get_bitcoin_block(&canoncial_tip_block_hash)
            .await
            .expect("storage failure")
            .expect("missing block");

        let context_window_end_block = futures::stream::iter(0..context_window)
            .fold(chain_tip.clone(), |block, _| async move {
                storage
                    .get_bitcoin_block(&block.parent_hash)
                    .await
                    .expect("storage failure")
                    .unwrap_or(block)
            })
            .await;

        let stacks_chain_tip = futures::stream::iter(chain_tip.confirms)
            .then(|stacks_block_hash| async move {
                storage
                    .get_stacks_block(&stacks_block_hash)
                    .await
                    .expect("missing block")
            })
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .max_by_key(|block| (block.block_height, block.block_hash))
            .expect("missing stacks block");

        let mut cursor = Some(stacks_chain_tip);
        let mut context_window_block_hashes = Vec::new();

        while let Some(stacks_block) = cursor {
            if context_window_end_block
                .confirms
                .contains(&stacks_block.block_hash)
            {
                break;
            }

            context_window_block_hashes.push(stacks_block.block_hash);
            cursor = storage
                .get_stacks_block(&stacks_block.parent_hash)
                .await
                .expect("storage failure");
        }

        context_window_block_hashes
    }

    async fn assert_only_deposit_requests_in_context_window_has_decisions(
        storage: &S,
        context_window: u16,
        deposit_requests: &[model::DepositRequest],
        num_expected_decisions: usize,
    ) {
        let context_window_block_hashes =
            Self::extract_context_window_block_hashes(context_window, storage).await;
        for deposit_request in deposit_requests {
            let signer_decisions = storage
                .get_deposit_signers(&deposit_request.txid, deposit_request.output_index)
                .await
                .unwrap();

            let blocks = storage
                .get_bitcoin_blocks_with_transaction(&deposit_request.txid)
                .await
                .unwrap();

            for deposit_request_block in blocks {
                if context_window_block_hashes.contains(&deposit_request_block) {
                    assert_eq!(signer_decisions.len(), num_expected_decisions);
                    assert!(signer_decisions.first().unwrap().is_accepted)
                } else {
                    assert_eq!(signer_decisions.len(), 0);
                }
            }
        }
    }

    async fn assert_only_withdraw_requests_in_context_window_has_decisions(
        storage: &S,
        context_window: u16,
        withdraw_requests: &[model::WithdrawalRequest],
        num_expected_decisions: usize,
    ) {
        let context_window_block_hashes =
            Self::extract_stacks_context_window_block_hashes(context_window, storage).await;

        for withdraw_request in withdraw_requests {
            let signer_decisions = storage
                .get_withdrawal_signers(withdraw_request.request_id, &withdraw_request.block_hash)
                .await
                .unwrap();

            if context_window_block_hashes.contains(&withdraw_request.block_hash) {
                assert_eq!(signer_decisions.len(), num_expected_decisions);
                assert!(signer_decisions.iter().all(|decision| decision.is_accepted))
            } else {
                assert!(signer_decisions.is_empty());
            }
        }
    }

    fn generate_test_data<R>(&self, rng: &mut R, signer_set: &BTreeSet<PublicKey>) -> TestData
    where
        R: rand::RngCore,
    {
        let signer_keys: Vec<_> = signer_set.iter().copied().collect();
        TestData::generate(rng, &signer_keys, &self.test_model_parameters)
    }
}

async fn store_dummy_dkg_shares<R, S>(
    rng: &mut R,
    signer_private_key: &[u8; 32],
    storage: &mut S,
    group_key: PublicKey,
) where
    R: rand::CryptoRng + rand::RngCore,
    S: storage::DbWrite,
{
    let shares =
        testing::dummy::encrypted_dkg_shares(&fake::Faker, rng, signer_private_key, group_key);
    storage
        .write_encrypted_dkg_shares(&shares)
        .await
        .expect("storage error");
}

/// This function runs a DKG round for the given signers and stores the
/// result in the provided stores for all signers.
async fn run_dkg_and_store_results_for_signers<'s: 'r, 'r, S, Rng>(
    signer_info: &[testing::wsts::SignerInfo],
    chain_tip: &model::BitcoinBlockHash,
    threshold: u32,
    stores: impl IntoIterator<Item = &'r mut S>,
    rng: &mut Rng,
) where
    S: storage::DbRead + storage::DbWrite + 's,
    Rng: rand::CryptoRng + rand::RngCore,
{
    let network = network::in_memory::Network::new();
    let mut testing_signer_set =
        testing::wsts::SignerSet::new(signer_info, threshold, || network.connect());
    let dkg_txid = testing::dummy::txid(&fake::Faker, rng);
    let bitcoin_chain_tip = *chain_tip;
    let (aggregate_key, all_dkg_shares) = testing_signer_set
        .run_dkg(bitcoin_chain_tip, dkg_txid, rng)
        .await;

    for (storage, encrypted_dkg_shares) in stores.into_iter().zip(all_dkg_shares) {
        testing_signer_set
            .write_as_rotate_keys_tx(storage, chain_tip, aggregate_key, rng)
            .await;

        storage
            .write_encrypted_dkg_shares(&encrypted_dkg_shares)
            .await
            .expect("failed to write encrypted shares");
    }
}
