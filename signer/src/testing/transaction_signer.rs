//! Test utilities for the transaction signer

use crate::blocklist_client;
use crate::error;
use crate::message;
use crate::network;
use crate::storage;
use crate::storage::model;
use crate::testing;
use crate::transaction_signer;

use crate::ecdsa::SignEcdsa as _;
use crate::network::MessageTransfer as _;

use bitcoin::hashes::Hash as _;
use futures::StreamExt as _;
use rand::SeedableRng as _;

/// Event loop harness
pub struct EventLoopHarness<S> {
    event_loop: EventLoop<S>,
    notification_tx: tokio::sync::watch::Sender<()>,
    storage: S,
}

impl<S> EventLoopHarness<S>
where
    S: storage::DbRead + storage::DbWrite + Clone + Send + 'static,
    error::Error: From<<S as storage::DbRead>::Error>,
    error::Error: From<<S as storage::DbWrite>::Error>,
{
    /// Create
    pub fn create<Rng: rand::RngCore + rand::CryptoRng>(
        rng: &mut Rng,
        network: network::in_memory::MpmcBroadcaster,
        storage: S,
        context_window: usize,
    ) -> Self {
        let blocklist_checker = ();
        let (notification_tx, block_observer_notifications) = tokio::sync::watch::channel(());
        let signer_private_key = p256k1::scalar::Scalar::random(rng);

        Self {
            event_loop: transaction_signer::TxSignerEventLoop {
                storage: storage.clone(),
                network,
                blocklist_checker,
                block_observer_notifications,
                signer_private_key,
                context_window,
            },
            notification_tx,
            storage,
        }
    }

    /// Start
    pub fn start(self) -> RunningEventLoopHandle<S> {
        let notification_tx = self.notification_tx;
        let join_handle = tokio::spawn(async { self.event_loop.run().await });
        let storage = self.storage;

        RunningEventLoopHandle {
            join_handle,
            notification_tx,
            storage,
        }
    }
}

/// Running event loop handle
pub struct RunningEventLoopHandle<S> {
    join_handle: tokio::task::JoinHandle<Result<(), error::Error>>,
    notification_tx: tokio::sync::watch::Sender<()>,
    storage: S,
}

impl<S> RunningEventLoopHandle<S> {
    /// Stop event loop
    pub async fn stop_event_loop(self) -> S {
        // While this explicit drop isn't strictly necessary, it serves to clarify our intention.
        drop(self.notification_tx);

        self.join_handle
            .await
            .expect("joining event loop failed")
            .expect("event loop returned error");

        self.storage
    }
}

type EventLoop<S> =
    transaction_signer::TxSignerEventLoop<network::in_memory::MpmcBroadcaster, S, ()>;

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
    pub context_window: usize,
    /// Num signers
    pub num_signers: usize,
}

impl<C, S> TestEnvironment<C>
where
    C: FnMut() -> S,
    S: storage::DbRead + storage::DbWrite + Clone + Send + 'static,
    error::Error: From<<S as storage::DbRead>::Error>,
    error::Error: From<<S as storage::DbWrite>::Error>,
{
    /// Assert that the transaction signer will make and store decisions
    /// for pending deposit requests.
    pub async fn assert_should_store_decisions_for_pending_deposit_requests(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();

        let event_loop_harness = EventLoopHarness::create(
            &mut rng,
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
        );

        let mut handle = event_loop_harness.start();

        let test_data = generate_test_data(&mut rng);
        Self::write_test_data(&test_data, &mut handle.storage).await;

        handle
            .notification_tx
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

        let event_loop_harness = EventLoopHarness::create(
            &mut rng,
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
        );

        let mut handle = event_loop_harness.start();

        let test_data = generate_test_data(&mut rng);
        Self::write_test_data(&test_data, &mut handle.storage).await;

        handle
            .notification_tx
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

        let mut event_loop_handles: Vec<_> = (0..self.num_signers)
            .map(|_| {
                let event_loop_harness = EventLoopHarness::create(
                    &mut rng,
                    network.connect(),
                    (self.storage_constructor)(),
                    self.context_window,
                );

                event_loop_harness.start()
            })
            .collect();

        let test_data = generate_test_data(&mut rng);
        for handle in event_loop_handles.iter_mut() {
            Self::write_test_data(&test_data, &mut handle.storage).await;
        }

        for handle in event_loop_handles.iter() {
            handle
                .notification_tx
                .send(())
                .expect("failed to send notification");
        }

        // TODO(258): Ensure we can wait for the signers to finish processing messages
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

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
    /// with an acknowledge message
    pub async fn assert_should_respond_to_bitcoin_transaction_sign_requests(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::in_memory::Network::new();

        let event_loop_harness = EventLoopHarness::create(
            &mut rng,
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
        );

        let mut handle = event_loop_harness.start();

        let test_data = generate_test_data(&mut rng);
        Self::write_test_data(&test_data, &mut handle.storage).await;

        let coordinator_private_key = p256k1::scalar::Scalar::random(&mut rng);

        let transaction_sign_request_payload: message::Payload =
            message::BitcoinTransactionSignRequest {
                tx: testing::dummy::tx(&fake::Faker, &mut rng),
            }
            .into();

        let chain_tip = handle
            .storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage failure")
            .expect("no chain tip");

        let mut network_handle = network.connect();

        network_handle
            .broadcast(
                transaction_sign_request_payload
                    .to_message(
                        bitcoin::BlockHash::from_slice(&chain_tip)
                            .expect("failed to convert to block hash"),
                    )
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

    async fn write_test_data(test_data: &testing::storage::model::TestData, storage: &mut S) {
        test_data.write_to(storage).await;
    }

    async fn extract_context_window_block_hashes(
        context_window: usize,
        storage: &S,
    ) -> Vec<model::BitcoinBlockHash> {
        let mut context_window_block_hashes = Vec::new();
        let mut block_hash = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .unwrap()
            .expect("found no canonical chain tip");

        for _ in 0..context_window {
            context_window_block_hashes.push(block_hash.clone());
            let Some(block) = storage.get_bitcoin_block(&block_hash).await.unwrap() else {
                break;
            };
            block_hash = block.parent_hash;
        }

        context_window_block_hashes
    }

    async fn extract_stacks_context_window_block_hashes(
        context_window: usize,
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
            .max_by_key(|block| (block.block_height, block.block_hash.clone()))
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
        context_window: usize,
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
        context_window: usize,
        withdraw_requests: &[model::WithdrawRequest],
        num_expected_decisions: usize,
    ) {
        let context_window_block_hashes =
            Self::extract_stacks_context_window_block_hashes(context_window, storage).await;

        for withdraw_request in withdraw_requests {
            let signer_decisions = storage
                .get_withdraw_signers(withdraw_request.request_id, &withdraw_request.block_hash)
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
}

fn generate_test_data(rng: &mut impl rand::RngCore) -> testing::storage::model::TestData {
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 5,
        num_withdraw_requests_per_block: 5,
    };

    testing::storage::model::TestData::generate(rng, &test_model_params)
}
