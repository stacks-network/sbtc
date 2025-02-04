//! Test utilities for the transaction signer

use std::collections::BTreeSet;
use std::time::Duration;

use crate::context::Context;
use crate::context::RequestDeciderEvent;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message::Payload;
use crate::network::in_memory2::SignerNetwork;
use crate::network::in_memory2::SignerNetworkInstance;
use crate::network::in_memory2::WanNetwork;
use crate::network::MessageTransfer as _;
use crate::request_decider::RequestDeciderEventLoop;
use crate::storage;
use crate::storage::model;
use crate::storage::DbRead;
use crate::storage::DbWrite;
use crate::testing;
use crate::testing::storage::model::TestData;

use hashbrown::HashSet;
use rand::SeedableRng as _;
use tokio::sync::broadcast;
use tokio::time::error::Elapsed;

use super::context::*;

/// A test harness for the request decider event loop.
pub struct RequestDeciderEventLoopHarness<C> {
    context: C,
    event_loop: TestRequestDeciderEventLoop<C>,
}

impl<C: Context + 'static> RequestDeciderEventLoopHarness<C> {
    /// Create the test harness.
    pub fn create(
        context: C,
        network: SignerNetwork,
        context_window: u16,
        deposit_decisions_retry_window: u16,
        signer_private_key: PrivateKey,
    ) -> Self {
        Self {
            event_loop: RequestDeciderEventLoop {
                context: context.clone(),
                network: network.spawn(),
                blocklist_checker: Some(()),
                signer_private_key,
                context_window,
                deposit_decisions_retry_window,
            },
            context,
        }
    }

    /// Start the event loop.
    pub fn start(self) -> RunningEventLoopHandle<C> {
        let join_handle = tokio::spawn(async { self.event_loop.run().await });

        let signal_rx = self.context.get_signal_receiver();

        RunningEventLoopHandle {
            join_handle,
            context: self.context,
            signal_rx,
        }
    }
}

/// A running event loop.
pub struct RunningEventLoopHandle<C> {
    context: C,
    join_handle: tokio::task::JoinHandle<Result<(), Error>>,
    signal_rx: broadcast::Receiver<SignerSignal>,
}

impl<C> RunningEventLoopHandle<C>
where
    C: Context,
{
    /// Wait for `expected` instances of the given event `msg`, timing out after `timeout`.
    pub async fn wait_for_events(
        &mut self,
        msg: RequestDeciderEvent,
        expected: u16,
        timeout: Duration,
    ) -> Result<(), Elapsed> {
        let future = async {
            let mut n = 0;
            loop {
                if let Ok(SignerSignal::Event(SignerEvent::RequestDecider(event))) =
                    self.signal_rx.recv().await
                {
                    if event == msg {
                        n += 1;
                    }

                    if n == expected {
                        return;
                    }
                }
            }
        };

        tokio::time::timeout(timeout, future).await
    }

    /// Abort the event loop
    pub fn abort(&self) {
        self.join_handle.abort();
    }
}

type TestRequestDeciderEventLoop<C> = RequestDeciderEventLoop<C, SignerNetworkInstance, ()>;

/// Test environment.
pub struct TestEnvironment<C> {
    /// Function to construct a storage instance
    pub context: C,
    /// Bitcoin context window
    pub context_window: u16,
    /// Deposit decisions retry window
    pub deposit_decisions_retry_window: u16,
    /// Num signers
    pub num_signers: usize,
    /// Signing threshold
    pub signing_threshold: u32,
    /// Test model parameters
    pub test_model_parameters: testing::storage::model::Params,
}

impl<C> TestEnvironment<C>
where
    C: Context + 'static,
{
    /// Assert that the transaction signer will make and store decisions
    /// for pending deposit requests.
    pub async fn assert_should_store_decisions_for_pending_deposit_requests(self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let wan_network = WanNetwork::default();

        let ctx1 = TestContext::default_mocked();
        let signer_network = wan_network.connect(&ctx1);

        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = &signer_info.first().cloned().unwrap();

        let ctx2 = TestContext::default_mocked();
        let other_signer = wan_network.connect(&ctx2);

        let mut network_rx = other_signer.spawn();
        let mut signal_rx = self.context.get_signal_receiver();

        let event_loop_harness = RequestDeciderEventLoopHarness::create(
            self.context.clone(),
            signer_network,
            self.context_window,
            self.deposit_decisions_retry_window,
            coordinator_signer_info.signer_private_key,
        );

        let handle = event_loop_harness.start();

        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        Self::write_test_data(&handle.context.get_storage_mut(), &test_data).await;

        let group_key = PublicKey::combine_keys(signer_set).unwrap();
        store_dummy_dkg_shares(
            &mut rng,
            &coordinator_signer_info.signer_private_key.to_bytes(),
            &handle.context.get_storage_mut(),
            group_key,
            signer_set.clone(),
        )
        .await;

        handle
            .context
            .signal(SignerSignal::Event(SignerEvent::BitcoinBlockObserved))
            .expect("failed to send signal");

        tokio::time::timeout(Duration::from_secs(10), async move {
            while !matches!(
                signal_rx.recv().await,
                Ok(SignerSignal::Event(SignerEvent::RequestDecider(
                    RequestDeciderEvent::PendingDepositRequestRegistered
                )))
            ) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timeout");

        // TODO: Figure out the race condition in the `should_store_decisions_for_pending_deposit_requests`
        // integration test.
        tokio::time::sleep(Duration::from_millis(250)).await;

        Self::assert_only_deposit_requests_in_context_window_has_decisions(
            &handle.context.get_storage(),
            self.context_window,
            &test_data.deposit_requests,
            1,
        )
        .await;

        tokio::time::timeout(Duration::from_secs(1), async move {
            while let Ok(msg) = network_rx.receive().await {
                if matches!(msg.payload, Payload::SignerDepositDecision(_)) {
                    break;
                }
            }
        })
        .await
        .expect("signer deposit decision was not broadcasted");
    }

    /// Assert that the transaction signer will make and store decisions
    /// for pending withdraw requests.
    pub async fn assert_should_store_decisions_for_pending_withdrawal_requests(self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let wan_network = WanNetwork::default();

        let ctx1 = TestContext::default_mocked();
        let signer_network = wan_network.connect(&ctx1);

        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = &signer_info.first().cloned().unwrap();

        let ctx2 = TestContext::default_mocked();
        let other_signer = wan_network.connect(&ctx2);

        let mut network_rx = other_signer.spawn();
        let mut signal_rx = self.context.get_signal_receiver();

        let event_loop_harness = RequestDeciderEventLoopHarness::create(
            self.context.clone(),
            signer_network,
            self.context_window,
            self.deposit_decisions_retry_window,
            coordinator_signer_info.signer_private_key,
        );

        let handle = event_loop_harness.start();

        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        Self::write_test_data(&handle.context.get_storage_mut(), &test_data).await;

        handle
            .context
            .signal(SignerSignal::Event(SignerEvent::BitcoinBlockObserved))
            .expect("failed to send signal");

        // let msg = TxSignerEvent::PendingWithdrawalRequestRegistered;
        // handle.wait_for_events(msg, 1, Duration::from_secs(10))
        //     .await
        //     .expect("timed out waiting for events");

        // TODO: For some reason this works but the above commented-out doesn't.
        // Probably to due with when the channel is subscribed. But that's weird
        // because the handle has its own copy of the receiver just for this.
        // Investigate.
        tokio::time::timeout(Duration::from_secs(10), async move {
            while !matches!(
                signal_rx.recv().await,
                Ok(SignerSignal::Event(SignerEvent::RequestDecider(
                    RequestDeciderEvent::PendingWithdrawalRequestRegistered
                )))
            ) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timeout");

        self.assert_only_withdraw_requests_in_context_window_has_decisions(
            self.context_window,
            &test_data.withdraw_requests,
            1,
        )
        .await;

        tokio::time::timeout(Duration::from_secs(1), async move {
            while let Ok(msg) = network_rx.receive().await {
                if matches!(msg.payload, Payload::SignerWithdrawalDecision(_)) {
                    break;
                }
            }
        })
        .await
        .expect("signer withdrawal decision was not broadcasted");
    }

    /// Assert that the transaction signer will make and store decisions
    /// received from other signers.
    pub async fn assert_should_store_decisions_received_from_other_signers(self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = WanNetwork::default();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers);
        let coordinator_signer_info = signer_info.first().cloned().unwrap();

        // Create a new event-loop for each signer, based on the number of signers
        // defined in `self.num_signers`. Note that it is important that each
        // signer has its own context (and thus storage and signalling channel).
        //
        // Each signer also gets its own `MpscBroadcaster` instance, which is
        // backed by the `network` instance, simulating a network connection.
        let mut event_loop_handles: Vec<_> = signer_info
            .into_iter()
            .map(|signer_info| {
                let ctx = TestContext::default_mocked();
                let net = network.connect(&ctx);
                let event_loop_harness = RequestDeciderEventLoopHarness::create(
                    ctx,
                    net,
                    self.context_window,
                    self.deposit_decisions_retry_window,
                    signer_info.signer_private_key,
                );

                event_loop_harness.start()
            })
            .collect();

        // Generate test data and write it to each signer's storage.
        let signer_set = &coordinator_signer_info.signer_public_keys;
        let test_data = self.generate_test_data(&mut rng, signer_set);
        for handle in event_loop_handles.iter_mut() {
            test_data.write_to(&handle.context.get_storage_mut()).await;

            let group_key = PublicKey::combine_keys(signer_set).unwrap();
            store_dummy_dkg_shares(
                &mut rng,
                &handle.context.config().signer.private_key.to_bytes(),
                &handle.context.get_storage_mut(),
                group_key,
                signer_set.clone(),
            )
            .await;
        }

        // For each signer, send a signal to simulate the observation of a new block.
        for handle in event_loop_handles.iter() {
            handle
                .context
                .signal(SignerSignal::Event(SignerEvent::BitcoinBlockObserved))
                .expect("failed to send signal");
        }

        let num_expected_decisions = (self.num_signers - 1) as u16
            * self.context_window
            * self.test_model_parameters.num_deposit_requests_per_block as u16;

        // Wait for the expected number of decisions to be received by each signer.
        for handle in event_loop_handles.iter_mut() {
            let msg = RequestDeciderEvent::ReceivedDepositDecision;
            handle
                .wait_for_events(msg, num_expected_decisions, Duration::from_secs(13))
                .await
                .expect("timed out waiting for events");
        }
        // Abort the event loops and assert that the decisions have been stored.
        for handle in event_loop_handles {
            Self::assert_only_deposit_requests_in_context_window_has_decisions(
                &handle.context.get_storage(),
                self.context_window,
                &test_data.deposit_requests,
                self.num_signers,
            )
            .await;
        }
    }

    async fn write_test_data<S>(storage: &S, test_data: &TestData)
    where
        S: DbWrite,
    {
        test_data.write_to(storage).await;
    }

    async fn extract_context_window_block_hashes<S>(
        storage: &S,
        context_window: u16,
    ) -> Vec<model::BitcoinBlockHash>
    where
        S: DbRead,
    {
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
        &self,
        context_window: u16,
    ) -> Vec<model::StacksBlockHash> {
        let storage = self.context.get_storage();

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

        let storage = self.context.get_storage();
        let mut context_window_end_block = chain_tip.clone();
        let mut context_window_bitcoin_blocks = HashSet::new();
        for _ in 0..context_window {
            context_window_bitcoin_blocks.insert(context_window_end_block.block_hash);
            context_window_end_block = storage
                .get_bitcoin_block(&context_window_end_block.parent_hash)
                .await
                .expect("storage failure")
                .unwrap_or(context_window_end_block);
        }

        let stacks_chain_tip = storage
            .get_stacks_chain_tip(&canoncial_tip_block_hash)
            .await
            .expect("storage failure")
            .expect("missing block");

        let mut cursor = Some(stacks_chain_tip);
        let mut context_window_block_hashes = Vec::new();

        while let Some(stacks_block) = cursor {
            if !context_window_bitcoin_blocks.contains(&stacks_block.bitcoin_anchor) {
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

    async fn assert_only_deposit_requests_in_context_window_has_decisions<S>(
        storage: &S,
        context_window: u16,
        deposit_requests: &[model::DepositRequest],
        num_expected_decisions: usize,
    ) where
        S: DbRead,
    {
        let context_window_block_hashes =
            Self::extract_context_window_block_hashes(storage, context_window).await;

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
                    assert!(signer_decisions.first().unwrap().can_accept)
                } else {
                    assert_eq!(signer_decisions.len(), 0);
                }
            }
        }
    }

    async fn assert_only_withdraw_requests_in_context_window_has_decisions(
        &self,
        context_window: u16,
        withdraw_requests: &[model::WithdrawalRequest],
        num_expected_decisions: usize,
    ) {
        let storage = self.context.get_storage();

        let context_window_block_hashes = self
            .extract_stacks_context_window_block_hashes(context_window)
            .await;

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
    storage: &S,
    group_key: PublicKey,
    signer_set: BTreeSet<PublicKey>,
) where
    R: rand::CryptoRng + rand::RngCore,
    S: storage::DbWrite,
{
    let mut shares =
        testing::dummy::encrypted_dkg_shares(&fake::Faker, rng, signer_private_key, group_key);
    shares.signer_set_public_keys = signer_set.into_iter().collect();

    storage
        .write_encrypted_dkg_shares(&shares)
        .await
        .expect("storage error");
}
