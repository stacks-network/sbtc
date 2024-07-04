//! Test utilities for the transaction signer

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;

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

use wsts::state_machine::coordinator;
use wsts::state_machine::coordinator::frost;
use wsts::state_machine::coordinator::Coordinator as _;
use wsts::state_machine::StateMachine as _;

struct EventLoopHarness<S> {
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
    fn create(
        network: network::in_memory::MpmcBroadcaster,
        storage: S,
        context_window: usize,
        signer_info: SignerInfo,
    ) -> Self {
        let blocklist_checker = ();
        let (notification_tx, block_observer_notifications) = tokio::sync::watch::channel(());

        Self {
            event_loop: transaction_signer::TxSignerEventLoop {
                storage: storage.clone(),
                network,
                blocklist_checker,
                block_observer_notifications,
                signer_private_key: signer_info.signer_private_key,
                signer_public_keys: signer_info.signer_public_keys,
                context_window,
                wsts_state_machines: HashMap::new(),
            },
            notification_tx,
            storage,
        }
    }

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

struct RunningEventLoopHandle<S> {
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
        let signer_info = generate_signer_info(&mut rng, self.num_signers);

        let event_loop_harness = EventLoopHarness::create(
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
            signer_info.first().cloned().unwrap(),
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
        let signer_info = generate_signer_info(&mut rng, self.num_signers);

        let event_loop_harness = EventLoopHarness::create(
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
            signer_info.first().cloned().unwrap(),
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
        let signer_info = generate_signer_info(&mut rng, self.num_signers);

        let mut event_loop_handles: Vec<_> = signer_info
            .into_iter()
            .map(|signer_info| {
                let event_loop_harness = EventLoopHarness::create(
                    network.connect(),
                    (self.storage_constructor)(),
                    self.context_window,
                    signer_info,
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
        let signer_info = generate_signer_info(&mut rng, self.num_signers);

        let event_loop_harness = EventLoopHarness::create(
            network.connect(),
            (self.storage_constructor)(),
            self.context_window,
            signer_info.first().cloned().unwrap(),
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

fn generate_signer_info<Rng: rand::RngCore + rand::CryptoRng>(
    rng: &mut Rng,
    num_signers: usize,
) -> Vec<SignerInfo> {
    let signer_keys: BTreeMap<_, _> = (0..num_signers)
        .map(|_| {
            let private = p256k1::scalar::Scalar::random(rng);
            let public =
                p256k1::ecdsa::PublicKey::new(&private).expect("failed to generate public key");

            (public, private)
        })
        .collect();

    let signer_public_keys: BTreeSet<_> = signer_keys.keys().cloned().collect();

    signer_keys
        .into_iter()
        .map(|(_, signer_private_key)| SignerInfo {
            signer_private_key,
            signer_public_keys: signer_public_keys.clone(),
        })
        .collect()
}

#[derive(Debug, Clone)]
struct SignerInfo {
    signer_private_key: p256k1::scalar::Scalar,
    signer_public_keys: BTreeSet<p256k1::ecdsa::PublicKey>,
}

struct Coordinator {
    network: network::in_memory::MpmcBroadcaster,
    wsts_coordinator: frost::Coordinator<wsts::v2::Aggregator>,
    private_key: p256k1::scalar::Scalar,
}

impl Coordinator {
    fn new(network: network::in_memory::MpmcBroadcaster, signer_info: SignerInfo) -> Self {
        let num_signers = signer_info.signer_public_keys.len().try_into().unwrap();
        let message_private_key = signer_info.signer_private_key;
        let private_key = message_private_key.clone();
        let signer_public_keys: hashbrown::HashMap<u32, _> = signer_info
            .signer_public_keys
            .into_iter()
            .enumerate()
            .map(|(idx, key)| {
                (
                    idx.try_into().unwrap(),
                    (&p256k1::point::Compressed::from(key.to_bytes()))
                        .try_into()
                        .expect("failed to convert public key"),
                )
            })
            .collect();
        let num_keys = num_signers;
        let threshold = num_keys / 3 * 2; // TODO: Configure
        let dkg_threshold = num_keys;
        let signer_key_ids = (0..num_signers)
            .map(|signer_id| (signer_id, std::iter::once(signer_id).collect()))
            .collect();
        let config = wsts::state_machine::coordinator::Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold,
            message_private_key,
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            signer_key_ids,
            signer_public_keys,
        };

        let wsts_coordinator = frost::Coordinator::new(config);

        Self {
            network,
            wsts_coordinator,
            private_key,
        }
    }

    async fn run_dkg(&mut self, bitcoin_chain_tip: bitcoin::BlockHash, txid: &bitcoin::Txid) {
        self.wsts_coordinator
            .move_to(coordinator::State::DkgPublicDistribute)
            .expect("failed to move state machine");

        let outbound = self
            .wsts_coordinator
            .start_public_shares()
            .expect("failed to start public shares");

        self.send_packet(bitcoin_chain_tip.clone(), txid.clone(), outbound)
            .await;

        loop {
            let msg = self.network.receive().await.expect("network error");

            let message::Payload::WstsMessage(wsts_msg) = msg.inner.payload else {
                continue;
            };

            let packet = wsts::net::Packet {
                msg: wsts_msg.inner,
                sig: Vec::new(),
            };

            let (outbound_packet, _) = self
                .wsts_coordinator
                .process_message(&packet)
                .expect("message processing failed");

            if let Some(packet) = outbound_packet {
                self.send_packet(bitcoin_chain_tip.clone(), txid.clone(), packet)
                    .await;
                assert!(matches!(
                    self.wsts_coordinator.state,
                    coordinator::State::DkgPrivateGather
                ));
                break;
            }
        }

        todo!();
    }

    async fn send_packet(
        &mut self,
        bitcoin_chain_tip: bitcoin::BlockHash,
        txid: bitcoin::Txid,
        packet: wsts::net::Packet,
    ) {
        let payload: message::Payload = message::WstsMessage { txid, inner: packet.msg }.into();

        let dkg_begin_msg = payload
            .to_message(bitcoin_chain_tip)
            .sign_ecdsa(&self.private_key)
            .expect("failed to sign message");

        self.network
            .broadcast(dkg_begin_msg)
            .await
            .expect("failed to broadcast dkg begin msg");
    }
}
