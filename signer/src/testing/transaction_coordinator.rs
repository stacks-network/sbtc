//! Test utilities for the transaction coordinator

use std::cell::RefCell;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::bitcoin::utxo::SignerUtxo;
use crate::bitcoin::MockBitcoinInteract;
use crate::context::Context;
use crate::context::RequestDeciderEvent;
use crate::emily_client::MockEmilyInteract;
use crate::error;
use crate::keys;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SignerScriptPubKey;
use crate::network;
use crate::network::in_memory2::SignerNetwork;
use crate::stacks::api::AccountInfo;
use crate::stacks::api::MockStacksInteract;
use crate::stacks::api::SubmitTxResponse;
use crate::stacks::contracts::AcceptWithdrawalV1;
use crate::stacks::contracts::AsContractCall;
use crate::stacks::contracts::ContractCall;
use crate::stacks::contracts::RotateKeysV1;
use crate::stacks::contracts::StacksTx;
use crate::storage::model;
use crate::storage::model::StacksTxId;
use crate::storage::model::ToLittleEndianOrder as _;
use crate::storage::model::WithdrawalAcceptEvent;
use crate::storage::DbRead;
use crate::storage::DbWrite;
use crate::testing;
use crate::testing::storage::model::TestData;
use crate::testing::wsts::SignerSet;
use crate::transaction_coordinator;
use crate::transaction_coordinator::coordinator_public_key;
use crate::transaction_coordinator::TxCoordinatorEventLoop;

use bitvec::field::BitField;
use blockstack_lib::chainstate::stacks::TransactionContractCall;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::net::api::getcontractsrc::ContractSrcResponse;
use clarity::vm::types::BuffData;
use clarity::vm::types::SequenceData;
use clarity::vm::Value;
use fake::Fake as _;
use fake::Faker;
use rand::SeedableRng as _;

use super::context::TestContext;
use super::context::WrappedMock;
use super::wallet::WALLET;

const EMPTY_BITCOIN_TX: bitcoin::Transaction = bitcoin::Transaction {
    version: bitcoin::transaction::Version::ONE,
    lock_time: bitcoin::absolute::LockTime::ZERO,
    input: vec![],
    output: vec![],
};

/// Method which gets the coordinator private key based on the given list
/// of `SignerInfo`.
pub fn select_coordinator(
    bitcoin_chain_tip: &model::BitcoinBlockHash,
    signer_info: &[testing::wsts::SignerInfo],
) -> keys::PrivateKey {
    // Ensure signer_info is not empty and grab the first one.
    let first_signer_info = signer_info.first().expect("signer_info cannot be empty");

    // Get the signer set public keys from the signer info. All of the provided
    // signer info's should have the same set of public keys.
    let signer_public_keys = &first_signer_info.signer_public_keys;

    // Determine the coordinator's public key.
    let coordinator_pub_key = coordinator_public_key(bitcoin_chain_tip, signer_public_keys)
        .expect("couldn't determine coordinator");

    // Find the coordinator's private key from the signer info based on the
    // public key we just determined.
    signer_info
        .iter()
        .find(|info| PublicKey::from_private_key(&info.signer_private_key) == coordinator_pub_key)
        .expect("couldn't find coordinator from public key")
        .signer_private_key
}

struct TxCoordinatorEventLoopHarness<C> {
    event_loop: EventLoop<C>,
    context: C,
    is_started: Arc<AtomicBool>,
}

impl<C> TxCoordinatorEventLoopHarness<C>
where
    C: Context + 'static,
{
    fn create(
        context: C,
        network: network::in_memory::MpmcBroadcaster,
        context_window: u16,
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
                signing_round_max_duration: Duration::from_secs(10),
                bitcoin_presign_request_max_duration: Duration::from_secs(10),
                dkg_max_duration: Duration::from_secs(10),
                is_epoch3: true,
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
    pub context_window: u16,
    /// Num signers
    pub num_signers: u16,
    /// Signing threshold
    pub signing_threshold: u16,
    /// Test model parameters
    pub test_model_parameters: testing::storage::model::Params,
}

impl<Storage>
    TestEnvironment<
        TestContext<
            Storage,
            WrappedMock<MockBitcoinInteract>, // We specify this explicitly to gain access to the mock client
            WrappedMock<MockStacksInteract>, // We specify this explicitly to gain access to the mock client
            WrappedMock<MockEmilyInteract>, // We specify this explicitly to gain access to the mock client
        >,
    >
where
    Storage: DbRead + DbWrite + Clone + Sync + Send + 'static,
{
    /// Asserts that TxCoordinatorEventLoop::get_pending_requests processes withdrawals
    pub async fn assert_processes_withdrawals(mut self) {
        // Setup network and signer info
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::InMemoryNetwork::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers as usize);
        let mut testing_signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });
        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut rng, &mut testing_signer_set)
            .await;
        let original_test_data = test_data.clone();

        // Add signer utxo to storage
        let tx_1 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_337_000_000_000),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        test_data.push_bitcoin_txs(
            &bitcoin_chain_tip,
            vec![(model::TransactionType::SbtcTransaction, tx_1.clone())],
        );
        test_data.remove(original_test_data);
        self.write_test_data(&test_data).await;

        // Add estimate_fee_rate
        self.context
            .with_bitcoin_client(|client| {
                client
                    .expect_estimate_fee_rate()
                    .times(1)
                    .returning(|| Box::pin(async { Ok(1.3) }));
            })
            .await;

        // Create the coordinator
        self.context.state().set_sbtc_contracts_deployed();
        let signer_network = SignerNetwork::single(&self.context);
        let coordinator = TxCoordinatorEventLoop {
            context: self.context,
            network: signer_network.spawn(),
            private_key: select_coordinator(&bitcoin_chain_tip.block_hash, &signer_info),
            threshold: self.signing_threshold,
            context_window: self.context_window,
            signing_round_max_duration: Duration::from_millis(500),
            bitcoin_presign_request_max_duration: Duration::from_millis(500),
            dkg_max_duration: Duration::from_millis(500),
            is_epoch3: true,
        };

        // Get pending withdrawals from coordinator
        let pending_requests = coordinator
            .get_pending_requests(
                &bitcoin_chain_tip.block_hash,
                &aggregate_key,
                &signer_info
                    .last()
                    .expect("Empty signer set!")
                    .signer_public_keys,
            )
            .await
            .expect("Error getting pending requests")
            .expect("Empty pending requests");
        let withdrawals = pending_requests.withdrawals;

        // Get pending withdrawals from storage
        let withdrawals_in_storage = coordinator
            .context
            .get_storage()
            .get_pending_accepted_withdrawal_requests(
                &bitcoin_chain_tip.block_hash,
                self.context_window,
                self.signing_threshold,
            )
            .await
            .expect("Error extracting withdrawals from db");

        // Assert that there are some withdrawals in storage while get_pending_requests return 0 withdrawals
        assert!(!withdrawals_in_storage.is_empty());
        for withdrawal in withdrawals_in_storage {
            assert!(withdrawals
                .iter()
                .any(|w| w.request_id == withdrawal.request_id && w.txid == withdrawal.txid));
        }
    }

    /// Assert that a coordinator should be able to coordiante a signing round
    pub async fn assert_should_be_able_to_coordinate_signing_rounds(
        mut self,
        delay_to_process_new_blocks: Duration,
    ) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::InMemoryNetwork::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers as usize);

        let mut testing_signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut rng, &mut testing_signer_set)
            .await;

        let original_test_data = test_data.clone();

        let tx_1 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_337_000_000_000),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        test_data.push_bitcoin_txs(
            &bitcoin_chain_tip,
            vec![(model::TransactionType::SbtcTransaction, tx_1.clone())],
        );

        test_data.remove(original_test_data);
        self.write_test_data(&test_data).await;

        self.context
            .with_bitcoin_client(|client| {
                client
                    .expect_estimate_fee_rate()
                    .times(1)
                    .returning(|| Box::pin(async { Ok(1.3) }));
            })
            .await;

        self.context
            .with_emily_client(|client| {
                client
                    .expect_accept_deposits()
                    .times(1..)
                    .returning(|_, _| {
                        Box::pin(async {
                            Ok(emily_client::models::UpdateDepositsResponse { deposits: vec![] })
                        })
                    });
            })
            .await;

        self.context
            .with_stacks_client(|client| {
                client
                    .expect_get_current_signers_aggregate_key()
                    .returning(move |_| Box::pin(std::future::ready(Ok(Some(aggregate_key)))));
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
        self.context
            .with_bitcoin_client(|client| {
                client
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
            })
            .await;

        // Get the private key of the coordinator of the signer set.
        let private_key = select_coordinator(&bitcoin_chain_tip.block_hash, &signer_info);

        // Bootstrap the tx coordinator within an event loop harness.
        self.context.state().set_sbtc_contracts_deployed();
        let event_loop_harness = TxCoordinatorEventLoopHarness::create(
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

        // Signal `RequestDeciderEvent::NewRequestsHandled` to trigger the coordinator.
        handle
            .context
            .signal(RequestDeciderEvent::NewRequestsHandled.into())
            .expect("failed to signal");

        // Await the `wait_for_tx_task` to receive the first transaction broadcasted.
        let broadcasted_tx = tokio::time::timeout(
            delay_to_process_new_blocks + Duration::from_secs(10),
            wait_for_transaction_task,
        )
        .await
        .unwrap()
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

    /// Assert that a coordinator should be able to skip the deployment the sbtc contracts
    /// if they are already deployed.
    pub async fn assert_skips_deploy_sbtc_contracts(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::InMemoryNetwork::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers as usize);

        let mut testing_signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut rng, &mut testing_signer_set)
            .await;

        let original_test_data = test_data.clone();

        let tx_1 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_337_000_000_000),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        test_data.push_bitcoin_txs(
            &bitcoin_chain_tip,
            vec![(model::TransactionType::SbtcTransaction, tx_1.clone())],
        );

        test_data.remove(original_test_data);
        self.write_test_data(&test_data).await;

        self.context
            .with_bitcoin_client(|client| {
                client
                    .expect_estimate_fee_rate()
                    .times(1)
                    .returning(|| Box::pin(async { Ok(1.3) }));
            })
            .await;

        self.context
            .with_emily_client(|client| {
                client
                    .expect_accept_deposits()
                    .times(1..)
                    .returning(|_, _| {
                        Box::pin(async {
                            Ok(emily_client::models::UpdateDepositsResponse { deposits: vec![] })
                        })
                    });
            })
            .await;

        self.context
            .with_stacks_client(|client| {
                client
                    .expect_get_current_signers_aggregate_key()
                    .returning(move |_| Box::pin(std::future::ready(Ok(Some(aggregate_key)))));
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
        self.context
            .with_bitcoin_client(|client| {
                client
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
            })
            .await;

        self.context
            .with_stacks_client(|client| {
                // Each call to get the contract source will return a ContractSrcResponse
                // meaning the contract is already deployed.
                client
                    .expect_get_contract_source()
                    .times(5)
                    .returning(|_, _| {
                        Box::pin(async {
                            Ok(ContractSrcResponse {
                                source: "".to_string(),
                                publish_height: 1,
                                marf_proof: None,
                            })
                        })
                    });

                client
                    .expect_estimate_fees()
                    .times(5)
                    .returning(|_, _, _| Box::pin(async { Ok(123000) }));

                client.expect_get_account().times(5).returning(|_| {
                    Box::pin(async {
                        Ok(AccountInfo {
                            balance: 1_000_000,
                            locked: 0,
                            unlock_height: 0,
                            nonce: 1,
                        })
                    })
                });
                client.expect_submit_tx().times(5).returning(|_| {
                    Box::pin(async {
                        Ok(SubmitTxResponse::Acceptance(*Faker.fake::<StacksTxId>()))
                    })
                });
            })
            .await;

        // Get the private key of the coordinator of the signer set.
        let private_key = select_coordinator(&bitcoin_chain_tip.block_hash, &signer_info);

        // Bootstrap the tx coordinator within an event loop harness.
        // We don't `set_sbtc_contracts_deployed` to force the coordinator to deploy the contracts
        let event_loop_harness = TxCoordinatorEventLoopHarness::create(
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

        // Signal `TxSignerEvent::NewRequestsHandled` to trigger the coordinator.
        handle
            .context
            .signal(RequestDeciderEvent::NewRequestsHandled.into())
            .expect("failed to signal");

        // Await the `wait_for_tx_task` to receive the first transaction broadcasted.
        let broadcasted_tx =
            tokio::time::timeout(Duration::from_secs(10), wait_for_transaction_task)
                .await
                .unwrap()
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

    /// Assert we get a withdrawal accept tx
    pub async fn assert_construct_withdrawal_accept_stacks_sign_request(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);

        // Add estimate_fee_rate
        self.context
            .with_stacks_client(|client| {
                client
                    .expect_estimate_fees()
                    .times(1)
                    .returning(|_, _, _| Box::pin(async { Ok(123000) }));
            })
            .await;

        let signer_network = SignerNetwork::single(&self.context);
        let private_key = PrivateKey::new(&mut rng);
        let bitcoin_aggregate_key = PublicKey::from_private_key(&private_key);
        let coordinator = TxCoordinatorEventLoop {
            context: self.context,
            network: signer_network.spawn(),
            private_key,
            threshold: self.signing_threshold,
            context_window: self.context_window,
            signing_round_max_duration: Duration::from_millis(500),
            bitcoin_presign_request_max_duration: Duration::from_millis(500),
            dkg_max_duration: Duration::from_millis(500),
            is_epoch3: true,
        };
        let withdrawal_accept: WithdrawalAcceptEvent = fake::Faker.fake_with_rng(&mut rng);
        let (sign_request, multi_tx) = coordinator
            .construct_withdrawal_accept_stacks_sign_request(
                withdrawal_accept.clone(),
                &bitcoin_aggregate_key,
                &WALLET.0,
            )
            .await
            .expect("Failed to construct withdrawal accept stacks sign request");

        assert_eq!(sign_request.tx_fee, 123000);
        assert_eq!(sign_request.aggregate_key, bitcoin_aggregate_key);
        assert_eq!(sign_request.txid, multi_tx.tx().txid());
        assert_eq!(sign_request.nonce, multi_tx.tx().get_origin_nonce());
        if let StacksTx::ContractCall(ContractCall::AcceptWithdrawalV1(call)) =
            sign_request.contract_tx
        {
            assert_eq!(call.tx_fee, withdrawal_accept.fee);
            assert_eq!(call.request_id, withdrawal_accept.request_id);
            assert_eq!(call.outpoint, withdrawal_accept.outpoint);
            assert_eq!(call.signer_bitmap, withdrawal_accept.signer_bitmap);
            assert_eq!(call.sweep_block_hash, withdrawal_accept.sweep_block_hash);
            assert_eq!(
                call.sweep_block_height,
                withdrawal_accept.sweep_block_height
            );
        } else {
            panic!("Expected ContractCall::AcceptWithdrawalV1");
        }

        if let TransactionPayload::ContractCall(TransactionContractCall {
            address,
            contract_name,
            function_name,
            function_args,
        }) = &multi_tx.tx().payload
        {
            assert_eq!(*address, *WALLET.0.address());
            assert_eq!(contract_name.to_string(), AcceptWithdrawalV1::CONTRACT_NAME);
            assert_eq!(function_name.to_string(), AcceptWithdrawalV1::FUNCTION_NAME);
            assert_eq!(
                *function_args,
                vec![
                    Value::UInt(withdrawal_accept.request_id as u128),
                    Value::Sequence(SequenceData::Buffer(BuffData {
                        data: withdrawal_accept.outpoint.txid.to_le_bytes().to_vec()
                    })),
                    Value::UInt(withdrawal_accept.signer_bitmap.load_le()),
                    Value::UInt(withdrawal_accept.outpoint.vout as u128),
                    Value::UInt(withdrawal_accept.fee as u128),
                    Value::Sequence(SequenceData::Buffer(BuffData {
                        data: withdrawal_accept.sweep_block_hash.to_le_bytes().to_vec()
                    })),
                    Value::UInt(withdrawal_accept.sweep_block_height as u128),
                ]
            );
        } else {
            panic!("Expected TransactionPayload::ContractCall(TransactionContractCall)");
        }
    }
}

impl<C> TestEnvironment<C>
where
    C: Context,
{
    /// Assert we get the correct UTXO in a simple case
    pub async fn assert_get_signer_utxo_simple(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::InMemoryNetwork::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers as usize);

        let mut signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut rng, &mut signer_set)
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
        test_data.push_bitcoin_txs(
            &block_ref,
            vec![(model::TransactionType::SbtcTransaction, tx.clone())],
        );

        let expected = SignerUtxo {
            outpoint: bitcoin::OutPoint::new(tx.compute_txid(), 0),
            amount: 42,
            public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
        };

        test_data.remove(original_test_data);
        self.write_test_data(&test_data).await;

        let storage = self.context.get_storage();

        let chain_tip = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage failure")
            .expect("missing block");
        assert_eq!(chain_tip, block_ref.block_hash);

        let signer_utxo = storage
            .get_signer_utxo(&chain_tip)
            .await
            .unwrap()
            .expect("no signer utxo");

        assert_eq!(signer_utxo, expected);
    }

    /// Assert we get the correct UTXO in a fork
    pub async fn assert_get_signer_utxo_fork(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::InMemoryNetwork::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers as usize);

        let mut signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, test_data) = self
            .prepare_database_and_run_dkg(&mut rng, &mut signer_set)
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
            test_data_rc.borrow_mut().push_bitcoin_txs(
                block_ref,
                vec![(model::TransactionType::SbtcTransaction, tx.clone())],
            );
            tx
        };

        // The scenario is: (* = no utxo)
        // [initial chain tip] +- [block a1] - [block a2] - [block a3*]
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
        self.write_test_data(&test_data).await;

        let storage = self.context.get_storage();

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
                .get_signer_utxo(&chain_tip.block_hash)
                .await
                .unwrap()
                .expect("no signer utxo");
            assert_eq!(signer_utxo, expected);
        }

        // Check context window
        assert!(storage
            .get_signer_utxo(&block_c2.block_hash)
            .await
            .unwrap()
            .is_some());
    }

    /// Assert we get the correct UTXO with a spending chain in a block
    pub async fn assert_get_signer_utxo_unspent(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::InMemoryNetwork::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers as usize);

        let mut signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut rng, &mut signer_set)
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
        test_data.push_bitcoin_txs(
            &block_ref,
            vec![
                (model::TransactionType::SbtcTransaction, tx_1.clone()),
                (model::TransactionType::SbtcTransaction, tx_3.clone()),
                (model::TransactionType::SbtcTransaction, tx_2.clone()),
            ],
        );

        let expected = SignerUtxo {
            outpoint: bitcoin::OutPoint::new(tx_3.compute_txid(), 0),
            amount: 3,
            public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
        };

        test_data.remove(original_test_data);
        self.write_test_data(&test_data).await;

        let storage = self.context.get_storage();

        let chain_tip = storage
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("storage failure")
            .expect("missing block");
        assert_eq!(chain_tip, block_ref.block_hash);

        let signer_utxo = storage
            .get_signer_utxo(&chain_tip)
            .await
            .unwrap()
            .expect("no signer utxo");

        assert_eq!(signer_utxo, expected);
    }

    /// Assert we get the correct UTXO in case of donations
    pub async fn assert_get_signer_utxo_donations(mut self) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let network = network::InMemoryNetwork::new();
        let signer_info = testing::wsts::generate_signer_info(&mut rng, self.num_signers as usize);

        let mut signer_set =
            testing::wsts::SignerSet::new(&signer_info, self.signing_threshold as u32, || {
                network.connect()
            });

        let (aggregate_key, bitcoin_chain_tip, mut test_data) = self
            .prepare_database_and_run_dkg(&mut rng, &mut signer_set)
            .await;

        let original_test_data = test_data.clone();

        // The scenario is:
        // [initial chain tip] +- [block a1 with signer utxo] - [block a2 with donation]
        //                     +- [block b1 with donation]

        let (block, block_a1) = test_data.new_block(
            &mut rng,
            &signer_set.signer_keys(),
            &self.test_model_parameters,
            Some(&bitcoin_chain_tip),
        );
        let tx_a1 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0xA1),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        test_data.push(block);
        test_data.push_bitcoin_txs(
            &block_a1,
            vec![(model::TransactionType::SbtcTransaction, tx_a1.clone())],
        );

        let (block, block_a2) = test_data.new_block(
            &mut rng,
            &signer_set.signer_keys(),
            &self.test_model_parameters,
            Some(&block_a1),
        );
        let tx_a2 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0xA2),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        test_data.push(block);
        test_data.push_bitcoin_txs(
            &block_a2,
            vec![(model::TransactionType::Donation, tx_a2.clone())],
        );

        let (block, block_b1) = test_data.new_block(
            &mut rng,
            &signer_set.signer_keys(),
            &self.test_model_parameters,
            Some(&bitcoin_chain_tip),
        );
        let tx_b1 = bitcoin::Transaction {
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(0xB1),
                script_pubkey: aggregate_key.signers_script_pubkey(),
            }],
            ..EMPTY_BITCOIN_TX
        };
        test_data.push(block);
        test_data.push_bitcoin_txs(
            &block_b1,
            vec![(model::TransactionType::Donation, tx_b1.clone())],
        );

        test_data.remove(original_test_data);
        self.write_test_data(&test_data).await;

        let storage = self.context.get_storage();

        // Check with chain tip A1
        let signer_utxo = storage
            .get_signer_utxo(&block_a1.block_hash)
            .await
            .unwrap()
            .expect("no signer utxo");
        assert_eq!(
            signer_utxo,
            SignerUtxo {
                outpoint: bitcoin::OutPoint::new(tx_a1.compute_txid(), 0),
                amount: 0xA1,
                public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
            }
        );

        // Check with chain tip A2
        let signer_utxo = storage
            .get_signer_utxo(&block_a2.block_hash)
            .await
            .unwrap()
            .expect("no signer utxo");
        assert_eq!(
            signer_utxo,
            SignerUtxo {
                outpoint: bitcoin::OutPoint::new(tx_a1.compute_txid(), 0),
                amount: 0xA1,
                public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
            }
        );

        // Check with chain tip B1
        let signer_utxo = storage
            .get_signer_utxo(&block_b1.block_hash)
            .await
            .unwrap()
            .expect("no signer utxo");
        assert_eq!(
            signer_utxo,
            SignerUtxo {
                outpoint: bitcoin::OutPoint::new(tx_b1.compute_txid(), 0),
                amount: 0xB1,
                public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
            }
        );
    }

    async fn prepare_database_and_run_dkg<Rng>(
        &mut self,
        rng: &mut Rng,
        signer_set: &mut SignerSet,
    ) -> (keys::PublicKey, model::BitcoinBlockRef, TestData)
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

        let bitcoin_chain_tip_ref = storage
            .get_bitcoin_block(&bitcoin_chain_tip)
            .await
            .expect("storage failure")
            .expect("missing block")
            .into();

        let dkg_txid = testing::dummy::txid(&fake::Faker, rng);
        let (aggregate_key, all_dkg_shares) = signer_set
            .run_dkg(
                bitcoin_chain_tip,
                dkg_txid.into(),
                rng,
                model::DkgSharesStatus::Verified,
            )
            .await;

        let encrypted_dkg_shares = all_dkg_shares.first().unwrap();

        signer_set
            .write_as_rotate_keys_tx(
                &self.context.get_storage_mut(),
                &bitcoin_chain_tip,
                encrypted_dkg_shares,
                rng,
            )
            .await;

        storage
            .write_encrypted_dkg_shares(encrypted_dkg_shares)
            .await
            .expect("failed to write encrypted shares");

        (aggregate_key, bitcoin_chain_tip_ref, test_data)
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
}
