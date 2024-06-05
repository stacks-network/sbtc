//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`TxSignerEventLoop`] documentation.

use crate::blocklist_client;
use crate::error;
use crate::network;
use crate::storage;
use crate::storage::model;

use crate::storage::DbRead;
use crate::storage::DbWrite;

use futures::StreamExt;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// # Transaction signer event loop
///
/// This struct contains the implementation of the transaction signer logic.
/// The event loop subscribes to storage update notifications from the block observer,
/// and listens to signer messages over the signer network.
///
/// ## On block observer notification
///
/// When the signer receives a notification from the block observer, indicating that
/// new blocks have been added to the signer state, it must go over each of the pending
/// requests and decide whether to accept or reject it. The decision is then persisted
/// and broadcast to the other signers. The following flowchart illustrates the flow.
///
/// ```mermaid
/// flowchart TD
///     SU[Block observer notification] --> FPR(Fetch pending requests)
///     FPR --> NR(Next request)
///     NR --> |deposit/withdraw| DAR(Decide to accept/reject)
///     NR ----> |none| DONE[Done]
///     DAR --> PD(Persist decision)
///     PD --> BD(Broadcast decision)
///     BD --> NR
/// ```
///
/// ## On signer message
///
/// When the signer receives a message from another signer, it needs to do a few different things
/// depending on the type of the message.
///
/// - **Signer decision**: When receiving a signer decision, the transaction signer
/// only needs to persist the decision to its database.
/// - **Stacks sign request**: When receiving a request to sign a stacks transaction,
/// the signer must verify that it has decided to sign the transaction, and if it has,
/// send a transaction signature back over the network.
/// - **Bitcoin sign request**: When receiving a request to sign a bitcoin transaction,
/// the signer must verify that it has decided to accept all requests that the
/// transaction fulfills. Once verified, the transaction signer creates a dedicated
/// WSTS state machine to participate in a signing round for this transaction. Thereafter,
/// the signer sends a bitcoin transaction sign ack message back over the network to signal
/// its readiness.
/// - **WSTS message**: When receiving a WSTS message, the signer will look up the corresponding
/// state machine and dispatch the WSTS message to it.
///
/// The following flowchart illustrates the process.
///
/// ```mermaid
/// flowchart TD
///     SM[Signer message received] --> |Signer decision| PD(Persist decision)
///
///     SM --> |Stacks sign request| CD1(Check decision)
///     CD1 --> SS(Send signature)
///
///     SM --> |Bitcoin sign request| CD2(Check decision)
///     CD2 --> WSM(Create WSTS state machine)
///     WSM --> ACK(Send Ack message)
///
///     SM --> |WSTS message| RWSM(Relay to WSTS state machine)
/// ```
#[derive(Debug)]
pub struct TxSignerEventLoop<Network, Storage, BlocklistChecker> {
    /// Interface to the signer network.
    pub network: Network,
    /// Database connection.
    pub storage: Storage,
    /// Blocklist checker.
    pub blocklist_checker: BlocklistChecker,
    /// Notification receiver from the block observer.
    pub block_observer_notifications: tokio::sync::watch::Receiver<()>,
    /// Private key of the signer for network communication.
    pub signer_private_key: p256k1::scalar::Scalar,
    /// How many blocks back from the chain tip the signer will look for requests.
    pub context_window: usize,
}

impl<N, S, B> TxSignerEventLoop<N, S, B>
where
    N: network::MessageTransfer,
    B: blocklist_client::BlocklistChecker,
    for<'a> &'a mut S: storage::DbRead + storage::DbWrite,
    for<'a> <&'a mut S as storage::DbRead>::Error: std::error::Error,
    for<'a> <&'a mut S as storage::DbWrite>::Error: std::error::Error,
    for<'a> error::Error: From<<&'a mut S as storage::DbRead>::Error>,
    for<'a> error::Error: From<<&'a mut S as storage::DbWrite>::Error>,
{
    /// Run the signer event loop
    #[tracing::instrument(skip(self))]
    pub async fn run(mut self) -> Result<(), error::Error> {
        loop {
            tokio::select! {
                result = self.block_observer_notifications.changed() => {
                    match result {
                        Ok(()) => self.handle_new_requests().await?,
                        Err(_) => {
                            tracing::info!("block observer notification channel closed");
                            break;
                        }
                    }
                }

                result = self.network.receive() => {
                    match result {
                        Ok(msg) => self.handle_signer_message(&msg).await?,
                        Err(error) => {
                            tracing::error!(%error,"signer network error");
                            break;
                        }
                    }
                }
            }
        }

        tracing::info!("shutting down transaction signer event loop");
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle_new_requests(&mut self) -> Result<(), error::Error> {
        let bitcoin_chain_tip = self
            .storage
            .get_bitcoin_canonical_chain_tip()
            .await?
            .ok_or(Error::NoChainTip)?;

        for deposit_request in self
            .get_pending_deposit_requests(&bitcoin_chain_tip)
            .await?
        {
            self.handle_pending_deposit_request(deposit_request).await?;
        }

        for withdraw_request in self
            .get_pending_withdraw_requests(&bitcoin_chain_tip)
            .await?
        {
            self.handle_pending_withdraw_request(withdraw_request)
                .await?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle_signer_message(&mut self, msg: &network::Msg) -> Result<(), error::Error> {
        // TODO(247): Expand to process signer decisions and write todos for remaining message types
        todo!();
    }

    #[tracing::instrument(skip(self))]
    async fn get_pending_deposit_requests(
        &mut self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Vec<model::DepositRequest>, error::Error> {
        Ok(self
            .storage
            .get_pending_deposit_requests(chain_tip, self.context_window)
            .await?)
    }

    #[tracing::instrument(skip(self))]
    async fn get_pending_withdraw_requests(
        &mut self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Vec<model::WithdrawRequest>, error::Error> {
        Ok(self
            .storage
            .get_pending_withdraw_requests(chain_tip, self.context_window)
            .await?)
    }

    #[tracing::instrument(skip(self))]
    async fn handle_pending_deposit_request(
        &mut self,
        deposit_request: model::DepositRequest,
    ) -> Result<(), error::Error> {
        let is_accepted = futures::stream::iter(&deposit_request.sender_addresses)
            .any(|address| async {
                self.blocklist_checker
                    .can_accept(address)
                    .await
                    .unwrap_or(false)
            })
            .await;

        let signer_pub_key = p256k1::ecdsa::PublicKey::new(&self.signer_private_key)?.to_bytes();

        let created_at = time::OffsetDateTime::now_utc();

        let signer_decision = model::DepositSigner {
            txid: deposit_request.txid,
            output_index: deposit_request.output_index,
            signer_pub_key,
            is_accepted,
            created_at,
        };

        self.storage
            .write_deposit_signer_decision(&signer_decision)
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle_pending_withdraw_request(
        &mut self,
        withdraw_request: model::WithdrawRequest,
    ) -> Result<(), error::Error> {
        let is_accepted = self
            .blocklist_checker
            .can_accept(&withdraw_request.sender_address)
            .await
            .unwrap_or(false);

        let signer_pub_key = p256k1::ecdsa::PublicKey::new(&self.signer_private_key)?.to_bytes();

        let created_at = time::OffsetDateTime::now_utc();

        let signer_decision = model::WithdrawSigner {
            request_id: withdraw_request.request_id,
            block_hash: withdraw_request.block_hash,
            signer_pub_key,
            is_accepted,
            created_at,
        };

        self.storage
            .write_withdraw_signer_decision(&signer_decision)
            .await?;

        Ok(())
    }
}

/// Errors occurring in the transaction signer loop.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No chain tip found.
    #[error("no bitcoin chain tip")]
    NoChainTip,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::network;
    use crate::storage;
    use crate::testing;
    use rand::SeedableRng;

    #[tokio::test]
    async fn should_store_decisions_for_pending_deposit_requests() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let context_window = 3;

        let (event_loop, block_observer_notification_tx, mut storage) =
            create_event_loop(&mut rng, context_window);

        let join_handle = start_event_loop(event_loop);

        let test_data =
            generate_and_write_test_data(&mut rng, &mut storage, &block_observer_notification_tx)
                .await;

        stop_event_loop(block_observer_notification_tx, join_handle).await;

        let context_window_block_hashes =
            extract_context_window_block_hashes(&storage, context_window).await;

        assert_only_deposit_requests_in_context_window_has_decisions(
            &context_window_block_hashes,
            &test_data.deposit_requests,
            &storage,
        )
        .await;
    }

    #[tokio::test]
    async fn should_store_decisions_for_pending_withdraw_requests() {
        // TODO(245): Write test
    }

    fn create_event_loop<Rng: rand::RngCore + rand::CryptoRng>(
        rng: &mut Rng,
        context_window: usize,
    ) -> (
        EventLoop,
        tokio::sync::watch::Sender<()>,
        storage::in_memory::SharedStore,
    ) {
        let storage = storage::in_memory::Store::new_shared();
        let network = network::in_memory::Network::new().connect();
        let blocklist_checker = ();
        let (block_observer_notification_tx, block_observer_notifications) =
            tokio::sync::watch::channel(());
        let signer_private_key = p256k1::scalar::Scalar::random(rng);

        (
            TxSignerEventLoop {
                storage: storage.clone(),
                network,
                blocklist_checker,
                block_observer_notifications,
                signer_private_key,
                context_window,
            },
            block_observer_notification_tx,
            storage,
        )
    }

    fn start_event_loop(
        event_loop: EventLoop,
    ) -> tokio::task::JoinHandle<Result<(), error::Error>> {
        tokio::spawn(async { event_loop.run().await })
    }

    async fn stop_event_loop(
        block_observer_notification_tx: tokio::sync::watch::Sender<()>,
        join_handle: tokio::task::JoinHandle<Result<(), error::Error>>,
    ) {
        // While this explicit drop isn't strictly necessary, it serves to clarify our intention.
        drop(block_observer_notification_tx);

        join_handle
            .await
            .expect("joining event loop failed")
            .expect("event loop returned error");
    }

    async fn generate_and_write_test_data(
        rng: &mut impl rand::RngCore,
        storage: &mut storage::in_memory::SharedStore,
        block_observer_notification_tx: &tokio::sync::watch::Sender<()>,
    ) -> testing::storage::model::TestData {
        let test_model_params = testing::storage::model::Params {
            num_bitcoin_blocks: 20,
            chain_type: testing::storage::model::ChainType::Chaotic,
            num_deposit_requests: 100,
        };

        let test_data = testing::storage::model::TestData::generate(rng, &test_model_params);
        test_data.write_to(storage).await;

        block_observer_notification_tx
            .send(())
            .expect("Failed to send notification");

        test_data
    }

    async fn extract_context_window_block_hashes(
        storage: &storage::in_memory::SharedStore,
        context_window: usize,
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

    async fn assert_only_deposit_requests_in_context_window_has_decisions(
        context_window_block_hashes: &[model::BitcoinBlockHash],
        deposit_requests: &[model::DepositRequest],
        storage: &storage::in_memory::SharedStore,
    ) {
        for deposit_request in deposit_requests {
            let signer_decisions = storage
                .get_deposit_signers(&deposit_request.txid, deposit_request.output_index)
                .await
                .unwrap();

            for deposit_request_block in storage
                .get_bitcoin_blocks_with_transaction(&deposit_request.txid)
                .await
                .unwrap()
            {
                if context_window_block_hashes.contains(&deposit_request_block) {
                    assert_eq!(signer_decisions.len(), 1);
                    assert!(signer_decisions.first().unwrap().is_accepted)
                } else {
                    assert_eq!(signer_decisions.len(), 0);
                }
            }
        }
    }

    impl blocklist_client::BlocklistChecker for () {
        async fn can_accept(
            &self,
            _address: &str,
        ) -> Result<
            bool,
            blocklist_api::apis::Error<blocklist_api::apis::address_api::CheckAddressError>,
        > {
            Ok(true)
        }
    }

    type EventLoop =
        TxSignerEventLoop<network::in_memory::MpmcBroadcaster, storage::in_memory::SharedStore, ()>;
}
