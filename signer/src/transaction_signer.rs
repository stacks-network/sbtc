//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`TxSignerEventLoop`] documentation.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::blocklist_client;
use crate::context::Context;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::context::TxCoordinatorEvent;
use crate::context::TxSignerEvent;
use crate::ecdsa::SignEcdsa as _;
use crate::ecdsa::Signed;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message;
use crate::message::SignerMessage;
use crate::message::StacksTransactionSignRequest;
use crate::network;
use crate::signature::SighashDigest as _;
use crate::stacks::contracts::AsContractCall as _;
use crate::stacks::contracts::ContractCall;
use crate::stacks::contracts::ReqContext;
use crate::stacks::contracts::StacksTx;
use crate::stacks::wallet::MultisigTx;
use crate::stacks::wallet::SignerWallet;
use crate::storage::model;
use crate::storage::DbRead as _;
use crate::storage::DbWrite as _;
use crate::wsts_state_machine;

use futures::StreamExt;
use futures::TryStreamExt;
use tokio::sync::Mutex;
use wsts::net::DkgEnd;
use wsts::net::DkgStatus;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// # Transaction signer event loop
///
/// This struct contains the implementation of the transaction signer
/// logic. The event loop subscribes to storage update notifications from
/// the block observer, and listens to signer messages over the signer
/// network.
///
/// ## On block observer notification
///
/// When the signer receives a notification from the block observer,
/// indicating that new blocks have been added to the signer state, it must
/// go over each of the pending requests and decide whether to accept or
/// reject it. The decision is then persisted and broadcast to the other
/// signers. The following flowchart illustrates the flow.
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
/// When the signer receives a message from another signer, it needs to do
/// a few different things depending on the type of the message.
///
/// - **Signer decision**: When receiving a signer decision, the
///   transaction signer only needs to persist the decision to its
///   database.
/// - **Stacks sign request**: When receiving a request to sign a stacks
///   transaction, the signer must verify that it has decided to sign the
///   transaction, and if it has, send a transaction signature back over
///   the network.
/// - **Bitcoin sign request**: When receiving a request to sign a bitcoin
///   transaction, the signer must verify that it has decided to accept all
///   requests that the transaction fulfills. Once verified, the
///   transaction signer creates a dedicated WSTS state machine to
///   participate in a signing round for this transaction. Thereafter, the
///   signer sends a bitcoin transaction sign ack message back over the
///   network to signal its readiness.
/// - **WSTS message**: When receiving a WSTS message, the signer will look
///   up the corresponding state machine and dispatch the WSTS message to
///   it.
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
pub struct TxSignerEventLoop<Context, Network, BlocklistChecker, Rng> {
    /// The signer context.
    pub context: Context,
    /// Interface to the signer network.
    pub network: Network,
    /// Blocklist checker.
    pub blocklist_checker: Option<BlocklistChecker>,
    /// Private key of the signer for network communication.
    pub signer_private_key: PrivateKey,
    /// WSTS state machines for active signing rounds and DKG rounds
    ///
    /// - For signing rounds, the TxID is the ID of the transaction to be
    ///   signed.
    ///
    /// - For DKG rounds, TxID should be the ID of the transaction that
    ///   defined the signer set.
    pub wsts_state_machines: HashMap<bitcoin::Txid, wsts_state_machine::SignerStateMachine>,
    /// The threshold for the signer
    pub threshold: u32,
    /// How many bitcoin blocks back from the chain tip the signer will look for requests.
    pub context_window: u16,
    /// Random number generator used for encryption
    pub rng: Rng,
}

impl<C, N, B, Rng> TxSignerEventLoop<C, N, B, Rng>
where
    C: Context,
    N: network::MessageTransfer,
    B: blocklist_client::BlocklistChecker,
    Rng: rand::RngCore + rand::CryptoRng,
{
    /// Run the signer event loop
    #[tracing::instrument(skip(self), name = "tx-signer")]
    pub async fn run(mut self) -> Result<(), Error> {
        let mut signal_rx = self.context.get_signal_receiver();
        let mut term = self.context.get_termination_handle();
        let mut network = self.network.clone();

        let signalled_events: Mutex<Vec<SignerEvent>> = Default::default();
        let network_messages: Mutex<Vec<Signed<SignerMessage>>> = Default::default();
        let shutdown_notify = AtomicBool::new(false);

        let should_shutdown = || shutdown_notify.load(std::sync::atomic::Ordering::Relaxed);

        // TODO: We should really split these operations out into two
        // separate main run-loops since they don't have anything to do
        // with each other.
        let signer_event_loop = async {
            if let Err(err) = self.context.signal(TxSignerEvent::EventLoopStarted.into()) {
                tracing::error!(%err, "error signalling event loop start");
                return;
            };

            tracing::debug!("signer event loop started");
            while !should_shutdown() {
                // Collect all events which have been signalled into this loop
                // iteration for processing.
                let mut events_guard = signalled_events.lock().await;
                let events = events_guard.drain(..).collect::<Vec<_>>();
                drop(events_guard);

                // Collect all network messages which have been received into
                // this loop iteration for processing.
                let mut network_messages_guard = network_messages.lock().await;
                let mut messages_to_process = network_messages_guard.drain(..).collect::<Vec<_>>();
                drop(network_messages_guard);

                // Append all `TxCoordinatorEvent::MessageGenerated` event messages
                // into `messages_to_process` for processing.
                events.iter().for_each(|event| {
                    if let SignerEvent::TxCoordinator(TxCoordinatorEvent::MessageGenerated(msg)) =
                        event
                    {
                        messages_to_process.push(msg.clone());
                    }
                });

                // Check if we've observed a new block.
                let new_block_observed = events
                    .iter()
                    .any(|event| matches!(event, SignerEvent::BitcoinBlockObserved));

                // If we've observed a new block, we need to handle any new requests.
                if new_block_observed {
                    if let Err(error) = self.handle_new_requests().await {
                        tracing::warn!(%error, "error handling new requests; skipping this round");
                    }
                }

                // Process all messages which have been received (both from the
                // network and from this signer's own transaction coordinator).
                for msg in messages_to_process {
                    match self.handle_signer_message(&msg).await {
                        Ok(()) | Err(Error::InvalidSignature) => (),
                        Err(error) => {
                            tracing::error!(%error, "error handling signer message");
                        }
                    }
                }

                // A small delay to avoid busy-looping if there are no events
                // to process.
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };

        // This task will poll the signal channel for new events and push them
        // into the `signalled_events` vec for processing in the main loop.
        let poll_signalled_events = async {
            while !should_shutdown() {
                if let Ok(SignerSignal::Event(event)) = signal_rx.recv().await {
                    signalled_events.lock().await.push(event);
                }
            }
        };

        // This task will poll the network for new messages and push them into
        // the `network_messages` vec for processing in the main loop.
        let poll_network_messages = async {
            while !should_shutdown() {
                if let Ok(msg) = network.receive().await {
                    network_messages.lock().await.push(msg);
                }
            }
        };

        // This task will wait for a termination signal and then set the
        // `shutdown_notify` flag to true, which will cause all of the other
        // tasks to shutdown.
        let poll_shutdown = async {
            term.wait_for_shutdown().await;
            tracing::info!(
                "termination signal received; transaction signer event loop is shutting down"
            );
            shutdown_notify.store(true, std::sync::atomic::Ordering::Relaxed);
        };

        tokio::join!(
            // Polling
            poll_signalled_events,
            poll_network_messages,
            poll_shutdown,
            // Main event loop
            signer_event_loop,
        );

        tracing::info!("transaction signer event loop has been stopped");
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle_new_requests(&mut self) -> Result<(), Error> {
        let bitcoin_chain_tip = self
            .context
            .get_storage()
            .get_bitcoin_canonical_chain_tip()
            .await?
            .ok_or(Error::NoChainTip)?;

        for deposit_request in self
            .get_pending_deposit_requests(&bitcoin_chain_tip)
            .await?
        {
            self.handle_pending_deposit_request(deposit_request, &bitcoin_chain_tip)
                .await?;
        }

        for withdraw_request in self
            .get_pending_withdraw_requests(&bitcoin_chain_tip)
            .await?
        {
            self.handle_pending_withdrawal_request(withdraw_request, &bitcoin_chain_tip)
                .await?;
        }

        self.context
            .signal(TxSignerEvent::NewRequestsHandled.into())?;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn handle_signer_message(&mut self, msg: &network::Msg) -> Result<(), Error> {
        if !msg.verify() {
            tracing::warn!("unable to verify message");
            return Err(Error::InvalidSignature);
        }

        let chain_tip_report = self
            .inspect_msg_chain_tip(msg.signer_pub_key, &msg.bitcoin_chain_tip)
            .await?;

        tracing::trace!(
            sender_is_coordinator = chain_tip_report.sender_is_coordinator,
            chain_tip_status = ?chain_tip_report.chain_tip_status,
            msg_chain_tip = %msg.bitcoin_chain_tip,
            ?msg.inner.payload,
            "handling message"
        );

        match (
            &msg.inner.payload,
            chain_tip_report.sender_is_coordinator,
            chain_tip_report.chain_tip_status,
        ) {
            (message::Payload::SignerDepositDecision(decision), _, _) => {
                self.persist_received_deposit_decision(decision, msg.signer_pub_key)
                    .await?;
            }

            (message::Payload::SignerWithdrawalDecision(decision), _, _) => {
                self.persist_received_withdraw_decision(decision, msg.signer_pub_key)
                    .await?;
            }

            (
                message::Payload::StacksTransactionSignRequest(request),
                true,
                ChainTipStatus::Canonical,
            ) => {
                self.handle_stacks_transaction_sign_request(
                    request,
                    &msg.bitcoin_chain_tip,
                    &msg.signer_pub_key,
                )
                .await?;
            }

            (
                message::Payload::BitcoinTransactionSignRequest(request),
                true,
                ChainTipStatus::Canonical,
            ) => {
                tracing::debug!("handling bitcoin transaction sign request");
                self.handle_bitcoin_transaction_sign_request(request, &msg.bitcoin_chain_tip)
                    .await?;
            }

            (message::Payload::WstsMessage(wsts_msg), _, _) => {
                self.handle_wsts_message(wsts_msg, &msg.bitcoin_chain_tip)
                    .await?;
            }

            (
                message::Payload::SweepTransactionInfo(sweep_tx),
                is_coordinator,
                ChainTipStatus::Canonical,
            ) => {
                if !is_coordinator {
                    tracing::warn!("received sweep transaction info from non-coordinator");
                    return Ok(());
                }

                tracing::debug!(
                    txid = %sweep_tx.txid,
                    sweep_broadcast_at = %sweep_tx.created_at_block_hash,
                    "received sweep transaction info; storing it"
                );
                self.context
                    .get_storage_mut()
                    .write_sweep_transaction(&sweep_tx.into())
                    .await?;
            }

            // Message types ignored by the transaction signer
            (message::Payload::StacksTransactionSignature(_), _, _)
            | (message::Payload::BitcoinTransactionSignAck(_), _, _) => (),

            // Any other combination should be logged
            _ => {
                tracing::warn!(?msg, ?chain_tip_report, "unexpected message");
            }
        };

        Ok(())
    }

    /// Find out the status of the given chain tip
    #[tracing::instrument(skip(self))]
    async fn inspect_msg_chain_tip(
        &mut self,
        msg_sender: PublicKey,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<MsgChainTipReport, Error> {
        let storage = self.context.get_storage();

        let is_known = storage
            .get_bitcoin_block(bitcoin_chain_tip)
            .await?
            .is_some();

        let is_canonical = storage
            .get_bitcoin_canonical_chain_tip()
            .await?
            .map(|canonical_chain_tip| &canonical_chain_tip == bitcoin_chain_tip)
            .unwrap_or(false);

        let signer_set = self.get_signer_public_keys(bitcoin_chain_tip).await?;

        let sender_is_coordinator = crate::transaction_coordinator::given_key_is_coordinator(
            msg_sender,
            bitcoin_chain_tip,
            &signer_set,
        );

        let chain_tip_status = match (is_known, is_canonical) {
            (true, true) => ChainTipStatus::Canonical,
            (true, false) => ChainTipStatus::Known,
            (false, _) => ChainTipStatus::Unknown,
        };

        Ok(MsgChainTipReport {
            sender_is_coordinator,
            chain_tip_status,
        })
    }

    #[tracing::instrument(skip(self, request))]
    async fn handle_bitcoin_transaction_sign_request(
        &mut self,
        request: &message::BitcoinTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let is_valid_sign_request = self
            .is_valid_bitcoin_transaction_sign_request(request)
            .await?;

        if is_valid_sign_request {
            let new_state_machine = wsts_state_machine::SignerStateMachine::load(
                &self.context.get_storage_mut(),
                request.aggregate_key,
                self.threshold,
                self.signer_private_key,
            )
            .await?;

            let txid = request.tx.compute_txid();

            self.wsts_state_machines.insert(txid, new_state_machine);

            let msg = message::BitcoinTransactionSignAck {
                txid: request.tx.compute_txid(),
            };

            self.send_message(msg, bitcoin_chain_tip).await?;
        } else {
            tracing::warn!("received invalid sign request");
        }

        Ok(())
    }

    async fn is_valid_bitcoin_transaction_sign_request(
        &self,
        _request: &message::BitcoinTransactionSignRequest,
    ) -> Result<bool, Error> {
        let signer_pub_key = self.signer_pub_key();
        let _accepted_deposit_requests = self
            .context
            .get_storage()
            .get_accepted_deposit_requests(&signer_pub_key)
            .await?;

        // TODO(286): Validate transaction
        // - Ensure all inputs are either accepted deposit requests
        //    or directly spendable by the signers.
        // - Ensure all outputs are either accepted withdrawals
        //    or pays to an approved signer set.
        // - Ensure the transaction fee is lower than the minimum
        //    `max_fee` of any request.

        Ok(true)
    }

    #[tracing::instrument(skip_all)]
    async fn handle_stacks_transaction_sign_request(
        &mut self,
        request: &StacksTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        origin_public_key: &PublicKey,
    ) -> Result<(), Error> {
        self.assert_valid_stacks_tx_sign_request(request, bitcoin_chain_tip, origin_public_key)
            .await?;

        // We need to set the nonce in order to get the exact transaction
        // that we need to sign.
        let wallet = SignerWallet::load(&self.context, bitcoin_chain_tip).await?;
        wallet.set_nonce(request.nonce);

        let multi_sig = MultisigTx::new_tx(&request.contract_tx, &wallet, request.tx_fee);
        let txid = multi_sig.tx().txid();

        // TODO(517): Remove the digest field from the request object and
        // serialize the entire message.
        debug_assert_eq!(multi_sig.tx().digest(), request.digest);
        debug_assert_eq!(txid, request.txid);

        let signature = crate::signature::sign_stacks_tx(multi_sig.tx(), &self.signer_private_key);

        let msg = message::StacksTransactionSignature { txid, signature };

        self.send_message(msg, bitcoin_chain_tip).await?;

        Ok(())
    }

    /// Check that the transaction is indeed valid. We specific checks that
    /// are run depend on the transaction being signed.
    pub async fn assert_valid_stacks_tx_sign_request(
        &self,
        request: &StacksTransactionSignRequest,
        chain_tip: &model::BitcoinBlockHash,
        origin_public_key: &PublicKey,
    ) -> Result<(), Error> {
        let db = self.context.get_storage();
        let public_key = self.signer_pub_key();

        let Some(shares) = db.get_encrypted_dkg_shares(&request.aggregate_key).await? else {
            return Err(Error::MissingDkgShares(request.aggregate_key));
        };
        // There is one check that applies to all Stacks transactions, and
        // that check is that the current signer is in the signing set
        // associated with the given aggregate key. We do this check here.
        if !shares.signer_set_public_keys.contains(&public_key) {
            return Err(Error::ValidationSignerSet(request.aggregate_key));
        }

        let Some(block) = db.get_bitcoin_block(chain_tip).await? else {
            return Err(Error::MissingBitcoinBlock(*chain_tip));
        };

        let req_ctx = ReqContext {
            chain_tip: block.into(),
            context_window: self.context_window,
            origin: *origin_public_key,
            aggregate_key: request.aggregate_key,
            signatures_required: shares.signature_share_threshold,
            deployer: self.context.config().signer.deployer,
        };
        let ctx = &self.context;
        match &request.contract_tx {
            StacksTx::ContractCall(ContractCall::AcceptWithdrawalV1(contract)) => {
                contract.validate(ctx, &req_ctx).await
            }
            StacksTx::ContractCall(ContractCall::CompleteDepositV1(contract)) => {
                contract.validate(ctx, &req_ctx).await
            }
            StacksTx::ContractCall(ContractCall::RejectWithdrawalV1(contract)) => {
                contract.validate(ctx, &req_ctx).await
            }
            StacksTx::ContractCall(ContractCall::RotateKeysV1(contract)) => {
                contract.validate(ctx, &req_ctx).await
            }
            StacksTx::SmartContract(smart_contract) => smart_contract.validate(ctx, &req_ctx).await,
        }
    }

    #[tracing::instrument(skip(self, msg))]
    async fn handle_wsts_message(
        &mut self,
        msg: &message::WstsMessage,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        tracing::info!("handling message");
        match &msg.inner {
            wsts::net::Message::DkgBegin(_) => {
                let signer_public_keys = self.get_signer_public_keys(bitcoin_chain_tip).await?;

                let state_machine = wsts_state_machine::SignerStateMachine::new(
                    signer_public_keys,
                    self.threshold,
                    self.signer_private_key,
                )?;
                self.wsts_state_machines.insert(msg.txid, state_machine);
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            wsts::net::Message::DkgPublicShares(_)
            | wsts::net::Message::DkgPrivateBegin(_)
            | wsts::net::Message::DkgPrivateShares(_) => {
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            wsts::net::Message::DkgEndBegin(_) => {
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
                self.store_dkg_shares(&msg.txid).await?;
            }
            // Clippy complains about how we could refactor this to use the
            // `std::collections::hash_map::Entry` type here to make things
            // more idiomatic. The issue with that approach is that it
            // requires a mutable reference of the `wsts_state_machines`
            // self to be taken at the same time as an immunable reference.
            // The compiler will complain about this so we silence the
            // warning.
            #[allow(clippy::map_entry)]
            wsts::net::Message::NonceRequest(_) => {
                // TODO(296): Validate that message is the appropriate sighash
                if !self.wsts_state_machines.contains_key(&msg.txid) {
                    let (maybe_aggregate_key, _) = self
                        .get_signer_set_and_aggregate_key(bitcoin_chain_tip)
                        .await?;

                    let state_machine = wsts_state_machine::SignerStateMachine::load(
                        &self.context.get_storage_mut(),
                        maybe_aggregate_key.ok_or(Error::NoDkgShares)?,
                        self.threshold,
                        self.signer_private_key,
                    )
                    .await?;

                    self.wsts_state_machines.insert(msg.txid, state_machine);
                }
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            wsts::net::Message::SignatureShareRequest(_) => {
                // TODO(296): Validate that message is the appropriate sighash
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            wsts::net::Message::DkgEnd(DkgEnd { status: DkgStatus::Success, .. }) => {
                tracing::info!("DKG ended in success");
            }
            wsts::net::Message::DkgEnd(DkgEnd {
                status: DkgStatus::Failure(fail),
                ..
            }) => {
                tracing::info!("DKG ended in failure: {fail:?}");
                // TODO(#414): handle DKG failure
            }
            wsts::net::Message::NonceResponse(_)
            | wsts::net::Message::SignatureShareResponse(_) => {
                tracing::debug!("ignoring message");
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self, msg))]
    async fn relay_message(
        &mut self,
        txid: bitcoin::Txid,
        msg: &wsts::net::Message,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let Some(state_machine) = self.wsts_state_machines.get_mut(&txid) else {
            tracing::warn!("missing signing round");
            return Ok(());
        };

        let outbound_messages = state_machine.process(msg).map_err(Error::Wsts)?;

        for outbound_message in outbound_messages.iter() {
            // The WSTS state machine assume we read our own messages
            state_machine
                .process(outbound_message)
                .map_err(Error::Wsts)?;
        }

        for outbound_message in outbound_messages {
            let msg = message::WstsMessage { txid, inner: outbound_message };

            tracing::debug!(?msg, "sending message");

            self.send_message(msg, bitcoin_chain_tip).await?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_pending_deposit_requests(
        &mut self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Vec<model::DepositRequest>, Error> {
        self.context
            .get_storage()
            .get_pending_deposit_requests(chain_tip, self.context_window)
            .await
    }

    #[tracing::instrument(skip(self))]
    async fn get_pending_withdraw_requests(
        &mut self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Vec<model::WithdrawalRequest>, Error> {
        self.context
            .get_storage()
            .get_pending_withdrawal_requests(chain_tip, self.context_window)
            .await
    }

    /// Check whether this signer accepts the deposit request. This
    /// involves:
    ///
    /// 1. Reach out to the blocklist client and find out whether we can
    ///    accept the deposit given all the input `scriptPubKey`s of the
    ///    transaction.
    /// 2. Check if we are a part of the signing set associated with the
    ///    public key locking the funds.
    ///
    /// If the block list client is not configured then the first check
    /// always passes.
    #[tracing::instrument(skip(self))]
    pub async fn handle_pending_deposit_request(
        &mut self,
        request: model::DepositRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let db = self.context.get_storage_mut();

        let signer_public_key = self.signer_pub_key();
        // Let's find out whether or not we can even sign for this deposit
        // request. If we cannot then we do not even reach out to the
        // blocklist client.
        //
        // We should have a record for the request because of where this
        // function is in the code path.
        let can_sign = db
            .can_sign_deposit_tx(&request.txid, request.output_index, &signer_public_key)
            .await?
            .unwrap_or(false);

        let is_accepted = can_sign && self.can_accept_deposit_request(&request).await?;

        let msg = message::SignerDepositDecision {
            txid: request.txid.into(),
            output_index: request.output_index,
            accepted: is_accepted,
            can_sign,
        };

        let signer_decision = model::DepositSigner {
            txid: request.txid,
            output_index: request.output_index,
            signer_pub_key: signer_public_key,
            is_accepted,
            can_sign,
        };

        self.context
            .get_storage_mut()
            .write_deposit_signer_decision(&signer_decision)
            .await?;

        self.send_message(msg, bitcoin_chain_tip).await?;

        self.context
            .signal(TxSignerEvent::PendingDepositRequestRegistered.into())?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle_pending_withdrawal_request(
        &mut self,
        withdrawal_request: model::WithdrawalRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        // TODO: Do we want to do this on the sender address or the
        // recipient address?
        let is_accepted = self
            .can_accept(&withdrawal_request.sender_address.to_string())
            .await;

        let msg = message::SignerWithdrawalDecision {
            request_id: withdrawal_request.request_id,
            block_hash: withdrawal_request.block_hash.0,
            accepted: is_accepted,
            txid: withdrawal_request.txid,
        };

        let signer_decision = model::WithdrawalSigner {
            request_id: withdrawal_request.request_id,
            block_hash: withdrawal_request.block_hash,
            signer_pub_key: self.signer_pub_key(),
            is_accepted,
            txid: withdrawal_request.txid,
        };

        self.context
            .get_storage_mut()
            .write_withdrawal_signer_decision(&signer_decision)
            .await?;

        self.send_message(msg, bitcoin_chain_tip).await?;

        self.context
            .signal(TxSignerEvent::PendingWithdrawalRequestRegistered.into())?;

        Ok(())
    }

    async fn can_accept(&self, address: &str) -> bool {
        let Some(client) = self.blocklist_checker.as_ref() else {
            return true;
        };

        client.can_accept(address).await.unwrap_or(false)
    }

    async fn can_accept_deposit_request(&self, req: &model::DepositRequest) -> Result<bool, Error> {
        // If we have not configured a blocklist checker, then we can
        // return early.
        let Some(client) = self.blocklist_checker.as_ref() else {
            return Ok(true);
        };

        // We turn all the input scriptPubKeys into addresses and check
        // those with the blocklist client.
        let bitcoin_network = bitcoin::Network::from(self.context.config().signer.network);
        let params = bitcoin_network.params();
        let addresses = req
            .sender_script_pub_keys
            .iter()
            .map(|script_pubkey| bitcoin::Address::from_script(script_pubkey, params))
            .collect::<Result<Vec<bitcoin::Address>, _>>()
            .map_err(|err| Error::BitcoinAddressFromScript(err, req.outpoint()))?;

        let responses = futures::stream::iter(&addresses)
            .then(|address| async { client.can_accept(&address.to_string()).await })
            .inspect_err(|error| tracing::error!(%error, "blocklist client issue"))
            .collect::<Vec<_>>()
            .await;

        // If any of the inputs addresses are fine then we pass the deposit
        // request.
        let can_accept = responses.into_iter().any(|res| res.unwrap_or(false));
        Ok(can_accept)
    }

    #[tracing::instrument(skip(self))]
    async fn persist_received_deposit_decision(
        &mut self,
        decision: &message::SignerDepositDecision,
        signer_pub_key: PublicKey,
    ) -> Result<(), Error> {
        let signer_decision = model::DepositSigner {
            txid: decision.txid.into(),
            output_index: decision.output_index,
            signer_pub_key,
            is_accepted: decision.accepted,
            can_sign: decision.can_sign,
        };

        self.context
            .get_storage_mut()
            .write_deposit_signer_decision(&signer_decision)
            .await?;

        self.context
            .signal(TxSignerEvent::ReceivedDepositDecision.into())?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn persist_received_withdraw_decision(
        &mut self,
        decision: &message::SignerWithdrawalDecision,
        signer_pub_key: PublicKey,
    ) -> Result<(), Error> {
        let signer_decision = model::WithdrawalSigner {
            request_id: decision.request_id,
            block_hash: decision.block_hash.into(),
            signer_pub_key,
            is_accepted: decision.accepted,
            txid: decision.txid,
        };

        self.context
            .get_storage_mut()
            .write_withdrawal_signer_decision(&signer_decision)
            .await?;

        self.context
            .signal(TxSignerEvent::ReceivedWithdrawalDecision.into())?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn store_dkg_shares(&mut self, txid: &bitcoin::Txid) -> Result<(), Error> {
        let state_machine = self
            .wsts_state_machines
            .get(txid)
            .ok_or(Error::MissingStateMachine)?;

        let encrypted_dkg_shares = state_machine.get_encrypted_dkg_shares(&mut self.rng)?;

        self.context
            .get_storage_mut()
            .write_encrypted_dkg_shares(&encrypted_dkg_shares)
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, msg))]
    async fn send_message(
        &mut self,
        msg: impl Into<message::Payload>,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let payload: message::Payload = msg.into();
        let msg = payload
            .to_message(*bitcoin_chain_tip)
            .sign_ecdsa(&self.signer_private_key)?;

        self.network.broadcast(msg.clone()).await?;
        self.context
            .signal(TxSignerEvent::MessageGenerated(msg).into())?;

        Ok(())
    }

    /// Return the signing set that can make sBTC related contract calls
    /// along with the current aggregate key to use for locking UTXOs on
    /// bitcoin.
    ///
    /// The aggregate key fetched here is the one confirmed on the
    /// canonical Stacks blockchain as part of a `rotate-keys` contract
    /// call. It will be the public key that is the result of a DKG run. If
    /// there are no rotate-keys transactions on the canonical stacks
    /// blockchain, then we fall back on the last known DKG shares row in
    /// our database, and return None as the aggregate key if no DKG shares
    /// can be found, implying that this signer has not participated in
    /// DKG.
    #[tracing::instrument(skip(self))]
    pub async fn get_signer_set_and_aggregate_key(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(Option<PublicKey>, BTreeSet<PublicKey>), Error> {
        let db = self.context.get_storage();

        // We are supposed to submit a rotate-keys transaction after
        // running DKG, but that transaction may not have been submitted
        // yet (if we have just run DKG) or it may not have been confirmed
        // on the canonical Stacks blockchain.
        //
        // If the signers have already run DKG, then we know that all
        // participating signers should have the same view of the latest
        // aggregate key, so we can fall back on the stored DKG shares for
        // getting the current aggregate key and associated signing set.
        match db.get_last_key_rotation(bitcoin_chain_tip).await? {
            Some(last_key) => {
                let aggregate_key = last_key.aggregate_key;
                let signer_set = last_key.signer_set.into_iter().collect();
                Ok((Some(aggregate_key), signer_set))
            }
            None => match db.get_latest_encrypted_dkg_shares().await? {
                Some(shares) => {
                    let signer_set = shares.signer_set_public_keys.into_iter().collect();
                    Ok((Some(shares.aggregate_key), signer_set))
                }
                None => Ok((None, self.context.config().signer.bootstrap_signing_set())),
            },
        }
    }

    /// Get the set of public keys for the current signing set.
    ///
    /// If there is a successful `rotate-keys` transaction in the database
    /// then we should use that as the source of truth for the current
    /// signing set, otherwise we fall back to the bootstrap keys in our
    /// config.
    #[tracing::instrument(skip_all)]
    pub async fn get_signer_public_keys(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<BTreeSet<PublicKey>, Error> {
        let db = self.context.get_storage();

        // Get the last rotate-keys transaction from the database on the
        // canonical Stacks blockchain (which we identify using the
        // canonical bitcoin blockchain). If we don't have such a
        // transaction then get the bootstrap keys from our config.
        match db.get_last_key_rotation(chain_tip).await? {
            Some(last_key) => Ok(last_key.signer_set.into_iter().collect()),
            None => Ok(self.context.config().signer.bootstrap_signing_set()),
        }
    }

    fn signer_pub_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.signer_private_key)
    }
}

/// Relevant information for validating incoming messages
/// relating to a particular chain tip.
#[derive(Debug, Clone, Copy)]
struct MsgChainTipReport {
    /// Whether the sender of the incoming message is the coordinator for this chain tip.
    sender_is_coordinator: bool,
    /// The status of the chain tip relative to the signers' perspective.
    chain_tip_status: ChainTipStatus,
}

/// The status of a chain tip relative to the known blocks in the signer database.
#[derive(Debug, Clone, Copy)]
enum ChainTipStatus {
    /// The chain tip is the tip of the canonical fork.
    Canonical,
    /// The chain tip is for a known block, but is not the canonical chain tip.
    Known,
    /// The chain tip belongs to a block that hasn't been seen yet.
    Unknown,
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::MockBitcoinInteract;
    use crate::emily_client::MockEmilyInteract;
    use crate::stacks::api::MockStacksInteract;
    use crate::storage::in_memory::SharedStore;
    use crate::testing;
    use crate::testing::context::*;

    fn test_environment() -> testing::transaction_signer::TestEnvironment<
        TestContext<
            SharedStore,
            WrappedMock<MockBitcoinInteract>,
            WrappedMock<MockStacksInteract>,
            WrappedMock<MockEmilyInteract>,
        >,
    > {
        let test_model_parameters = testing::storage::model::Params {
            num_bitcoin_blocks: 20,
            num_stacks_blocks_per_bitcoin_block: 3,
            num_deposit_requests_per_block: 5,
            num_withdraw_requests_per_block: 5,
            num_signers_per_request: 0,
        };

        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        testing::transaction_signer::TestEnvironment {
            context,
            context_window: 6,
            num_signers: 7,
            signing_threshold: 5,
            test_model_parameters,
        }
    }

    #[tokio::test]
    async fn should_store_decisions_for_pending_deposit_requests() {
        test_environment()
            .assert_should_store_decisions_for_pending_deposit_requests()
            .await;
    }

    #[tokio::test]
    async fn should_store_decisions_for_pending_withdraw_requests() {
        test_environment()
            .assert_should_store_decisions_for_pending_withdraw_requests()
            .await;
    }

    #[tokio::test]
    async fn should_store_decisions_received_from_other_signers() {
        test_environment()
            .assert_should_store_decisions_received_from_other_signers()
            .await;
    }

    #[tokio::test]
    async fn should_respond_to_bitcoin_transaction_sign_requests() {
        test_environment()
            .assert_should_respond_to_bitcoin_transaction_sign_requests()
            .await;
    }

    #[tokio::test]
    async fn should_be_able_to_participate_in_dkg() {
        test_environment()
            .assert_should_be_able_to_participate_in_dkg()
            .await;
    }

    #[tokio::test]
    async fn should_be_able_to_participate_in_signing_round() {
        test_environment()
            .assert_should_be_able_to_participate_in_signing_round()
            .await;
    }
}
