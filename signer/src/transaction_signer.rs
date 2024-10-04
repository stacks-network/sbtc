//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`TxSignerEventLoop`] documentation.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::time::Duration;

use crate::blocklist_client;
use crate::config::NetworkKind;
use crate::context::Context;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::context::TxSignerEvent;
use crate::ecdsa::SignEcdsa as _;
use crate::error::Error;
use crate::keys;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message;
use crate::message::StacksTransactionSignRequest;
use crate::network;
use crate::stacks::contracts::AsContractCall;
use crate::stacks::contracts::ContractCall;
use crate::stacks::contracts::ReqContext;
use crate::stacks::wallet::MultisigTx;
use crate::stacks::wallet::SignerWallet;
use crate::storage::model;
use crate::storage::model::BitcoinBlockRef;
use crate::storage::DbRead as _;
use crate::storage::DbWrite as _;
use crate::wsts_state_machine;

use clarity::types::chainstate::StacksAddress;
use futures::StreamExt;
use tokio::time::error::Elapsed;
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
    /// The network we are working in.
    pub network_kind: bitcoin::Network,
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
    #[tracing::instrument(skip(self))]
    pub async fn run(mut self) -> Result<(), Error> {
        let mut signal_rx = self.context.get_signal_receiver();
        let mut term = self.context.get_termination_handle();

        // TODO: We should really split these operations out into two separate
        // main run-loops since they don't have anything to do with eachother.
        //
        // We run the event loop like this because `tokio::select!()` could
        // potentially kill either `handle_new_requests()` or `handle_signer_message()`
        // in the middle of processing if they end-up running concurrently and
        // the other one finishes first.
        let run_task = async {
            loop {
                // First we empty the signal channel subscription, checking for
                // new Bitcoin block observed events. It doesn't matter how many
                // of these we get, we only care if it has happened. It's also
                // important that we empty this channel as quickly as possible
                // to avoid un-processed messagages being dropped.
                let mut new_block_observed = false;
                while let Ok(signal) = signal_rx.try_recv() {
                    if let SignerSignal::Event(SignerEvent::BitcoinBlockObserved) = signal {
                        new_block_observed = true;
                    }
                }

                // If we've observed a new block, we need to handle any new requests.
                if new_block_observed {
                    self.handle_new_requests().await?;
                }

                // Next, we define a future that polls the network for new messages
                // which times out after 5ms to ensure we don't block the above
                // loop. We don't have any methods (atm) on the Network that would
                // let us `try_recv` or peek. We can get rid of this later on if
                // we split this run-loop into two separate loops.
                let future = tokio::time::timeout(Duration::from_millis(5), self.network.receive());

                match future.await {
                    Ok(msg) => {
                        // Handle the received message.
                        let res = self.handle_signer_message(&msg?).await;
                        match res {
                            Ok(()) => (),
                            Err(Error::InvalidSignature) => (),
                            Err(error) => {
                                tracing::error!(%error, "fatal signer error");
                                return Err::<(), Error>(error);
                            }
                        }
                    }
                    Err(Elapsed { .. }) => (),
                }

                // We don't do any extra waiting here since we have the
                // `tokio::time::timeout` above.
            }
        };

        tokio::select! {
            _ = run_task => (),
            _ = term.wait_for_shutdown() => (),
        }

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

    #[tracing::instrument(skip(self))]
    async fn handle_signer_message(&mut self, msg: &network::Msg) -> Result<(), Error> {
        if !msg.verify() {
            tracing::warn!("unable to verify message");
            return Err(Error::InvalidSignature);
        }

        let chain_tip_report = self
            .inspect_msg_chain_tip(msg.signer_pub_key, &msg.bitcoin_chain_tip)
            .await?;

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
                message::Payload::StacksTransactionSignRequest(_request),
                true,
                ChainTipStatus::Canonical,
            ) => {

                //TODO(255): Implement
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
        msg_sender: keys::PublicKey,
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

        let sender_is_coordinator = if let Some(last_key_rotation) =
            storage.get_last_key_rotation(bitcoin_chain_tip).await?
        {
            let signer_set: BTreeSet<PublicKey> =
                last_key_rotation.signer_set.into_iter().collect();

            crate::transaction_coordinator::given_key_is_coordinator(
                msg_sender,
                bitcoin_chain_tip,
                &signer_set,
            )?
        } else {
            false
        };

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

    #[tracing::instrument(skip(self))]
    async fn handle_bitcoin_transaction_sign_request(
        &mut self,
        request: &message::BitcoinTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let is_valid_sign_request = self
            .is_valid_bitcoin_transaction_sign_request(request)
            .await?;

        if is_valid_sign_request {
            let signer_public_keys = self.get_signer_public_keys(bitcoin_chain_tip).await?;

            let new_state_machine = wsts_state_machine::SignerStateMachine::load(
                &self.context.get_storage_mut(),
                request.aggregate_key,
                signer_public_keys,
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
        &mut self,
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
        ctx: &impl Context,
        request: &message::StacksTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        self.assert_valid_stackstransaction_sign_request(ctx, request, bitcoin_chain_tip)
            .await?;

        let wallet = self.load_wallet(request, bitcoin_chain_tip).await?;
        let multi_sig = MultisigTx::new_tx(&request.contract_call, &wallet, request.tx_fee);
        let txid = multi_sig.tx().txid();

        let signature = crate::signature::sign_stacks_tx(multi_sig.tx(), &self.signer_private_key);

        let msg = message::StacksTransactionSignature { txid, signature };

        self.send_message(msg, bitcoin_chain_tip).await?;

        Ok(())
    }

    /// Load the multi-sig wallet corresponding to the signer set defined
    /// in the last key rotation.
    /// TODO(255): Add a tests
    async fn load_wallet(
        &self,
        request: &StacksTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<SignerWallet, Error> {
        let last_key_rotation = self
            .context
            .get_storage()
            .get_last_key_rotation(bitcoin_chain_tip)
            .await?
            .ok_or(Error::MissingKeyRotation)?;

        let public_keys = last_key_rotation.signer_set.as_slice();
        let signatures_required = last_key_rotation.signatures_required;
        let network_kind = match self.network_kind {
            bitcoin::Network::Bitcoin => NetworkKind::Mainnet,
            _ => NetworkKind::Testnet,
        };
        SignerWallet::new(
            public_keys,
            signatures_required,
            network_kind,
            request.nonce,
        )
    }

    async fn assert_valid_stackstransaction_sign_request(
        &mut self,
        ctx: &impl Context,
        request: &message::StacksTransactionSignRequest,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        // TODO(255): Finish the implementation
        let req_ctx = ReqContext {
            chain_tip: BitcoinBlockRef {
                block_hash: *chain_tip,
                // This is wrong
                block_height: 0,
            },
            context_window: self.context_window,
            // This is wrong
            origin: self.signer_pub_key(),
            // This is wrong
            aggregate_key: self.signer_pub_key(),
            signatures_required: self.threshold as u16,
            // This is wrong
            deployer: StacksAddress::burn_address(false),
        };
        match &request.contract_call {
            ContractCall::AcceptWithdrawalV1(contract) => contract.validate(ctx, &req_ctx).await,
            ContractCall::CompleteDepositV1(contract) => contract.validate(ctx, &req_ctx).await,
            ContractCall::RejectWithdrawalV1(contract) => contract.validate(ctx, &req_ctx).await,
            ContractCall::RotateKeysV1(contract) => contract.validate(ctx, &req_ctx).await,
        }
    }

    #[tracing::instrument(skip(self))]
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
            wsts::net::Message::NonceRequest(_) => {
                // TODO(296): Validate that message is the appropriate sighash
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
                // TODO(#414): handle DKG failute
            }
            wsts::net::Message::NonceResponse(_)
            | wsts::net::Message::SignatureShareResponse(_) => {
                tracing::debug!("ignoring message");
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
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

    /// TODO(#380): This function needs to filter deposit requests based on
    /// time as well. We need to do this because deposit requests are locked
    /// using OP_CSV, which lock up coins based on block hieght or
    /// multiples of 512 seconds measure by the median time past.
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

    #[tracing::instrument(skip(self))]
    async fn handle_pending_deposit_request(
        &mut self,
        request: model::DepositRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let params = self.network_kind.params();
        let addresses = request
            .sender_script_pub_keys
            .iter()
            .map(|script_pubkey| {
                bitcoin::Address::from_script(script_pubkey, params)
                    .map_err(|err| Error::BitcoinAddressFromScript(err, request.outpoint()))
            })
            .collect::<Result<Vec<bitcoin::Address>, _>>()?;

        let is_accepted = futures::stream::iter(&addresses)
            .any(|address| async { self.can_accept(&address.to_string()).await })
            .await;

        let msg = message::SignerDepositDecision {
            txid: request.txid.into(),
            output_index: request.output_index,
            accepted: is_accepted,
        };

        let signer_decision = model::DepositSigner {
            txid: request.txid,
            output_index: request.output_index,
            signer_pub_key: self.signer_pub_key(),
            is_accepted,
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
        };

        self.context
            .get_storage_mut()
            .write_deposit_signer_decision(&signer_decision)
            .await?;

        self.context
            .signal(TxSignerEvent::ReceivedDepositDecision.into())
            .expect("failed to send signal");

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
            .signal(TxSignerEvent::ReceivedWithdrawalDecision.into())
            .expect("failed to send signal");

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

        self.network.broadcast(msg).await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_signer_public_keys(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<BTreeSet<PublicKey>, Error> {
        let last_key_rotation = self
            .context
            .get_storage()
            .get_last_key_rotation(bitcoin_chain_tip)
            .await?
            .ok_or(Error::MissingKeyRotation)?;

        let signer_set = last_key_rotation.signer_set.into_iter().collect();

        Ok(signer_set)
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
    /// The status of the chain tip relative to the signers perspective.
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
            context_window: 3,
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
