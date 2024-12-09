//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`TxSignerEventLoop`] documentation.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::time::Duration;

use crate::bitcoin::validation::BitcoinTxContext;
use crate::context::Context;
use crate::context::P2PEvent;
use crate::context::SignerCommand;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::context::TxCoordinatorEvent;
use crate::context::TxSignerEvent;
use crate::ecdsa::SignEcdsa as _;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message;
use crate::message::BitcoinPreSignAck;
use crate::message::StacksTransactionSignRequest;
use crate::network;
use crate::stacks::contracts::AsContractCall as _;
use crate::stacks::contracts::ContractCall;
use crate::stacks::contracts::ReqContext;
use crate::stacks::contracts::StacksTx;
use crate::stacks::wallet::MultisigTx;
use crate::stacks::wallet::SignerWallet;
use crate::storage::model;
use crate::storage::DbRead;
use crate::storage::DbWrite as _;
use crate::wsts_state_machine::SignerStateMachine;

use bitcoin::hashes::Hash;
use bitcoin::TapSighash;
use futures::StreamExt;
use wsts::net::DkgEnd;
use wsts::net::DkgStatus;
use wsts::net::Message as WstsNetMessage;

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
pub struct TxSignerEventLoop<Context, Network, Rng> {
    /// The signer context.
    pub context: Context,
    /// Interface to the signer network.
    pub network: Network,
    /// Private key of the signer for network communication.
    pub signer_private_key: PrivateKey,
    /// WSTS state machines for active signing rounds and DKG rounds
    ///
    /// - For signing rounds, the TxID is the ID of the transaction to be
    ///   signed.
    ///
    /// - For DKG rounds, TxID should be the ID of the transaction that
    ///   defined the signer set.
    pub wsts_state_machines: HashMap<bitcoin::Txid, SignerStateMachine>,
    /// The threshold for the signer
    pub threshold: u32,
    /// How many bitcoin blocks back from the chain tip the signer will look for requests.
    pub context_window: u16,
    /// Random number generator used for encryption
    pub rng: Rng,
    /// The time the signer should pause for after receiving a DKG begin message
    /// before relaying to give the other signers time to catch up.
    pub dkg_begin_pause: Option<Duration>,
}

/// This function defines which messages this event loop is interested
/// in.
fn run_loop_message_filter(signal: &SignerSignal) -> bool {
    match signal {
        SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(msg))) => !matches!(
            msg.payload,
            message::Payload::SignerDepositDecision(_)
                | message::Payload::SignerWithdrawalDecision(_)
                | message::Payload::StacksTransactionSignature(_)
                | message::Payload::BitcoinTransactionSignAck(_)
                | message::Payload::BitcoinPreSignAck(_)
        ),
        SignerSignal::Command(SignerCommand::Shutdown)
        | SignerSignal::Event(SignerEvent::TxCoordinator(TxCoordinatorEvent::MessageGenerated(
            _,
        ))) => true,
        _ => false,
    }
}

impl<C, N, Rng> TxSignerEventLoop<C, N, Rng>
where
    C: Context,
    N: network::MessageTransfer,
    Rng: rand::RngCore + rand::CryptoRng,
{
    /// Run the signer event loop
    #[tracing::instrument(
        skip_all,
        fields(public_key = %self.signer_public_key()),
        name = "tx-signer"
    )]
    pub async fn run(mut self) -> Result<(), Error> {
        if let Err(error) = self.context.signal(TxSignerEvent::EventLoopStarted.into()) {
            tracing::error!(%error, "error signalling event loop start");
            return Err(error);
        };
        let mut signal_stream = self.context.as_signal_stream(run_loop_message_filter);

        while let Some(message) = signal_stream.next().await {
            match message {
                SignerSignal::Command(SignerCommand::Shutdown) => break,
                SignerSignal::Command(SignerCommand::P2PPublish(_)) => {}
                SignerSignal::Event(event) => match event {
                    SignerEvent::TxCoordinator(TxCoordinatorEvent::MessageGenerated(msg))
                    | SignerEvent::P2P(P2PEvent::MessageReceived(msg)) => {
                        if let Err(error) = self.handle_signer_message(&msg).await {
                            tracing::error!(%error, "error handling signer message");
                        }
                    }
                    _ => {}
                },
            }
        }

        tracing::info!("transaction signer event loop has been stopped");
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(chain_tip = tracing::field::Empty))]
    async fn handle_signer_message(&mut self, msg: &network::Msg) -> Result<(), Error> {
        let chain_tip_report = self
            .inspect_msg_chain_tip(msg.signer_public_key, &msg.bitcoin_chain_tip)
            .await?;
        let MsgChainTipReport {
            sender_is_coordinator,
            chain_tip_status,
            chain_tip,
        } = chain_tip_report;

        let span = tracing::Span::current();
        span.record("chain_tip", tracing::field::display(chain_tip));
        tracing::trace!(
            %sender_is_coordinator,
            %chain_tip_status,
            sender = %msg.signer_public_key,
            payload = %msg.inner.payload,
            "handling message from signer"
        );

        match (&msg.inner.payload, sender_is_coordinator, chain_tip_status) {
            (
                message::Payload::StacksTransactionSignRequest(request),
                true,
                ChainTipStatus::Canonical,
            ) => {
                self.handle_stacks_transaction_sign_request(
                    request,
                    &msg.bitcoin_chain_tip,
                    &msg.signer_public_key,
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
                self.handle_wsts_message(
                    wsts_msg,
                    &msg.bitcoin_chain_tip,
                    msg.signer_public_key,
                    &chain_tip_report,
                )
                .await?;
            }

            (message::Payload::BitcoinPreSignRequest(requests), _, _) => {
                self.handle_bitcoin_pre_sign_request(requests, &msg.bitcoin_chain_tip)
                    .await?;
            }
            // Message types ignored by the transaction signer
            (message::Payload::StacksTransactionSignature(_), _, _)
            | (message::Payload::BitcoinTransactionSignAck(_), _, _)
            | (message::Payload::SignerDepositDecision(_), _, _)
            | (message::Payload::SignerWithdrawalDecision(_), _, _) => (),

            // Any other combination should be logged
            _ => {
                tracing::warn!(?msg, ?chain_tip_report, "unexpected message");
            }
        };

        Ok(())
    }

    /// Find out the status of the given chain tip
    #[tracing::instrument(skip_all)]
    async fn inspect_msg_chain_tip(
        &mut self,
        msg_sender: PublicKey,
        msg_bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<MsgChainTipReport, Error> {
        let storage = self.context.get_storage();

        let chain_tip = storage
            .get_bitcoin_canonical_chain_tip()
            .await?
            .ok_or(Error::NoChainTip)?;

        let is_known = storage
            .get_bitcoin_block(msg_bitcoin_chain_tip)
            .await?
            .is_some();
        let is_canonical = msg_bitcoin_chain_tip == &chain_tip;

        let signer_set = self.get_signer_public_keys(&chain_tip).await?;
        let sender_is_coordinator = crate::transaction_coordinator::given_key_is_coordinator(
            msg_sender,
            &chain_tip,
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
            chain_tip,
        })
    }

    /// Processes the [`BitcoinPreSignRequest`] message.
    /// The signer reconstructs the sighashes for the provided requests
    /// based on the current state of its UTXO and fee details obtained
    /// from the coordinator.
    /// It validates the transactions and records its intent to sign them
    /// in the database.
    #[tracing::instrument(skip_all)]
    pub async fn handle_bitcoin_pre_sign_request(
        &mut self,
        request: &message::BitcoinPreSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let db = self.context.get_storage_mut();
        let bitcoin_block = db
            .get_bitcoin_block(bitcoin_chain_tip)
            .await
            .map_err(|_| Error::NoChainTip)?
            .ok_or_else(|| Error::NoChainTip)?;

        let (maybe_aggregate_key, _signer_set) = self
            .get_signer_set_and_aggregate_key(bitcoin_chain_tip)
            .await?;

        let btc_ctx = BitcoinTxContext {
            chain_tip: *bitcoin_chain_tip,
            chain_tip_height: bitcoin_block.block_height,
            context_window: self.context_window,
            signer_public_key: self.signer_public_key(),
            aggregate_key: maybe_aggregate_key.ok_or(Error::NoDkgShares)?,
        };

        tracing::debug!("validating bitcoin transaction pre-sign");
        let sighashes = request
            .construct_package_sighashes(&self.context, &btc_ctx)
            .await?;

        let deposits_sighashes: Vec<model::BitcoinTxSigHash> =
            sighashes.iter().flat_map(|s| s.to_input_rows()).collect();

        let withdrawals_outputs: Vec<model::BitcoinWithdrawalOutput> = sighashes
            .iter()
            .flat_map(|s| s.to_withdrawal_rows())
            .collect();

        tracing::debug!("storing sighashes to the database");
        db.write_bitcoin_txs_sighashes(&deposits_sighashes).await?;

        db.write_bitcoin_withdrawals_outputs(&withdrawals_outputs)
            .await?;

        self.send_message(BitcoinPreSignAck, bitcoin_chain_tip)
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn handle_bitcoin_transaction_sign_request(
        &mut self,
        request: &message::BitcoinTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let is_valid_sign_request = self
            .is_valid_bitcoin_transaction_sign_request(request)
            .await?;

        if is_valid_sign_request {
            let new_state_machine = SignerStateMachine::load(
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
        let signer_pub_key = self.signer_public_key();
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

        debug_assert_eq!(txid, request.txid);

        let signature = crate::signature::sign_stacks_tx(multi_sig.tx(), &self.signer_private_key);

        let msg = message::StacksTransactionSignature { txid, signature };

        self.send_message(msg, bitcoin_chain_tip).await?;

        Ok(())
    }

    /// Check that the transaction is indeed valid. We specific checks that
    /// are run depend on the transaction being signed.
    #[tracing::instrument(skip_all, fields(sender = %origin_public_key, txid = %request.txid), err)]
    pub async fn assert_valid_stacks_tx_sign_request(
        &self,
        request: &StacksTransactionSignRequest,
        chain_tip: &model::BitcoinBlockHash,
        origin_public_key: &PublicKey,
    ) -> Result<(), Error> {
        let db = self.context.get_storage();
        let public_key = self.signer_public_key();

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
        tracing::info!("running validation on stacks transaction");
        match &request.contract_tx {
            StacksTx::ContractCall(ContractCall::AcceptWithdrawalV1(contract)) => {
                contract.validate(ctx, &req_ctx).await?
            }
            StacksTx::ContractCall(ContractCall::CompleteDepositV1(contract)) => {
                contract.validate(ctx, &req_ctx).await?
            }
            StacksTx::ContractCall(ContractCall::RejectWithdrawalV1(contract)) => {
                contract.validate(ctx, &req_ctx).await?
            }
            StacksTx::ContractCall(ContractCall::RotateKeysV1(contract)) => {
                contract.validate(ctx, &req_ctx).await?
            }
            StacksTx::SmartContract(smart_contract) => {
                smart_contract.validate(ctx, &req_ctx).await?
            }
        };

        tracing::info!("stacks validation finished successfully");
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(txid = %msg.txid))]
    async fn handle_wsts_message(
        &mut self,
        msg: &message::WstsMessage,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        msg_public_key: PublicKey,
        chain_tip_report: &MsgChainTipReport,
    ) -> Result<(), Error> {
        match &msg.inner {
            WstsNetMessage::DkgBegin(_) => {
                tracing::info!("handling DkgBegin");

                if !chain_tip_report.sender_is_coordinator {
                    tracing::warn!("received coordinator message from non-coordinator signer");
                    return Ok(());
                }

                let signer_public_keys = self.get_signer_public_keys(bitcoin_chain_tip).await?;

                let state_machine = SignerStateMachine::new(
                    signer_public_keys,
                    self.threshold,
                    self.signer_private_key,
                )?;
                self.wsts_state_machines.insert(msg.txid, state_machine);

                if let Some(pause) = self.dkg_begin_pause {
                    // Let's give the others some slack
                    tracing::debug!(
                        "Sleeping a bit to give the other peers some slack to get DkgBegin"
                    );
                    tokio::time::sleep(pause).await;
                }

                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgPrivateBegin(_) => {
                tracing::info!("handling DkgPrivateBegin");
                if !chain_tip_report.sender_is_coordinator {
                    tracing::warn!("received coordinator message from non-coordinator signer");
                    return Ok(());
                }

                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgPublicShares(dkg_public_shares) => {
                tracing::info!(
                    signer_id = %dkg_public_shares.signer_id,
                    "handling DkgPublicShares",
                );
                let public_keys = match self.wsts_state_machines.get(&msg.txid) {
                    Some(state_machine) => &state_machine.public_keys,
                    None => return Err(Error::MissingStateMachine),
                };
                let signer_public_key = match public_keys.signers.get(&dkg_public_shares.signer_id)
                {
                    Some(key) => PublicKey::from(key),
                    None => return Err(Error::MissingPublicKey),
                };

                if signer_public_key != msg_public_key {
                    return Err(Error::InvalidSignature);
                }
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgPrivateShares(dkg_private_shares) => {
                tracing::info!(
                    signer_id = %dkg_private_shares.signer_id,
                    "handling DkgPrivateShares"
                );
                let public_keys = match self.wsts_state_machines.get(&msg.txid) {
                    Some(state_machine) => &state_machine.public_keys,
                    None => return Err(Error::MissingStateMachine),
                };
                let signer_public_key = match public_keys.signers.get(&dkg_private_shares.signer_id)
                {
                    Some(key) => PublicKey::from(key),
                    None => return Err(Error::MissingPublicKey),
                };

                if signer_public_key != msg_public_key {
                    return Err(Error::InvalidSignature);
                }
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgEndBegin(_) => {
                tracing::info!("handling DkgEndBegin");
                if !chain_tip_report.sender_is_coordinator {
                    tracing::warn!("received coordinator message from non-coordinator signer");
                    return Ok(());
                }
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            // Clippy complains about how we could refactor this to use the
            // `std::collections::hash_map::Entry` type here to make things
            // more idiomatic. The issue with that approach is that it
            // requires a mutable reference of the `wsts_state_machines`
            // self to be taken at the same time as an immutable reference.
            // The compiler will complain about this, so we silence the
            // warning.
            #[allow(clippy::map_entry)]
            WstsNetMessage::NonceRequest(request) => {
                tracing::info!("handling NonceRequest");
                if !chain_tip_report.sender_is_coordinator {
                    tracing::warn!("received coordinator message from non-coordinator signer");
                    return Ok(());
                }

                let db = self.context.get_storage();
                Self::validate_bitcoin_sign_request(&db, &request.message).await?;

                if !self.wsts_state_machines.contains_key(&msg.txid) {
                    let (maybe_aggregate_key, _) = self
                        .get_signer_set_and_aggregate_key(bitcoin_chain_tip)
                        .await?;

                    let state_machine = SignerStateMachine::load(
                        &db,
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
            WstsNetMessage::SignatureShareRequest(request) => {
                tracing::info!("handling SignatureShareRequest");
                if !chain_tip_report.sender_is_coordinator {
                    tracing::warn!("received coordinator message from non-coordinator signer");
                    return Ok(());
                }

                let db = self.context.get_storage();
                Self::validate_bitcoin_sign_request(&db, &request.message).await?;
                self.relay_message(msg.txid, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgEnd(dkg_end) => {
                match &dkg_end.status {
                    DkgStatus::Success => {
                        tracing::info!(
                            signer_id = %dkg_end.signer_id,
                            "handling DkgEnd success from signer"
                        );
                    }
                    DkgStatus::Failure(fail) => {
                        // TODO(#414): handle DKG failure
                        tracing::info!(
                            signer_id = %dkg_end.signer_id,
                            reason = ?fail,
                            "handling DkgEnd failure",
                        );
                    }
                }
            }
            WstsNetMessage::NonceResponse(_) | WstsNetMessage::SignatureShareResponse(_) => {
                tracing::trace!("ignoring message");
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn relay_message(
        &mut self,
        txid: bitcoin::Txid,
        msg: &WstsNetMessage,
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

        for outbound in outbound_messages {
            // We cannot store DKG shares until the signer state machine
            // emits a DkgEnd message, because that is the only way to know
            // whether it has truly received all relevant messages from its
            // peers.
            if let WstsNetMessage::DkgEnd(DkgEnd { status: DkgStatus::Success, .. }) = outbound {
                self.store_dkg_shares(&txid).await?;
            }
            let msg = message::WstsMessage { txid, inner: outbound };

            self.send_message(msg, bitcoin_chain_tip).await?;
        }

        Ok(())
    }

    /// Check whether we will sign the message, which is supposed to be a
    /// bitcoin sighash
    async fn validate_bitcoin_sign_request<D>(db: &D, message: &[u8]) -> Result<(), Error>
    where
        D: DbRead,
    {
        let sighash = TapSighash::from_slice(message)
            .map_err(Error::SigHashConversion)?
            .into();

        match db.will_sign_bitcoin_tx_sighash(&sighash).await? {
            Some(true) => Ok(()),
            Some(false) => Err(Error::InvalidSigHash(sighash)),
            None => Err(Error::UnknownSigHash(sighash)),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn store_dkg_shares(&mut self, txid: &bitcoin::Txid) -> Result<(), Error> {
        let state_machine = self
            .wsts_state_machines
            .get(txid)
            .ok_or(Error::MissingStateMachine)?;

        let encrypted_dkg_shares = state_machine.get_encrypted_dkg_shares(&mut self.rng)?;

        tracing::debug!("storing DKG shares");
        self.context
            .get_storage_mut()
            .write_encrypted_dkg_shares(&encrypted_dkg_shares)
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn send_message(
        &mut self,
        msg: impl Into<message::Payload>,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let payload: message::Payload = msg.into();
        tracing::trace!(%payload, "broadcasting message");

        let msg = payload
            .to_message(*bitcoin_chain_tip)
            .sign_ecdsa(&self.signer_private_key);

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
    #[tracing::instrument(skip_all)]
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

    fn signer_public_key(&self) -> PublicKey {
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
    /// The bitcoin chain tip.
    chain_tip: model::BitcoinBlockHash,
}

/// The status of a chain tip relative to the known blocks in the signer database.
#[derive(Debug, Clone, Copy, strum::Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
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

        // TODO: fix tech debt #893 then raise threshold to 5
        testing::transaction_signer::TestEnvironment {
            context,
            context_window: 6,
            num_signers: 7,
            signing_threshold: 3,
            test_model_parameters,
        }
    }

    #[ignore = "we have a test for this"]
    #[tokio::test]
    async fn should_respond_to_bitcoin_transaction_sign_requests() {
        test_environment()
            .assert_should_respond_to_bitcoin_transaction_sign_requests()
            .await;
    }

    #[ignore = "we have a test for this"]
    #[tokio::test]
    async fn should_be_able_to_participate_in_dkg() {
        test_environment()
            .assert_should_be_able_to_participate_in_dkg()
            .await;
    }

    #[ignore = "we have a test for this"]
    #[tokio::test]
    async fn should_be_able_to_participate_in_signing_round() {
        test_environment()
            .assert_should_be_able_to_participate_in_signing_round()
            .await;
    }
}
