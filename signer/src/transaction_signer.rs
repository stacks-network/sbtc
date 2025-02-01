//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`TxSignerEventLoop`] documentation.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
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
use crate::keys::PublicKeyXOnly;
use crate::message;
use crate::message::BitcoinPreSignAck;
use crate::message::StacksTransactionSignRequest;
use crate::message::WstsMessageId;
use crate::metrics::Metrics;
use crate::metrics::BITCOIN_BLOCKCHAIN;
use crate::metrics::STACKS_BLOCKCHAIN;
use crate::network;
use crate::stacks::contracts::AsContractCall as _;
use crate::stacks::contracts::ContractCall;
use crate::stacks::contracts::ReqContext;
use crate::stacks::contracts::StacksTx;
use crate::stacks::wallet::MultisigTx;
use crate::stacks::wallet::SignerWallet;
use crate::storage::model;
use crate::storage::model::SigHash;
use crate::storage::DbRead;
use crate::storage::DbWrite as _;
use crate::wsts_state_machine::FrostCoordinator;
use crate::wsts_state_machine::SignerStateMachine;
use crate::wsts_state_machine::StateMachineId;
use crate::wsts_state_machine::WstsCoordinator;

use bitcoin::hashes::Hash as _;
use bitcoin::TapSighash;
use futures::StreamExt;
use lru::LruCache;
use wsts::net::DkgEnd;
use wsts::net::DkgStatus;
use wsts::net::Message as WstsNetMessage;
use wsts::state_machine::OperationResult;

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
    ///
    /// - For signing arbitrary data, the TxID is all zeroes.
    ///
    pub wsts_state_machines: LruCache<StateMachineId, SignerStateMachine>,
    /// The threshold for the signer
    pub threshold: u32,
    /// How many bitcoin blocks back from the chain tip the signer will look for requests.
    pub context_window: u16,
    /// Random number generator used for encryption
    pub rng: Rng,
    /// The time the signer should pause for after receiving a DKG begin message
    /// before relaying to give the other signers time to catch up.
    pub dkg_begin_pause: Option<Duration>,
    /// WSTS FROST state machines for verifying full and correct participation
    /// during DKG using the FROST algorithm. This is then used during the
    /// verification of the Stacks rotate-keys transaction.
    pub wsts_frost_state_machines: LruCache<StateMachineId, FrostCoordinator>,
    /// Results of the FROST verification rounds.
    pub wsts_frost_results: LruCache<StateMachineId, bool>,
}

/// This struct represents a signature hash and the public key that locks
/// it.
///
/// The struct is only created when the signer has validated the bitcoin
/// transaction and has agreed to sign the sighash.
struct AcceptedSigHash {
    /// The signature hash to be signed.
    sighash: SigHash,
    /// The public key that is used to lock the above signature hash.
    public_key: PublicKeyXOnly,
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
    /// Creates a new instance of the [`TxSignerEventLoop`] using the given
    /// [`Context`] (and its `config()`),
    /// [`MessageTransfer`](network::MessageTransfer), and random number
    /// generator.
    pub fn new(context: C, network: N, rng: Rng) -> Result<Self, Error> {
        // The _ as usize cast is fine, since we know that
        // MAX_SIGNER_STATE_MACHINES is less than u32::MAX, and we only support
        // running this binary on 32 or 64-bit CPUs.
        let max_state_machines = NonZeroUsize::new(crate::MAX_SIGNER_STATE_MACHINES as usize)
            .ok_or(Error::TypeConversion)?;

        let config = context.config();
        let signer_private_key = config.signer.private_key;
        let context_window = config.signer.context_window;
        let threshold = config.signer.bootstrap_signatures_required.into();

        Ok(Self {
            context,
            network,
            signer_private_key,
            context_window,
            wsts_state_machines: LruCache::new(max_state_machines),
            threshold,
            rng,
            dkg_begin_pause: None,
            wsts_frost_state_machines: LruCache::new(
                NonZeroUsize::new(5).ok_or(Error::TypeConversion)?,
            ),
            wsts_frost_results: LruCache::new(NonZeroUsize::new(5).ok_or(Error::TypeConversion)?),
        })
    }

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
                let instant = std::time::Instant::now();
                let pre_validation_status = self
                    .handle_bitcoin_pre_sign_request(requests, &msg.bitcoin_chain_tip)
                    .await;

                let status = if pre_validation_status.is_ok() {
                    "success"
                } else {
                    "failure"
                };
                metrics::histogram!(
                    Metrics::ValidationDurationSeconds,
                    "blockchain" => BITCOIN_BLOCKCHAIN,
                    "kind" => "sweep-presign",
                    "status" => status,
                )
                .record(instant.elapsed());

                metrics::counter!(
                    Metrics::SignRequestsTotal,
                    "blockchain" => BITCOIN_BLOCKCHAIN,
                    "kind" => "sweep-presign",
                    "status" => status,
                )
                .increment(1);
                pre_validation_status?;
            }
            // Message types ignored by the transaction signer
            (message::Payload::StacksTransactionSignature(_), _, _)
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
    async fn handle_stacks_transaction_sign_request(
        &mut self,
        request: &StacksTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        origin_public_key: &PublicKey,
    ) -> Result<(), Error> {
        let instant = std::time::Instant::now();
        let validation_status = self
            .assert_valid_stacks_tx_sign_request(request, bitcoin_chain_tip, origin_public_key)
            .await;

        metrics::histogram!(
            Metrics::ValidationDurationSeconds,
            "blockchain" => STACKS_BLOCKCHAIN,
            "kind" => request.tx_kind(),
        )
        .record(instant.elapsed());
        metrics::counter!(
            Metrics::SignRequestsTotal,
            "blockchain" => STACKS_BLOCKCHAIN,
            "kind" => request.tx_kind(),
            "status" => if validation_status.is_ok() { "success" } else { "failed" },
        )
        .increment(1);
        validation_status?;

        // We need to set the nonce in order to get the exact transaction
        // that we need to sign.
        let wallet = SignerWallet::load(&self.context, bitcoin_chain_tip).await?;
        wallet.set_nonce(request.nonce);

        let multi_sig = MultisigTx::new_tx(&request.contract_tx, &wallet, request.tx_fee);
        let txid = multi_sig.tx().txid();

        if txid != request.txid {
            return Err(Error::SignerCoordinatorTxidMismatch(txid, request.txid));
        }

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
            return Err(Error::MissingDkgShares(request.aggregate_key.into()));
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
                let aggregate_key = contract.aggregate_key.x_only_public_key().0.into();
                let frost_result = self
                    .wsts_frost_results
                    .peek(&StateMachineId::RotateKey(aggregate_key, *chain_tip));
                dbg!(&self.wsts_frost_results);

                if !matches!(frost_result, Some(true)) {
                    tracing::warn!("no successful frost signing round for the pre-rotate-keys verification signing round; refusing to sign");
                    return Err(Error::FrostVerificationNotSuccessful);
                }

                contract.validate(ctx, &req_ctx).await?
            }
            StacksTx::SmartContract(smart_contract) => {
                smart_contract.validate(ctx, &req_ctx).await?
            }
        };

        tracing::info!("stacks validation finished successfully");
        Ok(())
    }

    /// Process WSTS messages
    #[tracing::instrument(skip_all, fields(
        msg_id = %msg.id,
        msg_type = %msg.type_id(),
        dkg_signer_id = tracing::field::Empty,
        dkg_id = tracing::field::Empty,
        dkg_sign_id = tracing::field::Empty,
        dkg_iter_id = tracing::field::Empty,
        dkg_txid = tracing::field::Empty,
        sender_public_key = %msg_public_key,
    ))]
    pub async fn handle_wsts_message(
        &mut self,
        msg: &message::WstsMessage,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        msg_public_key: PublicKey,
        chain_tip_report: &MsgChainTipReport,
    ) -> Result<(), Error> {
        let span = tracing::Span::current();

        match &msg.inner {
            WstsNetMessage::DkgBegin(request) => {
                span.record("dkg_id", request.dkg_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!("responding to dkg-begin");

                // Assert that DKG should be allowed to proceed given the current state
                // and configuration.
                assert_allow_dkg_begin(&self.context, bitcoin_chain_tip).await?;

                let signer_public_keys = self.get_signer_public_keys(bitcoin_chain_tip).await?;

                let state_machine = SignerStateMachine::new(
                    signer_public_keys,
                    self.threshold,
                    self.signer_private_key,
                )?;
                let id = StateMachineId::Dkg(*bitcoin_chain_tip);
                self.wsts_state_machines.put(id, state_machine);

                if let Some(pause) = self.dkg_begin_pause {
                    // Let's give the others some slack
                    tracing::debug!(
                        "sleeping a bit to give the other peers some slack to get dkg-begin"
                    );
                    tokio::time::sleep(pause).await;
                }

                let id = StateMachineId::Dkg(*bitcoin_chain_tip);
                self.relay_message(id, msg.id, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgPrivateBegin(request) => {
                span.record("dkg_id", request.dkg_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!("responding to dkg-private-begin");

                let id = StateMachineId::Dkg(*bitcoin_chain_tip);
                self.relay_message(id, msg.id, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgPublicShares(request) => {
                span.record("dkg_id", request.dkg_id);
                span.record("dkg_signer_id", request.signer_id);

                tracing::debug!("responding to dkg-public-shares");

                let id = StateMachineId::Dkg(*bitcoin_chain_tip);
                self.validate_sender(&id, request.signer_id, &msg_public_key)?;
                self.relay_message(id, msg.id, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgPrivateShares(request) => {
                span.record("dkg_id", request.dkg_id);
                span.record("dkg_signer_id", request.signer_id);

                tracing::debug!("responding to dkg-private-shares");

                let id = StateMachineId::Dkg(*bitcoin_chain_tip);
                self.validate_sender(&id, request.signer_id, &msg_public_key)?;
                self.relay_message(id, msg.id, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgEndBegin(request) => {
                span.record("dkg_id", request.dkg_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!("responding to dkg-end-begin");

                let id = StateMachineId::Dkg(*bitcoin_chain_tip);
                self.relay_message(id, msg.id, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::DkgEnd(request) => {
                span.record("dkg_id", request.dkg_id);
                span.record("dkg_signer_id", request.signer_id);

                match &request.status {
                    DkgStatus::Success => {
                        tracing::info!(status = "success", "signer reports successful dkg round");
                    }
                    DkgStatus::Failure(fail) => {
                        // TODO(#414): handle DKG failure
                        tracing::warn!(status = "failure", reason = ?fail, "signer reports failed dkg round");
                    }
                }
            }
            WstsNetMessage::NonceRequest(request) => {
                span.record("dkg_id", request.dkg_id);
                span.record("dkg_sign_id", request.sign_id);
                span.record("dkg_iter_id", request.sign_iter_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!(signature_type = ?request.signature_type, "responding to nonce-request");

                let db = self.context.get_storage();

                let (id, aggregate_key) = match msg.id {
                    WstsMessageId::Dkg(_) => {
                        tracing::warn!(
                            "received nonce-request for DKG round, which is not supported"
                        );
                        return Ok(());
                    }
                    WstsMessageId::BitcoinTxid(txid) => {
                        span.record("txid", txid.to_string());
                        tracing::info!(
                            "responding to nonce-request for bitcoin transaction signing"
                        );

                        let accepted_sighash =
                            Self::validate_bitcoin_sign_request(&db, &request.message).await;

                        let validation_status = match &accepted_sighash {
                            Ok(_) => "success",
                            Err(Error::SigHashConversion(_)) => "improper-sighash",
                            Err(Error::UnknownSigHash(_)) => "unknown-sighash",
                            Err(Error::InvalidSigHash(_)) => "invalid-sighash",
                            Err(_) => "unexpected-failure",
                        };

                        metrics::counter!(
                            Metrics::SignRequestsTotal,
                            "blockchain" => BITCOIN_BLOCKCHAIN,
                            "kind" => "sweep",
                            "status" => validation_status,
                        )
                        .increment(1);

                        let accepted_sighash = accepted_sighash?;
                        let id = StateMachineId::BitcoinSign(accepted_sighash.sighash);

                        (id, accepted_sighash.public_key)
                    }
                    WstsMessageId::RotateKey(key) => {
                        // This is a rotate-key verification signing round. The
                        // data provided by the coordinator for signing is
                        // expected to be the current bitcoin chain tip block
                        // hash, which we validate and return an error if it
                        // does not match our view of the current chain tip. We
                        // also verify that the provided aggregate key matches
                        // our latest aggregate key.

                        let new_key: PublicKeyXOnly = key.into();
                        let current_key = db
                            .get_latest_encrypted_dkg_shares()
                            .await?
                            .ok_or(Error::NoDkgShares)?
                            .aggregate_key
                            .into();

                        if new_key != current_key {
                            tracing::warn!(
                                "aggregate key mismatch for rotate-key verification signing"
                            );
                            return Err(Error::AggregateKeyMismatch(
                                Box::new(current_key),
                                Box::new(new_key),
                            ));
                        }

                        tracing::info!(%key, "responding to nonce-request for rotate-key signing");

                        if request.message.len() != 32 {
                            tracing::warn!(
                                "data received for rotate-key verification signing is not 32 bytes"
                            );
                            return Err(Error::InvalidSigningOperation);
                        }
                        if (bitcoin_chain_tip.as_ref()) != request.message.as_slice() {
                            tracing::warn!(
                                data = %hex::encode(&request.message),
                                "data received for rotate-key verification signing does not match current bitcoin chain tip block hash"
                            );
                            return Err(Error::InvalidSigningOperation);
                        }

                        let state_machine_id = self
                            .ensure_rotate_key_state_machine(*bitcoin_chain_tip, new_key)
                            .await?;
                        self.handle_rotate_key_message(new_key, state_machine_id, &msg.inner)
                            .await?;

                        (state_machine_id, new_key)
                    }
                };

                let state_machine = SignerStateMachine::load(
                    &db,
                    aggregate_key,
                    self.threshold,
                    self.signer_private_key,
                )
                .await?;

                self.wsts_state_machines.put(id, state_machine);
                self.relay_message(id, msg.id, &msg.inner, bitcoin_chain_tip)
                    .await?;
            }
            WstsNetMessage::SignatureShareRequest(request) => {
                span.record("dkg_id", request.dkg_id);
                span.record("dkg_sign_id", request.sign_id);
                span.record("dkg_iter_id", request.sign_iter_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                let db = self.context.get_storage();

                let id = match msg.id {
                    WstsMessageId::Dkg(_) => {
                        tracing::warn!("received signature-share-request for DKG round, which is not supported");
                        return Ok(());
                    }
                    WstsMessageId::BitcoinTxid(txid) => {
                        span.record("txid", txid.to_string());
                        tracing::info!(
                            signature_type = ?request.signature_type,
                            "responding to signature-share-request for bitcoin transaction signing"
                        );

                        let accepted_sighash =
                            Self::validate_bitcoin_sign_request(&db, &request.message).await?;

                        accepted_sighash.sighash.into()
                    }
                    WstsMessageId::RotateKey(key) => {
                        // This is a rotate-key verification signing round. The
                        // data provided by the coordinator for signing is
                        // expected to be the current bitcoin chain tip block
                        // hash, which we validate and return an error if it
                        // does not match our view of the current chain tip. We
                        // also verify that the provided aggregate key matches
                        // our latest aggregate key.

                        let new_key: PublicKeyXOnly = key.into();
                        let current_key = db
                            .get_latest_encrypted_dkg_shares()
                            .await?
                            .ok_or(Error::NoDkgShares)?
                            .aggregate_key
                            .into();

                        if new_key != current_key {
                            tracing::warn!(
                                "aggregate key mismatch for rotate-key verification signing"
                            );
                            return Err(Error::AggregateKeyMismatch(
                                Box::new(current_key),
                                Box::new(new_key),
                            ));
                        }

                        if request.message.len() != 32 {
                            tracing::warn!(
                                "data received for rotate-key verification signing is not 32 bytes"
                            );
                            return Err(Error::InvalidSigningOperation);
                        }
                        if (bitcoin_chain_tip.as_ref()) != request.message.as_slice() {
                            tracing::warn!(
                                data = %hex::encode(&request.message),
                                "data received for rotate-key verification signing does not match current bitcoin chain tip block hash"
                            );
                            return Err(Error::InvalidSigningOperation);
                        }

                        tracing::info!(
                            signature_type = ?request.signature_type,
                            "responding to signature-share-request for rotate-key verification signing"
                        );

                        let key = key.into();
                        let state_machine_id = self
                            .ensure_rotate_key_state_machine(*bitcoin_chain_tip, key)
                            .await?;
                        self.handle_rotate_key_message(key, state_machine_id, &msg.inner)
                            .await?;
                        state_machine_id
                    }
                };

                let response = self
                    .relay_message(id, msg.id, &msg.inner, bitcoin_chain_tip)
                    .await;

                self.wsts_state_machines.pop(&id);
                response?;
            }
            WstsNetMessage::NonceResponse(request) => {
                span.record("dkg_id", request.dkg_id);
                span.record("dkg_signer_id", request.signer_id);
                span.record("dkg_sign_id", request.sign_id);
                span.record("dkg_iter_id", request.sign_iter_id);

                let WstsMessageId::RotateKey(key) = msg.id else {
                    return Ok(());
                };

                let key = key.into();

                let state_machine_id = self
                    .ensure_rotate_key_state_machine(*bitcoin_chain_tip, key)
                    .await?;
                self.handle_rotate_key_message(key, state_machine_id, &msg.inner)
                    .await?;
            }
            WstsNetMessage::SignatureShareResponse(request) => {
                span.record("dkg_id", request.dkg_id);
                span.record("dkg_signer_id", request.signer_id);
                span.record("dkg_sign_id", request.sign_id);
                span.record("dkg_iter_id", request.sign_iter_id);

                let WstsMessageId::RotateKey(key) = msg.id else {
                    return Ok(());
                };

                let key = key.into();

                let state_machine_id = self
                    .ensure_rotate_key_state_machine(*bitcoin_chain_tip, key)
                    .await?;
                self.handle_rotate_key_message(key, state_machine_id, &msg.inner)
                    .await?;
            }
        }

        Ok(())
    }

    /// This function is used to verify that the sender in the message
    /// matches the signer in the corresponding state machine.
    fn validate_sender(
        &mut self,
        id: &StateMachineId,
        signer_id: u32,
        sender_public_key: &PublicKey,
    ) -> Result<(), Error> {
        let public_keys = match self.wsts_state_machines.get(id) {
            Some(state_machine) => &state_machine.public_keys,
            None => return Err(Error::MissingStateMachine),
        };

        let wsts_public_key = public_keys
            .signers
            .get(&signer_id)
            .map(PublicKey::from)
            .ok_or(Error::MissingPublicKey)?;

        if &wsts_public_key != sender_public_key {
            let sender = Box::new(*sender_public_key);
            let wsts = Box::new(wsts_public_key);
            return Err(Error::PublicKeyMismatch { wsts, sender });
        }

        Ok(())
    }

    /// Check whether we will sign the message, which is supposed to be a
    /// bitcoin sighash
    async fn validate_bitcoin_sign_request<D>(db: &D, msg: &[u8]) -> Result<AcceptedSigHash, Error>
    where
        D: DbRead,
    {
        let sighash = TapSighash::from_slice(msg)
            .map_err(Error::SigHashConversion)?
            .into();

        match db.will_sign_bitcoin_tx_sighash(&sighash).await? {
            Some((true, public_key)) => Ok(AcceptedSigHash { public_key, sighash }),
            Some((false, _)) => Err(Error::InvalidSigHash(sighash)),
            None => Err(Error::UnknownSigHash(sighash)),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn store_dkg_shares(&mut self, id: &StateMachineId) -> Result<(), Error> {
        let state_machine = self
            .wsts_state_machines
            .get(id)
            .ok_or(Error::MissingStateMachine)?;

        let encrypted_dkg_shares = state_machine.get_encrypted_dkg_shares(&mut self.rng)?;

        tracing::debug!("storing DKG shares");
        self.context
            .get_storage_mut()
            .write_encrypted_dkg_shares(&encrypted_dkg_shares)
            .await?;

        Ok(())
    }

    async fn ensure_rotate_key_state_machine(
        &mut self,
        bitcoin_chain_tip: model::BitcoinBlockHash,
        aggregate_key: PublicKeyXOnly,
    ) -> Result<StateMachineId, Error> {
        let state_machine_id = StateMachineId::RotateKey(aggregate_key, bitcoin_chain_tip);

        match self.wsts_frost_state_machines.get_mut(&state_machine_id) {
            Some(_) => {}
            None => {
                let storage = self.context.get_storage();

                let dkg_shares = storage
                    .get_encrypted_dkg_shares(aggregate_key)
                    .await?
                    .ok_or_else(|| {
                        tracing::warn!("no DKG shares found for requested aggregate key");
                        Error::MissingDkgShares(aggregate_key)
                    })?;

                let signing_set: BTreeSet<PublicKey> = dkg_shares
                    .signer_set_public_keys
                    .into_iter()
                    .collect::<BTreeSet<_>>();

                tracing::debug!(
                    num_signers = signing_set.len(),
                    %aggregate_key,
                    threshold = %dkg_shares.signature_share_threshold,
                    "creating now frost coordinator to track pre-rotate-key validation signing round"
                );

                let coordinator = FrostCoordinator::load(
                    &storage,
                    aggregate_key,
                    signing_set,
                    dkg_shares.signature_share_threshold,
                    self.signer_private_key,
                )
                .await?;

                self.wsts_frost_state_machines
                    .get_or_insert_mut(state_machine_id, || coordinator);
            }
        }

        Ok(state_machine_id)
    }

    #[tracing::instrument(skip_all)]
    async fn handle_rotate_key_message(
        &mut self,
        aggregate_key: PublicKeyXOnly,
        id: StateMachineId,
        msg: &WstsNetMessage,
    ) -> Result<(), Error> {
        let state_machine = self.wsts_frost_state_machines.get_mut(&id);
        let Some(state_machine) = state_machine else {
            tracing::warn!("missing frost coordinator for pre-rotate-key validation");
            return Err(Error::MissingFrostStateMachine(Box::new(aggregate_key)));
        };

        tracing::info!(?msg, "processing frost coordinator message");

        let (_, result) = state_machine.process_message(msg)?;

        match result {
            Some(OperationResult::SignSchnorr(_)) => {
                tracing::info!("successfully completed pre-rotate-key validation signing round");
                self.wsts_frost_results.put(id, true);
                self.wsts_frost_state_machines.pop(&id);
            }
            Some(OperationResult::SignError(error)) => {
                tracing::warn!(
                    ?msg,
                    ?error,
                    "failed to complete pre-rotate-key validation signing round"
                );
                self.wsts_frost_results.put(id, false);
            }
            None => {}
            result => {
                tracing::warn!(?result, "unexpected frost coordinator result");
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn relay_message(
        &mut self,
        state_machine_id: StateMachineId,
        wsts_id: WstsMessageId,
        msg: &WstsNetMessage,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let Some(state_machine) = self.wsts_state_machines.get_mut(&state_machine_id) else {
            tracing::warn!("missing signing round");
            return Err(Error::MissingStateMachine);
        };

        let mut frost_coordinator = if let StateMachineId::RotateKey(_, _) = state_machine_id {
            self.wsts_frost_state_machines.get_mut(&state_machine_id)
        } else {
            None
        };

        let outbound_messages = state_machine.process(msg).map_err(Error::Wsts)?;

        for outbound_message in outbound_messages.iter() {
            // The WSTS state machine assume we read our own messages
            state_machine
                .process(outbound_message)
                .map_err(Error::Wsts)?;

            if let Some(frost_coordinator) = &mut frost_coordinator {
                let (_, result) = frost_coordinator.process_message(outbound_message)?;
                tracing::info!(?outbound_message, ?result, state = ?frost_coordinator.state, "\x1b[1;36mfrost coordinator\x1b[0m relay_message result")
            }
        }

        for outbound in outbound_messages {
            // We cannot store DKG shares until the signer state machine
            // emits a DkgEnd message, because that is the only way to know
            // whether it has truly received all relevant messages from its
            // peers.
            if let WstsNetMessage::DkgEnd(DkgEnd { status: DkgStatus::Success, .. }) = outbound {
                self.store_dkg_shares(&state_machine_id).await?;
                self.wsts_state_machines.pop(&state_machine_id);
            }
            let msg = message::WstsMessage { id: wsts_id, inner: outbound };

            self.send_message(msg, bitcoin_chain_tip).await?;
        }

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

/// Asserts whether a `DkgBegin` WSTS message should be allowed to proceed
/// based on the current state of the signer and the DKG configuration.
async fn assert_allow_dkg_begin(
    context: &impl Context,
    bitcoin_chain_tip: &model::BitcoinBlockHash,
) -> Result<(), Error> {
    let storage = context.get_storage();
    let config = context.config();

    // Get the bitcoin block at the chain tip so that we know the height
    let bitcoin_chain_tip_block = storage
        .get_bitcoin_block(bitcoin_chain_tip)
        .await?
        .ok_or(Error::NoChainTip)?;

    // Get the number of DKG shares that have been stored
    let dkg_shares_entry_count = storage.get_encrypted_dkg_shares_count().await?;

    // Get DKG configuration parameters
    let dkg_min_bitcoin_block_height = config.signer.dkg_min_bitcoin_block_height;
    let dkg_target_rounds = config.signer.dkg_target_rounds;

    // Determine the action based on the DKG shares count and the rerun height (if configured)
    match (
        dkg_shares_entry_count,
        dkg_target_rounds,
        dkg_min_bitcoin_block_height,
    ) {
        (0, _, _) => {
            tracing::info!(
                ?dkg_min_bitcoin_block_height,
                %dkg_target_rounds,
                "no DKG shares exist; proceeding with DKG"
            );
        }
        (current, target, Some(dkg_min_height)) => {
            if current >= target.get() {
                tracing::warn!(
                    ?dkg_min_bitcoin_block_height,
                    %dkg_target_rounds,
                    dkg_current_rounds = %dkg_shares_entry_count,
                    "The target number of DKG shares has been reached; aborting"
                );
                return Err(Error::DkgHasAlreadyRun);
            }
            if bitcoin_chain_tip_block.block_height < dkg_min_height.get() {
                tracing::warn!(
                    ?dkg_min_bitcoin_block_height,
                    %dkg_target_rounds,
                    dkg_current_rounds = %dkg_shares_entry_count,
                    "bitcoin chain tip is below the minimum height for DKG rerun; aborting"
                );
                return Err(Error::DkgHasAlreadyRun);
            }
            tracing::info!(
                ?dkg_min_bitcoin_block_height,
                %dkg_target_rounds,
                dkg_current_rounds = %dkg_shares_entry_count,
                "DKG rerun height has been met and we are below the target number of rounds; proceeding with DKG"
            );
        }
        // Note that we account for all (0, _, _) cases above (i.e. first DKG round)
        (_, _, None) => {
            tracing::warn!(
                ?dkg_min_bitcoin_block_height,
                %dkg_target_rounds,
                dkg_current_rounds = %dkg_shares_entry_count,
                "attempt to run multiple DKGs without a configured re-run height; aborting"
            );
            return Err(Error::DkgHasAlreadyRun);
        }
    }

    Ok(())
}

/// Relevant information for validating incoming messages
/// relating to a particular chain tip.
#[derive(Debug, Clone, Copy)]
pub struct MsgChainTipReport {
    /// Whether the sender of the incoming message is the coordinator for this chain tip.
    pub sender_is_coordinator: bool,
    /// The status of the chain tip relative to the signers' perspective.
    pub chain_tip_status: ChainTipStatus,
    /// The bitcoin chain tip.
    pub chain_tip: model::BitcoinBlockHash,
}

impl MsgChainTipReport {
    /// Checks if the message is for the canonical chain tip from the coordinator
    pub fn is_from_canonical_coordinator(&self) -> bool {
        self.chain_tip_status == ChainTipStatus::Canonical && self.sender_is_coordinator
    }
}

/// The status of a chain tip relative to the known blocks in the signer database.
#[derive(Debug, Clone, Copy, PartialEq, strum::Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainTipStatus {
    /// The chain tip is the tip of the canonical fork.
    Canonical,
    /// The chain tip is for a known block, but is not the canonical chain tip.
    Known,
    /// The chain tip belongs to a block that hasn't been seen yet.
    Unknown,
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};

    use bitcoin::Txid;
    use fake::{Fake, Faker};
    use network::InMemoryNetwork;
    use test_case::test_case;

    use crate::bitcoin::MockBitcoinInteract;
    use crate::context::Context;
    use crate::emily_client::MockEmilyInteract;
    use crate::stacks::api::MockStacksInteract;
    use crate::storage::in_memory::SharedStore;
    use crate::storage::{model, DbWrite};
    use crate::testing;
    use crate::testing::context::*;

    use super::*;

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
            consecutive_blocks: false,
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
    async fn should_be_able_to_participate_in_dkg() {
        test_environment()
            .assert_should_be_able_to_participate_in_dkg()
            .await;
    }

    #[test_case(0, None, 1, 100, true; "first DKG allowed without min height")]
    #[test_case(0, Some(100), 1, 5, true; "first DKG allowed regardless of min height")]
    #[test_case(1, None, 2, 100, false; "subsequent DKG not allowed without min height")]
    #[test_case(1, Some(101), 1, 100, false; "subsequent DKG not allowed with current height lower than min height")]
    #[test_case(1, Some(100), 1, 100, false; "subsequent DKG not allowed when target rounds reached")]
    #[test_case(1, Some(100), 2, 100, true; "subsequent DKG allowed when target rounds not reached and min height met")]
    #[test_log::test(tokio::test)]
    async fn test_assert_allow_dkg_begin(
        dkg_rounds_current: u32,
        dkg_min_bitcoin_block_height: Option<u64>,
        dkg_target_rounds: u32,
        chain_tip_height: u64,
        should_allow: bool,
    ) {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|s| {
                s.signer.dkg_min_bitcoin_block_height =
                    dkg_min_bitcoin_block_height.map(NonZeroU64::new).flatten();
                s.signer.dkg_target_rounds = NonZeroU32::new(dkg_target_rounds).unwrap();
            })
            .build();

        let storage = context.get_storage_mut();

        // Write `dkg_shares` entries for the `current` number of rounds, simulating
        // the signer having participated in that many successful DKG rounds.
        for _ in 0..dkg_rounds_current {
            storage
                .write_encrypted_dkg_shares(&Faker.fake())
                .await
                .unwrap();
        }

        // Dummy chain tip hash which will be used to fetch the block height
        let bitcoin_chain_tip: model::BitcoinBlockHash = Faker.fake();

        // Write a bitcoin block at the given height, simulating the chain tip.
        storage
            .write_bitcoin_block(&model::BitcoinBlock {
                block_height: chain_tip_height,
                parent_hash: Faker.fake(),
                block_hash: bitcoin_chain_tip,
            })
            .await
            .unwrap();

        // Test the case
        let result = assert_allow_dkg_begin(&context, &bitcoin_chain_tip).await;

        // Assert the result
        match should_allow {
            true => assert!(result.is_ok()),
            false => assert!(matches!(result, Err(Error::DkgHasAlreadyRun))),
        }
    }

    #[tokio::test]
    async fn test_handle_wsts_message_asserts_dkg_begin() {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let storage = context.get_storage_mut();
        let network = InMemoryNetwork::new();

        // Write 1 DKG shares entry to the database, simulating that DKG has
        // successfully run once.
        storage
            .write_encrypted_dkg_shares(&Faker.fake())
            .await
            .unwrap();

        // Dummy chain tip hash which will be used to fetch the block height.
        let bitcoin_chain_tip: model::BitcoinBlockHash = Faker.fake();

        // Write a bitcoin block at the given height, simulating the chain tip.
        storage
            .write_bitcoin_block(&model::BitcoinBlock {
                block_height: 100,
                parent_hash: Faker.fake(),
                block_hash: bitcoin_chain_tip,
            })
            .await
            .unwrap();

        // Create our signer instance.
        let mut signer = TxSignerEventLoop {
            context,
            network: network.connect(),
            signer_private_key: PrivateKey::new(&mut rand::rngs::OsRng),
            context_window: 1,
            wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
            threshold: 1,
            rng: rand::rngs::OsRng,
            dkg_begin_pause: None,
            wsts_frost_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            wsts_frost_results: LruCache::new(NonZeroUsize::new(5).unwrap()),
        };

        // Create a DkgBegin message to be handled by the signer.
        let msg = message::WstsMessage {
            id: WstsMessageId::Dkg(Faker.fake()),
            inner: WstsNetMessage::DkgBegin(wsts::net::DkgBegin { dkg_id: 0 }),
        };

        // Create a chain tip report for the message.
        let chain_tip_report = MsgChainTipReport {
            sender_is_coordinator: true,
            chain_tip_status: ChainTipStatus::Canonical,
            chain_tip: bitcoin_chain_tip,
        };

        // Attempt to handle the DkgBegin message. This should fail using the
        // default settings, as the default settings allow only one DKG round.
        let result = signer
            .handle_wsts_message(&msg, &bitcoin_chain_tip, Faker.fake(), &chain_tip_report)
            .await;

        // Assert that the DkgBegin message was not allowed to proceed and
        // that we receive the expected error.
        assert!(matches!(result, Err(Error::DkgHasAlreadyRun)));
    }

    #[tokio::test]
    async fn test_handle_wsts_message_non_canonical_dkg_begin() {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let storage = context.get_storage_mut();
        let network = InMemoryNetwork::new();

        // Write 1 DKG shares entry to the database, simulating that DKG has
        // successfully run once.
        storage
            .write_encrypted_dkg_shares(&Faker.fake())
            .await
            .unwrap();

        // Dummy chain tip hash which will be used to fetch the block height.
        let bitcoin_chain_tip: model::BitcoinBlockHash = Faker.fake();

        // Write a bitcoin block at the given height, simulating the chain tip.
        storage
            .write_bitcoin_block(&model::BitcoinBlock {
                block_height: 100,
                parent_hash: Faker.fake(),
                block_hash: bitcoin_chain_tip,
            })
            .await
            .unwrap();

        // Create our signer instance.
        let mut signer = TxSignerEventLoop {
            context,
            network: network.connect(),
            signer_private_key: PrivateKey::new(&mut rand::rngs::OsRng),
            context_window: 1,
            wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
            threshold: 1,
            rng: rand::rngs::OsRng,
            dkg_begin_pause: None,
            wsts_frost_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            wsts_frost_results: LruCache::new(NonZeroUsize::new(5).unwrap()),
        };

        // Create a DkgBegin message to be handled by the signer.
        let msg = message::WstsMessage {
            id: Txid::all_zeros().into(),
            inner: WstsNetMessage::DkgBegin(wsts::net::DkgBegin { dkg_id: 0 }),
        };

        // Create a chain tip report for the message as if it was coming from a
        // non canonical chain tip
        let chain_tip_report = MsgChainTipReport {
            sender_is_coordinator: true,
            chain_tip_status: ChainTipStatus::Known,
            chain_tip: Faker.fake(),
        };

        // We shouldn't get an error as we stop to process the message early
        signer
            .handle_wsts_message(&msg, &bitcoin_chain_tip, Faker.fake(), &chain_tip_report)
            .await
            .expect("expected success");
    }

    #[test_case(
        WstsNetMessage::DkgPrivateBegin(wsts::net::DkgPrivateBegin {
            dkg_id: 0,
            signer_ids: vec![],
            key_ids: vec![],
        }); "DkgPrivateBegin")]
    #[test_case(
        WstsNetMessage::DkgEndBegin(wsts::net::DkgEndBegin {
            dkg_id: 0,
            signer_ids: vec![],
            key_ids: vec![],
        }); "DkgEndBegin")]
    #[test_case(
        WstsNetMessage::NonceRequest(wsts::net::NonceRequest {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            message: vec![],
            signature_type: wsts::net::SignatureType::Schnorr,
        }); "NonceRequest")]
    #[test_case(
        WstsNetMessage::SignatureShareRequest(wsts::net::SignatureShareRequest {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            message: vec![],
            signature_type: wsts::net::SignatureType::Schnorr,
            nonce_responses: vec![],
        }); "SignatureShareRequest")]
    #[tokio::test]
    async fn test_handle_wsts_message_non_canonical(wsts_message: WstsNetMessage) {
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let storage = context.get_storage_mut();
        let network = InMemoryNetwork::new();

        let bitcoin_chain_tip: model::BitcoinBlockHash = Faker.fake();

        // Write a bitcoin block at the given height, simulating the chain tip.
        storage
            .write_bitcoin_block(&model::BitcoinBlock {
                block_height: 100,
                parent_hash: Faker.fake(),
                block_hash: bitcoin_chain_tip,
            })
            .await
            .unwrap();

        // Create our signer instance.
        let mut signer = TxSignerEventLoop {
            context,
            network: network.connect(),
            signer_private_key: PrivateKey::new(&mut rand::rngs::OsRng),
            context_window: 1,
            wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
            threshold: 1,
            rng: rand::rngs::OsRng,
            dkg_begin_pause: None,
            wsts_frost_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            wsts_frost_results: LruCache::new(NonZeroUsize::new(5).unwrap()),
        };

        let msg = message::WstsMessage {
            id: Txid::all_zeros().into(),
            inner: wsts_message,
        };

        // Create a chain tip report for the message as if it was coming from a
        // non canonical chain tip
        let chain_tip_report = MsgChainTipReport {
            sender_is_coordinator: true,
            chain_tip_status: ChainTipStatus::Known,
            chain_tip: Faker.fake(),
        };

        // We shouldn't get an error as we stop to process the message early
        signer
            .handle_wsts_message(&msg, &bitcoin_chain_tip, Faker.fake(), &chain_tip_report)
            .await
            .expect("expected success");
    }
}
