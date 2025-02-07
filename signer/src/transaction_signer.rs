//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`TxSignerEventLoop`] documentation.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::time::Duration;

use crate::bitcoin::utxo::UnsignedMockTransaction;
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
use crate::message::Payload;
use crate::message::StacksTransactionSignRequest;
use crate::message::WstsMessageId;
use crate::metrics::Metrics;
use crate::metrics::BITCOIN_BLOCKCHAIN;
use crate::metrics::STACKS_BLOCKCHAIN;
use crate::network;
use crate::signature::TaprootSignature;
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
    /// WSTS state machines for active signing and DKG rounds.
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
    pub dkg_verification_state_machines: LruCache<StateMachineId, FrostCoordinator>,
    /// Results of DKG verification rounds.
    pub dkg_verification_results: LruCache<StateMachineId, UnsignedMockTransaction>,
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
        let dkg_begin_pause = config.signer.dkg_begin_pause.map(Duration::from_secs);

        Ok(Self {
            context,
            network,
            signer_private_key,
            context_window,
            wsts_state_machines: LruCache::new(max_state_machines),
            threshold,
            rng,
            dkg_begin_pause,
            dkg_verification_state_machines: LruCache::new(
                NonZeroUsize::new(5).ok_or(Error::TypeConversion)?,
            ),
            dkg_verification_results: LruCache::new(
                NonZeroUsize::new(5).ok_or(Error::TypeConversion)?,
            ),
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
                            tracing::error!(%error, "error processing signer message");
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
        span.record("chain_tip", tracing::field::display(chain_tip.block_hash));
        tracing::trace!(
            %sender_is_coordinator,
            %chain_tip_status,
            sender = %msg.signer_public_key,
            payload = %msg.inner.payload,
            "handling message from signer"
        );

        let payload = &msg.inner.payload;
        match (payload, sender_is_coordinator, chain_tip_status) {
            (Payload::StacksTransactionSignRequest(request), true, ChainTipStatus::Canonical) => {
                self.handle_stacks_transaction_sign_request(
                    request,
                    &chain_tip,
                    &msg.signer_public_key,
                )
                .await?;
            }

            (Payload::WstsMessage(wsts_msg), _, ChainTipStatus::Canonical) => {
                self.handle_wsts_message(wsts_msg, msg.signer_public_key, &chain_tip_report)
                    .await?;
            }

            (Payload::BitcoinPreSignRequest(requests), true, ChainTipStatus::Canonical) => {
                let instant = std::time::Instant::now();
                let pre_validation_status = self
                    .handle_bitcoin_pre_sign_request(requests, &chain_tip)
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
            (Payload::StacksTransactionSignature(_), _, _)
            | (Payload::SignerDepositDecision(_), _, _)
            | (Payload::SignerWithdrawalDecision(_), _, _) => (),

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
            .get_bitcoin_canonical_chain_tip_ref()
            .await?
            .ok_or(Error::NoChainTip)?;

        let is_known = storage
            .get_bitcoin_block(msg_bitcoin_chain_tip)
            .await?
            .is_some();
        let is_canonical = msg_bitcoin_chain_tip == &chain_tip.block_hash;

        let signer_set = self.context.state().current_signer_public_keys();
        let sender_is_coordinator = crate::transaction_coordinator::given_key_is_coordinator(
            msg_sender,
            &chain_tip.block_hash,
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
        chain_tip: &model::BitcoinBlockRef,
    ) -> Result<(), Error> {
        let db = self.context.get_storage_mut();

        let maybe_aggregate_key = self.context.state().current_aggregate_key();

        let btc_ctx = BitcoinTxContext {
            chain_tip: chain_tip.block_hash,
            chain_tip_height: chain_tip.block_height,
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

        self.send_message(BitcoinPreSignAck, &chain_tip.block_hash)
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn handle_stacks_transaction_sign_request(
        &mut self,
        request: &StacksTransactionSignRequest,
        chain_tip: &model::BitcoinBlockRef,
        origin_public_key: &PublicKey,
    ) -> Result<(), Error> {
        let instant = std::time::Instant::now();
        let validation_status = self
            .assert_valid_stacks_tx_sign_request(request, chain_tip, origin_public_key)
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
        let wallet = SignerWallet::load(&self.context, &chain_tip.block_hash).await?;
        wallet.set_nonce(request.nonce);

        let multi_sig = MultisigTx::new_tx(&request.contract_tx, &wallet, request.tx_fee);
        let txid = multi_sig.tx().txid();

        if txid != request.txid {
            return Err(Error::SignerCoordinatorTxidMismatch(txid, request.txid));
        }

        let signature = crate::signature::sign_stacks_tx(multi_sig.tx(), &self.signer_private_key);

        let msg = message::StacksTransactionSignature { txid, signature };

        self.send_message(msg, &chain_tip.block_hash).await?;

        Ok(())
    }

    /// Check that the transaction is indeed valid. We specific checks that
    /// are run depend on the transaction being signed.
    #[tracing::instrument(skip_all, fields(sender = %origin_public_key, txid = %request.txid), err)]
    pub async fn assert_valid_stacks_tx_sign_request(
        &self,
        request: &StacksTransactionSignRequest,
        chain_tip: &model::BitcoinBlockRef,
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

        let req_ctx = ReqContext {
            chain_tip: *chain_tip,
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

    /// Process WSTS messages
    #[tracing::instrument(skip_all, fields(
        wsts_msg_id = %msg.id,
        wsts_msg_type = %msg.type_id(),
        wsts_signer_id = tracing::field::Empty,
        wsts_dkg_id = tracing::field::Empty,
        wsts_sign_id = tracing::field::Empty,
        wsts_sign_iter_id = tracing::field::Empty,
        sender_public_key = %msg_public_key,
    ))]
    pub async fn handle_wsts_message(
        &mut self,
        msg: &message::WstsMessage,
        msg_public_key: PublicKey,
        chain_tip_report: &MsgChainTipReport,
    ) -> Result<(), Error> {
        // Constants for tracing.
        const WSTS_DKG_ID: &str = "wsts_dkg_id";
        const WSTS_SIGNER_ID: &str = "wsts_signer_id";
        const WSTS_SIGN_ID: &str = "wsts_sign_id";
        const WSTS_SIGN_ITER_ID: &str = "wsts_sign_iter_id";
        // Get the current tracing span.
        let span = tracing::Span::current();

        let MsgChainTipReport { chain_tip, .. } = chain_tip_report;

        match &msg.inner {
            WstsNetMessage::DkgBegin(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!("processing message");

                // Assert that DKG should be allowed to proceed given the current state
                // and configuration.
                assert_allow_dkg_begin(&self.context, chain_tip).await?;

                let signer_public_keys = self.context.state().current_signer_public_keys();

                let state_machine = SignerStateMachine::new(
                    signer_public_keys,
                    self.threshold,
                    self.signer_private_key,
                )?;
                let id = StateMachineId::Dkg(*chain_tip);
                self.wsts_state_machines.put(id, state_machine);

                if let Some(pause) = self.dkg_begin_pause {
                    // Let's give the others some slack
                    tracing::debug!(
                        "sleeping a bit to give the other peers some slack to get dkg-begin"
                    );
                    tokio::time::sleep(pause).await;
                }

                self.relay_message(id, msg.id, &msg.inner, &chain_tip.block_hash)
                    .await?;
            }
            WstsNetMessage::DkgPrivateBegin(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!("processing message");

                let id = StateMachineId::Dkg(*chain_tip);
                self.relay_message(id, msg.id, &msg.inner, &chain_tip.block_hash)
                    .await?;
            }
            WstsNetMessage::DkgPublicShares(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);
                span.record(WSTS_SIGNER_ID, request.signer_id);

                tracing::debug!("processing message");

                let id = StateMachineId::Dkg(*chain_tip);
                self.validate_sender(&id, request.signer_id, &msg_public_key)?;
                self.relay_message(id, msg.id, &msg.inner, &chain_tip.block_hash)
                    .await?;
            }
            WstsNetMessage::DkgPrivateShares(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);
                span.record(WSTS_SIGNER_ID, request.signer_id);

                tracing::debug!("processing message");

                let id = StateMachineId::Dkg(*chain_tip);
                self.validate_sender(&id, request.signer_id, &msg_public_key)?;
                self.relay_message(id, msg.id, &msg.inner, &chain_tip.block_hash)
                    .await?;
            }
            WstsNetMessage::DkgEndBegin(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!("processing message");
                let id = StateMachineId::Dkg(*chain_tip);
                self.relay_message(id, msg.id, &msg.inner, &chain_tip.block_hash)
                    .await?;
            }
            WstsNetMessage::DkgEnd(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);
                span.record(WSTS_SIGNER_ID, request.signer_id);

                match &request.status {
                    DkgStatus::Success => {
                        tracing::info!(
                            wsts_dkg_status = "success",
                            "signer reports successful DKG round"
                        );
                    }
                    DkgStatus::Failure(reason) => {
                        tracing::warn!(
                            wsts_dkg_status = "failure",
                            ?reason,
                            "signer reports failed DKG round"
                        );
                    }
                }
            }
            WstsNetMessage::NonceRequest(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);
                span.record(WSTS_SIGN_ID, request.sign_id);
                span.record(WSTS_SIGN_ITER_ID, request.sign_iter_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!(signature_type = ?request.signature_type, "processing message");

                let db = self.context.get_storage();

                let (id, aggregate_key) = match msg.id {
                    WstsMessageId::Dkg(_) => {
                        tracing::warn!("received message is not allowed in the current context");
                        return Ok(());
                    }
                    WstsMessageId::Sweep(txid) => {
                        span.record("txid", txid.to_string());

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
                    WstsMessageId::DkgVerification(key) => {
                        // This is a DKG verification signing round. The data
                        // provided by the coordinator for signing is expected
                        // to be the current bitcoin chain tip block hash, which
                        // we validate and return an error if it does not match
                        // our view of the current chain tip. We also verify
                        // that the provided aggregate key matches our latest
                        // aggregate key.

                        let new_key: PublicKeyXOnly = key.into();

                        // Validate the received message.
                        Self::validate_dkg_verification_message(
                            &db,
                            &new_key,
                            Some(&request.message),
                        )
                        .await?;

                        let (state_machine_id, _, mock_tx) = self
                            .ensure_dkg_verification_state_machine(&chain_tip.block_hash, new_key)
                            .await?;

                        let tap_sighash = mock_tx.compute_sighash()?;
                        if tap_sighash.as_byte_array() != request.message.as_slice() {
                            tracing::warn!("🔐 sighash mismatch for DKG verification signing");
                            return Err(Error::InvalidSigningOperation);
                        }

                        self.handle_dkg_verification_message(state_machine_id, &msg.inner)
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
                self.relay_message(id, msg.id, &msg.inner, &chain_tip.block_hash)
                    .await?;
            }
            WstsNetMessage::SignatureShareRequest(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);
                span.record(WSTS_SIGN_ID, request.sign_id);
                span.record(WSTS_SIGN_ITER_ID, request.sign_iter_id);

                if !chain_tip_report.is_from_canonical_coordinator() {
                    tracing::warn!(
                        ?chain_tip_report,
                        "received coordinator message from a non canonical coordinator"
                    );
                    return Ok(());
                }

                tracing::debug!(signature_type = ?request.signature_type, "processing message");

                let db = self.context.get_storage();

                let id = match msg.id {
                    WstsMessageId::Dkg(_) => {
                        tracing::warn!("received message is not allowed in the current context");
                        return Ok(());
                    }
                    WstsMessageId::Sweep(txid) => {
                        span.record("txid", txid.to_string());
                        tracing::debug!(
                            signature_type = ?request.signature_type,
                            "processing message"
                        );

                        let accepted_sighash =
                            Self::validate_bitcoin_sign_request(&db, &request.message).await?;

                        accepted_sighash.sighash.into()
                    }
                    WstsMessageId::DkgVerification(key) => {
                        // This is a DKG verification signing round. The data
                        // provided by the coordinator for signing is expected
                        // to be the current bitcoin chain tip block hash, which
                        // we validate and return an error if it does not match
                        // our view of the current chain tip. We also verify
                        // that the provided aggregate key matches our latest
                        // aggregate key.

                        let new_key: PublicKeyXOnly = key.into();

                        // Validate the received message.
                        Self::validate_dkg_verification_message(
                            &db,
                            &new_key,
                            Some(&request.message),
                        )
                        .await?;

                        tracing::info!(
                            signature_type = ?request.signature_type,
                            "🔐 responding to signature-share-request for DKG verification signing"
                        );

                        let (state_machine_id, _, mock_tx) = self
                            .ensure_dkg_verification_state_machine(&chain_tip.block_hash, new_key)
                            .await?;

                        let tap_sighash = mock_tx.compute_sighash()?;
                        if tap_sighash.as_byte_array() != request.message.as_slice() {
                            tracing::warn!("🔐 sighash mismatch for DKG verification signing");
                            return Err(Error::InvalidSigningOperation);
                        }

                        self.handle_dkg_verification_message(state_machine_id, &msg.inner)
                            .await?;
                        state_machine_id
                    }
                };

                let response = self
                    .relay_message(id, msg.id, &msg.inner, &chain_tip.block_hash)
                    .await;

                self.wsts_state_machines.pop(&id);
                response?;
            }
            WstsNetMessage::NonceResponse(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);
                span.record(WSTS_SIGNER_ID, request.signer_id);
                span.record(WSTS_SIGN_ID, request.sign_id);
                span.record(WSTS_SIGN_ITER_ID, request.sign_iter_id);

                let WstsMessageId::DkgVerification(key) = msg.id else {
                    return Ok(());
                };

                let new_key: PublicKeyXOnly = key.into();

                Self::validate_dkg_verification_message(
                    &self.context.get_storage(),
                    &new_key,
                    Some(&request.message),
                )
                .await?;

                let (state_machine_id, _, mock_tx) = self
                    .ensure_dkg_verification_state_machine(&chain_tip.block_hash, new_key)
                    .await?;

                let tap_sighash = mock_tx.compute_sighash()?;
                if tap_sighash.as_byte_array() != request.message.as_slice() {
                    tracing::warn!("🔐 sighash mismatch for DKG verification signing");
                    return Err(Error::InvalidSigningOperation);
                }

                self.handle_dkg_verification_message(state_machine_id, &msg.inner)
                    .await?;
            }
            WstsNetMessage::SignatureShareResponse(request) => {
                span.record(WSTS_DKG_ID, request.dkg_id);
                span.record(WSTS_SIGNER_ID, request.signer_id);
                span.record(WSTS_SIGN_ID, request.sign_id);
                span.record(WSTS_SIGN_ITER_ID, request.sign_iter_id);

                let WstsMessageId::DkgVerification(key) = msg.id else {
                    return Ok(());
                };

                let new_key = key.into();

                Self::validate_dkg_verification_message(
                    &self.context.get_storage(),
                    &new_key,
                    None,
                )
                .await?;

                let (state_machine_id, _, _) = self
                    .ensure_dkg_verification_state_machine(&chain_tip.block_hash, new_key)
                    .await?;

                self.handle_dkg_verification_message(state_machine_id, &msg.inner)
                    .await?;
            }
        }

        Ok(())
    }

    /// Validate a DKG verification message, asserting that:
    /// - The new key provided by the peer matches our view of the latest
    ///   aggregate key (not the _current_ key, but the key which we intend to
    ///   rotate to).
    /// - That the message data can be converted into a bitcoin block hash which
    ///   matches the current bitcoin chain tip block hash.
    async fn validate_dkg_verification_message<DB>(
        storage: &DB,
        new_key: &PublicKeyXOnly,
        message: Option<&[u8]>,
    ) -> Result<(), Error>
    where
        DB: DbRead,
    {
        let latest_key = storage
            .get_latest_encrypted_dkg_shares()
            .await?
            .ok_or(Error::NoDkgShares)?
            .aggregate_key
            .into();

        // Ensure that the new key matches the current aggregate key.
        if *new_key != latest_key {
            tracing::warn!("🔐 aggregate key mismatch for DKG verification signing");
            return Err(Error::AggregateKeyMismatch(
                Box::new(latest_key),
                Box::new(*new_key),
            ));
        }

        // If we don't have a message (i.e. from `SignatureShareResponse`) then
        // we can exit early.
        let Some(message) = message else {
            return Ok(());
        };

        // Ensure that the received message is 32 bytes long (the length of the
        // sighash we'll be signing).
        if message.len() != 32 {
            tracing::warn!("🔐 data received for DKG verification signing is not 32 bytes");
            return Err(Error::InvalidSigningOperation);
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

        let StateMachineId::Dkg(started_at) = id else {
            return Err(Error::UnexpectedStateMachineId(Box::new(*id)));
        };

        let encrypted_dkg_shares =
            state_machine.get_encrypted_dkg_shares(&mut self.rng, started_at)?;

        tracing::debug!("🔐 storing DKG shares");
        self.context
            .get_storage_mut()
            .write_encrypted_dkg_shares(&encrypted_dkg_shares)
            .await?;

        Ok(())
    }

    async fn create_frost_coordinator<S>(
        storage: &S,
        aggregate_key: PublicKeyXOnly,
        signer_private_key: PrivateKey,
    ) -> Result<FrostCoordinator, Error>
    where
        S: DbRead + Send + Sync,
    {
        let dkg_shares = storage
            .get_encrypted_dkg_shares(aggregate_key)
            .await?
            .ok_or_else(|| {
                tracing::warn!("🔐 no DKG shares found for requested aggregate key");
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
            "🔐 creating now FROST coordinator to track DKG verification signing round"
        );

        FrostCoordinator::load(
            storage,
            aggregate_key,
            signing_set,
            dkg_shares.signature_share_threshold,
            signer_private_key,
        )
        .await
    }

    /// Ensures that a DKG verification state machine exists for the given
    /// aggregate key and bitcoin chain tip block hash. If the state machine
    /// exists already then the id is simply returned back; otherwise, a new
    /// state machine is created and stored in this instance.
    ///
    /// The `aggregate_key` provided here should be the _new_ aggregate key
    /// which is being verified.
    async fn ensure_dkg_verification_state_machine(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        aggregate_key: PublicKeyXOnly,
    ) -> Result<
        (
            StateMachineId,
            &mut FrostCoordinator,
            &UnsignedMockTransaction,
        ),
        Error,
    > {
        let state_machine_id = StateMachineId::RotateKey(aggregate_key, *bitcoin_chain_tip);

        if !self
            .dkg_verification_state_machines
            .contains(&state_machine_id)
        {
            let storage = self.context.get_storage();
            let coordinator =
                Self::create_frost_coordinator(&storage, aggregate_key, self.signer_private_key)
                    .await?;
            self.dkg_verification_state_machines
                .put(state_machine_id, coordinator);
        }

        let state_machine = self
            .dkg_verification_state_machines
            .get_mut(&state_machine_id)
            .ok_or(Error::MissingFrostStateMachine(aggregate_key))?;

        let mock_tx = self
            .dkg_verification_results
            .get_or_insert(state_machine_id, || {
                UnsignedMockTransaction::new(aggregate_key.into())
            });

        Ok((state_machine_id, state_machine, mock_tx))
    }

    #[tracing::instrument(skip_all)]
    async fn handle_dkg_verification_message(
        &mut self,
        id: StateMachineId,
        msg: &WstsNetMessage,
    ) -> Result<(), Error> {
        // We should only be handling messages for the DKG verification state
        // machine. We'll grab the aggregate key from the id as well.
        let aggregate_key = match id {
            StateMachineId::RotateKey(aggregate_key, _) => aggregate_key,
            _ => {
                tracing::warn!("🔐 unexpected state machine id for DKG verification signing round");
                return Err(Error::UnexpectedStateMachineId(Box::new(id)));
            }
        };

        let state_machine = self.dkg_verification_state_machines.get_mut(&id);
        let Some(state_machine) = state_machine else {
            tracing::warn!("🔐 missing FROST coordinator for DKG verification");
            return Err(Error::MissingFrostStateMachine(aggregate_key));
        };

        tracing::trace!(?msg, "🔐 processing FROST coordinator message");

        let (_, result) = state_machine.process_message(msg)?;

        match result {
            Some(OperationResult::SignTaproot(sig)) => {
                tracing::info!("🔐 successfully completed DKG verification signing round");
                self.dkg_verification_state_machines.pop(&id);

                let Some(mock_tx) = self.dkg_verification_results.pop(&id) else {
                    tracing::warn!(
                        "🔐 missing mock transaction for DKG verification signing round"
                    );
                    return Err(Error::MissingMockTransaction);
                };

                // Perform verification of the signature.
                tracing::info!("🔐 verifying that the signature can be used to spend a UTXO locked by the new aggregate key");
                let signature: TaprootSignature = sig.into();
                mock_tx
                    .verify_signature(&signature)
                    .inspect_err(|e| tracing::warn!(?e, "🔐 signature verification failed"))?;
                tracing::info!("🔐 signature verification successful");

                self.context
                    .get_storage_mut()
                    .verify_dkg_shares(aggregate_key)
                    .await?;
                tracing::info!(
                    "🔐 DKG shares entry has been marked as verified; it is now able to be used"
                );
            }
            Some(OperationResult::SignError(error)) => {
                tracing::warn!(
                    ?msg,
                    ?error,
                    "🔐 failed to complete DKG verification signing round"
                );
                self.dkg_verification_results.pop(&id);
                return Err(Error::DkgVerificationFailed(aggregate_key));
            }
            None => {}
            result => {
                tracing::warn!(
                    ?result,
                    "🔐 unexpected result received from the FROST coordinator"
                );
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

        // If this is a DKG verification then we need to process the message in
        // the frost coordinator as well to be able to properly follow the
        // signing round (which is otherwise handled by the signer state
        // machine).
        let mut frost_coordinator = if let StateMachineId::RotateKey(_, _) = state_machine_id {
            self.dkg_verification_state_machines
                .get_mut(&state_machine_id)
        } else {
            None
        };

        let outbound_messages = state_machine.process(msg).map_err(Error::Wsts)?;

        for outbound_message in outbound_messages.iter() {
            // The WSTS state machine assumes we read our own messages
            state_machine
                .process(outbound_message)
                .map_err(Error::Wsts)?;

            // Process the message in the frost coordinator as well, if we have
            // one. Note that we _do not_ send any messages to the network; the
            // frost coordinator is only following the round.
            if let Some(ref mut frost_coordinator) = frost_coordinator {
                frost_coordinator.process_message(outbound_message)?;
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

    fn signer_public_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.signer_private_key)
    }
}

/// Asserts whether a `DkgBegin` WSTS message should be allowed to proceed
/// based on the current state of the signer and the DKG configuration.
pub async fn assert_allow_dkg_begin(
    context: &impl Context,
    bitcoin_chain_tip: &model::BitcoinBlockRef,
) -> Result<(), Error> {
    let storage = context.get_storage();
    let config = context.config();

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
            if bitcoin_chain_tip.block_height < dkg_min_height.get() {
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
    pub chain_tip: model::BitcoinBlockRef,
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
            let mut shares: model::EncryptedDkgShares = Faker.fake();
            shares.dkg_shares_status = model::DkgSharesStatus::Verified;

            storage.write_encrypted_dkg_shares(&shares).await.unwrap();
        }

        // Dummy chain tip hash which will be used to fetch the block height
        let bitcoin_chain_tip = model::BitcoinBlockRef {
            block_hash: Faker.fake(),
            block_height: chain_tip_height,
        };

        // Write a bitcoin block at the given height, simulating the chain tip.
        storage
            .write_bitcoin_block(&model::BitcoinBlock {
                block_height: chain_tip_height,
                parent_hash: Faker.fake(),
                block_hash: bitcoin_chain_tip.block_hash,
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
        let mut shares: model::EncryptedDkgShares = Faker.fake();
        shares.dkg_shares_status = model::DkgSharesStatus::Verified;

        storage.write_encrypted_dkg_shares(&shares).await.unwrap();

        // Dummy chain tip hash which will be used to fetch the block height.
        let bitcoin_chain_tip = model::BitcoinBlockRef {
            block_hash: Faker.fake(),
            block_height: 100,
        };

        // Write a bitcoin block at the given height, simulating the chain tip.
        storage
            .write_bitcoin_block(&model::BitcoinBlock {
                block_height: 100,
                parent_hash: Faker.fake(),
                block_hash: bitcoin_chain_tip.block_hash,
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
            dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            dkg_verification_results: LruCache::new(NonZeroUsize::new(5).unwrap()),
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
            .handle_wsts_message(&msg, Faker.fake(), &chain_tip_report)
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
        let mut shares: model::EncryptedDkgShares = Faker.fake();
        shares.dkg_shares_status = model::DkgSharesStatus::Verified;

        storage.write_encrypted_dkg_shares(&shares).await.unwrap();

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
            dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            dkg_verification_results: LruCache::new(NonZeroUsize::new(5).unwrap()),
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
            .handle_wsts_message(&msg, Faker.fake(), &chain_tip_report)
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
            dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            dkg_verification_results: LruCache::new(NonZeroUsize::new(5).unwrap()),
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
            .handle_wsts_message(&msg, Faker.fake(), &chain_tip_report)
            .await
            .expect("expected success");
    }
}
