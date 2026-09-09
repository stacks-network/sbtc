//! # Transaction coordinator
//!
//! This module contains the transaction coordinator, which is the component of the sBTC signer
//! responsible for constructing transactions and coordinating signing rounds.
//!
//! For more details, see the [`TxCoordinatorEventLoop`] documentation.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::time::Duration;

use blockstack_lib::chainstate::stacks::StacksTransaction;
use futures::Stream;
use futures::StreamExt as _;
use sha2::Digest as _;

use crate::BITCOIN_FEE_RATE_RANGE;
use crate::DEPOSIT_LOCKTIME_BLOCK_BUFFER;
use crate::MAX_BITCOIN_FEE_RATE;
use crate::MIN_BITCOIN_FEE_RATE;
use crate::WITHDRAWAL_BLOCKS_EXPIRY;
use crate::WITHDRAWAL_DUST_LIMIT;
use crate::WITHDRAWAL_EXPIRY_BUFFER;
use crate::bitcoin::BitcoinInteract as _;
use crate::bitcoin::rpc::assess_mempool_sweep_transaction_fees;
use crate::bitcoin::utxo;
use crate::bitcoin::utxo::UnsignedMockTransaction;
use crate::context::Context;
use crate::context::P2PEvent;
use crate::context::RequestDeciderEvent;
use crate::context::SbtcLimits;
use crate::context::SignerCommand;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::context::TxCoordinatorEvent;
use crate::context::TxSignerEvent;
use crate::ecdsa::SignEcdsa as _;
use crate::ecdsa::Signed;
use crate::emily_client::EmilyInteract as _;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message;
use crate::message::BitcoinPreSignRequest;
use crate::message::Payload;
use crate::message::SignerMessage;
use crate::message::StacksTransactionSignRequest;
use crate::message::WstsMessageId;
use crate::metrics::BITCOIN_BLOCKCHAIN;
use crate::metrics::Metrics;
use crate::metrics::STACKS_BLOCKCHAIN;
use crate::network;
use crate::signature::TaprootSignature;
use crate::stacks::api::FeePriority;
use crate::stacks::api::StacksEpochStatus;
use crate::stacks::api::StacksInteract as _;
use crate::stacks::api::SubmitTxResponse;
use crate::stacks::api::TxRejection;
use crate::stacks::contracts::AcceptWithdrawalV1;
use crate::stacks::contracts::AsTxPayload;
use crate::stacks::contracts::CompleteDepositV1;
use crate::stacks::contracts::ContractCall;
use crate::stacks::contracts::RejectWithdrawalV1;
use crate::stacks::contracts::RotateKeysV1;
use crate::stacks::contracts::SMART_CONTRACTS;
use crate::stacks::contracts::SmartContract;
use crate::stacks::wallet::MultisigTx;
use crate::stacks::wallet::SignerWallet;
use crate::storage::DbRead;
use crate::storage::model;
use crate::storage::model::BitcoinBlockRef;
use crate::storage::model::StacksTxId;
use crate::wsts_state_machine::FireCoordinator;
use crate::wsts_state_machine::FrostCoordinator;
use crate::wsts_state_machine::WstsCoordinator;
use sbtc::WITHDRAWAL_MIN_CONFIRMATIONS;

use bitcoin::hashes::Hash as _;
use wsts::net::SignatureType;
use wsts::state_machine::OperationResult as WstsOperationResult;
use wsts::state_machine::StateMachine as _;
use wsts::state_machine::coordinator::State as WstsCoordinatorState;

/// The rejection reason for a transaction that is rejected from the mempool
/// because of a conflicting nonce.
const REJECTION_REASON_CONFLICTING_NONCE_IN_MEMPOOL: &str = "ConflictingNonceInMempool";

/// The target confirmation block used in case of package construction retry.
///
/// Target a confirmation block that will not impact the requests cancellation.
/// This is a best effort approach, it will not guarantee that the sweep we are
/// constructing will not be in the mempool when the requests expire.
/// If that happens, users will need to either pay more fees to RBF our sweep
/// (for deposits reclaim) or wait for a new sweep from us. Note that this can
/// happen regardless of what fee we use to construct the sweep.
const FEE_RETRY_TARGET_BLOCKS: u16 = {
    let taget_block = if WITHDRAWAL_EXPIRY_BUFFER < DEPOSIT_LOCKTIME_BLOCK_BUFFER as u64 {
        // This is safe, as DEPOSIT_LOCKTIME_BLOCK_BUFFER is a u16
        WITHDRAWAL_EXPIRY_BUFFER as u16
    } else {
        DEPOSIT_LOCKTIME_BLOCK_BUFFER
    };

    // `estimatesmartfee` RPC expects the confirmation target to be within [1, 1008].
    assert!(taget_block >= 1);
    assert!(taget_block <= 1008);

    taget_block
};

#[cfg_attr(doc, aquamarine::aquamarine)]
/// # Transaction coordinator event loop
///
/// This struct contains the implementation of the transaction coordinator
/// logic. The coordinator subscribes to [`TxSignerEvent::NewRequestsHandled`]
/// events (from the transaction signer) and listens to signer messages over the
/// signer P2P network.
///
/// The transaction coordinator will look up the canonical chain tip from the
/// database upon receiving a [`TxSignerEvent::NewRequestsHandled`] event from
/// the transaction signer. This tip is used to decide whether this particular
/// signer is selected as the signers' coordinator or if it should be passive in
/// favor of another signer as the coordinator in the signer network.
///
/// When the coordinator is selected, that coordinator will begin by looking up
/// the signer UTXO, and do a fee rate estimation for both Bitcoin and Stacks.
/// With that in place it will proceed to look up any pending[^1] and active[^2]
/// requests to process.
///
/// The pending requests are used to construct a transaction package, which is a
/// set of bitcoin transactions fulfilling a subset of the requests. Which
/// pending requests that end up in the transaction package depends on the
/// amount of signers deciding to accept the request, and on the maximum fee
/// allowed in the requests. Once the package has been constructed, the
/// coordinator proceeds by coordinating WSTS signing rounds for each of the
/// transactions in the package. The signed transactions are then broadcast to
/// bitcoin.
///
/// Pending deposit and withdrawal requests are used to construct a Bitcoin
/// transaction package consisting of a set of inputs and outputs that fulfill
/// these requests. The fulfillment of pending requests in the transaction
/// package depends on the number of signers agreeing to accept each request and
/// the maximum fee stipulated in the request. Once the package is assembled,
/// the coordinator coordinates WSTS signing rounds for each transaction within
/// the package. The successfully signed transactions are then broadcast to the
/// Bitcoin network.
///
/// For the active requests, the coordinator will go over each one and create
/// appropriate stacks response transactions (which are the `withdrawal-accept`,
/// `withdrawal-reject` and `deposit-accept` contract calls). These transactions
/// are sent through the signers for signatures, and once enough signatures has
/// been gathered, the coordinator broadcasts them to the Stacks blockchain.
///
/// [^1]: A deposit or withdraw request is considered pending if it is confirmed
///       on chain but hasn't been fulfilled in an sBTC transaction yet.
/// [^2]: A deposit or withdraw request is considered active if has been
///       fulfilled in an sBTC transaction,
///       but the result hasn't been acknowledged on Stacks as a
///       `deposit-accept`, `withdraw-accept` or `withdraw-reject` transaction.
///
/// The whole flow is illustrated in the following flowchart.
///
/// ```mermaid
/// flowchart TD
///     SM[New requests handled notification] --> GCT(Get canonical chain tip)
///     GCT --> ISC{Is selected?}
///     ISC --> |No| DONE[Done]
///     ISC --> |Yes| GSU(Get signer UTXO)
///     GSU --> ESF(Estimate fee rates)
///
///     ESF --> GPR(Get accepted pending requests)
///     GPR --> CTP(Compute transaction package)
///     CTP --> CSR(Coordinate signing rounds)
///     CSR --> BST(Broadcast signed transactions)
///
///     ESF --> GAR(Get active requests)
///     GAR --> CRT(Construct response transactions)
///     CRT --> CMS(Coordinate multisig signature gather)
///     CMS --> BST
///     BST --> DONE
/// ```
#[derive(Debug)]
pub struct TxCoordinatorEventLoop<Context, Network> {
    /// The signer context.
    pub context: Context,
    /// Interface to the signer network.
    pub network: Network,
    /// Private key of the coordinator for network communication.
    pub private_key: PrivateKey,
    /// How many bitcoin blocks back from the chain tip the signer will
    /// look for requests.
    pub context_window: u16,
    /// The maximum duration of a signing round before the coordinator will
    /// time out and return an error.
    pub signing_round_max_duration: Duration,
    /// The maximum duration of a pre-sign request before the coordinator will
    /// time out and start sending the requests to the signers.
    pub bitcoin_presign_request_max_duration: Duration,
    /// The maximum duration of distributed key generation before the
    /// coordinator will time out and return an error.
    pub dkg_max_duration: Duration,
    /// An indicator for whether the Stacks blockchain has reached Nakamoto
    /// 3. If we are not in Nakamoto 3 or later, then the coordinator does
    /// not do any work.
    pub is_epoch3: bool,
}

/// The parameters for the [`TxCoordinatorEventLoop::get_pending_requests`] function.
#[derive(Debug)]
pub struct GetPendingRequestsParams<'a> {
    /// The current bitcoin chain tip (ref).
    pub bitcoin_chain_tip: &'a model::BitcoinBlockRef,
    /// The current stacks chain tip (hash).
    pub stacks_chain_tip: &'a model::StacksBlockHash,
    /// The current signers' aggregate key.
    pub aggregate_key: &'a PublicKey,
    /// The current sBTC limits.
    pub sbtc_limits: &'a SbtcLimits,
    /// The threshold for the minimum number of 'accept' votes required for a
    /// request to be considered for the sweep transaction package, and the
    /// number of signatures required for each transaction.
    pub signature_threshold: u16,
}

/// This function defines which messages this event loop is interested
/// in.
fn run_loop_message_filter(signal: &SignerSignal) -> bool {
    matches!(
        signal,
        SignerSignal::Event(SignerEvent::RequestDecider(
            RequestDeciderEvent::NewRequestsHandled(_),
        )) | SignerSignal::Command(SignerCommand::Shutdown)
    )
}

/// During DKG or message signing, we only need the following message
/// types, so we construct a stream with only these messages.
fn signed_message_filter(event: &SignerSignal) -> bool {
    matches!(
        event,
        SignerSignal::Event(SignerEvent::TxSigner(TxSignerEvent::MessageGenerated(_)))
            | SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(_)))
    )
}

impl<C, N> TxCoordinatorEventLoop<C, N>
where
    C: Context,
    N: network::MessageTransfer,
{
    /// Run the coordinator event loop
    #[tracing::instrument(skip_all, name = "tx-coordinator")]
    pub async fn run(mut self) -> Result<(), Error> {
        tracing::info!("starting transaction coordinator event loop");
        let mut signal_stream = self.context.as_signal_stream(run_loop_message_filter);

        while let Some(message) = signal_stream.next().await {
            match message {
                SignerSignal::Command(SignerCommand::Shutdown) => break,
                SignerSignal::Command(SignerCommand::P2PPublish(_)) => {}
                SignerSignal::Event(SignerEvent::RequestDecider(
                    RequestDeciderEvent::NewRequestsHandled(chain_tip),
                )) => {
                    tracing::debug!("received signal; processing requests");
                    if let Err(error) = self.process_new_blocks(chain_tip).await {
                        tracing::error!(%error, "error processing requests; skipping this round");
                    }
                    tracing::trace!("sending tenure completed signal");
                    self.context
                        .signal(TxCoordinatorEvent::TenureCompleted(chain_tip).into())?;
                }
                SignerSignal::Event(_) => {}
            }
        }

        tracing::info!("transaction coordinator event loop is stopping");

        Ok(())
    }

    /// A function that filters the [`Context::as_signal_stream`] stream
    /// for items that the coordinator might care about, which includes
    /// some network messages and transaction signer messages.
    async fn to_signed_message(event: SignerSignal) -> Option<Signed<SignerMessage>> {
        match event {
            SignerSignal::Event(SignerEvent::TxSigner(TxSignerEvent::MessageGenerated(msg)))
            | SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(msg))) => Some(*msg),
            _ => None,
        }
    }

    async fn is_epoch3(&mut self) -> Result<bool, Error> {
        if self.is_epoch3 {
            return Ok(true);
        }

        tracing::debug!("checking whether we are in epoch 3.0 or later");
        let epoch_status = self.context.get_stacks_client().get_epoch_status().await?;

        match epoch_status {
            StacksEpochStatus::PreNakamoto {
                reported_bitcoin_height,
                nakamoto_start_height,
            } => {
                tracing::debug!(
                    %reported_bitcoin_height,
                    %nakamoto_start_height,
                    "the stacks node has not reached epoch 3.0; skipping this round"
                );
                Ok(false)
            }
            StacksEpochStatus::PostNakamoto { nakamoto_start_height } => {
                tracing::debug!(%nakamoto_start_height, "the stacks node is in epoch 3.0 or later; proceeding");
                self.is_epoch3 = true;
                Ok(true)
            }
        }
    }

    /// A function for processing new blocks
    #[tracing::instrument(skip_all, fields(
        public_key = %self.signer_public_key(),
        bitcoin_tip_hash = %bitcoin_chain_tip.block_hash,
        bitcoin_tip_height = %bitcoin_chain_tip.block_height,
    ))]
    pub async fn process_new_blocks(
        &mut self,
        bitcoin_chain_tip: BitcoinBlockRef,
    ) -> Result<(), Error> {
        if !self.is_epoch3().await? {
            return Ok(());
        }

        // If we are not the coordinator, then we have no business
        // coordinating DKG or constructing bitcoin and stacks
        // transactions, might as well return early.
        if !self.is_coordinator(bitcoin_chain_tip.as_ref()) {
            tracing::debug!("we are not the coordinator, so nothing to do");
            return Ok(());
        }

        let bitcoin_processing_delay = self.context.config().signer.bitcoin_processing_delay;
        if bitcoin_processing_delay > Duration::ZERO {
            tracing::debug!("sleeping before processing new bitcoin block");
            tokio::time::sleep(bitcoin_processing_delay).await;
        }

        // If we need to bail here then there is some bug in the code,
        // since `process_new_blocks` should only be called after the state
        // has been updated with the bitcoin chain tip.
        let Some(state_chain_tip) = self.context.state().bitcoin_chain_tip() else {
            tracing::error!("no bitcoin chain tip in state, skipping processing");
            return Err(Error::NoChainTip);
        };

        // The bitcoin chain tip could have changed since we observed the
        // bitcoin block given as an input here. If so, we can safely skip
        // processing this block since other signers are likely to ignore
        // us.
        if bitcoin_chain_tip != state_chain_tip {
            tracing::info!(
                state_bitcoin_tip_hash = %state_chain_tip.block_hash,
                state_bitcoin_tip_height = %state_chain_tip.block_height,
                "bitcoin chain tip has changed, skipping processing"
            );
            return Ok(());
        }

        let maybe_registry_signer_set_info = self.context.state().registry_signer_set_info();

        tracing::debug!("we are the coordinator");
        metrics::counter!(Metrics::CoordinatorTenuresTotal).increment(1);

        tracing::debug!("determining if we need to coordinate DKG");
        let should_coordinate_dkg = should_run_dkg(&self.context, &bitcoin_chain_tip).await?;
        let aggregate_key = if should_coordinate_dkg {
            match self.coordinate_dkg(&bitcoin_chain_tip).await {
                Ok(key) => key,
                Err(error) => {
                    tracing::error!(%error, "failed to coordinate DKG; using existing aggregate key");
                    maybe_registry_signer_set_info
                        .as_ref()
                        .map(|info| info.aggregate_key)
                        .ok_or(Error::MissingAggregateKey(*bitcoin_chain_tip.block_hash))?
                }
            }
        } else {
            // If we do not have signer set info in the registry, then we
            // are in the bootstrap phase. Our latest DKG shares may be
            // 'Unverified', but if we are here then they were not 'Failed'
            // when we made to call to `should_run_dkg`, since we
            // will coordinate DKG if our last DKG shares are 'Failed'. But
            // we could be loading 'Failed' shares here.
            match maybe_registry_signer_set_info.as_ref() {
                Some(info) => info.aggregate_key,
                None => self
                    .context
                    .get_storage()
                    .get_latest_encrypted_dkg_shares()
                    .await?
                    .map(|shares| shares.aggregate_key)
                    .ok_or(Error::NoDkgShares)?,
            }
        };

        let chain_tip_hash = &bitcoin_chain_tip.block_hash;

        tracing::debug!("loading the signer stacks wallet");
        let wallet = self.get_signer_wallet().await?;

        if !self.context.state().sbtc_contracts_deployed() {
            self.deploy_smart_contracts(chain_tip_hash, &wallet, &aggregate_key)
                .await?;

            return Ok(());
        }

        let rotate_key_txid = self.check_and_submit_rotate_key_transaction(
            &bitcoin_chain_tip,
            &wallet,
            &aggregate_key,
        );

        // If a rotate-keys contract call has been submitted, we stop our
        // tenure to make sure that all signers are up to date with the
        // same information when signing any transactions. In particular,
        // signers use the sbtc-registry contract for figuring out the new
        // signers' scriptPubKey and for bitcoin transactions, and need to
        // have the same view of the signers wallet for confirming stacks
        // transactions.
        if let Some(txid) = rotate_key_txid.await? {
            tracing::info!(%txid, "a rotate-keys contract call has been successfully submitted; stopping my tenure");
            return Ok(());
        }

        // If we have just run DKG again but did not successfully submit
        // the key rotation transaction for it, then the aggregate key
        // above is not the right one, and we should use the aggregate key
        // in the registry if it's available.
        let Some(signer_set_info) = maybe_registry_signer_set_info.as_ref() else {
            return Err(Error::NoKeyRotationEvent);
        };

        let bitcoin_processing_fut = self.construct_and_sign_bitcoin_sbtc_transactions(
            &bitcoin_chain_tip,
            &signer_set_info.aggregate_key,
            &signer_set_info.signer_set,
        );

        if let Err(error) = bitcoin_processing_fut.await {
            tracing::error!(%error, "failed to construct and sign bitcoin transactions");
        }

        self.construct_and_sign_stacks_response_transactions(
            &bitcoin_chain_tip,
            &wallet,
            &signer_set_info.aggregate_key,
        )
        .await?;
        tracing::debug!("coordinator tenure completed successfully");

        Ok(())
    }

    /// Submit the rotate key tx for the latest DKG shares, if the aggregate key
    /// differs from the one in the smart contract registry
    #[tracing::instrument(skip_all)]
    async fn check_and_submit_rotate_key_transaction(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        wallet: &SignerWallet,
        aggregate_key: &PublicKey,
    ) -> Result<Option<StacksTxId>, Error> {
        let last_dkg = self
            .context
            .get_storage()
            .get_latest_encrypted_dkg_shares()
            .await?;

        // If we don't have DKG shares nothing to do here
        let Some(last_dkg) = last_dkg else {
            return Ok(None);
        };

        let current_aggregate_key = self
            .context
            .state()
            .registry_signer_set_info()
            .map(|info| info.aggregate_key);

        let (needs_verification, needs_rotate_key) = assert_rotate_key_action(
            &self.context,
            &last_dkg,
            current_aggregate_key,
            bitcoin_chain_tip,
        )?;
        if !needs_verification && !needs_rotate_key {
            tracing::debug!(
                "stacks node is up to date with the current aggregate key and no DKG verification required"
            );
            return Ok(None);
        }
        tracing::info!(%needs_verification, %needs_rotate_key, "DKG verification and/or key rotation needed");

        if needs_verification {
            // Perform DKG verification before submitting the rotate key transaction.
            tracing::info!(
                "🔐 beginning DKG verification before submitting rotate-key transaction"
            );
            let result = self
                .perform_dkg_verification(&bitcoin_chain_tip.block_hash, &last_dkg.aggregate_key);

            // If the DKG verification fails, we don't submit the rotate
            // key transaction, and we do not want to bail on the tenure,
            // since there may be work for us to do. So, we return None and
            // continue with our work, and hope for successful DKG
            // verification in the next tenure.
            if let Err(error) = result.await {
                tracing::error!(%error, "DKG verification failed but we're continuing with our tenure");
                return Ok(None);
            }

            tracing::info!("🔐 DKG verification successful");
        }

        if needs_rotate_key {
            tracing::info!(
                "our aggregate key differs from the one in the registry contract; a key rotation may be necessary"
            );

            // current_aggregate_key define which wallet can sign stacks tx interacting
            // with the registry smart contract; fallbacks to `aggregate_key` if it's
            // the first rotate key tx.
            let signing_key = &current_aggregate_key.unwrap_or(*aggregate_key);

            // Construct, sign and submit the rotate key transaction.
            tracing::info!("preparing to submit a rotate-key transaction");
            let txid = self
                .construct_and_sign_rotate_key_transaction(
                    &bitcoin_chain_tip.block_hash,
                    signing_key,
                    &last_dkg.aggregate_key,
                    wallet,
                )
                .await
                .inspect_err(
                    |error| tracing::error!(%error, "failed to sign or submit rotate-key transaction"),
                )?;

            tracing::info!(%txid, "rotate-key transaction submitted successfully");
            return Ok(Some(txid));
        }

        Ok(None)
    }

    /// Constructs a BitcoinPreSignRequest from the given transaction package and
    /// sends it to the signers. Waits for acknowledgments from the signers until
    /// the threshold is met or a timeout occurs.
    /// If the signal stream closes unexpectedly, triggers a shutdown.
    #[tracing::instrument(skip_all)]
    async fn construct_and_send_bitcoin_presign_request(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        signer_btc_state: &utxo::SignerBtcState,
        transaction_package: &[utxo::UnsignedTransaction<'_>],
    ) -> Result<(), Error> {
        // Constructing a pre-sign request with empty request IDs is
        // invalid. The other signers should reject the message if we send
        // one, so let's not create it.
        if transaction_package.is_empty() {
            tracing::debug!("no requests to handle this tenure, exiting");
            return Ok(());
        }
        // Create the BitcoinPreSignRequest from the transaction package
        let sbtc_requests = BitcoinPreSignRequest {
            request_package: transaction_package
                .iter()
                .map(|tx| (&tx.requests).into())
                .collect(),
            fee_rate: signer_btc_state.fee_rate,
            last_fees: signer_btc_state.last_fees.map(Into::into),
        };

        let presign_ack_filter = |event: &SignerSignal| {
            matches!(
                event,
                SignerSignal::Event(SignerEvent::TxSigner(TxSignerEvent::MessageGenerated(_)))
                    | SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(_)))
                    | SignerSignal::Command(SignerCommand::Shutdown)
            )
        };

        // Create a signal stream with the defined filter
        let signal_stream = self.context.as_signal_stream(presign_ack_filter);
        let signature_threshold = self.context.config().signer.bootstrap_signatures_required;

        // Send the presign request message
        tracing::debug!(request = %sbtc_requests, "sending pre-sign request");
        self.send_message(sbtc_requests, bitcoin_chain_tip).await?;

        tokio::pin!(signal_stream);
        let future = async {
            let target_tip = *bitcoin_chain_tip;
            let mut acknowledged_signers = HashSet::new();

            while acknowledged_signers.len() < signature_threshold as usize {
                match signal_stream.next().await {
                    None => {
                        tracing::warn!("signer signal stream closed unexpectedly, shutting down");
                        return Err(Error::SignerShutdown);
                    }
                    Some(SignerSignal::Command(SignerCommand::Shutdown)) => {
                        tracing::info!("signer shutdown signal received, shutting down");
                        return Err(Error::SignerShutdown);
                    }
                    Some(event) => match Self::to_signed_message(event).await {
                        Some(Signed {
                            inner:
                                SignerMessage {
                                    bitcoin_chain_tip,
                                    payload: Payload::BitcoinPreSignAck(_),
                                    ..
                                },
                            signer_public_key,
                            ..
                        }) => {
                            if bitcoin_chain_tip == target_tip {
                                acknowledged_signers.insert(signer_public_key);
                            } else {
                                tracing::warn!(
                                    signer = %signer_public_key,
                                    received_chain_tip = %bitcoin_chain_tip,
                                    "bitcoin presign ack observed for a different chain tip"
                                );
                            }
                        }
                        // We can ignore other types of payload
                        _ => continue,
                    },
                };
            }

            Ok(())
        };

        let instant = std::time::Instant::now();

        // Wait for the future to complete with a timeout
        let res = tokio::time::timeout(self.bitcoin_presign_request_max_duration, future)
            .await
            .map_err(|_| {
                Error::CoordinatorTimeout(self.bitcoin_presign_request_max_duration.as_secs())
            });

        let status = match &res {
            Ok(Ok(_)) => "success",
            Ok(Err(_)) => "failure",
            Err(_) => "timeout",
        };

        metrics::histogram!(
            Metrics::SigningRoundDurationSeconds,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "kind" => "sweep-presign",
            "status" => status,
        )
        .record(instant.elapsed());
        metrics::counter!(
            Metrics::SignRequestsTotal,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "kind" => "sweep-presign-broadcast",
            "status" => status,
        )
        .increment(1);

        res?
    }

    /// Construct and coordinate WSTS signing rounds for sBTC transactions on Bitcoin,
    /// fulfilling pending deposit and withdraw requests.
    #[tracing::instrument(skip_all, fields(
        stacks_tip_hash = tracing::field::Empty,
        stacks_tip_height = tracing::field::Empty,
    ))]
    async fn construct_and_sign_bitcoin_sbtc_transactions(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        aggregate_key: &PublicKey,
        signer_public_keys: &BTreeSet<PublicKey>,
    ) -> Result<(), Error> {
        // Fetch the stacks chain tip from the signer state.
        let stacks_chain_tip = self
            .context
            .state()
            .stacks_chain_tip()
            .ok_or(Error::NoStacksChainTip)?;

        let span = tracing::Span::current();
        span.record("stacks_tip_hash", stacks_chain_tip.block_hash.to_hex());
        span.record("stacks_tip_height", *stacks_chain_tip.block_height);

        // Create a future that fetches pending deposit and withdrawal requests
        // from the database.
        let pending_requests_fut = self.get_pending_requests(
            bitcoin_chain_tip,
            &stacks_chain_tip.block_hash,
            aggregate_key,
            signer_public_keys,
        );

        // If `get_pending_requests()` returns `Ok(None)` then there are no
        // eligible requests to service; we can exit early.
        let Some(mut pending_requests) = pending_requests_fut.await? else {
            tracing::debug!("no requests to handle on bitcoin");
            return Ok(());
        };

        tracing::debug!(
            num_deposits = %pending_requests.deposits.len(),
            num_withdrawals = pending_requests.withdrawals.len(),
            "there are eligible requests to handle"
        );

        // Construct the transaction package and store it in the database.
        // We first try using the fee rate from Bitcoin (targeting 1 block
        // confirmation), then if that's too high to construct any package we
        // retry once with a lower fee rate to avoid wasting the tenure.
        let mut transaction_package = pending_requests.construct_transactions()?;

        if transaction_package.is_empty() {
            let fallback_fee = self.context.config().bitcoin.fallback_fee;

            let retry_fee_rate = match fallback_fee {
                Some(fee) => fee,
                None => {
                    self.estimate_bitcoin_tx_fee(FEE_RETRY_TARGET_BLOCKS)
                        .await?
                }
            };

            if retry_fee_rate < pending_requests.signer_state.fee_rate {
                tracing::debug!(
                    original_fee_rate = %pending_requests.signer_state.fee_rate,
                    %retry_fee_rate,
                    "empty request package, retrying with lower fee rate"
                );
                pending_requests.signer_state.fee_rate = retry_fee_rate;
                transaction_package = pending_requests.construct_transactions()?;
            }
        }

        // Send the pre-sign request to the signers and wait for their
        // acknowledgments.
        self.construct_and_send_bitcoin_presign_request(
            bitcoin_chain_tip.as_ref(),
            &pending_requests.signer_state,
            &transaction_package,
        )
        .await?;

        // Construct, sign and broadcast the bitcoin transactions.
        for mut transaction in transaction_package {
            self.sign_and_broadcast(bitcoin_chain_tip.as_ref(), &mut transaction)
                .await?;

            // TODO: if this (considering also fallback clients) fails, we will
            // need to handle the inconsistency of having the sweep tx confirmed
            // but emily deposit still marked as pending.
            let _ = self
                .context
                .get_emily_client()
                .accept_deposits(&transaction)
                .await
                .inspect_err(|error| {
                    tracing::warn!(%error, "could not accept deposits on Emily");
                });

            let _ = self
                .context
                .get_emily_client()
                .accept_withdrawals(&transaction)
                .await
                .inspect_err(|error| {
                    tracing::warn!(%error, "could not accept withdrawals on Emily");
                });
        }

        Ok(())
    }

    /// Construct and coordinate signing rounds for `deposit-accept`,
    /// `withdraw-accept` and `withdraw-reject` transactions.
    ///
    /// # Notes
    ///
    /// This function does the following.
    /// 1. Load the stacks wallet from the database. This wallet is
    ///    determined by the public keys and threshold stored in the last
    ///    [`RotateKeysTransaction`] object that is returned from the
    ///    database.
    /// 2. Fetch all requests from the database where we can finish the
    ///    fulfillment with only a Stacks transaction. These are requests
    ///    that where we have a response transactions on bitcoin fulfilling
    ///    the deposit or withdrawal request.
    /// 3. Construct a sign-request object for each of the requests
    ///    identified in (2).
    /// 4. Broadcast this sign-request to the network and wait for
    ///    responses.
    /// 5. If there are enough signatures then broadcast the transaction.
    #[tracing::instrument(skip_all)]
    async fn construct_and_sign_stacks_response_transactions(
        &mut self,
        chain_tip: &model::BitcoinBlockRef,
        wallet: &SignerWallet,
        bitcoin_aggregate_key: &PublicKey,
    ) -> Result<(), Error> {
        let fut = self.construct_and_sign_stacks_deposit_response_transactions(
            chain_tip,
            wallet,
            bitcoin_aggregate_key,
        );
        if let Err(error) = fut.await {
            tracing::error!(%error, "could not process deposit response transactions on stacks");
        }

        let fut = self.construct_and_sign_stacks_withdrawal_response_transactions(
            chain_tip,
            wallet,
            bitcoin_aggregate_key,
        );
        if let Err(error) = fut.await {
            tracing::error!(%error, "could not process withdrawal response transactions on stacks");
        }

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn construct_and_sign_stacks_deposit_response_transactions(
        &mut self,
        chain_tip: &model::BitcoinBlockRef,
        wallet: &SignerWallet,
        bitcoin_aggregate_key: &PublicKey,
    ) -> Result<(), Error> {
        let db = self.context.get_storage();
        let stacks = self.context.get_stacks_client();
        let deployer = self.context.config().signer.deployer.clone();

        // Fetch deposit requests from the database where
        // there has been a confirmed bitcoin transaction associated with
        // the request.
        //
        // For deposits, there will be at most one such bitcoin transaction
        // on the blockchain identified by the chain tip, where an input is
        // the deposit UTXO.

        let stacks_chain_tip = self
            .context
            .state()
            .stacks_chain_tip()
            .ok_or(Error::NoStacksChainTip)?
            .block_hash;
        let swept_deposits = db
            .get_swept_deposit_requests(chain_tip.as_ref(), &stacks_chain_tip, self.context_window)
            .await?;

        if swept_deposits.is_empty() {
            tracing::debug!("no deposit stacks transactions to create");
            return Ok(());
        }

        tracing::debug!(
            swept_deposits = %swept_deposits.len(),
            "we have deposit requests that may need a response on stacks"
        );

        for req in swept_deposits {
            if self.context.state().bitcoin_chain_tip().as_ref() != Some(chain_tip) {
                tracing::info!("new bitcoin chain tip, stopping coordinator activities");
                return Ok(());
            }

            let outpoint = req.deposit_outpoint();

            let is_completed = stacks.is_deposit_completed(&deployer, &outpoint).await;
            match is_completed {
                Err(error) => {
                    tracing::warn!(%error, %outpoint, "could not check deposit status");
                    continue;
                }
                Ok(true) => {
                    // The request is already completed according to the contract
                    continue;
                }
                Ok(false) => (),
            };

            let sign_request_fut =
                self.construct_deposit_stacks_sign_request(req, bitcoin_aggregate_key, wallet);

            let (sign_request, multi_tx) = match sign_request_fut.await {
                Ok(res) => res,
                Err(error) => {
                    tracing::error!(%error, "could not construct a transaction completing the deposit request");
                    continue;
                }
            };

            // If we fail to sign the transaction for some reason, we adjust the
            // nonce and try the next transaction.
            // This is not a fatal error, since we could fail to sign the
            // transaction because someone else is now the coordinator, and
            // all the signers are now ignoring us.
            let process_request_fut =
                self.process_sign_request(sign_request, chain_tip.as_ref(), multi_tx, wallet);

            let status = match process_request_fut.await {
                Ok(txid) => {
                    tracing::info!(%txid, "successfully submitted complete-deposit transaction");
                    "success"
                }
                Err(error) => {
                    tracing::warn!(%error, %outpoint, "could not process the stacks sign request for a deposit");
                    adjust_nonce(wallet, &error);
                    "failure"
                }
            };

            metrics::counter!(
                Metrics::TransactionsSubmittedTotal,
                "blockchain" => STACKS_BLOCKCHAIN,
                "status" => status,
                "kind" => "complete-deposit"
            )
            .increment(1);
        }

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn construct_and_sign_stacks_withdrawal_response_transactions(
        &mut self,
        chain_tip: &model::BitcoinBlockRef,
        wallet: &SignerWallet,
        bitcoin_aggregate_key: &PublicKey,
    ) -> Result<(), Error> {
        let db = self.context.get_storage();
        let stacks_chain_tip = self
            .context
            .state()
            .stacks_chain_tip()
            .ok_or(Error::NoStacksChainTip)?
            .block_hash;

        // Fetch withdrawal requests from the database where there has been
        // a confirmed bitcoin transaction associated with the request.
        let swept_withdrawals = db
            .get_swept_withdrawal_requests(
                &chain_tip.block_hash,
                &stacks_chain_tip,
                self.context_window,
            )
            .await
            .inspect_err(|error| tracing::error!(%error, "could not fetch swept withdrawals"))
            .unwrap_or_default();

        // Fetch withdrawal requests that have not been swept for quite
        // some time.
        let rejected_withdrawals = db
            .get_pending_rejected_withdrawal_requests(
                chain_tip,
                &stacks_chain_tip,
                self.context_window,
            )
            .await
            .inspect_err(|error| tracing::error!(%error, "could not fetch rejected withdrawals"))
            .unwrap_or_default();

        if swept_withdrawals.is_empty() && rejected_withdrawals.is_empty() {
            tracing::debug!("no withdrawal stacks transactions to create");
            return Ok(());
        }

        tracing::debug!(
            swept_withdrawals = %swept_withdrawals.len(),
            rejected_withdrawals = %rejected_withdrawals.len(),
            "we have withdrawals requests that may need completion"
        );

        for swept_request in swept_withdrawals {
            if self.context.state().bitcoin_chain_tip().as_ref() != Some(chain_tip) {
                tracing::info!("new bitcoin chain tip, stopping coordinator activities");
                return Ok(());
            }

            let withdrawal_id = swept_request.qualified_id();
            let fut = self.construct_and_sign_withdrawal_accept(
                chain_tip,
                wallet,
                bitcoin_aggregate_key,
                swept_request,
            );

            if let Err(error) = fut.await {
                tracing::warn!(
                    %error,
                    %withdrawal_id,
                    "could not construct and sign withdrawal accept"
                );
            }
        }

        for withdrawal in rejected_withdrawals {
            if self.context.state().bitcoin_chain_tip().as_ref() != Some(chain_tip) {
                tracing::info!("new bitcoin chain tip, stopping coordinator activities");
                return Ok(());
            }

            let withdrawal_id = withdrawal.qualified_id();
            let fut = self.construct_and_sign_withdrawal_reject(
                chain_tip,
                wallet,
                bitcoin_aggregate_key,
                withdrawal,
            );
            if let Err(error) = fut.await {
                tracing::warn!(
                    %error,
                    %withdrawal_id,
                    "could not construct and sign withdrawal reject"
                );
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(withdrawal_id = %request.qualified_id()))]
    async fn construct_and_sign_withdrawal_accept(
        &mut self,
        chain_tip: &model::BitcoinBlockRef,
        wallet: &SignerWallet,
        bitcoin_aggregate_key: &PublicKey,
        request: model::SweptWithdrawalRequest,
    ) -> Result<(), Error> {
        let stacks = self.context.get_stacks_client();
        let deployer = self.context.config().signer.deployer.clone();

        let is_completed = stacks
            .is_withdrawal_completed(&deployer, request.request_id)
            .await?;

        if is_completed {
            tracing::warn!("swept withdrawal request already processed");
            return Ok(());
        }

        tracing::debug!("processing withdrawal request");
        let sign_request_fut = self.construct_withdrawal_accept_stacks_sign_request(
            request,
            bitcoin_aggregate_key,
            wallet,
        );

        let (sign_request, multi_tx) = sign_request_fut.await?;
        tracing::debug!("constructed withdrawal accept sign request");

        // If we fail to sign the transaction for some reason, we adjust the
        // nonce and try the next transaction.
        // This is not a fatal error, since we could fail to sign the
        // transaction because someone else is now the coordinator, and
        // all the signers are now ignoring us.
        let process_request_fut =
            self.process_sign_request(sign_request, &chain_tip.block_hash, multi_tx, wallet);

        tracing::debug!("processed withdrawal request");

        let status = match process_request_fut.await {
            Ok(txid) => {
                tracing::info!(%txid, "successfully submitted accept-withdrawal transaction");
                "success"
            }
            Err(error) => {
                tracing::warn!(%error, "could not process the stacks sign request for a withdrawal");
                adjust_nonce(wallet, &error);
                "failure"
            }
        };

        metrics::counter!(
            Metrics::TransactionsSubmittedTotal,
            "blockchain" => STACKS_BLOCKCHAIN,
            "status" => status,
            "kind" => "complete-withdrawal-accept",
        )
        .increment(1);

        tracing::debug!("processed withdrawal requests successfully");

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(withdrawal_id = %request.qualified_id()))]
    async fn construct_and_sign_withdrawal_reject(
        &mut self,
        chain_tip: &model::BitcoinBlockRef,
        wallet: &SignerWallet,
        bitcoin_aggregate_key: &PublicKey,
        request: model::WithdrawalRequest,
    ) -> Result<(), Error> {
        let db = self.context.get_storage();
        let stacks = self.context.get_stacks_client();
        let deployer = self.context.config().signer.deployer.clone();

        let is_completed = stacks
            .is_withdrawal_completed(&deployer, request.request_id)
            .await?;

        if is_completed {
            // The request is already completed according to the contract
            return Ok(());
        }

        // The `DbRead::is_withdrawal_inflight` function considers whether
        // the given withdrawal has been included in a sweep transaction
        // that could have been submitted. With this check we are more
        // confident that it is safe to reject the withdrawal.
        let qualified_id = request.qualified_id();
        let withdrawal_inflight = db
            .is_withdrawal_inflight(&qualified_id, &chain_tip.block_hash)
            .await?;
        if withdrawal_inflight {
            return Ok(());
        }

        // The `DbRead::is_withdrawal_active` function considers whether
        // we need to worry about a fork making a sweep fulfilling
        // withdrawal active in the mempool.
        let withdrawal_is_active = db
            .is_withdrawal_active(&qualified_id, chain_tip, WITHDRAWAL_MIN_CONFIRMATIONS)
            .await?;

        if withdrawal_is_active {
            return Ok(());
        }

        let sign_request_fut = self.construct_withdrawal_reject_stacks_sign_request(
            &request,
            bitcoin_aggregate_key,
            wallet,
        );

        let (sign_request, multi_tx) = sign_request_fut.await?;

        // If we fail to sign the transaction for some reason, we adjust the
        // nonce and try the next transaction.
        // This is not a fatal error, since we could fail to sign the
        // transaction because someone else is now the coordinator, and
        // all the signers are now ignoring us.
        let process_request_fut =
            self.process_sign_request(sign_request, chain_tip.as_ref(), multi_tx, wallet);

        let status = match process_request_fut.await {
            Ok(txid) => {
                tracing::info!(%txid, "successfully submitted withdrawal reject transaction");
                "success"
            }
            Err(error) => {
                tracing::warn!(%error, "could not process the stacks sign request for a withdrawal reject");
                adjust_nonce(wallet, &error);
                "failure"
            }
        };

        metrics::counter!(
            Metrics::TransactionsSubmittedTotal,
            "blockchain" => STACKS_BLOCKCHAIN,
            "status" => status,
            "kind" => "complete-withdrawal-reject",
        )
        .increment(1);

        Ok(())
    }

    /// Performs verification of the DKG process by running a FROST signing
    /// round using the new key. This is done to assert that all signers have
    /// successfully signed with the new aggregate key before proceeding with
    /// the actual rotate keys transaction.
    ///
    /// The idea behind this is that since the rotate-keys contract call is a
    /// Stacks transaction and thus only signed using the signers' private keys,
    /// we have no guarantees at this point that there wasn't a fault in the DKG
    /// process. By running a FROST signing round, we can cryptographically
    /// assert that all signers have signed with the new aggregate key, and thus
    /// have valid private shares before we proceed with the actual rotate keys
    /// transaction. This is guaranteed by the FROST coordinator, which requires
    /// 100% signing participation vs. FIRE which only uses `threshold` signers.
    #[tracing::instrument(skip_all)]
    async fn perform_dkg_verification(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        aggregate_key: &PublicKey,
    ) -> Result<(), Error> {
        let (x_only_pubkey, _) = aggregate_key.x_only_public_key();

        // Note that while we specify the threshold as `signatures_required` in
        // the coordinator below, the FROST coordinator implicitly requires all
        // signers to participate.
        tracing::info!(%aggregate_key, "🔐 preparing to coordinate a FROST signing round to verify the aggregate key");
        let mut frost_coordinator = FrostCoordinator::load(
            &self.context.get_storage(),
            aggregate_key.into(),
            self.private_key,
        )
        .await?;

        // We create an `UnsignedMockTransaction` which tries to spend an input
        // locked by the new aggregate key in the same way that the signer
        // UTXO's are locked. This transaction is then used to compute the
        // sighash that the signers will sign.
        //
        // This transaction does not spend from a valid (existing) UTXO and is
        // never broadcast to the Bitcoin network.
        let mock_tx = UnsignedMockTransaction::new(x_only_pubkey);
        let tap_sighash = mock_tx.compute_sighash()?;

        // Perform the signing round. We will not use the resulting signature
        // for anything here, rather each signer will also construct an
        // `UnsignedMockTransaction` upon completion of the signing rounds and
        // attempt to spend the locked UTXO input with the resulting signature.
        // If script signature validation fails for any of the signers, they
        // will mark the DKG round as failed and will refuse to sign the rotate
        // keys transaction.
        tracing::info!("🔐 beginning verification signing round");
        let signature = self.coordinate_signing_round(
            bitcoin_chain_tip,
            &mut frost_coordinator,
            WstsMessageId::DkgVerification(*aggregate_key),
            tap_sighash.as_byte_array(),
            SignatureType::Taproot,
        )
        .await
        .inspect_err(|error| {
            tracing::warn!(%error, "🔐 failed to assert that all signers have signed with the new aggregate key; aborting");
        })?;

        // Verify the signature against the mock transaction. This signer's
        // tx-signer will also perform this verification, but we want to exit
        // early if the signature is invalid to avoid moving on to the
        // rotate-key contract call unnecessarily.
        mock_tx.verify_signature(&signature)
            .inspect_err(|error| {
                tracing::warn!(%error, "🔐 signing round completed successfully, but the signature failed validation; aborting");
            })?;

        tracing::info!("🔐 all signers have signed with the new aggregate key; proceeding");

        Ok(())
    }

    /// Construct and coordinate signing round for a `rotate-keys-wrapper` transaction.
    #[tracing::instrument(skip_all)]
    async fn construct_and_sign_rotate_key_transaction(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        aggregate_key: &PublicKey,
        rotate_key_aggregate_key: &PublicKey,
        wallet: &SignerWallet,
    ) -> Result<StacksTxId, Error> {
        // TODO: we should validate the contract call before asking others
        // to sign it.
        let rotate_keys_v1 = RotateKeysV1::load(&self.context, rotate_key_aggregate_key).await?;
        let contract_call = ContractCall::RotateKeysV1(Box::new(rotate_keys_v1));

        // Rotate key transactions should be done as soon as possible, so
        // we set the fee rate to the high priority fee. We also require
        // signatures from all signers, so we specify the total signer count
        // as the number of signatures to include in the estimation transaction
        // as each signature increases the transaction size.
        let tx_fee = self
            .estimate_stacks_tx_fee(wallet, &contract_call, FeePriority::High)
            .await?;

        let multi_tx = MultisigTx::new_tx(&contract_call, wallet, tx_fee);
        let tx = multi_tx.tx();

        // We can now proceed with the actual rotate key transaction.
        let sign_request = StacksTransactionSignRequest {
            aggregate_key: Some(*aggregate_key),
            contract_tx: contract_call.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid().into(),
        };

        self.process_sign_request(sign_request, bitcoin_chain_tip, multi_tx, wallet)
            .await
    }

    /// Sign and broadcast the stacks transaction
    #[tracing::instrument(skip_all)]
    async fn process_sign_request(
        &mut self,
        sign_request: StacksTransactionSignRequest,
        chain_tip: &model::BitcoinBlockHash,
        multi_tx: MultisigTx,
        wallet: &SignerWallet,
    ) -> Result<StacksTxId, Error> {
        let kind = sign_request.tx_kind();

        let instant = std::time::Instant::now();
        let tx = self
            .sign_stacks_transaction(sign_request, multi_tx, chain_tip, wallet)
            .await;

        let status = if tx.is_ok() { "success" } else { "failure" };

        metrics::histogram!(
            Metrics::SigningRoundDurationSeconds,
            "blockchain" => STACKS_BLOCKCHAIN,
            "kind" => kind,
            "status" => status,
        )
        .record(instant.elapsed());
        metrics::counter!(
            Metrics::SigningRoundsCompletedTotal,
            "blockchain" => STACKS_BLOCKCHAIN,
            "kind" => kind,
            "status" => status,
        )
        .increment(1);

        // Submit the transaction to the Stacks node
        let submit_tx_result = self.context.get_stacks_client().submit_tx(&tx?).await;

        match submit_tx_result {
            Ok(SubmitTxResponse::Acceptance(txid)) => Ok(txid),
            Ok(SubmitTxResponse::Rejection(err)) => Err(err.into()),
            Err(err) => Err(err),
        }
    }

    /// Transform the swept deposit request into a Stacks sign request
    /// object.
    ///
    /// This function uses bitcoin-core to help with the fee assessment of
    /// the deposit request, and stacks-core for fee estimation of the
    /// transaction.
    #[tracing::instrument(skip_all)]
    async fn construct_deposit_stacks_sign_request(
        &self,
        req: model::SweptDepositRequest,
        bitcoin_aggregate_key: &PublicKey,
        wallet: &SignerWallet,
    ) -> Result<(StacksTransactionSignRequest, MultisigTx), Error> {
        // Retrieve the Bitcoin sweep transaction from the Bitcoin node. We
        // can't get it from the database because the transaction is
        // only in the node's mempool at this point.
        let tx_info = self
            .context
            .get_bitcoin_client()
            .get_tx_info(&req.sweep_txid, &req.sweep_block_hash)
            .await?
            .ok_or_else(|| {
                Error::BitcoinTxMissing(req.sweep_txid.into(), Some(req.sweep_block_hash.into()))
            })?;

        let outpoint = req.deposit_outpoint();
        let assessed_bitcoin_fee = tx_info
            .assess_input_fee(&outpoint)
            .ok_or_else(|| Error::OutPointMissing(outpoint))?;

        // TODO: we should validate the contract call before asking others
        // to sign it.
        let complete_deposit_v1 = CompleteDepositV1 {
            amount: req.amount - assessed_bitcoin_fee.to_sat(),
            outpoint,
            recipient: req.recipient.into(),
            deployer: self.context.config().signer.deployer.clone(),
            sweep_txid: req.sweep_txid,
            sweep_block_hash: req.sweep_block_hash,
            sweep_block_height: req.sweep_block_height,
        };
        let contract_call = ContractCall::CompleteDepositV1(complete_deposit_v1.into());

        // complete-deposit requests should confirm promptly; medium priority
        // is appropriate without overpaying.
        let tx_fee = self
            .estimate_stacks_tx_fee(wallet, &contract_call, FeePriority::Medium)
            .await?;

        let multi_tx = MultisigTx::new_tx(&contract_call, wallet, tx_fee);
        let tx = multi_tx.tx();

        let sign_request = StacksTransactionSignRequest {
            aggregate_key: Some(*bitcoin_aggregate_key),
            contract_tx: contract_call.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid().into(),
        };

        Ok((sign_request, multi_tx))
    }

    /// Transform the swept withdrawal request into a Stacks sign request
    /// object.
    ///
    /// This function uses stacks-core for fee estimation of the transaction.
    #[tracing::instrument(skip_all)]
    pub async fn construct_withdrawal_accept_stacks_sign_request(
        &self,
        req: model::SweptWithdrawalRequest,
        bitcoin_aggregate_key: &PublicKey,
        wallet: &SignerWallet,
    ) -> Result<(StacksTransactionSignRequest, MultisigTx), Error> {
        tracing::debug!("constructing withdrawal accept sign request");
        // Retrieve the Bitcoin sweep transaction and compute the assessed fee
        // from the Bitcoin node
        let btc_client = self.context.get_bitcoin_client();

        let tx_info = btc_client
            .get_tx_info(&req.sweep_txid, &req.sweep_block_hash)
            .await?
            .ok_or_else(|| {
                Error::BitcoinTxMissing(req.sweep_txid.into(), Some(req.sweep_block_hash.into()))
            })?;

        let outpoint = req.withdrawal_outpoint();
        let qualified_id = req.qualified_id();

        let assessed_bitcoin_fee = tx_info
            .assess_output_fee(outpoint.vout as usize)
            .ok_or_else(|| Error::VoutMissing(outpoint.txid, outpoint.vout))?;

        let accept_withdrawal_v1 = AcceptWithdrawalV1 {
            id: qualified_id,
            outpoint,
            tx_fee: assessed_bitcoin_fee.to_sat(),
            signer_bitmap: 0,
            deployer: self.context.config().signer.deployer.clone(),
            sweep_block_hash: req.sweep_block_hash,
            sweep_block_height: req.sweep_block_height,
        };
        let contract_call = ContractCall::AcceptWithdrawalV1(Box::new(accept_withdrawal_v1));

        // Estimate the fee for the stacks transaction
        let tx_fee = self
            .estimate_stacks_tx_fee(wallet, &contract_call, FeePriority::Medium)
            .await?;

        let multi_tx = MultisigTx::new_tx(&contract_call, wallet, tx_fee);
        let tx = multi_tx.tx();

        let sign_request = StacksTransactionSignRequest {
            aggregate_key: Some(*bitcoin_aggregate_key),
            contract_tx: contract_call.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid().into(),
        };

        Ok((sign_request, multi_tx))
    }

    /// Construct a withdrawal reject transaction
    #[tracing::instrument(skip_all)]
    pub async fn construct_withdrawal_reject_stacks_sign_request(
        &self,
        req: &model::WithdrawalRequest,
        bitcoin_aggregate_key: &PublicKey,
        wallet: &SignerWallet,
    ) -> Result<(StacksTransactionSignRequest, MultisigTx), Error> {
        let reject_withdrawal_v1 = RejectWithdrawalV1 {
            id: req.qualified_id(),
            signer_bitmap: 0,
            deployer: self.context.config().signer.deployer.clone(),
        };
        let contract_call = ContractCall::RejectWithdrawalV1(Box::new(reject_withdrawal_v1));

        // Estimate the fee for the stacks transaction
        let tx_fee = self
            .estimate_stacks_tx_fee(wallet, &contract_call, FeePriority::Medium)
            .await?;

        let multi_tx = MultisigTx::new_tx(&contract_call, wallet, tx_fee);
        let tx = multi_tx.tx();

        let sign_request = StacksTransactionSignRequest {
            aggregate_key: Some(*bitcoin_aggregate_key),
            contract_tx: contract_call.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid().into(),
        };

        Ok((sign_request, multi_tx))
    }

    /// Attempt to sign the stacks transaction.
    #[tracing::instrument(skip_all)]
    async fn sign_stacks_transaction(
        &mut self,
        req: StacksTransactionSignRequest,
        mut multi_tx: MultisigTx,
        chain_tip: &model::BitcoinBlockHash,
        wallet: &SignerWallet,
    ) -> Result<StacksTransaction, Error> {
        let txid = req.txid;

        let signal_stream = self
            .context
            .as_signal_stream(signed_message_filter)
            .filter_map(Self::to_signed_message);

        tokio::pin!(signal_stream);

        // We ask for the signers to sign our transaction (including
        // ourselves, via our tx signer event loop)
        self.send_message(req, chain_tip).await?;

        let max_duration = self.signing_round_max_duration;

        let future = async {
            while multi_tx.num_signatures() < wallet.signatures_required() {
                // If signal_stream.next() returns None then one of the
                // underlying streams has closed. That means either the
                // network stream, the internal message stream, or the
                // termination handler stream has closed. This is all bad,
                // so we trigger a shutdown.
                let Some(msg) = signal_stream.next().await else {
                    tracing::warn!("signal stream returned None, shutting down");
                    self.context.get_termination_handle().signal_shutdown();
                    return Err(Error::SignerShutdown);
                };

                if &msg.bitcoin_chain_tip != chain_tip {
                    tracing::warn!(
                        sender = %msg.signer_public_key,
                        "concurrent signing round message observed"
                    );
                    continue;
                }

                let sig = match msg.inner.payload {
                    Payload::StacksTransactionSignature(sig) if sig.txid == txid => sig,
                    _ => continue,
                };

                if let Err(error) = multi_tx.add_signature(sig.signature) {
                    tracing::warn!(
                        %txid,
                        %error,
                        offending_public_key = %msg.signer_public_key,
                        "got an invalid signature"
                    );
                }
            }

            Ok::<_, Error>(multi_tx.finalize_transaction())
        };

        tokio::time::timeout(max_duration, future)
            .await
            .map_err(|_| Error::SignatureTimeout(txid))?
    }

    /// Coordinate a signing round for the given request
    /// and broadcast it once it's signed.
    #[tracing::instrument(skip_all)]
    async fn sign_and_broadcast(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        transaction: &mut utxo::UnsignedTransaction<'_>,
    ) -> Result<(), Error> {
        let db = self.context.get_storage();
        let sighashes = transaction.construct_digests()?;
        let locking_public_key = sighashes.signers_aggregate_key.into();
        let mut fire_coordinator =
            FireCoordinator::load(&db, locking_public_key, self.private_key).await?;

        let msg = sighashes.signers.to_raw_hash().to_byte_array();

        let txid = transaction.tx.compute_txid();
        let message_id = txid.into();
        let instant = std::time::Instant::now();
        let signature = self
            .coordinate_signing_round(
                bitcoin_chain_tip,
                &mut fire_coordinator,
                message_id,
                &msg,
                SignatureType::Taproot,
            )
            .await?;

        metrics::histogram!(
            Metrics::SigningRoundDurationSeconds,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "kind" => "sweep",
        )
        .record(instant.elapsed());

        metrics::counter!(
            Metrics::SigningRoundsCompletedTotal,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "kind" => "sweep",
        )
        .increment(1);

        let signer_witness = bitcoin::Witness::p2tr_key_spend(&signature.into());

        let mut deposit_witness = Vec::new();

        for (deposit, sighash) in sighashes.deposits.into_iter() {
            let msg = sighash.to_raw_hash().to_byte_array();

            let locking_public_key = deposit.signers_public_key.into();
            let mut fire_coordinator =
                FireCoordinator::load(&db, locking_public_key, self.private_key).await?;

            let instant = std::time::Instant::now();
            let signature = self
                .coordinate_signing_round(
                    bitcoin_chain_tip,
                    &mut fire_coordinator,
                    message_id,
                    &msg,
                    SignatureType::Schnorr,
                )
                .await?;

            metrics::histogram!(
                Metrics::SigningRoundDurationSeconds,
                "blockchain" => BITCOIN_BLOCKCHAIN,
                "kind" => "sweep",
            )
            .record(instant.elapsed());
            metrics::counter!(
                Metrics::SigningRoundsCompletedTotal,
                "blockchain" => BITCOIN_BLOCKCHAIN,
                "kind" => "sweep",
            )
            .increment(1);

            let witness = deposit.construct_witness_data(signature.into());

            deposit_witness.push(witness);
        }

        let witness_data: Vec<bitcoin::Witness> = std::iter::once(signer_witness)
            .chain(deposit_witness)
            .collect();

        transaction
            .tx
            .input
            .iter_mut()
            .zip(witness_data)
            .for_each(|(tx_in, witness)| {
                tx_in.witness = witness;
            });

        tracing::info!("broadcasting bitcoin transaction");
        // Broadcast the transaction to the Bitcoin network.
        let response = self
            .context
            .get_bitcoin_client()
            .broadcast_transaction(&transaction.tx)
            .await;

        let status = if response.is_ok() {
            tracing::info!("bitcoin transaction accepted by bitcoin-core");
            "success"
        } else {
            "failure"
        };
        metrics::counter!(crate::metrics::Metrics::ValidationDurationSeconds).increment(1);
        metrics::counter!(
            Metrics::TransactionsSubmittedTotal,
            "blockchain" => BITCOIN_BLOCKCHAIN,
            "status" => status,
        )
        .increment(1);

        response
    }

    #[tracing::instrument(skip_all)]
    async fn coordinate_signing_round<Coordinator>(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        coordinator: &mut Coordinator,
        id: WstsMessageId,
        msg: &[u8],
        signature_type: SignatureType,
    ) -> Result<TaprootSignature, Error>
    where
        Coordinator: WstsCoordinator,
    {
        let outbound = coordinator.start_signing_round(msg, bitcoin_chain_tip, signature_type)?;

        // We create a signal stream before sending a message so that there
        // is no race condition with the steam and the getting a response.
        let signal_stream = self
            .context
            .as_signal_stream(signed_message_filter)
            .filter_map(Self::to_signed_message);

        let msg = message::WstsMessage { id, inner: outbound };
        self.send_message(msg, bitcoin_chain_tip).await?;

        let max_duration = self.signing_round_max_duration;
        let run_signing_round =
            self.drive_wsts_state_machine(signal_stream, bitcoin_chain_tip, coordinator, id);

        let operation_result = tokio::time::timeout(max_duration, run_signing_round)
            .await
            .map_err(|_| Error::CoordinatorTimeout(max_duration.as_secs()))??;

        match operation_result {
            WstsOperationResult::SignTaproot(sig) | WstsOperationResult::SignSchnorr(sig) => {
                Ok(sig.into())
            }
            result => Err(Error::UnexpectedOperationResult(Box::new(result))),
        }
    }

    /// Set up a WSTS coordinator state machine and run DKG with the other
    /// signers in the signing set.
    #[tracing::instrument(skip_all)]
    async fn coordinate_dkg(
        &mut self,
        chain_tip: &model::BitcoinBlockRef,
    ) -> Result<PublicKey, Error> {
        tracing::info!("Coordinating DKG");
        let block_hash = chain_tip.block_hash;
        // Get the current signer set for running DKG.
        let signer_set = self.context.config().signer.bootstrap_signing_set.clone();
        let threshold = self.context.config().signer.bootstrap_signatures_required;

        let block_height = chain_tip.block_height;
        let mut state_machine =
            FireCoordinator::new(signer_set, threshold, self.private_key, block_height);

        // Okay let's move the coordinator state machine to the beginning
        // of the DKG phase.
        state_machine
            .move_to(WstsCoordinatorState::DkgPublicDistribute)
            .map_err(Error::wsts_coordinator)?;

        let outbound = state_machine
            .start_public_shares()
            .map_err(Error::wsts_coordinator)?;

        let id = WstsMessageId::Dkg(chain_tip.block_hash.into_bytes());
        let msg = message::WstsMessage { id, inner: outbound };

        // We create a signal stream before sending a message so that there
        // is no race condition with the steam and the getting a response.
        let signal_stream = self
            .context
            .as_signal_stream(signed_message_filter)
            .filter_map(Self::to_signed_message);

        // This message effectively kicks off DKG. The `TxSignerEventLoop`s
        // running on the signers will pick up this message and act on it,
        // including our own. When they do they create a signing state
        // machine and begin DKG.
        self.send_message(msg, &block_hash).await?;

        // Now that DKG has "begun" we need to drive it to completion.
        let max_duration = self.dkg_max_duration;
        let dkg_fut =
            self.drive_wsts_state_machine(signal_stream, &block_hash, &mut state_machine, id);

        let operation_result = tokio::time::timeout(max_duration, dkg_fut)
            .await
            .map_err(|_| Error::CoordinatorTimeout(max_duration.as_secs()))??;

        match operation_result {
            WstsOperationResult::Dkg(aggregate_key) => PublicKey::try_from(&aggregate_key),
            result => Err(Error::UnexpectedOperationResult(Box::new(result))),
        }
    }

    #[tracing::instrument(skip_all)]
    async fn drive_wsts_state_machine<S, Coordinator>(
        &mut self,
        signal_stream: S,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        coordinator: &mut Coordinator,
        id: WstsMessageId,
    ) -> Result<WstsOperationResult, Error>
    where
        S: Stream<Item = Signed<SignerMessage>>,
        Coordinator: WstsCoordinator,
    {
        // We only allow the coordinator to send us certain kinds of
        // messages. So later, we need to check whether the sender is the
        // coordinator, and for that we need to use the "coordinator signer
        // set", which may differ from the set of signers sending us
        // messages right now.
        let signer_set = self.context.coordinator_signer_set();
        tokio::pin!(signal_stream);

        // Let's get the next message from the network or the
        // TxSignerEventLoop.
        //
        // If signal_stream.next() returns None then one of the underlying
        // streams has closed. That means either the internal message
        // channel, or the termination handler channel has closed. This is
        // all bad, so we trigger a shutdown.
        while let Some(msg) = signal_stream.next().await {
            if &msg.bitcoin_chain_tip != bitcoin_chain_tip {
                tracing::warn!(sender = %msg.signer_public_key, "concurrent WSTS activity observed");
                continue;
            }

            let Payload::WstsMessage(wsts_msg) = msg.inner.payload else {
                continue;
            };

            let msg_public_key = msg.signer_public_key;

            let sender_is_coordinator =
                given_key_is_coordinator(msg_public_key, bitcoin_chain_tip, &signer_set);

            let public_keys = &coordinator.get_config().signer_public_keys;
            let public_key_point = p256k1::point::Point::from(msg_public_key);

            let msg = wsts_msg.inner;

            // check that messages were signed by correct key
            let is_authenticated = Self::authenticate_message(
                &msg,
                public_keys,
                public_key_point,
                sender_is_coordinator,
            );

            if !is_authenticated {
                continue;
            }

            let (outbound_message, operation_result) = match coordinator.process_message(&msg) {
                Ok(val) => val,
                Err(err) => {
                    tracing::warn!(?msg, reason = %err, "ignoring message");
                    continue;
                }
            };

            if let Some(message) = outbound_message {
                let msg = message::WstsMessage { id, inner: message };
                self.send_message(msg, bitcoin_chain_tip).await?;
            }

            match operation_result {
                Some(res) => return Ok(res),
                None => continue,
            }
        }

        tracing::warn!("signal stream returned None, shutting down");
        self.context.get_termination_handle().signal_shutdown();
        Err(Error::SignerShutdown)
    }

    fn authenticate_message(
        msg: &wsts::net::Message,
        public_keys: &HashMap<u32, p256k1::point::Point>,
        public_key_point: p256k1::point::Point,
        sender_is_coordinator: bool,
    ) -> bool {
        let check_signer_public_key = |signer_id| match public_keys.get(&signer_id) {
            Some(signer_public_key) if public_key_point != *signer_public_key => {
                tracing::warn!(
                    ?msg,
                    reason = "message was signed by the wrong signer",
                    "ignoring packet"
                );
                false
            }
            None => {
                tracing::warn!(
                    ?msg,
                    reason = "no public key for signer",
                    %signer_id,
                    "ignoring packet"
                );
                false
            }
            _ => true,
        };
        match msg {
            wsts::net::Message::DkgBegin(_)
            | wsts::net::Message::DkgPrivateBegin(_)
            | wsts::net::Message::DkgEndBegin(_)
            | wsts::net::Message::NonceRequest(_)
            | wsts::net::Message::SignatureShareRequest(_) => {
                if !sender_is_coordinator {
                    tracing::warn!(
                        ?msg,
                        reason = "got coordinator message from sender who is not coordinator",
                        "ignoring packet"
                    );
                    false
                } else {
                    true
                }
            }

            wsts::net::Message::DkgPublicShares(dkg_public_shares) => {
                check_signer_public_key(dkg_public_shares.signer_id)
            }
            wsts::net::Message::DkgPrivateShares(dkg_private_shares) => {
                check_signer_public_key(dkg_private_shares.signer_id)
            }
            wsts::net::Message::DkgEnd(dkg_end) => check_signer_public_key(dkg_end.signer_id),
            wsts::net::Message::NonceResponse(nonce_response) => {
                check_signer_public_key(nonce_response.signer_id)
            }
            wsts::net::Message::SignatureShareResponse(sig_share_response) => {
                check_signer_public_key(sig_share_response.signer_id)
            }
        }
    }

    /// Determine if this signer is the signer set's coordinator for the
    /// specified bitcoin block hash.
    ///
    /// The coordinator is decided using the hash of the bitcoin chain tip
    /// and signer set info from the registry if present. We don't use the
    /// chain tip directly because it typically starts with a lot of
    /// leading zeros.
    pub fn is_coordinator(&self, bitcoin_chain_tip: &model::BitcoinBlockHash) -> bool {
        let signer_public_keys = self.context.coordinator_signer_set();

        let signer_public_key = self.signer_public_key();
        given_key_is_coordinator(signer_public_key, bitcoin_chain_tip, &signer_public_keys)
    }

    /// Constructs a new [`utxo::SignerBtcState`] based on the current market
    /// fee rate, the signer's UTXO, and the last sweep package.
    #[tracing::instrument(skip_all)]
    pub async fn get_btc_state(
        &self,
        chain_tip: &model::BitcoinBlockHash,
        aggregate_key: &PublicKey,
    ) -> Result<utxo::SignerBtcState, Error> {
        let bitcoin_client = self.context.get_bitcoin_client();
        // Target next block confirmation
        let fee_rate = self.estimate_bitcoin_tx_fee(1).await?;

        // Retrieve the signer's current UTXO.
        let utxo = self
            .context
            .get_storage()
            .get_signer_utxo(chain_tip)
            .await?
            .ok_or(Error::MissingSignerUtxo)?;

        // We still need to send these to the other signers, since they may
        // not have upgraded their binaries yet.
        let last_fees = assess_mempool_sweep_transaction_fees(&bitcoin_client, &utxo).await?;

        Ok(utxo::SignerBtcState {
            fee_rate,
            utxo,
            public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
            last_fees,
            magic_bytes: [b'T', b'3'], //TODO(#472): Use the correct magic bytes.
        })
    }

    /// Fetches pending withdrawal requests from storage and filters them based
    /// on the remaining consensus rules as defined in #741.
    ///
    /// ## Consensus Rules Overview
    ///
    /// 1. [x] The request must not have been swept within the current canonical
    ///    Bitcoin chain.
    /// 2. [x] The request must be confirmed in a canonical Stacks block.
    /// 3. [x] The request must have reached the required number of Bitcoin
    /// 4. [x] The request must be approved:
    ///     - [x] By the required number of signers (this is implemented as a
    ///       pre-filter in the query, any signer),
    ///     - [x] And by the required number of signers _in the current signer
    ///       set_.
    /// 5. [ ] The request has been approved by this signer. **Note:** This rule
    ///     does not apply within the coordinator module, where decisions are
    ///     made collectively based on consensus rules rather than an individual
    ///     signer's approval. However, the coordinator's signer module still
    ///     processes the request according to these same rules.
    /// 6. [ ] The assessed fees will be within the constraints of the request's
    ///    specified maximum fee (this is handled during packaging).
    /// 7. [x] The request must not have expired (handled in the query).
    /// 8. [x] The request amount must be above the dust limit.
    /// 9. [x] The request must be within the current sBTC caps.
    ///
    /// ## Function Parameters
    /// - `storage`: Reference to a `DbRead` implementation.
    /// - `expiry_window`: The number of blocks which a withdrawal request is
    ///   considered definitively expired and will not be returned (exclusive).
    /// - `expiry_buffer`: The number of blocks _prior to_ the expiration of a
    ///   withdrawal request that it is considered "soft expired" and will be
    ///   skipped/logged (exclusive).
    /// - `min_confirmations`: The minimum number of confirmations required for
    ///   a withdrawal request to be considered valid (inclusive).
    /// - `params`: A reference to a `GetPendingRequestsParams` struct.
    #[tracing::instrument(skip_all)]
    pub async fn get_eligible_pending_withdrawal_requests<DB>(
        storage: &DB,
        expiry_window: u64,
        expiry_buffer: u64,
        min_confirmations: u64,
        params: &GetPendingRequestsParams<'_>,
    ) -> Result<Vec<utxo::WithdrawalRequest>, Error>
    where
        DB: DbRead,
    {
        // Constants used for logging (local to this method).
        const REQUEST_SKIPPED_MESSAGE: &str = "skipping withdrawal request";
        const SKIP_REASON_AMOUNT_IS_DUST: &str = "amount_is_dust";
        const SKIP_REASON_PER_WITHDRAWAL_CAP_EXCEEDED: &str = "per_withdrawal_cap_exceeded";
        const SKIP_REASON_INSUFFICIENT_CONFIRMATIONS: &str = "insufficient_confirmations";
        const SKIP_REASON_INSUFFICIENT_VOTES: &str = "insufficient_votes";
        const SKIP_REASON_SOFT_EXPIRY: &str = "soft_expiry";

        let mut eligible_withdrawals = Vec::new();

        // Determine the minimum bitcoin block height we should consider for
        // withdrawals.
        let min_bitcoin_height = params
            .bitcoin_chain_tip
            .block_height
            .saturating_sub(expiry_window);

        // We also calculate the minimum bitcoin block height for withdrawals
        // that are considered valid (not expired) based on the soft expiry. We
        // will not propose these withdrawals in the sweep transaction, but we
        // will log them as skipped.
        let min_soft_bitcoin_height = min_bitcoin_height.saturating_add(expiry_buffer);

        // Fetch pending withdrawal requests from storage. This method, with the
        // given inputs, performs the following filtering according to consensus
        // rules:
        //
        // - [1]  The request has not been swept in the canonical bitcoin chain,
        // - [2]  Is confirmed in a canonical stacks block,
        // - [4a] Is accepted by >= `threshold` signers (pre-filter),
        // - [7]  Is not expired; we only retrieve requests whose bitcoin block
        //        height is greater than `min_bitcoin_height`.
        let pending_withdraw_requests = storage
            .get_pending_accepted_withdrawal_requests(
                params.bitcoin_chain_tip.as_ref(),
                params.stacks_chain_tip,
                min_bitcoin_height,
                params.signature_threshold,
            )
            .await?;

        // If we didn't find any pending withdrawal requests, we can exit early.
        if pending_withdraw_requests.is_empty() {
            tracing::debug!("no pending withdrawal requests eligible for consideration found");
            return Ok(eligible_withdrawals);
        }

        // Iterate over the pending withdrawal requests we fetched above and
        // validate them against the remaining consensus rules.
        for req in pending_withdraw_requests {
            if req.bitcoin_block_height < min_soft_bitcoin_height {
                tracing::debug!(
                    request_id = req.request_id,
                    bitcoin_block_height = *req.bitcoin_block_height,
                    min_soft_bitcoin_height = *min_soft_bitcoin_height,
                    reason = SKIP_REASON_SOFT_EXPIRY,
                    message = REQUEST_SKIPPED_MESSAGE
                );
                continue;
            }

            // [8] Ensure that the withdrawal request amount is at or above the
            // dust limit specified in `WITHDRAWAL_DUST_LIMIT`.
            if req.amount < WITHDRAWAL_DUST_LIMIT {
                tracing::debug!(
                    request_id = req.request_id,
                    amount = req.amount,
                    reason = SKIP_REASON_AMOUNT_IS_DUST,
                    message = REQUEST_SKIPPED_MESSAGE
                );
                continue;
            }

            // [9] Ensure that the withdrawal request amount is within the
            // current sBTC caps.
            let per_withdrawal_cap = params.sbtc_limits.per_withdrawal_cap().to_sat();
            if req.amount > per_withdrawal_cap {
                tracing::debug!(
                    request_id = req.request_id,
                    amount = req.amount,
                    per_withdrawal_cap = per_withdrawal_cap,
                    reason = SKIP_REASON_PER_WITHDRAWAL_CAP_EXCEEDED,
                    message = REQUEST_SKIPPED_MESSAGE
                );
                continue;
            }

            // Calculate the number of blocks passed (confirmations) since the
            // bitcoin anchor of the stacks block confirming the withdrawal
            // request.
            let num_confirmations: u64 = *params
                .bitcoin_chain_tip
                .block_height
                .saturating_sub(req.bitcoin_block_height);

            // [3] Ensure that we have the required number of confirmations for
            // the withdrawal request.
            if num_confirmations < min_confirmations {
                tracing::debug!(
                    request_id = req.request_id,
                    num_confirmations,
                    required_confirmations = min_confirmations,
                    reason = SKIP_REASON_INSUFFICIENT_CONFIRMATIONS,
                    message = REQUEST_SKIPPED_MESSAGE
                );
                continue;
            }

            // Fetch the votes for the withdrawal request from storage for the
            // public keys of the signers in the current signing set, based on
            // the current signers' aggregate key. Note: this could have been
            // baked into the initial query, but we need the votes' values for
            // our return value.
            let votes = storage
                .get_withdrawal_request_signer_votes(&req.qualified_id(), params.aggregate_key)
                .await?;

            // Calculate the number of votes accepted, rejected, and missing.
            // The vote will be `None` if we don't have a record of the signer's
            // vote in the database, otherwise it will be `Some(bool)` where
            // `true` = accept and `false` = reject.
            let (num_votes_accepted, num_votes_rejected, num_votes_missing) = votes.iter().fold(
                (0_u16, 0_u16, 0_u16),
                |(accepted, rejected, missing), vote| match vote.is_accepted {
                    Some(true) => (accepted + 1, rejected, missing),
                    Some(false) => (accepted, rejected + 1, missing),
                    None => (accepted, rejected, missing + 1),
                },
            );

            // [4] Ensure that the withdrawal request has been accepted by the
            // required number of signers _in the current signer set_ (the
            // initial query only checks the total number of votes accepted by
            // any signer).
            if num_votes_accepted < params.signature_threshold {
                tracing::warn!(
                    request_id = req.request_id,
                    num_votes_accepted,
                    num_votes_rejected,
                    num_votes_missing,
                    required_votes = params.signature_threshold,
                    reason = SKIP_REASON_INSUFFICIENT_VOTES,
                    message = REQUEST_SKIPPED_MESSAGE
                );
                continue;
            }

            let withdrawal = utxo::WithdrawalRequest::from_model(req, votes);
            eligible_withdrawals.push(withdrawal);
        }

        Ok(eligible_withdrawals)
    }

    /// TODO(#742): This function needs to filter deposit requests based on
    /// time as well. We need to do this because deposit requests are locked
    /// using OP_CSV, which lock up coins based on block height or
    /// multiples of 512 seconds measure by the median time past.
    #[tracing::instrument(skip_all)]
    pub async fn get_eligible_pending_deposit_requests<DB>(
        storage: &DB,
        context_window: u16,
        params: &GetPendingRequestsParams<'_>,
    ) -> Result<Vec<utxo::DepositRequest>, Error>
    where
        DB: DbRead,
    {
        tracing::debug!("fetching eligible deposit requests");
        let mut eligible_deposits: Vec<utxo::DepositRequest> = Vec::new();

        // First, we fetch pending deposit requests with initial filtering
        // done by the storage layer.
        let pending_deposit_requests = storage
            .get_pending_accepted_deposit_requests(
                params.bitcoin_chain_tip,
                context_window,
                params.signature_threshold,
            )
            .await?;

        // If there are no pending deposit requests, we can exit early.
        if pending_deposit_requests.is_empty() {
            tracing::debug!("no pending deposit requests eligible for consideration found");
            return Ok(eligible_deposits);
        }

        // Iterate through each deposit request, fetch its votes from storage
        // for the public keys of the signers in the current signing set, based
        // on the current signers' aggregate key.
        for req in pending_deposit_requests {
            let votes = storage
                .get_deposit_request_signer_votes(&req.txid, req.output_index, params.aggregate_key)
                .await?;

            let deposit = utxo::DepositRequest::from_model(req, votes);
            eligible_deposits.push(deposit);
        }

        Ok(eligible_deposits)
    }

    /// Fetches pending deposit and withdrawal requests from storage and filters
    /// them based on consensus rules defined in #741 and [**missing**: deposit
    /// consensus ticket?].
    #[tracing::instrument(skip_all)]
    pub async fn get_pending_requests(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockRef,
        stacks_chain_tip: &model::StacksBlockHash,
        aggregate_key: &PublicKey,
        signer_public_keys: &BTreeSet<PublicKey>,
    ) -> Result<Option<utxo::SbtcRequests>, Error> {
        tracing::info!("preparing pending requests for processing");

        let storage = self.context.get_storage();
        let config = self.context.config();

        // Get the current sBTC limits (caps).
        let sbtc_limits = self.context.state().get_current_limits();
        let signature_threshold = config.signer.bootstrap_signatures_required;

        // Setup the parameters for fetching pending requests.
        let params = GetPendingRequestsParams {
            bitcoin_chain_tip,
            stacks_chain_tip,
            aggregate_key,
            signature_threshold,
            sbtc_limits: &sbtc_limits,
        };

        // Fetch eligible deposit requests from storage.
        let deposits =
            Self::get_eligible_pending_deposit_requests(&storage, self.context_window, &params)
                .await?;

        // Fetch eligible withdrawal requests from storage.
        let withdrawals = Self::get_eligible_pending_withdrawal_requests(
            &storage,
            WITHDRAWAL_BLOCKS_EXPIRY,
            WITHDRAWAL_EXPIRY_BUFFER,
            WITHDRAWAL_MIN_CONFIRMATIONS,
            &params,
        )
        .await?;

        // If there are no pending deposit or withdrawal requests, we return
        // `None` to signal that there is no work to be done.
        if deposits.is_empty() && withdrawals.is_empty() {
            return Ok(None);
        }

        // Get the current signers' BTC state.
        let signer_state = self
            .get_btc_state(&bitcoin_chain_tip.block_hash, aggregate_key)
            .await?;

        // Count the number of signers in the current signer set.
        let num_signers = signer_public_keys
            .len()
            .try_into()
            .map_err(|_| Error::TypeConversion)?;

        let max_deposits_per_bitcoin_tx = config.signer.max_deposits_per_bitcoin_tx.get();

        // Construct and return the `utxo::SbtcRequests` object.
        Ok(Some(utxo::SbtcRequests {
            deposits,
            withdrawals,
            signer_state,
            accept_threshold: signature_threshold,
            num_signers,
            sbtc_limits,
            max_deposits_per_bitcoin_tx,
        }))
    }

    /// Takes a [`Payload`], converts it to a [`Message`], signs it with the
    /// signer's private key, and broadcasts it to the network.
    ///
    /// This method also generates a [`TxCoordinatorEvent::MessageGenerated`]
    /// event upon successful completion for the local tx-signer to pick up.
    #[tracing::instrument(skip_all)]
    async fn send_message(
        &mut self,
        msg: impl Into<Payload>,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let msg = msg
            .into()
            .to_message(*bitcoin_chain_tip)
            .sign_ecdsa(&self.private_key);

        self.network.broadcast(msg.clone()).await?;
        self.context
            .signal(TxCoordinatorEvent::MessageGenerated(Box::new(msg)).into())?;

        Ok(())
    }

    /// Deploy an sBTC smart contract to the stacks node.
    #[tracing::instrument(skip_all, fields(smart_contract = %contract_deploy))]
    async fn deploy_smart_contract(
        &mut self,
        contract_deploy: SmartContract,
        chain_tip: &model::BitcoinBlockHash,
        bitcoin_aggregate_key: &PublicKey,
        wallet: &SignerWallet,
    ) -> Result<(), Error> {
        let stacks = self.context.get_stacks_client();

        // Maybe this smart contract has already been deployed, let's check
        // that first.
        let deployer = self.context.config().signer.deployer.clone();
        if contract_deploy.is_deployed(&stacks, &deployer).await? {
            return Ok(());
        }

        // The contract is not deployed yet, so we can proceed
        tracing::info!("contract not deployed yet, proceeding with deployment");

        let sign_request_fut = self.construct_deploy_contracts_stacks_sign_request(
            contract_deploy,
            bitcoin_aggregate_key,
            wallet,
        );

        let (sign_request, multi_tx) = sign_request_fut.await?;

        // If we fail to sign the transaction for some reason, we adjust the
        // nonce and try the next transaction.
        // This is not a fatal error, since we could fail to sign the
        // transaction because someone else is now the coordinator, and
        // all the signers are now ignoring us.
        let process_request_fut =
            self.process_sign_request(sign_request, chain_tip, multi_tx, wallet);

        match process_request_fut.await {
            Ok(txid) => {
                tracing::info!(%txid, "successfully submitted contract deploy transaction");
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "could not process the stacks sign request for a contract deploy"
                );
                adjust_nonce(wallet, &error);
                Err(error)
            }
        }
    }

    /// Estimates the fees for the contract deploy transaction, constructs the
    /// [`StacksTransactionSignRequest`] to be broadcast to the signers for
    /// signing and returns it along with the corresponding [`MultisigTx`] being
    /// signed.
    async fn construct_deploy_contracts_stacks_sign_request(
        &self,
        contract_deploy: SmartContract,
        bitcoin_aggregate_key: &PublicKey,
        wallet: &SignerWallet,
    ) -> Result<(StacksTransactionSignRequest, MultisigTx), Error> {
        let tx_fee = self
            .estimate_stacks_tx_fee(wallet, &contract_deploy.tx_payload(), FeePriority::High)
            .await?;

        let multi_tx = MultisigTx::new_tx(&contract_deploy, wallet, tx_fee);
        let tx = multi_tx.tx();

        let sign_request = StacksTransactionSignRequest {
            aggregate_key: Some(*bitcoin_aggregate_key),
            contract_tx: contract_deploy.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid().into(),
        };

        Ok((sign_request, multi_tx))
    }

    /// Deploy all sBTC smart contracts to the stacks node (if not already deployed).
    /// If a contract fails to deploy, the function will return an error.
    #[tracing::instrument(skip_all)]
    pub async fn deploy_smart_contracts(
        &mut self,
        chain_tip: &model::BitcoinBlockHash,
        wallet: &SignerWallet,
        bitcoin_aggregate_key: &PublicKey,
    ) -> Result<(), Error> {
        for contract in SMART_CONTRACTS {
            self.deploy_smart_contract(contract, chain_tip, bitcoin_aggregate_key, wallet)
                .await?;
        }

        Ok(())
    }

    async fn get_signer_wallet(&self) -> Result<SignerWallet, Error> {
        let wallet = SignerWallet::load(&self.context).await?;

        // We need to know the nonce to use, so we reach out to our stacks
        // node for the account information for our multi-sig address.
        //
        // Note that the wallet object will automatically increment the
        // nonce for each transaction that it creates.
        let stacks = self.context.get_stacks_client();
        let account = stacks.get_account(wallet.address()).await?;
        wallet.set_nonce(account.nonce);

        Ok(wallet)
    }

    /// Helper method to get this signer's public key from its private key.
    fn signer_public_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.private_key)
    }

    /// Estimate the fee rate for a bitcoin transaction targeting
    /// confirmation within `num_blocks` blocks.
    ///
    /// # Notes
    ///
    /// - This function includes a defensive check against bitcoin-core
    ///   returning a bogus fee rate.
    /// - NaN fee rates returned by bitcoin-core are set to 1.0.
    #[tracing::instrument(skip_all, fields(%num_blocks))]
    async fn estimate_bitcoin_tx_fee(&self, num_blocks: u16) -> Result<f64, Error> {
        let mut fee_rate = self
            .context
            .get_bitcoin_client()
            .estimate_fee_rate(num_blocks)
            .await?;

        if fee_rate.is_nan() {
            // This really shouldn't happen, but if it does there is
            // probably a bug in bitcoin-core so we want to know about it.
            tracing::error!(%fee_rate, "bitcoin-core returned a NaN fee rate, using 1");
            fee_rate = 1.0;
        }

        if !BITCOIN_FEE_RATE_RANGE.contains(&fee_rate) {
            tracing::warn!(%fee_rate, "invalid fee rate, clamping it");
            fee_rate = fee_rate.clamp(MIN_BITCOIN_FEE_RATE, MAX_BITCOIN_FEE_RATE);
        }

        Ok(fee_rate)
    }

    /// Estimate transaction fees for a Stacks contract call. This function
    /// caps the calculated fee to the configured maximum fee for a Stacks
    /// transaction.
    async fn estimate_stacks_tx_fee<T>(
        &self,
        wallet: &SignerWallet,
        contract_call: &T,
        fee_priority: FeePriority,
    ) -> Result<u64, Error>
    where
        T: AsTxPayload + Send + Sync,
    {
        // Get the configured max Stacks transaction fee in microSTX.
        let stacks_fees_max_ustx = self.context.config().signer.stacks_fees_max_ustx.get();

        // Calculate the stacks fee for the contract call and cap it to the configured maximum.
        let tx_fee = self
            .context
            .get_stacks_client()
            .estimate_fees(wallet, contract_call, fee_priority)
            .await?
            .min(stacks_fees_max_ustx);

        Ok(tx_fee)
    }
}

/// Check if the provided public key is the coordinator for the provided chain
/// tip
pub fn given_key_is_coordinator(
    pub_key: PublicKey,
    bitcoin_chain_tip: &model::BitcoinBlockHash,
    signer_public_keys: &BTreeSet<PublicKey>,
) -> bool {
    coordinator_public_key(bitcoin_chain_tip, signer_public_keys) == Some(pub_key)
}

/// Find the coordinator public key
pub fn coordinator_public_key(
    bitcoin_chain_tip: &model::BitcoinBlockHash,
    signer_public_keys: &BTreeSet<PublicKey>,
) -> Option<PublicKey> {
    // Create a hash of the bitcoin chain tip. SHA256 will always result in
    // a 32 byte digest.
    let mut hasher = sha2::Sha256::new();
    hasher.update(bitcoin_chain_tip.into_bytes());
    let digest: [u8; 32] = hasher.finalize().into();

    // Use the first 4 bytes of the digest to create a u32 index. Since `digest`
    // is 32 bytes and we explicitly take the first 4 bytes, this is safe.
    #[allow(clippy::expect_used)]
    let u32_bytes = digest[..4]
        .try_into()
        .expect("BUG: failed to take first 4 bytes of digest");

    // Convert the first 4 bytes of the digest to a u32 index.
    let index = u32::from_be_bytes(u32_bytes);

    let num_signers = signer_public_keys.len();

    signer_public_keys
        .iter()
        .nth((index as usize) % num_signers)
        .copied()
}

/// Determine, according to the current state of the signer and configuration,
/// whether or not a new DKG round should run.
pub async fn should_run_dkg(
    context: &impl Context,
    bitcoin_chain_tip: &model::BitcoinBlockRef,
) -> Result<bool, Error> {
    let storage = context.get_storage();
    let config = context.config();

    let latest_dkg_shares = storage.get_latest_non_failed_dkg_shares().await?;
    let Some(latest_dkg_shares) = latest_dkg_shares else {
        tracing::info!("no non-failed DKG shares exist; proceeding with DKG");
        return Ok(true);
    };

    // If the latest shares are unverified, we want to prioritize verifying them
    // instead of doing new DKG rounds. If we fail to do so they will eventually
    // be marked as failed, and we will resume DKG-ing.
    if latest_dkg_shares.dkg_shares_status == model::DkgSharesStatus::Unverified {
        tracing::debug!("latest shares are unverified; skipping DKG");
        return Ok(false);
    }

    // If the registry has signer set info, we may need to run DKG based on it
    if let Some(registry_signer_info) = context.state().registry_signer_set_info() {
        // If the registry differs from the config we may need to run DKG
        if registry_signer_info.signatures_required != config.signer.bootstrap_signatures_required
            || registry_signer_info.signer_set != config.signer.bootstrap_signing_set
        {
            // If we don't have new shares for the config already, we need DKG
            if latest_dkg_shares.signature_share_threshold
                != config.signer.bootstrap_signatures_required
                || latest_dkg_shares.signer_set_public_keys() != config.signer.bootstrap_signing_set
            {
                tracing::info!(
                    "signer set config differs from registry and latest DKG shares; proceeding with DKG"
                );
                return Ok(true);
            } else {
                tracing::debug!(
                    "signer set config differs from registry, but we already have verified shares for it; checking other conditions"
                );
            }
        }
    }

    // If the config specifies a `dkg_min_bitcoin_block_height` then we want to
    // run DKG if we don't have non-failed shares created after that height.
    if let Some(dkg_min_height) = config.signer.dkg_min_bitcoin_block_height
        && latest_dkg_shares.started_at_bitcoin_block_height < dkg_min_height
        && bitcoin_chain_tip.block_height >= dkg_min_height
    {
        tracing::info!(
            %dkg_min_height,
            "reached DKG minimum height and no non-failed shares after that; proceeding with DKG"
        );
        return Ok(true);
    }

    // If we reach here then nothing suggested we want to run DKG
    Ok(false)
}

/// Assert, given the last dkg and smart contract current aggregate key, if we
/// need to verify the shares and/or issue a rotate key call.
pub fn assert_rotate_key_action<C>(
    context: &C,
    last_dkg: &model::EncryptedDkgShares,
    current_aggregate_key: Option<PublicKey>,
    bitcoin_chain_tip: &model::BitcoinBlockRef,
) -> Result<(bool, bool), Error>
where
    C: Context,
{
    let base_needs_rotate_key = Some(last_dkg.aggregate_key) != current_aggregate_key;

    // Check if past verification window, if we are, skip verification
    let dkg_verification_window = context.config().signer.dkg_verification_window;
    let max_verification_height = last_dkg
        .started_at_bitcoin_block_height
        .saturating_add(dkg_verification_window as u64);

    let past_verification_window = bitcoin_chain_tip.block_height > max_verification_height;

    let needs_verification = match last_dkg.dkg_shares_status {
        model::DkgSharesStatus::Unverified => !past_verification_window,
        model::DkgSharesStatus::Verified => base_needs_rotate_key && !past_verification_window,
        model::DkgSharesStatus::Failed => {
            return Err(Error::DkgVerificationFailed(last_dkg.aggregate_key.into()));
        }
    };

    // Similar logic to needs_rotate_key: if shares are Unverified &
    // past the verification window, don't attempt to submit a key
    // rotation transaction.
    let needs_rotate_key = match last_dkg.dkg_shares_status {
        model::DkgSharesStatus::Unverified => base_needs_rotate_key && !past_verification_window,
        model::DkgSharesStatus::Verified => base_needs_rotate_key,
        model::DkgSharesStatus::Failed => {
            return Err(Error::DkgVerificationFailed(last_dkg.aggregate_key.into()));
        }
    };

    Ok((needs_verification, needs_rotate_key))
}

/// Adjust the wallet nonce based on the error
pub fn adjust_nonce(wallet: &SignerWallet, error: &Error) {
    match error {
        // For `ConflictingNonceInMempool` we don't want to decrement the nonce
        // to avoid failing also the following submissions
        Error::StacksTxRejection(TxRejection { reason, .. })
            if reason == REJECTION_REASON_CONFLICTING_NONCE_IN_MEMPOOL => {}
        _ => wallet.set_nonce(wallet.get_nonce().saturating_sub(1)),
    }
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::MockBitcoinInteract;
    use crate::context::Context as _;
    use crate::emily_client::MockEmilyInteract;
    use crate::error::Error;
    use crate::keys::PrivateKey;
    use crate::keys::PublicKey;
    use crate::network::in_memory2::WanNetwork;
    use crate::stacks::api::MockStacksInteract;
    use crate::storage::DbWrite as _;
    use crate::storage::memory::SharedStore;
    use crate::storage::model;
    use crate::storage::model::BitcoinBlockHeight;
    use crate::storage::model::DkgSharesStatus;
    use crate::testing::context::*;
    use crate::testing::get_rng;
    use crate::testing::transaction_coordinator::TestEnvironment;
    use crate::testing::{self};

    use fake::Fake as _;
    use fake::Faker;
    use rand::SeedableRng as _;
    use test_case::test_case;

    use super::assert_rotate_key_action;
    use super::should_run_dkg;
    use super::*;

    #[allow(clippy::type_complexity)]
    fn test_environment() -> TestEnvironment<
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
            num_signers_per_request: 7,
            consecutive_blocks: false,
        };

        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.bootstrap_signatures_required = 3;
            })
            .build();

        // TODO: fix tech debt #893 then raise threshold to 5
        TestEnvironment {
            context,
            context_window: 5,
            num_signers: 7,
            signing_threshold: 3,
            test_model_parameters,
        }
    }

    #[ignore = "we have a test for this"]
    #[test_log::test(tokio::test)]
    async fn should_be_able_to_coordinate_signing_rounds() {
        test_environment()
            .assert_should_be_able_to_coordinate_signing_rounds(std::time::Duration::ZERO)
            .await;
    }

    #[ignore = "we have a test for this"]
    #[tokio::test]
    async fn should_be_able_to_skip_deploy_sbtc_contracts() {
        test_environment()
            .assert_skips_deploy_sbtc_contracts()
            .await;
    }

    #[ignore = "This is sensitive to the values set in the config"]
    #[tokio::test]
    async fn should_wait_before_processing_bitcoin_blocks() {
        // NOTE: Above test `should_be_able_to_coordinate_signing_rounds`
        // could be removed as redundant now.

        // Measure baseline.
        let baseline_start = std::time::Instant::now();
        test_environment()
            .assert_should_be_able_to_coordinate_signing_rounds(std::time::Duration::ZERO)
            .await;
        // Locally this takes a couple seconds to execute.
        // This truncates the decimals.
        let baseline_elapsed = std::time::Duration::from_secs(baseline_start.elapsed().as_secs());

        let delay_i = 3;
        let delay = std::time::Duration::from_secs(delay_i);
        testing::set_var(
            "SIGNER_SIGNER__BITCOIN_PROCESSING_DELAY",
            delay_i.to_string(),
        );
        let start = std::time::Instant::now();
        test_environment()
            .assert_should_be_able_to_coordinate_signing_rounds(delay)
            .await;
        more_asserts::assert_gt!(start.elapsed(), delay + baseline_elapsed);
    }

    /// Check that we skip processing bitcoin blocks if the chain tip in
    /// the state doesn't match the block hash passed in.
    #[tokio::test]
    async fn should_skip_processing_bitcoin_blocks_if_chain_tip_has_changed() {
        let mut rng = testing::get_rng();
        let ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.bootstrap_signatures_required = 1;
                settings.signer.bootstrap_signing_set =
                    std::iter::once(settings.signer.public_key()).collect();
            })
            .build();

        let network = WanNetwork::default();
        let net = network.connect(&ctx);

        let mut ev = TxCoordinatorEventLoop {
            network: net.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            private_key: ctx.config().signer.private_key,
            signing_round_max_duration: Duration::from_secs(10),
            bitcoin_presign_request_max_duration: Duration::from_secs(10),
            dkg_max_duration: Duration::from_secs(10),
            is_epoch3: true,
        };

        let chain_tip1: BitcoinBlockRef = fake::Faker.fake_with_rng(&mut rng);
        let chain_tip2: BitcoinBlockRef = fake::Faker.fake_with_rng(&mut rng);

        // There is only one signer in the signer set, us, so we should
        // always be coordinator.
        assert!(ev.is_coordinator(&chain_tip1.block_hash));
        assert!(ev.is_coordinator(&chain_tip2.block_hash));

        // We should bail if the chain tip is not set.
        let error = ev.process_new_blocks(chain_tip2).await.unwrap_err();
        assert_matches::assert_matches!(error, Error::NoChainTip);

        // Now the chain tip in the state is set but it does not match the
        // chain tip passed in, so we should bail early and return Ok(())
        ctx.state().set_bitcoin_chain_tip(chain_tip1);
        ev.process_new_blocks(chain_tip2).await.unwrap();

        // Now the chain tip in the state matches the chain tip passed in,
        // so we should process the blocks. However, we do not have any
        // signer set info in the state, so we'll bail with an error.
        let error = ev.process_new_blocks(chain_tip1).await.unwrap_err();
        assert_matches::assert_matches!(error, Error::MissingAggregateKey(_));
    }

    /// Check that we skip processing bitcoin blocks if the chain tip in
    /// the state doesn't match the block hash passed in.
    #[tokio::test]
    async fn should_skip_processing_bitcoin_blocks_if_not_coordinator() {
        let mut rng = testing::get_rng();
        let ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                // If we are the coordinator then we will wait for 10
                // seconds. However, in this test we shouldn't be the
                // coordinator, so we should exit early. If there is a bug
                // and we are the coordinator then we'll end up waiting for
                // one second due to the timeout below.
                settings.signer.bitcoin_processing_delay = Duration::from_secs(10);
            })
            .build();

        let network = WanNetwork::default();
        let net = network.connect(&ctx);

        let mut ev = TxCoordinatorEventLoop {
            network: net.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            private_key: PrivateKey::new(&mut rng),
            signing_round_max_duration: Duration::from_secs(10),
            bitcoin_presign_request_max_duration: Duration::from_secs(10),
            dkg_max_duration: Duration::from_secs(10),
            is_epoch3: true,
        };

        let chain_tip1: BitcoinBlockRef = fake::Faker.fake_with_rng(&mut rng);
        // The given private key is randomly generated so it is unlikely to
        // be part of the bootstrap signing set, and so unlikely to be
        // coordinator.
        assert!(!ev.is_coordinator(&chain_tip1.block_hash));

        ctx.state().set_bitcoin_chain_tip(chain_tip1);

        // `process_new_blocks` will exit early since we are not the
        // coordinator. If we were the cooridnator then we would try to
        // wait for 10 seconds, resulting in a timeout error.
        tokio::time::timeout(Duration::from_secs(1), ev.process_new_blocks(chain_tip1))
            .await
            .unwrap()
            .unwrap();
    }

    /// Check that is_coordinator uses the registry for figuring out who
    /// the cooridnator is and falls back to the config if the registry has
    /// no signer set info.
    #[tokio::test]
    async fn is_coordinator_uses_registry_for_coordinator() {
        let mut rng = testing::get_rng();
        let ctx = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|settings| {
                settings.signer.bootstrap_signatures_required = 1;
                settings.signer.bootstrap_signing_set =
                    std::iter::once(settings.signer.public_key()).collect();
            })
            .build();

        let network = WanNetwork::default();
        let net = network.connect(&ctx);

        let ev = TxCoordinatorEventLoop {
            network: net.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            private_key: ctx.config().signer.private_key,
            signing_round_max_duration: Duration::from_secs(10),
            bitcoin_presign_request_max_duration: Duration::from_secs(10),
            dkg_max_duration: Duration::from_secs(10),
            is_epoch3: true,
        };

        // We should always be the coordinator since the registry is unset
        // and we're the only signer in the bootstrap signing set.
        assert!(ev.context.state().registry_signer_set_info().is_none());

        for _ in 0..100 {
            let chain_tip1: BitcoinBlockRef = fake::Faker.fake_with_rng(&mut rng);
            assert!(ev.is_coordinator(&chain_tip1.block_hash));
        }

        // Now let's set the signer set in the registry to some random
        // signer set without our key. Now we should never be the
        // coordinator.
        let signer_set_info = crate::stacks::api::SignerSetInfo {
            aggregate_key: Faker.fake_with_rng(&mut rng),
            signer_set: std::iter::repeat_with(|| Faker.fake_with_rng(&mut rng))
                .take(2)
                .collect(),
            signatures_required: 2,
        };

        ctx.state().update_registry_signer_set_info(signer_set_info);

        // If we were part of the signing set, there is a 2^(-128) chance
        // that this check would pass.
        for _ in 0..128 {
            let chain_tip1: BitcoinBlockRef = fake::Faker.fake_with_rng(&mut rng);
            assert!(!ev.is_coordinator(&chain_tip1.block_hash));
        }
    }

    #[tokio::test]
    async fn should_get_signer_utxo_simple() {
        test_environment().assert_get_signer_utxo_simple().await;
    }

    #[tokio::test]
    async fn should_get_signer_utxo_fork() {
        test_environment().assert_get_signer_utxo_fork().await;
    }

    #[tokio::test]
    async fn should_get_signer_utxo_unspent() {
        test_environment().assert_get_signer_utxo_unspent().await;
    }

    #[tokio::test]
    async fn should_get_signer_utxo_donations() {
        test_environment().assert_get_signer_utxo_donations().await;
    }

    #[tokio::test]
    async fn should_construct_withdrawal_accept_stacks_sign_request() {
        test_environment()
            .assert_construct_withdrawal_accept_stacks_sign_request()
            .await;
    }

    #[tokio::test]
    async fn should_construct_withdrawal_reject_stacks_sign_request() {
        test_environment()
            .assert_construct_withdrawal_reject_stacks_sign_request()
            .await;
    }

    #[test_case(&[], None, 100, true; "no dkg, no min")]
    #[test_case(&[], Some(100), 99, true; "no dkg, min not reached")]
    #[test_case(&[], Some(100), 100, true; "no dkg, min reached")]
    #[test_case(&[], Some(100), 101, true; "no dkg, min exceeded")]
    #[test_case(&[(DkgSharesStatus::Unverified, 15)], None, 100, false; "unverified shares, no min")]
    #[test_case(&[(DkgSharesStatus::Verified, 15)], None, 100, false; "verified shares, no min")]
    #[test_case(&[(DkgSharesStatus::Failed, 15)], None, 100, true; "failed shares, no min")]
    #[test_case(&[(DkgSharesStatus::Unverified, 15)], Some(100), 99, false; "unverified shares, min not reached")]
    #[test_case(&[(DkgSharesStatus::Verified, 15)], Some(100), 99, false; "verified shares, min not reached")]
    #[test_case(&[(DkgSharesStatus::Failed, 15)], Some(100), 99, true; "failed shares, min not reached")]
    #[test_case(&[(DkgSharesStatus::Unverified, 15)], Some(100), 100, false; "unverified shares, min reached")]
    #[test_case(&[(DkgSharesStatus::Verified, 15)], Some(100), 100, true; "verified shares, min reached")]
    #[test_case(&[(DkgSharesStatus::Failed, 15)], Some(100), 100, true; "failed shares, min reached")]
    #[test_case(
        &[(DkgSharesStatus::Verified, 15), (DkgSharesStatus::Unverified, 99)],
        Some(100), 101, false; "unverified shares before min, min reached")]
    #[test_case(
        &[(DkgSharesStatus::Verified, 15), (DkgSharesStatus::Verified, 99)],
        Some(100), 101, true; "verified shares before min, min reached")]
    #[test_case(
        &[(DkgSharesStatus::Verified, 15), (DkgSharesStatus::Failed, 99)],
        Some(100), 101, true; "failed shares before min, min reached")]
    #[test_case(
        &[(DkgSharesStatus::Verified, 15), (DkgSharesStatus::Unverified, 101)],
        Some(100), 101, false; "unverified shares after min, min reached")]
    #[test_case(
        &[(DkgSharesStatus::Verified, 15), (DkgSharesStatus::Verified, 101)],
        Some(100), 101, false; "verified shares after min, min reached")]
    #[test_case(
        &[(DkgSharesStatus::Verified, 15), (DkgSharesStatus::Failed, 101)],
        Some(100), 101, true; "failed shares after min, min reached")]
    #[test_case(&[(DkgSharesStatus::Verified, 100)], Some(100), 100, false; "verified shares matching min and chain tip")]
    #[test_log::test(tokio::test)]
    async fn test_should_run_dkg(
        dkg_shares: &[(DkgSharesStatus, u64)],
        dkg_min_bitcoin_block_height: Option<u64>,
        chain_tip_height: u64,
        expect_dkg: bool,
    ) {
        let mut rng = get_rng();
        let chain_tip_height = chain_tip_height.into();
        let dkg_min_bitcoin_block_height =
            dkg_min_bitcoin_block_height.map(BitcoinBlockHeight::from);
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .modify_settings(|s| {
                s.signer.dkg_min_bitcoin_block_height = dkg_min_bitcoin_block_height;
            })
            .build();

        let storage = context.get_storage_mut();

        for (dkg_status, dkg_height) in dkg_shares {
            let shares = model::EncryptedDkgShares {
                dkg_shares_status: *dkg_status,
                started_at_bitcoin_block_height: (*dkg_height).into(),
                ..Faker.fake_with_rng(&mut rng)
            };
            storage.write_encrypted_dkg_shares(&shares).await.unwrap();
        }

        // Dummy chain tip hash which will be used to fetch the block height
        let bitcoin_chain_tip = model::BitcoinBlockRef {
            block_height: chain_tip_height,
            block_hash: Faker.fake_with_rng(&mut rng),
        };

        // Write a bitcoin block at the given height, simulating the chain tip.
        storage
            .write_bitcoin_block(&model::BitcoinBlock {
                block_hash: bitcoin_chain_tip.block_hash,
                block_height: bitcoin_chain_tip.block_height,
                parent_hash: Faker.fake_with_rng(&mut rng),
            })
            .await
            .unwrap();

        let aggregate_key = Faker.fake_with_rng(&mut rng);
        prevent_dkg_on_changed_signer_set_info(&context, aggregate_key);

        // Test the case
        let result = should_run_dkg(&context, &bitcoin_chain_tip)
            .await
            .expect("failed to check if DKG should be coordinated");

        // Assert the result
        assert_eq!(result, expect_dkg);
    }

    fn public_key_from_seed(seed: u64) -> PublicKey {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        PublicKey::from_private_key(&PrivateKey::new(&mut rng))
    }

    struct RotateKeyActionTest {
        shares_status: model::DkgSharesStatus,
        shares_key_seed: u64,
        current_aggregate_key_seed: Option<u64>,
        needs_verification: bool,
        needs_rotate_key: bool,
    }

    // Test cases for assert_rotate_key_action with dkg_verification_window = 10
    // Chain tip height = 100, so verification window is heights 90-100
    // Tests with needs_verification = true use DKG start height 90 (within window)
    // Tests with needs_verification = false use DKG start height 89 (past window)

    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Unverified,
            shares_key_seed: 1,
            current_aggregate_key_seed: None,
            needs_verification: true,
            needs_rotate_key: true,
        }; "unverified, no key, within window")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Verified,
            shares_key_seed: 1,
            current_aggregate_key_seed: None,
            needs_verification: true,
            needs_rotate_key: true,
        }; "verified, no key")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Unverified,
            shares_key_seed: 1,
            current_aggregate_key_seed: Some(1),
            needs_verification: true,
            needs_rotate_key: false,
        }; "unverified, key up to date, within window")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Verified,
            shares_key_seed: 1,
            current_aggregate_key_seed: Some(1),
            needs_verification: false,
            needs_rotate_key: false,
        }; "verified, key up to date")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Unverified,
            shares_key_seed: 2,
            current_aggregate_key_seed: Some(1),
            needs_verification: true,
            needs_rotate_key: true,
        }; "unverified, new key, within window")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Verified,
            shares_key_seed: 2,
            current_aggregate_key_seed: Some(1),
            needs_verification: true,
            needs_rotate_key: true,
        }; "verified, new key")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Unverified,
            shares_key_seed: 1,
            current_aggregate_key_seed: None,
            needs_verification: false,
            needs_rotate_key: false,
        }; "unverified, no key, past window")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Unverified,
            shares_key_seed: 1,
            current_aggregate_key_seed: Some(1),
            needs_verification: false,
            needs_rotate_key: false,
        }; "unverified, key up to date, past window")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Unverified,
            shares_key_seed: 2,
            current_aggregate_key_seed: Some(1),
            needs_verification: false,
            needs_rotate_key: false,
        }; "unverified, new key, past window")]
    #[tokio::test]
    async fn test_assert_rotate_key_action(scenario: RotateKeyActionTest) -> Result<(), Error> {
        // dkg_verification_window = 10 (default value)
        // Current chain tip height = 100
        // For needs_verification = true: DKG started at height 90 (within 10-block window)
        // For needs_verification = false: DKG started at height 89 (past 10-block window)
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let mut last_dkg: model::EncryptedDkgShares = Faker.fake();
        last_dkg.dkg_shares_status = scenario.shares_status;
        last_dkg.aggregate_key = public_key_from_seed(scenario.shares_key_seed);

        // Set the DKG start height based on whether we expect verification or not
        // If we expect verification (needs_verification = true), set within window
        // If we don't expect verification (needs_verification = false), set past window
        if scenario.needs_verification {
            // Set within verification window (10 blocks before current height of 100)
            last_dkg.started_at_bitcoin_block_height = 90u64.into();
        } else {
            // Set past verification window (11 blocks before current height of 100)
            last_dkg.started_at_bitcoin_block_height = 89u64.into();
        }

        let current_aggregate_key = scenario
            .current_aggregate_key_seed
            .map(public_key_from_seed);

        // Write a bitcoin block at the appropriate height to simulate the current chain tip
        let chain_tip_height = 100u64;
        let bitcoin_chain_tip: model::BitcoinBlockHash = Faker.fake();

        let bitcoin_chain_tip_ref = model::BitcoinBlockRef {
            block_hash: bitcoin_chain_tip,
            block_height: chain_tip_height.into(),
        };

        let (needs_verification, needs_rotate_key) = assert_rotate_key_action(
            &context,
            &last_dkg,
            current_aggregate_key,
            &bitcoin_chain_tip_ref,
        )?;
        assert_eq!(needs_verification, scenario.needs_verification);
        assert_eq!(needs_rotate_key, scenario.needs_rotate_key);
        Ok(())
    }

    #[test_case(None; "no key")]
    #[test_case(Some(public_key_from_seed(1)); "key up to date")]
    #[test_case(Some(public_key_from_seed(2)); "new key")]
    #[tokio::test]
    async fn test_assert_rotate_key_action_failure(current_aggregate_key: Option<PublicKey>) {
        // dkg_verification_window = 10 (default value)
        // Current chain tip height = 100
        // DKG started at height 89 (past 10-block window, but this test fails regardless)
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let mut last_dkg: model::EncryptedDkgShares = Faker.fake();
        last_dkg.dkg_shares_status = model::DkgSharesStatus::Failed;
        last_dkg.aggregate_key = public_key_from_seed(1);
        // Set the DKG start height to ensure verification window check passes
        last_dkg.started_at_bitcoin_block_height = 89u64.into(); // 11 blocks before current height of 100

        // Write a bitcoin block at height 100 to simulate the current chain tip
        let bitcoin_chain_tip: model::BitcoinBlockHash = Faker.fake();

        let bitcoin_chain_tip_ref = model::BitcoinBlockRef {
            block_hash: bitcoin_chain_tip,
            block_height: 100u64.into(),
        };

        let result = assert_rotate_key_action(
            &context,
            &last_dkg,
            current_aggregate_key,
            &bitcoin_chain_tip_ref,
        );
        match result {
            Err(Error::DkgVerificationFailed(key)) => {
                assert_eq!(key, last_dkg.aggregate_key.into());
            }
            _ => {
                panic!("unexpected result")
            }
        }
    }

    #[tokio::test]
    async fn test_assert_rotate_key_action_verification_window_elapsed() {
        // dkg_verification_window = 10 (default value)
        // Current chain tip height = 100
        // DKG started at height 79 (21 blocks past the 10-block verification window)
        let context = TestContext::builder()
            .with_in_memory_storage()
            .with_mocked_clients()
            .build();

        let mut last_dkg: model::EncryptedDkgShares = Faker.fake();
        last_dkg.dkg_shares_status = model::DkgSharesStatus::Unverified;
        last_dkg.aggregate_key = public_key_from_seed(1);
        // Set the DKG start height to be outside the verification window
        last_dkg.started_at_bitcoin_block_height = 79u64.into(); // 21 blocks before current height of 100

        // Write a bitcoin block at height 100 to simulate the current chain tip
        let bitcoin_chain_tip: model::BitcoinBlockHash = Faker.fake();

        let bitcoin_chain_tip_ref = model::BitcoinBlockRef {
            block_hash: bitcoin_chain_tip,
            block_height: 100u64.into(),
        };

        let result = assert_rotate_key_action(&context, &last_dkg, None, &bitcoin_chain_tip_ref);

        // Now we expect success: neither verification nor key
        // rotation are needed since we are past the verification
        // window of 10 bitcoin blocks
        match result {
            Ok((needs_verification, needs_rotate_key)) => {
                assert!(!needs_verification);
                assert!(!needs_rotate_key);
            }
            Err(e) => {
                panic!("expected success but got error: {e:?}")
            }
        }
    }
}
