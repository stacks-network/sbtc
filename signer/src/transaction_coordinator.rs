//! # Transaction coordinator
//!
//! This module contains the transaction coordinator, which is the component of the sBTC signer
//! responsible for constructing transactions and coordinating signing rounds.
//!
//! For more details, see the [`TxCoordinatorEventLoop`] documentation.

use std::collections::BTreeSet;
use std::collections::HashSet;
use std::time::Duration;

use blockstack_lib::chainstate::stacks::StacksTransaction;
use futures::Stream;
use futures::StreamExt as _;
use futures::future::try_join_all;
use sha2::Digest;

use crate::WITHDRAWAL_BLOCKS_EXPIRY;
use crate::WITHDRAWAL_DUST_LIMIT;
use crate::WITHDRAWAL_EXPIRY_BUFFER;
use crate::WITHDRAWAL_MIN_CONFIRMATIONS;
use crate::bitcoin::BitcoinInteract;
use crate::bitcoin::TransactionLookupHint;
use crate::bitcoin::utxo;
use crate::bitcoin::utxo::Fees;
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
use crate::emily_client::EmilyInteract;
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
use crate::stacks::api::GetNakamotoStartHeight;
use crate::stacks::api::StacksInteract;
use crate::stacks::api::SubmitTxResponse;
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
use crate::storage::model::StacksTxId;
use crate::wsts_state_machine::FireCoordinator;
use crate::wsts_state_machine::FrostCoordinator;
use crate::wsts_state_machine::WstsCoordinator;

use bitcoin::hashes::Hash as _;
use wsts::net::SignatureType;
use wsts::state_machine::OperationResult as WstsOperationResult;
use wsts::state_machine::StateMachine as _;
use wsts::state_machine::coordinator::State as WstsCoordinatorState;

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
    /// the number of signatures required.
    pub threshold: u16,
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
    /// The public keys of the current signer set.
    pub signer_public_keys: &'a BTreeSet<PublicKey>,
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
            RequestDeciderEvent::NewRequestsHandled,
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
                SignerSignal::Event(event) => {
                    if let SignerEvent::RequestDecider(RequestDeciderEvent::NewRequestsHandled) =
                        event
                    {
                        tracing::debug!("received signal; processing requests");
                        if let Err(error) = self.process_new_blocks().await {
                            tracing::error!(
                                %error,
                                "error processing requests; skipping this round"
                            );
                        }
                        tracing::trace!("sending tenure completed signal");
                        self.context
                            .signal(TxCoordinatorEvent::TenureCompleted.into())?;
                    }
                }
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
            | SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(msg))) => Some(msg),
            _ => None,
        }
    }

    async fn is_epoch3(&mut self) -> Result<bool, Error> {
        if self.is_epoch3 {
            return Ok(true);
        }
        tracing::debug!("checked for whether we are in epoch 3 or later");
        let pox_info = self.context.get_stacks_client().get_pox_info().await?;

        let Some(nakamoto_start_height) = pox_info.nakamoto_start_height() else {
            return Ok(false);
        };

        let is_epoch3 = pox_info.current_burnchain_block_height > nakamoto_start_height;
        if is_epoch3 {
            self.is_epoch3 = is_epoch3;
            tracing::debug!("we are in epoch 3 or later; time to do work");
        }
        Ok(is_epoch3)
    }

    #[tracing::instrument(skip_all, fields(
        public_key = %self.signer_public_key(),
        bitcoin_tip_hash = tracing::field::Empty,
        bitcoin_tip_height = tracing::field::Empty,
    ))]
    async fn process_new_blocks(&mut self) -> Result<(), Error> {
        if !self.is_epoch3().await? {
            return Ok(());
        }

        let bitcoin_processing_delay = self.context.config().signer.bitcoin_processing_delay;
        if bitcoin_processing_delay > Duration::ZERO {
            tracing::debug!("sleeping before processing new bitcoin block");
            tokio::time::sleep(bitcoin_processing_delay).await;
        }

        let bitcoin_chain_tip = self
            .context
            .get_storage()
            .get_bitcoin_canonical_chain_tip_ref()
            .await?
            .ok_or(Error::NoChainTip)?;

        let span = tracing::Span::current();
        span.record(
            "bitcoin_tip_hash",
            tracing::field::display(bitcoin_chain_tip.block_hash),
        );
        span.record("bitcoin_tip_height", bitcoin_chain_tip.block_height);

        // We first need to determine if we are the coordinator, so we need
        // to know the current signing set. If we are the coordinator then
        // we need to know the aggregate key for constructing bitcoin
        // transactions. We need to know the current signing set and the
        // current aggregate key.
        let maybe_aggregate_key = self.context.state().current_aggregate_key();
        let signer_public_keys = self.context.state().current_signer_public_keys();

        // If we are not the coordinator, then we have no business
        // coordinating DKG or constructing bitcoin and stacks
        // transactions, might as well return early.
        if !self.is_coordinator(bitcoin_chain_tip.as_ref(), &signer_public_keys) {
            // Before returning, we also check if all the smart contracts are
            // deployed: we do this as some other coordinator could have deployed
            // them, in which case we need to updated our state.
            self.all_smart_contracts_deployed().await?;

            tracing::debug!("we are not the coordinator, so nothing to do");
            return Ok(());
        }

        tracing::debug!("we are the coordinator");
        metrics::counter!(Metrics::CoordinatorTenuresTotal).increment(1);

        tracing::debug!("determining if we need to coordinate DKG");
        let should_coordinate_dkg =
            should_coordinate_dkg(&self.context, &bitcoin_chain_tip).await?;
        let aggregate_key = if should_coordinate_dkg {
            self.coordinate_dkg(bitcoin_chain_tip.as_ref()).await?
        } else {
            maybe_aggregate_key.ok_or(Error::MissingAggregateKey(*bitcoin_chain_tip.block_hash))?
        };

        let chain_tip_hash = &bitcoin_chain_tip.block_hash;

        tracing::debug!("loading the signer stacks wallet");
        let wallet = self.get_signer_wallet(chain_tip_hash).await?;

        self.deploy_smart_contracts(chain_tip_hash, &wallet, &aggregate_key)
            .await?;

        self.check_and_submit_rotate_key_transaction(chain_tip_hash, &wallet, &aggregate_key)
            .await?;

        let bitcoin_processing_fut = self.construct_and_sign_bitcoin_sbtc_transactions(
            &bitcoin_chain_tip,
            &aggregate_key,
            &signer_public_keys,
        );

        if let Err(error) = bitcoin_processing_fut.await {
            tracing::error!(%error, "failed to construct and sign bitcoin transactions");
        }

        self.construct_and_sign_stacks_response_transactions(
            &bitcoin_chain_tip,
            &wallet,
            &aggregate_key,
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
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        wallet: &SignerWallet,
        aggregate_key: &PublicKey,
    ) -> Result<(), Error> {
        if !self.all_smart_contracts_deployed().await? {
            return Ok(());
        }

        let last_dkg = self
            .context
            .get_storage()
            .get_latest_encrypted_dkg_shares()
            .await?;

        // If we don't have DKG shares nothing to do here
        let Some(last_dkg) = last_dkg else {
            return Ok(());
        };

        let current_aggregate_key = self
            .context
            .get_stacks_client()
            .get_current_signers_aggregate_key(&self.context.config().signer.deployer)
            .await?;

        let (needs_verification, needs_rotate_key) =
            assert_rotate_key_action(&last_dkg, current_aggregate_key)?;
        if !needs_verification && !needs_rotate_key {
            tracing::debug!(
                "stacks node is up to date with the current aggregate key and no DKG verification required"
            );
            return Ok(());
        }
        tracing::info!(%needs_verification, %needs_rotate_key, "DKG verification and/or key rotation needed");

        if needs_verification {
            // Perform DKG verification before submitting the rotate key transaction.
            tracing::info!(
                "🔐 beginning DKG verification before submitting rotate-key transaction"
            );
            self.perform_dkg_verification(bitcoin_chain_tip, &last_dkg.aggregate_key, wallet)
                .await?;
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
                    bitcoin_chain_tip,
                    signing_key,
                    &last_dkg.aggregate_key,
                    wallet,
                )
                .await
                .inspect_err(
                    |error| tracing::error!(%error, "failed to sign or submit rotate-key transaction"),
                )?;

            tracing::info!(%txid, "rotate-key transaction submitted successfully");
        }

        Ok(())
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
            last_fees: signer_btc_state.last_fees,
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

        // Send the presign request message
        self.send_message(sbtc_requests, bitcoin_chain_tip).await?;

        tokio::pin!(signal_stream);
        let future = async {
            let target_tip = *bitcoin_chain_tip;
            let mut acknowledged_signers = HashSet::new();

            while acknowledged_signers.len() < self.threshold as usize {
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
        let storage = self.context.get_storage();

        // Fetch the stacks chain tip from the database.
        let stacks_chain_tip = storage
            .get_stacks_chain_tip(&bitcoin_chain_tip.block_hash)
            .await?
            .ok_or(Error::NoStacksChainTip)?;

        let span = tracing::Span::current();
        span.record("stacks_tip_hash", stacks_chain_tip.block_hash.to_hex());
        span.record("stacks_tip_height", stacks_chain_tip.block_height);

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
        let Some(pending_requests) = pending_requests_fut.await? else {
            tracing::debug!("no requests to handle on bitcoin");
            return Ok(());
        };

        tracing::debug!(
            num_deposits = %pending_requests.deposits.len(),
            num_withdrawals = pending_requests.withdrawals.len(),
            "there are eligible requests to handle"
        );

        // Construct the transaction package and store it in the database.
        let transaction_package = pending_requests.construct_transactions()?;

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
            self.sign_and_broadcast(
                bitcoin_chain_tip.as_ref(),
                signer_public_keys,
                &mut transaction,
            )
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
        let deployer = self.context.config().signer.deployer;

        // Fetch deposit requests from the database where
        // there has been a confirmed bitcoin transaction associated with
        // the request.
        //
        // For deposits, there will be at most one such bitcoin transaction
        // on the blockchain identified by the chain tip, where an input is
        // the deposit UTXO.

        let swept_deposits = db
            .get_swept_deposit_requests(chain_tip.as_ref(), self.context_window)
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
            if &self.context.state().bitcoin_chain_tip() != chain_tip {
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

            // If we fail to sign the transaction for some reason, we
            // decrement the nonce by one, and try the next transaction.
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
                    wallet.set_nonce(wallet.get_nonce().saturating_sub(1));
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

        // Fetch withdrawal requests from the database where there has been
        // a confirmed bitcoin transaction associated with the request.
        let swept_withdrawals = db
            .get_swept_withdrawal_requests(&chain_tip.block_hash, self.context_window)
            .await
            .inspect_err(|error| tracing::error!(%error, "could not fetch swept withdrawals"))
            .unwrap_or_default();

        // Fetch withdrawal requests that have not been swept for quite
        // some time.
        let rejected_withdrawals = db
            .get_pending_rejected_withdrawal_requests(chain_tip, self.context_window)
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
            if &self.context.state().bitcoin_chain_tip() != chain_tip {
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
            if &self.context.state().bitcoin_chain_tip() != chain_tip {
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
        let deployer = self.context.config().signer.deployer;

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

        // If we fail to sign the transaction for some reason, we
        // decrement the nonce by one, and try the next transaction.
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
                wallet.set_nonce(wallet.get_nonce().saturating_sub(1));
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
        let deployer = self.context.config().signer.deployer;

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

        // If we fail to sign the transaction for some reason, we
        // decrement the nonce by one, and try the next transaction.
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
                wallet.set_nonce(wallet.get_nonce().saturating_sub(1));
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
        wallet: &SignerWallet,
    ) -> Result<(), Error> {
        let (x_only_pubkey, _) = aggregate_key.x_only_public_key();

        // Note that while we specify the threshold as `signatures_required` in
        // the coordinator below, the FROST coordinator implicitly requires all
        // signers to participate.
        tracing::info!(%aggregate_key, "🔐 preparing to coordinate a FROST signing round to verify the aggregate key");
        let mut frost_coordinator = FrostCoordinator::load(
            &self.context.get_storage(),
            aggregate_key.into(),
            wallet.public_keys().iter().cloned(),
            wallet.signatures_required(),
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
            SignatureType::Taproot(None),
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
        let contract_call = ContractCall::RotateKeysV1(RotateKeysV1::new(
            wallet,
            self.context.config().signer.deployer,
            rotate_key_aggregate_key,
        ));

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
            aggregate_key: *aggregate_key,
            contract_tx: contract_call.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid(),
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
            Ok(SubmitTxResponse::Acceptance(txid)) => Ok(txid.into()),
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
        let contract_call = ContractCall::CompleteDepositV1(CompleteDepositV1 {
            amount: req.amount - assessed_bitcoin_fee.to_sat(),
            outpoint,
            recipient: req.recipient.into(),
            deployer: self.context.config().signer.deployer,
            sweep_txid: req.sweep_txid,
            sweep_block_hash: req.sweep_block_hash,
            sweep_block_height: req.sweep_block_height,
        });

        // Complete deposit requests should be done as soon as possible, so
        // we set the fee rate to the high priority fee.
        let tx_fee = self
            .estimate_stacks_tx_fee(wallet, &contract_call, FeePriority::High)
            .await?;

        let multi_tx = MultisigTx::new_tx(&contract_call, wallet, tx_fee);
        let tx = multi_tx.tx();

        let sign_request = StacksTransactionSignRequest {
            aggregate_key: *bitcoin_aggregate_key,
            contract_tx: contract_call.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid(),
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

        let contract_call = ContractCall::AcceptWithdrawalV1(AcceptWithdrawalV1 {
            id: qualified_id,
            outpoint,
            tx_fee: assessed_bitcoin_fee.to_sat(),
            signer_bitmap: 0,
            deployer: self.context.config().signer.deployer,
            sweep_block_hash: req.sweep_block_hash,
            sweep_block_height: req.sweep_block_height,
        });

        // Estimate the fee for the stacks transaction
        let tx_fee = self
            .estimate_stacks_tx_fee(wallet, &contract_call, FeePriority::Medium)
            .await?;

        let multi_tx = MultisigTx::new_tx(&contract_call, wallet, tx_fee);
        let tx = multi_tx.tx();

        let sign_request = StacksTransactionSignRequest {
            aggregate_key: *bitcoin_aggregate_key,
            contract_tx: contract_call.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid(),
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
        let contract_call = ContractCall::RejectWithdrawalV1(RejectWithdrawalV1 {
            id: req.qualified_id(),
            signer_bitmap: 0,
            deployer: self.context.config().signer.deployer,
        });

        // Estimate the fee for the stacks transaction
        let tx_fee = self
            .estimate_stacks_tx_fee(wallet, &contract_call, FeePriority::High)
            .await?;

        let multi_tx = MultisigTx::new_tx(&contract_call, wallet, tx_fee);
        let tx = multi_tx.tx();

        let sign_request = StacksTransactionSignRequest {
            aggregate_key: *bitcoin_aggregate_key,
            contract_tx: contract_call.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid(),
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
        signer_public_keys: &BTreeSet<PublicKey>,
        transaction: &mut utxo::UnsignedTransaction<'_>,
    ) -> Result<(), Error> {
        let sighashes = transaction.construct_digests()?;
        let mut fire_coordinator = FireCoordinator::load(
            &self.context.get_storage(),
            sighashes.signers_aggregate_key.into(),
            signer_public_keys.clone(),
            self.threshold,
            self.private_key,
        )
        .await?;
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
                SignatureType::Taproot(None),
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

            let mut fire_coordinator = FireCoordinator::load(
                &self.context.get_storage(),
                deposit.signers_public_key.into(),
                signer_public_keys.clone(),
                self.threshold,
                self.private_key,
            )
            .await?;

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
        let outbound = coordinator.start_signing_round(msg, signature_type)?;

        // We create a signal stream before sending a message so that there
        // is no race condition with the steam and the getting a response.
        let signal_stream = self
            .context
            .as_signal_stream(signed_message_filter)
            .filter_map(Self::to_signed_message);

        let msg = message::WstsMessage { id, inner: outbound.msg };
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
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<PublicKey, Error> {
        tracing::info!("Coordinating DKG");
        // Get the current signer set for running DKG.
        //
        // Also, note that in order to change the signing set we must first
        // run DKG (which the current function is doing), and DKG requires
        // us to define signing set (which is returned in the next
        // non-comment line). That function essentially uses the signing
        // set of the last DKG (either through the last rotate-keys
        // contract call or from the `dkg_shares` table) so we wind up
        // never changing the signing set.
        let signer_set = self.context.state().current_signer_public_keys();

        let mut state_machine = FireCoordinator::new(signer_set, self.threshold, self.private_key);

        // Okay let's move the coordinator state machine to the beginning
        // of the DKG phase.
        state_machine
            .move_to(WstsCoordinatorState::DkgPublicDistribute)
            .map_err(Error::wsts_coordinator)?;

        let outbound = state_machine
            .start_public_shares()
            .map_err(Error::wsts_coordinator)?;

        // We identify the DKG round by a 32-byte hash based on the coordinator
        // identity and current bitcoin chain tip.
        let identifier = self.coordinator_id(chain_tip);
        let id = WstsMessageId::Dkg(identifier);
        let msg = message::WstsMessage { id, inner: outbound.msg };

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
        self.send_message(msg, chain_tip).await?;

        // Now that DKG has "begun" we need to drive it to completion.
        let max_duration = self.dkg_max_duration;
        let dkg_fut =
            self.drive_wsts_state_machine(signal_stream, chain_tip, &mut state_machine, id);

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
        // this assumes that the signer set doesn't change for the duration of this call,
        // but we're already assuming that the bitcoin chain tip doesn't change
        // alternately we could hit the DB every time we get a new message
        let signer_set = self.context.state().current_signer_public_keys();
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

            let (outbound_packet, operation_result) = match coordinator.process_message(&msg) {
                Ok(val) => val,
                Err(err) => {
                    tracing::warn!(?msg, reason = %err, "ignoring message");
                    continue;
                }
            };

            if let Some(packet) = outbound_packet {
                let msg = message::WstsMessage { id, inner: packet.msg };
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
        public_keys: &hashbrown::HashMap<u32, p256k1::point::Point>,
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

    // Determine if the current coordinator is the coordinator.
    //
    // The coordinator is decided using the hash of the bitcoin
    // chain tip. We don't use the chain tip directly because
    // it typically starts with a lot of leading zeros.
    //
    // Note that this function is technically not fallible,
    // but for now we have chosen to return phantom errors
    // instead of adding expects/unwraps in the code.
    // Ideally the code should be formulated in a way to guarantee
    // it being infallible without relying on sequentially coupling
    // expressions. However, that is left for future work.
    fn is_coordinator(
        &self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        signer_public_keys: &BTreeSet<PublicKey>,
    ) -> bool {
        given_key_is_coordinator(
            self.signer_public_key(),
            bitcoin_chain_tip,
            signer_public_keys,
        )
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
        let fee_rate = bitcoin_client.estimate_fee_rate().await?;

        // Retrieve the signer's current UTXO.
        let utxo = self
            .context
            .get_storage()
            .get_signer_utxo(chain_tip)
            .await?
            .ok_or(Error::MissingSignerUtxo)?;

        let last_fees = self.assess_mempool_sweep_transaction_fees(&utxo).await?;

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
                    bitcoin_block_height = req.bitcoin_block_height,
                    min_soft_bitcoin_height,
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
            let num_confirmations = params
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
                params.bitcoin_chain_tip.as_ref(),
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

        // Setup the parameters for fetching pending requests.
        let params = GetPendingRequestsParams {
            bitcoin_chain_tip,
            stacks_chain_tip,
            aggregate_key,
            signer_public_keys,
            signature_threshold: self.threshold,
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
            accept_threshold: self.threshold,
            num_signers,
            sbtc_limits,
            max_deposits_per_bitcoin_tx,
        }))
    }

    /// This function provides a deterministic 32-byte identifier for the
    /// signer.
    fn coordinator_id(&self, chain_tip: &model::BitcoinBlockHash) -> [u8; 32] {
        sha2::Sha256::new_with_prefix("SIGNER_COORDINATOR_ID")
            .chain_update(self.signer_public_key().serialize())
            .chain_update(chain_tip.into_bytes())
            .finalize()
            .into()
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
            .signal(TxCoordinatorEvent::MessageGenerated(msg).into())?;

        Ok(())
    }

    /// Deploy an sBTC smart contract to the stacks node.
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
        let deployer = self.context.config().signer.deployer;
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

        // If we fail to sign the transaction for some reason, we
        // decrement the nonce by one, and try the next transaction.
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
                wallet.set_nonce(wallet.get_nonce().saturating_sub(1));
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
            aggregate_key: *bitcoin_aggregate_key,
            contract_tx: contract_deploy.into(),
            nonce: tx.get_origin_nonce(),
            tx_fee: tx.get_tx_fee(),
            txid: tx.txid(),
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
        if self.all_smart_contracts_deployed().await? {
            return Ok(());
        }

        for contract in SMART_CONTRACTS {
            self.deploy_smart_contract(contract, chain_tip, bitcoin_aggregate_key, wallet)
                .await?;
        }

        Ok(())
    }

    async fn all_smart_contracts_deployed(&mut self) -> Result<bool, Error> {
        if self.context.state().sbtc_contracts_deployed() {
            return Ok(true);
        }

        let stacks = self.context.get_stacks_client();
        let deployer = self.context.config().signer.deployer;

        for contract in SMART_CONTRACTS {
            if !contract.is_deployed(&stacks, &deployer).await? {
                return Ok(false);
            }
        }

        self.context.state().set_sbtc_contracts_deployed();
        Ok(true)
    }

    async fn get_signer_wallet(
        &self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<SignerWallet, Error> {
        let wallet = SignerWallet::load(&self.context, chain_tip).await?;

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

    /// Assesses the total fees paid for any outstanding sweep transactions in
    /// the mempool which may need to be RBF'd. If there are no sweep
    /// transactions which are spending the signer's UTXO, then this function
    /// will return [`None`].
    ///
    /// TODO: This method currently blindly assumes that the mempool transactions
    /// are correct. Maybe we need some validation?
    #[tracing::instrument(skip_all, fields(signer_utxo = %signer_utxo.outpoint))]
    pub async fn assess_mempool_sweep_transaction_fees(
        &self,
        signer_utxo: &utxo::SignerUtxo,
    ) -> Result<Option<Fees>, Error> {
        let bitcoin_client = self.context.get_bitcoin_client();

        // Find the mempool transactions that are spending the provided UTXO.
        let mempool_txs_spending_utxo = bitcoin_client
            .find_mempool_transactions_spending_output(&signer_utxo.outpoint)
            .await?;

        // If no transactions are found, we have nothing to do.
        if mempool_txs_spending_utxo.is_empty() {
            tracing::debug!(
                outpoint = %signer_utxo.outpoint,
                "no mempool transactions found spending signer output; nothing to do"
            );
            return Ok(None);
        }

        tracing::debug!(
            outpoint = %signer_utxo.outpoint,
            "found mempool transactions spending signer output; assessing fees"
        );

        // If we have some transactions, we need to find the one that pays the
        // highest fee. This is the transaction that we will use as the root of
        // the sweep package. Note that even if only one transaction was
        // returned above, we still need to get the fee for it, which is why
        // there's no special logic for one vs multiple.
        //
        // This can technically error if the mempool transactions are not found,
        // but it shouldn't happen since we got the transaction ids from
        // bitcoin-core itself.
        let best_sweep_root = try_join_all(mempool_txs_spending_utxo.iter().map(|txid| {
            let bitcoin_client = bitcoin_client.clone();
            async move {
                bitcoin_client
                    .get_transaction_fee(txid, Some(TransactionLookupHint::Mempool))
                    .await
                    .map(|fee| (txid, fee))
            }
        }))
        .await?
        .into_iter()
        .max_by_key(|(_, fees)| fees.fee);

        // Since we got the transaction ids from bitcoin-core, these should
        // not be missing, but we double-check here just in case (it could
        // happen that the client has failed-over to the next node which isn't
        // in sync with the previous one, for example).
        let Some((best_sweep_root_txid, fees)) = best_sweep_root else {
            tracing::warn!(
                outpoint = %signer_utxo.outpoint,
                "no fees found for mempool transactions spending signer output"
            );
            return Ok(None);
        };

        // Retrieve all descendant transactions of the best sweep root.
        let descendant_txids = bitcoin_client
            .find_mempool_descendants(best_sweep_root_txid)
            .await?;

        // Retrieve fees for all descendant transactions. If there were no
        // descendants then this will just result in an empty list.
        let descendant_fees = try_join_all(descendant_txids.iter().map(|txid| {
            let bitcoin_client = bitcoin_client.clone();
            async move {
                bitcoin_client
                    .get_transaction_fee(txid, Some(TransactionLookupHint::Mempool))
                    .await
            }
        }))
        .await?;

        // Sum the fees of the best sweep root and its descendants, while also
        // summing the vsize of the transactions for fee-rate calculation later.
        // If there were no descendants then this will just be the fee and size
        // from the best root sweep transaction.
        let (total_fees, total_vsize) = descendant_fees
            .into_iter()
            .fold((fees.fee, fees.vsize), |acc, fees| {
                (acc.0 + fees.fee, acc.1 + fees.vsize)
            });

        // Calculate the fee rate based on the total fees and vsizes of the
        // transactions which we've found. Since this is returning transactions
        // from bitcoin-core, we should have valid fees and sizes, so we don't
        // need to check for division by zero.
        let rate = total_fees as f64 / total_vsize as f64;

        Ok(Some(Fees { total: total_fees, rate }))
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
/// whether or not a new DKG round should be coordinated.
pub async fn should_coordinate_dkg(
    context: &impl Context,
    bitcoin_chain_tip: &model::BitcoinBlockRef,
) -> Result<bool, Error> {
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
            Ok(true)
        }
        (current, target, Some(dkg_min_height))
            if current < target.get() && bitcoin_chain_tip.block_height >= dkg_min_height.get() =>
        {
            tracing::info!(
                ?dkg_min_bitcoin_block_height,
                %dkg_target_rounds,
                dkg_current_rounds = %dkg_shares_entry_count,
                "DKG rerun height has been met and we are below the target number of rounds; proceeding with DKG"
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Assert, given the last dkg and smart contract current aggregate key, if we
/// need to verify the shares and/or issue a rotate key call.
pub fn assert_rotate_key_action(
    last_dkg: &model::EncryptedDkgShares,
    current_aggregate_key: Option<PublicKey>,
) -> Result<(bool, bool), Error> {
    let needs_rotate_key = Some(last_dkg.aggregate_key) != current_aggregate_key;

    let needs_verification = match last_dkg.dkg_shares_status {
        model::DkgSharesStatus::Unverified => true,
        model::DkgSharesStatus::Verified => needs_rotate_key,
        model::DkgSharesStatus::Failed => {
            return Err(Error::DkgVerificationFailed(last_dkg.aggregate_key.into()));
        }
    };

    Ok((needs_verification, needs_rotate_key))
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroU64};

    use crate::bitcoin::MockBitcoinInteract;
    use crate::context::Context;
    use crate::emily_client::MockEmilyInteract;
    use crate::error::Error;
    use crate::keys::{PrivateKey, PublicKey};
    use crate::stacks::api::MockStacksInteract;
    use crate::storage::in_memory::SharedStore;
    use crate::storage::{DbWrite, model};
    use crate::testing;
    use crate::testing::context::*;
    use crate::testing::transaction_coordinator::TestEnvironment;

    use fake::{Fake, Faker};
    use rand::SeedableRng as _;
    use test_case::test_case;

    use super::assert_rotate_key_action;
    use super::should_coordinate_dkg;

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

    #[test_case(0, None, 1, 100, true; "first DKG allowed without min height")]
    #[test_case(0, Some(100), 1, 5, true; "first DKG allowed regardless of min height")]
    #[test_case(1, None, 2, 100, false; "subsequent DKG not allowed without min height")]
    #[test_case(1, Some(101), 1, 100, false; "subsequent DKG not allowed with current height lower than min height")]
    #[test_case(1, Some(100), 1, 100, false; "subsequent DKG not allowed when target rounds reached")]
    #[test_case(1, Some(100), 2, 100, true; "subsequent DKG allowed when target rounds not reached and min height met")]
    #[test_log::test(tokio::test)]
    async fn test_should_coordinate_dkg(
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
                    dkg_min_bitcoin_block_height.and_then(NonZeroU64::new);
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
            block_height: chain_tip_height,
            block_hash: Faker.fake(),
        };

        // Write a bitcoin block at the given height, simulating the chain tip.
        storage
            .write_bitcoin_block(&model::BitcoinBlock {
                block_hash: bitcoin_chain_tip.block_hash,
                block_height: bitcoin_chain_tip.block_height,
                parent_hash: Faker.fake(),
            })
            .await
            .unwrap();

        // Test the case
        let result = should_coordinate_dkg(&context, &bitcoin_chain_tip)
            .await
            .expect("failed to check if DKG should be coordinated");

        // Assert the result
        assert_eq!(result, should_allow);
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

    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Unverified,
            shares_key_seed: 1,
            current_aggregate_key_seed: None,
            needs_verification: true,
            needs_rotate_key: true,
        }; "unverified, no key")]
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
        }; "unverified, key up to date")]
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
        }; "unverified, new key")]
    #[test_case(
        RotateKeyActionTest {
            shares_status: model::DkgSharesStatus::Verified,
            shares_key_seed: 2,
            current_aggregate_key_seed: Some(1),
            needs_verification: true,
            needs_rotate_key: true,
        }; "verified, new key")]
    fn test_assert_rotate_key_action(scenario: RotateKeyActionTest) {
        let last_dkg = model::EncryptedDkgShares {
            dkg_shares_status: scenario.shares_status,
            aggregate_key: public_key_from_seed(scenario.shares_key_seed),
            ..Faker.fake()
        };
        let current_aggregate_key = scenario
            .current_aggregate_key_seed
            .map(public_key_from_seed);

        let (needs_verification, needs_rotate_key) =
            assert_rotate_key_action(&last_dkg, current_aggregate_key).unwrap();
        assert_eq!(needs_verification, scenario.needs_verification);
        assert_eq!(needs_rotate_key, scenario.needs_rotate_key);
    }

    #[test_case(None; "no key")]
    #[test_case(Some(public_key_from_seed(1)); "key up to date")]
    #[test_case(Some(public_key_from_seed(2)); "new key")]
    fn test_assert_rotate_key_action_failure(current_aggregate_key: Option<PublicKey>) {
        let last_dkg = model::EncryptedDkgShares {
            dkg_shares_status: model::DkgSharesStatus::Failed,
            aggregate_key: public_key_from_seed(1),
            ..Faker.fake()
        };

        let result = assert_rotate_key_action(&last_dkg, current_aggregate_key);
        match result {
            Err(Error::DkgVerificationFailed(key)) => {
                assert_eq!(key, last_dkg.aggregate_key.into());
            }
            _ => {
                panic!("unexpected result")
            }
        }
    }
}
