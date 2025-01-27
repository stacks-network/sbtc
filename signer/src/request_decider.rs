//! # Request decider event loop
//!
//! This module contains the request decider, which is the component of the sBTC signer
//! responsible for deciding whether to accept or reject a request.
//!
//! For more details, see the [`RequestDeciderEventLoop`] documentation.

use std::time::Duration;

use crate::block_observer::BlockObserver;
use crate::blocklist_client::BlocklistChecker;
use crate::context::Context;
use crate::context::P2PEvent;
use crate::context::RequestDeciderEvent;
use crate::context::SignerCommand;
use crate::context::SignerEvent;
use crate::context::SignerSignal;
use crate::ecdsa::SignEcdsa as _;
use crate::ecdsa::Signed;
use crate::emily_client::EmilyInteract;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message::Payload;
use crate::message::SignerDepositDecision;
use crate::message::SignerMessage;
use crate::message::SignerWithdrawalDecision;
use crate::network::MessageTransfer;
use crate::storage::model;
use crate::storage::model::BitcoinBlockHash;
use crate::storage::model::DepositSigner;
use crate::storage::model::WithdrawalSigner;
use crate::storage::DbRead as _;
use crate::storage::DbWrite as _;

use futures::StreamExt;
use futures::TryStreamExt;

/// This struct is responsible for deciding whether to accept or reject
/// requests and persisting requests from other signers.
#[derive(Debug)]
pub struct RequestDeciderEventLoop<C, N, B> {
    /// The signer context.
    pub context: C,
    /// Interface to the signer network.
    pub network: N,
    /// Blocklist checker.
    pub blocklist_checker: Option<B>,
    /// Private key of the signer for network communication.
    pub signer_private_key: PrivateKey,
    /// How many bitcoin blocks back from the chain tip the signer will look for requests.
    pub context_window: u16,
}

/// This function defines which messages this event loop is interested
/// in.
fn run_loop_message_filter(signal: &SignerSignal) -> bool {
    matches!(
        signal,
        SignerSignal::Command(SignerCommand::Shutdown)
            | SignerSignal::Event(SignerEvent::P2P(P2PEvent::MessageReceived(_)))
            | SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
    )
}

impl<C, N, B> RequestDeciderEventLoop<C, N, B>
where
    C: Context,
    N: MessageTransfer,
    B: BlocklistChecker,
{
    /// Run the request decider event loop
    #[tracing::instrument(
        skip_all,
        fields(public_key = %self.signer_public_key()),
        name = "request-decider"
    )]
    pub async fn run(mut self) -> Result<(), Error> {
        let start_message = RequestDeciderEvent::EventLoopStarted.into();
        if let Err(error) = self.context.signal(start_message) {
            tracing::error!(%error, "error signaling event loop start");
            return Err(error);
        };

        let mut signal_stream = self.context.as_signal_stream(run_loop_message_filter);

        while let Some(message) = signal_stream.next().await {
            match message {
                SignerSignal::Command(SignerCommand::Shutdown) => break,
                SignerSignal::Command(SignerCommand::P2PPublish(_)) => {}
                SignerSignal::Event(event) => match event {
                    SignerEvent::P2P(P2PEvent::MessageReceived(msg)) => {
                        if let Err(error) = self.handle_signer_message(&msg).await {
                            tracing::error!(%error, "error handling signer message");
                        }
                    }
                    SignerEvent::BitcoinBlockObserved => {
                        if let Err(error) = self.handle_new_requests().await {
                            tracing::warn!(%error, "error handling new requests; skipping this round");
                        }

                        let message = RequestDeciderEvent::NewRequestsHandled.into();
                        // If there is an error here then the application
                        // is on its way down since
                        // [`SignerContext::signal`] sends a shutdown
                        // signal on error. We've also logged the error
                        // already.
                        if self.context.signal(message).is_err() {
                            break;
                        }
                    }
                    _ => {}
                },
            }
        }

        tracing::info!("request decider event loop has been stopped");
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(chain_tip = tracing::field::Empty))]
    async fn handle_new_requests(&mut self) -> Result<(), Error> {
        let requests_processing_delay = self.context.config().signer.requests_processing_delay;
        if requests_processing_delay > Duration::ZERO {
            tracing::debug!("sleeping before processing new requests");
            tokio::time::sleep(requests_processing_delay).await;
        }

        let db = self.context.get_storage();
        let chain_tip = db
            .get_bitcoin_canonical_chain_tip()
            .await?
            .ok_or(Error::NoChainTip)?;

        let signer_public_key = self.signer_public_key();

        let span = tracing::Span::current();
        span.record("chain_tip", tracing::field::display(chain_tip));

        let deposit_requests = db
            .get_pending_deposit_requests(&chain_tip, self.context_window, &signer_public_key)
            .await?;

        for deposit_request in deposit_requests {
            let outpoint = deposit_request.outpoint();
            let _ = self
                .handle_pending_deposit_request(deposit_request, &chain_tip)
                .await
                .inspect_err(|error| {
                    tracing::warn!(
                        %error,
                        %outpoint,
                        "error handling new deposit request"
                    )
                });
        }

        let withdraw_requests = db
            .get_pending_withdrawal_requests(&chain_tip, self.context_window, &signer_public_key)
            .await?;

        for withdraw_request in withdraw_requests {
            let request_id = withdraw_request.request_id;
            let _ = self
                .handle_pending_withdrawal_request(withdraw_request, &chain_tip)
                .await
                .inspect_err(|error| {
                    tracing::warn!(
                        %error,
                        %request_id,
                        "error handling new withdrawal request"
                    )
                });
        }

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn handle_signer_message(&mut self, msg: &Signed<SignerMessage>) -> Result<(), Error> {
        tracing::trace!(payload = %msg.inner.payload, "handling message");
        match &msg.inner.payload {
            Payload::SignerDepositDecision(decision) => {
                self.persist_received_deposit_decision(decision, msg.signer_public_key)
                    .await?;
            }
            Payload::SignerWithdrawalDecision(decision) => {
                self.persist_received_withdraw_decision(decision, msg.signer_public_key)
                    .await?;
            }
            Payload::StacksTransactionSignRequest(_)
            | Payload::BitcoinPreSignRequest(_)
            | Payload::BitcoinPreSignAck(_)
            | Payload::WstsMessage(_)
            | Payload::StacksTransactionSignature(_) => (),
        };

        Ok(())
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
    #[tracing::instrument(skip_all)]
    pub async fn handle_pending_deposit_request(
        &mut self,
        request: model::DepositRequest,
        chain_tip: &BitcoinBlockHash,
    ) -> Result<(), Error> {
        let db = self.context.get_storage_mut();

        let signer_public_key = self.signer_public_key();
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

        let can_accept = self.can_accept_deposit_request(&request).await?;

        let msg = SignerDepositDecision {
            txid: request.txid.into(),
            output_index: request.output_index,
            can_accept,
            can_sign,
        };

        let signer_decision = DepositSigner {
            txid: request.txid,
            output_index: request.output_index,
            signer_pub_key: signer_public_key,
            can_accept,
            can_sign,
        };

        db.write_deposit_signer_decision(&signer_decision).await?;

        self.send_message(msg, chain_tip).await?;

        self.context
            .signal(RequestDeciderEvent::PendingDepositRequestRegistered.into())?;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn handle_pending_withdrawal_request(
        &mut self,
        withdrawal_request: model::WithdrawalRequest,
        chain_tip: &BitcoinBlockHash,
    ) -> Result<(), Error> {
        // TODO: Do we want to do this on the sender address or the
        // recipient address?
        let is_accepted = self
            .can_accept_withdrawal_request(&withdrawal_request)
            .await?;

        let msg = SignerWithdrawalDecision {
            request_id: withdrawal_request.request_id,
            block_hash: withdrawal_request.block_hash.into_bytes(),
            accepted: is_accepted,
            txid: withdrawal_request.txid,
        };

        let signer_decision = WithdrawalSigner {
            request_id: withdrawal_request.request_id,
            block_hash: withdrawal_request.block_hash,
            signer_pub_key: self.signer_public_key(),
            is_accepted,
            txid: withdrawal_request.txid,
        };

        self.context
            .get_storage_mut()
            .write_withdrawal_signer_decision(&signer_decision)
            .await?;

        self.send_message(msg, chain_tip).await?;

        self.context
            .signal(RequestDeciderEvent::PendingWithdrawalRequestRegistered.into())?;

        Ok(())
    }

    async fn can_accept_withdrawal_request(
        &self,
        req: &model::WithdrawalRequest,
    ) -> Result<bool, Error> {
        // If we have not configured a blocklist checker, then we can
        // return early.
        let Some(client) = self.blocklist_checker.as_ref() else {
            return Ok(true);
        };

        let result = client
            .can_accept(&req.sender_address.to_string())
            .await
            .unwrap_or(false);

        Ok(result)
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

        // If all of the inputs addresses are fine then we pass the deposit
        // request.
        let can_accept = responses.into_iter().all(|res| res.unwrap_or(false));
        Ok(can_accept)
    }

    /// Save the given decision into the database
    ///
    /// If we do not have a record of the associated deposit request in our
    /// database then we fetch it from Emily and then attempt to persist
    /// it.
    #[tracing::instrument(skip_all, fields(sender = %signer_pub_key))]
    pub async fn persist_received_deposit_decision(
        &mut self,
        decision: &SignerDepositDecision,
        signer_pub_key: PublicKey,
    ) -> Result<(), Error> {
        let txid = decision.txid.into();
        let output_index = decision.output_index;
        let signer_decision = DepositSigner {
            txid,
            output_index,
            signer_pub_key,
            can_accept: decision.can_accept,
            can_sign: decision.can_sign,
        };

        let db = self.context.get_storage_mut();
        // Before storing a decision in the database, we first check to see
        // if we have a record of the associated deposit request. If we
        // don't have a record then fetch it from Emily and store it before
        // storing the decision.
        if !db.deposit_request_exists(&txid, output_index).await? {
            tracing::debug!("no record of the deposit request, fetching from emily");
            let processor = BlockObserver {
                context: self.context.clone(),
                bitcoin_blocks: (),
            };
            let deposit_request = self
                .context
                .get_emily_client()
                .get_deposit(&txid, output_index)
                .await?;

            if let Some(request) = deposit_request {
                processor.load_requests(&[request]).await?;
            }
        }
        // We still might not have a record of the deposit request (perhaps
        // it failed validation). In this case we do not persist the
        // decision and move on.
        if !db.deposit_request_exists(&txid, output_index).await? {
            tracing::debug!(
                %txid,
                %output_index,
                sender = %signer_pub_key,
                "we still do not have a record of the deposit request"
            );
            return Ok(());
        }
        db.write_deposit_signer_decision(&signer_decision).await?;

        self.context
            .signal(RequestDeciderEvent::ReceivedDepositDecision.into())?;

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(sender = %signer_pub_key))]
    async fn persist_received_withdraw_decision(
        &mut self,
        decision: &SignerWithdrawalDecision,
        signer_pub_key: PublicKey,
    ) -> Result<(), Error> {
        let signer_decision = WithdrawalSigner {
            request_id: decision.request_id,
            block_hash: decision.block_hash.into(),
            signer_pub_key,
            is_accepted: decision.accepted,
            txid: decision.txid,
        };

        // TODO: we need to check to see if we have the withdrawal request
        // first.

        self.context
            .get_storage_mut()
            .write_withdrawal_signer_decision(&signer_decision)
            .await?;

        self.context
            .signal(RequestDeciderEvent::ReceivedWithdrawalDecision.into())?;

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    async fn send_message(
        &mut self,
        msg: impl Into<Payload>,
        chain_tip: &BitcoinBlockHash,
    ) -> Result<(), Error> {
        let payload: Payload = msg.into();
        let msg = payload
            .to_message(*chain_tip)
            .sign_ecdsa(&self.signer_private_key);

        self.network.broadcast(msg).await?;

        Ok(())
    }

    fn signer_public_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.signer_private_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::MockBitcoinInteract;
    use crate::emily_client::MockEmilyInteract;
    use crate::stacks::api::MockStacksInteract;
    use crate::storage::in_memory::SharedStore;
    use crate::testing;
    use crate::testing::context::*;

    fn test_environment() -> testing::request_decider::TestEnvironment<
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

        testing::request_decider::TestEnvironment {
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
    async fn should_store_decisions_for_pending_withdrawal_requests() {
        test_environment()
            .assert_should_store_decisions_for_pending_withdrawal_requests()
            .await;
    }

    #[tokio::test]
    async fn should_store_decisions_received_from_other_signers() {
        test_environment()
            .assert_should_store_decisions_received_from_other_signers()
            .await;
    }
}
