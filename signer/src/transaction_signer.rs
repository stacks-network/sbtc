//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`TxSignerEventLoop`] documentation.

use std::collections::BTreeSet;
use std::collections::HashMap;

use crate::blocklist_client;
use crate::config::NetworkKind;
use crate::ecdsa::SignEcdsa as _;
use crate::error;
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message;
use crate::message::StacksTransactionSignRequest;
use crate::network;
use crate::stacks::contracts::AsContractCall;
use crate::stacks::contracts::ContractCall;
use crate::stacks::wallet::MultisigTx;
use crate::stacks::wallet::SignerWallet;
use crate::storage;
use crate::storage::model;
use crate::wsts_state_machine;

use bitcoin::hashes::Hash;
use futures::StreamExt;
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
pub struct TxSignerEventLoop<Network, Storage, BlocklistChecker, Rng> {
    /// Interface to the signer network.
    pub network: Network,
    /// Database connection.
    pub storage: Storage,
    /// Blocklist checker.
    pub blocklist_checker: BlocklistChecker,
    /// Notification receiver from the block observer.
    pub block_observer_notifications: tokio::sync::watch::Receiver<()>,
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
    pub context_window: usize,
    /// The network we are working in.
    pub network_kind: bitcoin::Network,
    /// Random number generator used for encryption
    pub rng: Rng,
    #[cfg(feature = "testing")]
    /// Optional channel to communicate progress usable for testing
    pub test_observer_tx: Option<tokio::sync::mpsc::Sender<TxSignerEvent>>,
}

/// Event useful for tests
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TxSignerEvent {
    /// Received a deposit decision
    ReceviedDepositDecision,
    /// Received a withdraw decision
    ReceivedWithdrawDecision,
}

impl<N, S, B, Rng> TxSignerEventLoop<N, S, B, Rng>
where
    N: network::MessageTransfer,
    error::Error: From<N::Error>,
    B: blocklist_client::BlocklistChecker,
    S: storage::DbRead + storage::DbWrite + Send + Sync,
    error::Error: From<<S as storage::DbRead>::Error>,
    error::Error: From<<S as storage::DbWrite>::Error>,
    Rng: rand::RngCore + rand::CryptoRng,
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
                        Ok(msg) => {
                            let res = self.handle_signer_message(&msg).await;
                            match res {
                                Ok(()) => (),
                                Err(error::Error::InvalidSignature) => (),
                                Err(error) => {
                                    tracing::error!(%error, "fatal signer error");
                                    return Err(error)}
                            }
                        },
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
            .ok_or(error::Error::NoChainTip)?;

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
            self.handle_pending_withdraw_request(withdraw_request)
                .await?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle_signer_message(&mut self, msg: &network::Msg) -> Result<(), error::Error> {
        if !msg.verify() {
            tracing::warn!("unable to verify message");
            return Err(error::Error::InvalidSignature);
        }

        // TODO(297): Validate the chain tip against database
        let bitcoin_chain_tip = msg.bitcoin_chain_tip.to_byte_array().to_vec();

        match &msg.inner.payload {
            message::Payload::SignerDepositDecision(decision) => {
                self.persist_received_deposit_decision(decision, msg.signer_pub_key)
                    .await?;
            }

            message::Payload::SignerWithdrawDecision(decision) => {
                self.persist_received_withdraw_decision(decision, msg.signer_pub_key)
                    .await?;
            }

            message::Payload::StacksTransactionSignRequest(_request) => {

                //TODO(255): Implement
            }

            message::Payload::BitcoinTransactionSignRequest(request) => {
                self.handle_bitcoin_transaction_sign_request(request, &bitcoin_chain_tip)
                    .await?;
            }

            message::Payload::WstsMessage(wsts_msg) => {
                self.handle_wsts_message(wsts_msg, &bitcoin_chain_tip)
                    .await?;
            }

            // Message types ignored by the transaction signer
            message::Payload::StacksTransactionSignature(_)
            | message::Payload::BitcoinTransactionSignAck(_) => (),
        };

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle_bitcoin_transaction_sign_request(
        &mut self,
        request: &message::BitcoinTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), error::Error> {
        let is_valid_sign_request = self
            .is_valid_bitcoin_transaction_sign_request(request)
            .await?;

        if is_valid_sign_request {
            let signer_public_keys = self.get_signer_public_keys(bitcoin_chain_tip).await?;

            let new_state_machine = wsts_state_machine::SignerStateMachine::load(
                &mut self.storage,
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
    ) -> Result<bool, error::Error> {
        let signer_pub_key = self.signer_pub_key();
        let _accepted_deposit_requests = self
            .storage
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
        request: &message::StacksTransactionSignRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let is_valid_sign_request = self
            .is_valid_stackstransaction_sign_request(request, bitcoin_chain_tip)
            .await?;

        let wallet = self.load_wallet(request, bitcoin_chain_tip).await?;
        let multi_sig = MultisigTx::new_tx(&request.contract_call, &wallet, request.tx_fee);
        let txid = multi_sig.tx().txid();

        if is_valid_sign_request {
            let signature =
                crate::signature::sign_stacks_tx(multi_sig.tx(), &self.signer_private_key);

            let msg = message::StacksTransactionSignature { txid, signature };

            self.send_message(msg, bitcoin_chain_tip).await?;
        } else {
            tracing::warn!(%txid, "received invalid sign request for stacks tx");
        }

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
            .storage
            .get_last_key_rotation(bitcoin_chain_tip)
            .await?
            .ok_or(error::Error::MissingKeyRotation)?;

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

    async fn is_valid_stackstransaction_sign_request(
        &mut self,
        request: &message::StacksTransactionSignRequest,
        _bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<bool, Error> {
        // TODO(255): Finish the implementation
        match &request.contract_call {
            ContractCall::AcceptWithdrawalV1(contract) => contract.validate(&self.storage).await,
            ContractCall::CompleteDepositV1(contract) => contract.validate(&self.storage).await,
            ContractCall::RejectWithdrawalV1(contract) => contract.validate(&self.storage).await,
            ContractCall::RotateKeysV1(contract) => contract.validate(&self.storage).await,
        }
    }

    #[tracing::instrument(skip(self))]
    async fn handle_wsts_message(
        &mut self,
        msg: &message::WstsMessage,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), error::Error> {
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
    ) -> Result<(), error::Error> {
        let Some(state_machine) = self.wsts_state_machines.get_mut(&txid) else {
            tracing::warn!("missing signing round");
            return Ok(());
        };

        let outbound_messages = state_machine.process(msg).map_err(error::Error::Wsts)?;

        for outbound_message in outbound_messages.iter() {
            // The WSTS state machine assume we read our own messages
            state_machine
                .process(outbound_message)
                .map_err(error::Error::Wsts)?;
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
    ) -> Result<Vec<model::DepositRequest>, error::Error> {
        Ok(self
            .storage
            .get_pending_deposit_requests(
                chain_tip,
                self.context_window
                    .try_into()
                    .map_err(|_| error::Error::TypeConversion)?,
            )
            .await?)
    }

    #[tracing::instrument(skip(self))]
    async fn get_pending_withdraw_requests(
        &mut self,
        chain_tip: &model::BitcoinBlockHash,
    ) -> Result<Vec<model::WithdrawRequest>, error::Error> {
        Ok(self
            .storage
            .get_pending_withdraw_requests(
                chain_tip,
                self.context_window
                    .try_into()
                    .map_err(|_| error::Error::TypeConversion)?,
            )
            .await?)
    }

    #[tracing::instrument(skip(self))]
    async fn handle_pending_deposit_request(
        &mut self,
        deposit_request: model::DepositRequest,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), error::Error> {
        let is_accepted = futures::stream::iter(&deposit_request.sender_addresses)
            .any(|address| async {
                self.blocklist_checker
                    .can_accept(address)
                    .await
                    .unwrap_or(false)
            })
            .await;

        let msg = message::SignerDepositDecision {
            txid: bitcoin::Txid::from_slice(&deposit_request.txid)
                .map_err(error::Error::SliceConversion)?,
            output_index: deposit_request
                .output_index
                .try_into()
                .map_err(|_| error::Error::TypeConversion)?,
            accepted: is_accepted,
        };

        let signer_decision = model::DepositSigner {
            txid: deposit_request.txid,
            output_index: deposit_request.output_index,
            signer_pub_key: self.signer_pub_key(),
            is_accepted,
        };

        self.storage
            .write_deposit_signer_decision(&signer_decision)
            .await?;

        self.send_message(msg, bitcoin_chain_tip).await?;

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

        let signer_decision = model::WithdrawSigner {
            request_id: withdraw_request.request_id,
            block_hash: withdraw_request.block_hash,
            signer_pub_key: self.signer_pub_key(),
            is_accepted,
        };

        self.storage
            .write_withdraw_signer_decision(&signer_decision)
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn persist_received_deposit_decision(
        &mut self,
        decision: &message::SignerDepositDecision,
        signer_pub_key: PublicKey,
    ) -> Result<(), error::Error> {
        let txid = decision.txid.to_byte_array().to_vec();
        let output_index = decision
            .output_index
            .try_into()
            .map_err(|_| error::Error::TypeConversion)?;
        let is_accepted = decision.accepted;

        let signer_decision = model::DepositSigner {
            txid,
            output_index,
            signer_pub_key,
            is_accepted,
        };

        self.storage
            .write_deposit_signer_decision(&signer_decision)
            .await?;

        #[cfg(feature = "testing")]
        if let Some(ref tx) = self.test_observer_tx {
            tx.send(TxSignerEvent::ReceviedDepositDecision)
                .await
                .map_err(|_| error::Error::ObserverDropped)?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn persist_received_withdraw_decision(
        &mut self,
        decision: &message::SignerWithdrawDecision,
        signer_pub_key: PublicKey,
    ) -> Result<(), error::Error> {
        let request_id = decision
            .request_id
            .try_into()
            .map_err(|_| error::Error::TypeConversion)?;

        let block_hash = decision.block_hash.to_vec();
        let is_accepted = decision.accepted;

        let signer_decision = model::WithdrawSigner {
            request_id,
            block_hash,
            signer_pub_key,
            is_accepted,
        };

        self.storage
            .write_withdraw_signer_decision(&signer_decision)
            .await?;

        #[cfg(feature = "testing")]
        if let Some(ref tx) = self.test_observer_tx {
            tx.send(TxSignerEvent::ReceivedWithdrawDecision)
                .await
                .map_err(|_| error::Error::ObserverDropped)?;
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn store_dkg_shares(&mut self, txid: &bitcoin::Txid) -> Result<(), error::Error> {
        let state_machine = self
            .wsts_state_machines
            .get(txid)
            .ok_or(error::Error::MissingStateMachine)?;

        let encrypted_dkg_shares = state_machine.get_encrypted_dkg_shares(&mut self.rng)?;

        self.storage
            .write_encrypted_dkg_shares(&encrypted_dkg_shares)
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, msg))]
    async fn send_message(
        &mut self,
        msg: impl Into<message::Payload>,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), error::Error> {
        let bitcoin_chain_tip = bitcoin::BlockHash::from_slice(bitcoin_chain_tip)
            .map_err(error::Error::SliceConversion)?;
        let payload: message::Payload = msg.into();
        let msg = payload
            .to_message(bitcoin_chain_tip)
            .sign_ecdsa(&self.signer_private_key)?;

        self.network.broadcast(msg).await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_signer_public_keys(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<BTreeSet<PublicKey>, error::Error> {
        let last_key_rotation = self
            .storage
            .get_last_key_rotation(bitcoin_chain_tip)
            .await?
            .ok_or(error::Error::MissingKeyRotation)?;

        let signer_set = last_key_rotation.signer_set.into_iter().collect();

        Ok(signer_set)
    }

    fn signer_pub_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.signer_private_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::storage;
    use crate::testing;

    fn test_environment(
    ) -> testing::transaction_signer::TestEnvironment<fn() -> storage::in_memory::SharedStore> {
        let test_model_parameters = testing::storage::model::Params {
            num_bitcoin_blocks: 20,
            num_stacks_blocks_per_bitcoin_block: 3,
            num_deposit_requests_per_block: 5,
            num_withdraw_requests_per_block: 5,
            num_signers_per_request: 0,
        };

        testing::transaction_signer::TestEnvironment {
            storage_constructor: storage::in_memory::Store::new_shared,
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
