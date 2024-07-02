//! # Transaction signer
//!
//! This module contains the transaction signer, which is the component of the sBTC signer
//! responsible for participating in signing rounds.
//!
//! For more details, see the [`TxSignerEventLoop`] documentation.

use crate::blocklist_client;
use crate::ecdsa::SignEcdsa;
use crate::error;
use crate::message;
use crate::network;
use crate::storage;
use crate::storage::model;

use bitcoin::hashes::Hash;
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
    /// How many bitcoin blocks back from the chain tip the signer will look for requests.
    pub context_window: usize,
}

impl<N, S, B> TxSignerEventLoop<N, S, B>
where
    N: network::MessageTransfer,
    error::Error: From<N::Error>,
    B: blocklist_client::BlocklistChecker,
    S: storage::DbRead + storage::DbWrite,
    error::Error: From<<S as storage::DbRead>::Error>,
    error::Error: From<<S as storage::DbWrite>::Error>,
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

        match &msg.inner.payload {
            message::Payload::SignerDepositDecision(decision) => {
                self.persist_received_deposit_decision(decision, &msg.signer_pub_key)
                    .await?;
            }

            message::Payload::SignerWithdrawDecision(decision) => {
                self.persist_received_withdraw_decision(decision, &msg.signer_pub_key)
                    .await?;
            }

            message::Payload::StacksTransactionSignRequest(_) => {
                //TODO(255): Implement
            }

            message::Payload::BitcoinTransactionSignRequest(_) => {
                //TODO(256): Implement
            }

            message::Payload::WstsMessage(_) => {
                //TODO(257): Implement
            }

            // Message types ignored by the transaction signer
            message::Payload::StacksTransactionSignature(_)
            | message::Payload::BitcoinTransactionSignAck(_) => (),
        };

        Ok(())
    }

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
            .get_pending_withdraw_requests(chain_tip, self.context_window)
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

        let signer_pub_key = p256k1::ecdsa::PublicKey::new(&self.signer_private_key)?
            .to_bytes()
            .to_vec();

        let created_at = time::OffsetDateTime::now_utc();

        let msg_payload: message::Payload = message::SignerDepositDecision {
            txid: bitcoin::Txid::from_slice(&deposit_request.txid)
                .map_err(error::Error::SliceConversion)?,
            output_index: deposit_request
                .output_index
                .try_into()
                .map_err(|_| error::Error::TypeConversion)?,
            accepted: is_accepted,
        }
        .into();

        let msg = msg_payload
            .to_message(
                bitcoin::BlockHash::from_slice(bitcoin_chain_tip)
                    .map_err(error::Error::SliceConversion)?,
            )
            .sign_ecdsa(&self.signer_private_key)?;

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

        self.network.broadcast(msg).await?;

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

        let signer_pub_key = p256k1::ecdsa::PublicKey::new(&self.signer_private_key)?
            .to_bytes()
            .to_vec();

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

    #[tracing::instrument(skip(self))]
    async fn persist_received_deposit_decision(
        &mut self,
        decision: &message::SignerDepositDecision,
        signer_pub_key: &p256k1::ecdsa::PublicKey,
    ) -> Result<(), error::Error> {
        let txid = decision.txid.to_byte_array().to_vec();
        let output_index = decision
            .output_index
            .try_into()
            .map_err(|_| error::Error::TypeConversion)?;
        let signer_pub_key = signer_pub_key.to_bytes().to_vec();
        let is_accepted = decision.accepted;
        let created_at = time::OffsetDateTime::now_utc();

        let signer_decision = model::DepositSigner {
            txid,
            output_index,
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
    async fn persist_received_withdraw_decision(
        &mut self,
        decision: &message::SignerWithdrawDecision,
        signer_pub_key: &p256k1::ecdsa::PublicKey,
    ) -> Result<(), error::Error> {
        let request_id = decision
            .request_id
            .try_into()
            .map_err(|_| error::Error::TypeConversion)?;

        let block_hash = decision.block_hash.to_vec();
        let signer_pub_key = signer_pub_key.to_bytes().to_vec();
        let is_accepted = decision.accepted;
        let created_at = time::OffsetDateTime::now_utc();

        let signer_decision = model::WithdrawSigner {
            request_id,
            block_hash,
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
    use crate::storage;
    use crate::testing;

    fn test_environment(
    ) -> testing::transaction_signer::TestEnvironment<fn() -> storage::in_memory::SharedStore> {
        testing::transaction_signer::TestEnvironment {
            storage_constructor: storage::in_memory::Store::new_shared,
            context_window: 3,
            num_signers: 7,
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
}
