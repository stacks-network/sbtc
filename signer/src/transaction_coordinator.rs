//! # Transaction coordinator
//!
//! This module contains the transaction coordinator, which is the component of the sBTC signer
//! responsible for constructing transactions and coordinating signing rounds.
//!
//! For more details, see the [`TxCoordinatorEventLoop`] documentation.

use std::collections::BTreeSet;

use sha2::Digest;

use crate::bitcoin::utxo;
use crate::bitcoin::BitcoinInteract;
use crate::context::{messaging::SignerEvent, messaging::SignerSignal, Context};
use crate::error::Error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::message;
use crate::network;
use crate::stacks::contracts::CompleteDepositV1;
use crate::stacks::contracts::ContractCall;
use crate::stacks::wallet::SignerWallet;
use crate::storage::model;
use crate::storage::DbRead as _;
use crate::wsts_state_machine;

use crate::ecdsa::SignEcdsa as _;
use bitcoin::hashes::Hash as _;
use wsts::state_machine::coordinator::Coordinator as _;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// # Transaction coordinator event loop
///
/// This struct contains the implementation of the transaction coordinator logic.
/// Like the transaction signer, the coordinator event loop also subscribes to storage
/// update notifications from the block observer and listens to signer messages over
/// the signer network.
///
/// The transaction coordinator will look up the canonical chain tip from
/// the database upon receiving a storage update notification from the
/// block observer. This tip is used to decide whether this particular
/// signer is selected as the signers' coordinator or if it should be
/// passive in favor of another signer as the coordinator in the signer
/// network.
///
/// When the coordinator is selected, that coordinator will begin by looking up the signer UTXO, and
/// do a fee rate estimation for both Bitcoin and Stacks. With that in place it will
/// proceed to look up any pending[^1] and active[^2] requests to process.
///
/// The pending requests are used to construct a transaction package, which is a set of bitcoin
/// transactions fulfilling a subset of the requests. Which pending requests that end up in the
/// transaction package depends on the amount of singers deciding to accept the request, and on
/// the maximum fee allowed in the requests. Once the package has been constructed, the
/// coordinator proceeds by coordinating WSTS signing rounds for each of the transactions in the
/// package. The signed transactions are then broadcast to bitcoin.

/// Pending deposit and withdrawal requests are used to construct a Bitcoin
/// transaction package consisting of a set of inputs and outputs that
/// fulfill these requests. The fulfillment of pending requests in the
/// transaction package depends on the number of signers agreeing to accept
/// each request and the maximum fee stipulated in the request. Once the
/// package is assembled, the coordinator coordinates WSTS signing rounds for
/// each transaction within the package. The successfully signed
/// transactions are then broadcast to the Bitcoin network.
///
/// For the active requests, the coordinator will go over each one and create appropriate
/// stacks response transactions (which are the `withdrawal-accept`, `withdrawal-reject`
/// and `deposit-accept` contract calls). These transactions are sent through the
/// signers for signatures, and once enough signatures has been gathered,
/// the coordinator broadcasts them to the Stacks blockchain.
///
/// [^1]: A deposit or withdraw request is considered pending if it is confirmed
///       on chain but hasn't been fulfilled in an sBTC transaction yet.
/// [^2]: A deposit or withdraw request is considered active if has been fulfilled in an sBTC transaction,
///       but the result hasn't been acknowledged on Stacks as a `deposit-accept`,
///       `withdraw-accept` or `withdraw-reject` transaction.
///
/// The whole flow is illustrated in the following flowchart.
///
/// ```mermaid
/// flowchart TD
///     SM[Block observer notification] --> GCT(Get canonical chain tip)
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
    /// How many bitcoin blocks back from the chain tip the signer will look for requests.
    pub context_window: u16,
    /// The bitcoin network we're targeting
    pub bitcoin_network: bitcoin::Network,
    /// The maximum duration of a signing round before the coordinator will time out and return an error.
    pub signing_round_max_duration: std::time::Duration,
}

impl<C, N> TxCoordinatorEventLoop<C, N>
where
    C: Context,
    N: network::MessageTransfer,
{
    /// Run the coordinator event loop
    #[tracing::instrument(skip(self))]
    pub async fn run(mut self) -> Result<(), Error> {
        tracing::info!("starting transaction coordinator event loop");
        let mut term = self.context.get_termination_handle();
        let mut signal_rx = self.context.get_signal_receiver();

        loop {
            tokio::select! {
                _ = term.wait_for_shutdown() => {
                    tracing::info!("received termination signal");
                    break;
                },
                signal = signal_rx.recv() => match signal {
                    // We're only interested in block observer notifications, which
                    // is our trigger to do some work.
                    Ok(SignerSignal::Event(SignerEvent::BitcoinBlockObserved)) => {
                        tracing::debug!("received block observer notification");
                        self.process_new_blocks().await?;
                    },
                    // If we get an error receiving,
                    Err(error) => {
                        tracing::error!(?error, "error receiving signal; application is probably shutting down");
                        break;
                    },
                    // Otherwise, we've received some other signal that we're not interested
                    // in, so we just continue.
                    _ => {
                        tracing::warn!("ignoring signal");
                        continue;
                    }
                },
            }
        }

        tracing::info!("transaction coordinator event loop is stopping");

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn process_new_blocks(&mut self) -> Result<(), Error> {
        let bitcoin_chain_tip = self
            .context
            .get_storage()
            .get_bitcoin_canonical_chain_tip()
            .await?
            .ok_or(Error::NoChainTip)?;

        let wallet = SignerWallet::load(&self.context, &bitcoin_chain_tip).await?;

        if self.is_coordinator(&bitcoin_chain_tip, wallet.public_keys())? {
            self.construct_and_sign_bitcoin_sbtc_transactions(&bitcoin_chain_tip, &wallet)
                .await?;

            self.construct_and_sign_stacks_sbtc_response_transactions(&bitcoin_chain_tip, &wallet)
                .await?;
        }

        Ok(())
    }

    /// Construct and coordinate WSTS signing rounds for sBTC transactions on Bitcoin,
    /// fulfilling pending deposit and withdraw requests.
    #[tracing::instrument(skip(self))]
    async fn construct_and_sign_bitcoin_sbtc_transactions(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        wallet: &SignerWallet,
    ) -> Result<(), Error> {
        let signer_btc_state = self.get_btc_state(wallet.aggregate_key()).await?;

        let pending_requests = self
            .get_pending_requests(bitcoin_chain_tip, signer_btc_state, wallet)
            .await?;

        let transaction_package = pending_requests.construct_transactions()?;

        for transaction in transaction_package {
            self.sign_and_broadcast(bitcoin_chain_tip, wallet, transaction)
                .await?;
        }

        Ok(())
    }

    /// Construct and coordinate signing rounds for
    /// `deposit-accept`, `withdraw-accept` and `withdraw-reject` transactions.
    #[tracing::instrument(skip_all)]
    async fn construct_and_sign_stacks_sbtc_response_transactions(
        &mut self,
        chain_tip: &model::BitcoinBlockHash,
        wallet: &SignerWallet,
    ) -> Result<(), Error> {
        let db = self.context.get_storage();
        let btc_rpc = self.context.get_bitcoin_client();
        // let stacks =

        // Fetch deposit and withdrawal requests from the database where
        // there has been a confirmed bitcoin transaction associated with
        // the request.
        //
        // For deposits, there will be at most one such bitcoin transaction
        // on the blockchain identified by the chain tip, where an input is
        // the deposit UTXO.
        //
        // For withdrawals, we need to have a record of the `request_id`
        // associated with the bitcoin transaction's outputs.

        let deposit_requests = db
            .get_pending_accepted_deposit_requests(
                chain_tip,
                self.context_window,
                wallet.signatures_required(),
            )
            .await?;

        // TODO: We need to filter the above deposit requests further to
        // exclude those that do not been used in a bitcoin transaction.
        for req in deposit_requests.iter() {
            let tx_info = btc_rpc.get_tx_info(&req.txid, chain_tip).await?.unwrap();
            let block_ref = db.get_bitcoin_block(chain_tip).await?.unwrap();

            let outpoint = req.outpoint();

            let tx = CompleteDepositV1 {
                amount: req.amount - tx_info.assess_input_fee(&outpoint).unwrap().to_sat(),
                outpoint,
                recipient: req.recipient.clone().into(),
                deployer: self.context.config().signer.deployer,
                // Wrong
                sweep_txid: req.txid,
                // Wrong
                sweep_block_hash: *chain_tip,
                // Wrong
                sweep_block_height: block_ref.block_height,
            };

            let _contract = ContractCall::CompleteDepositV1(tx);
            //     let wallet = SignerWallet::new(public_keys, self.signatures_required, self.bitcoin_network, 0)?;
            //     let multi_tx = MultisigTx::new_contract_call(contract, wallet, tx_fee)

            //     let req = StacksTransactionSignRequest {
            //         aggregate_key,
            //         contract_call: ContractCall::CompleteDepositV1(tx),
            //         nonce: 0,
            //         tx_fee: 0,
            //         digest:
            //     };
        }

        // TODO(320): Implement
        Ok(())
    }

    /// Coordinate a signing round for the given request
    /// and broadcast it once it's signed.
    #[tracing::instrument(skip(self))]
    async fn sign_and_broadcast(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        wallet: &SignerWallet,
        mut transaction: utxo::UnsignedTransaction<'_>,
    ) -> Result<(), Error> {
        let mut coordinator_state_machine = wsts_state_machine::CoordinatorStateMachine::load(
            &mut self.context.get_storage_mut(),
            *wallet.aggregate_key(),
            wallet.public_keys().clone(),
            wallet.signatures_required(),
            self.private_key,
        )
        .await?;

        let sighashes = transaction.construct_digests()?;
        let msg = sighashes.signers.to_raw_hash().to_byte_array();

        let txid = transaction.tx.compute_txid();

        let signature = self
            .coordinate_signing_round(
                bitcoin_chain_tip,
                &mut coordinator_state_machine,
                txid,
                &msg,
            )
            .await?;

        let signature = bitcoin::taproot::Signature {
            signature: secp256k1::schnorr::Signature::from_slice(&signature.to_bytes())
                .map_err(|_| Error::TypeConversion)?,
            sighash_type: bitcoin::TapSighashType::Default,
        };
        let signer_witness = bitcoin::Witness::p2tr_key_spend(&signature);

        let mut deposit_witness = Vec::new();

        for (deposit, sighash) in sighashes.deposits.into_iter() {
            let msg = sighash.to_raw_hash().to_byte_array();

            let signature = self
                .coordinate_signing_round(
                    bitcoin_chain_tip,
                    &mut coordinator_state_machine,
                    txid,
                    &msg,
                )
                .await?;

            let signature = bitcoin::taproot::Signature {
                signature: secp256k1::schnorr::Signature::from_slice(&signature.to_bytes())
                    .map_err(|_| Error::TypeConversion)?,
                sighash_type: bitcoin::TapSighashType::Default,
            };

            let witness = deposit.construct_witness_data(signature);

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

        self.context
            .get_bitcoin_client()
            .broadcast_transaction(&transaction.tx)
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn coordinate_signing_round(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        coordinator_state_machine: &mut wsts_state_machine::CoordinatorStateMachine,
        txid: bitcoin::Txid,
        msg: &[u8],
    ) -> Result<wsts::taproot::SchnorrProof, Error> {
        let outbound = coordinator_state_machine
            .start_signing_round(msg, true, None)
            .map_err(wsts_state_machine::coordinator_error)?;

        let msg = message::WstsMessage { txid, inner: outbound.msg };
        self.send_message(msg, bitcoin_chain_tip).await?;

        let max_duration = self.signing_round_max_duration;
        let run_signing_round = self.relay_messages_to_wsts_state_machine_until_signature_created(
            bitcoin_chain_tip,
            coordinator_state_machine,
            txid,
        );

        tokio::time::timeout(max_duration, run_signing_round)
            .await
            .map_err(|_| Error::CoordinatorTimeout(self.signing_round_max_duration.as_secs()))?
    }

    #[tracing::instrument(skip(self))]
    async fn relay_messages_to_wsts_state_machine_until_signature_created(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        coordinator_state_machine: &mut wsts_state_machine::CoordinatorStateMachine,
        txid: bitcoin::Txid,
    ) -> Result<wsts::taproot::SchnorrProof, Error> {
        loop {
            let msg = self.network.receive().await?;

            if &msg.bitcoin_chain_tip != bitcoin_chain_tip {
                tracing::warn!(?msg, "concurrent wsts signing round message observed");
                continue;
            }

            let message::Payload::WstsMessage(wsts_msg) = msg.inner.payload else {
                continue;
            };

            let packet = wsts::net::Packet {
                msg: wsts_msg.inner,
                sig: Vec::new(),
            };

            let (outbound_packet, operation_result) =
                match coordinator_state_machine.process_message(&packet) {
                    Ok(val) => val,
                    Err(err) => {
                        tracing::warn!(?packet, reason = %err, "ignoring packet");
                        continue;
                    }
                };

            if let Some(packet) = outbound_packet {
                let msg = message::WstsMessage { txid, inner: packet.msg };
                self.send_message(msg, bitcoin_chain_tip).await?;
            }

            match operation_result {
                Some(wsts::state_machine::OperationResult::SignTaproot(signature)) => {
                    return Ok(signature)
                }
                None => continue,
                Some(_) => return Err(Error::UnexpectedOperationResult),
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
    ) -> Result<bool, Error> {
        given_key_is_coordinator(self.pub_key(), bitcoin_chain_tip, signer_public_keys)
    }

    #[tracing::instrument(skip(self))]
    async fn get_btc_state(
        &mut self,
        aggregate_key: &PublicKey,
    ) -> Result<utxo::SignerBtcState, Error> {
        let bitcoin_client = self.context.get_bitcoin_client();
        let fee_rate = bitcoin_client.estimate_fee_rate().await?;
        let Some(chain_tip) = self
            .context
            .get_storage()
            .get_bitcoin_canonical_chain_tip()
            .await?
        else {
            return Err(Error::NoChainTip);
        };

        let utxo = self
            .context
            .get_storage()
            .get_signer_utxo(&chain_tip, aggregate_key, self.context_window)
            .await?
            .ok_or(Error::MissingSignerUtxo)?;
        let last_fees = bitcoin_client.get_last_fee(utxo.outpoint).await?;

        Ok(utxo::SignerBtcState {
            fee_rate,
            utxo,
            public_key: bitcoin::XOnlyPublicKey::from(aggregate_key),
            last_fees,
            magic_bytes: [0, 0], //TODO(#472): Use the correct magic bytes.
        })
    }

    /// TODO(#380): This function needs to filter deposit requests based on
    /// time as well. We need to do this because deposit requests are locked
    /// using OP_CSV, which lock up coins based on block height or
    /// multiples of 512 seconds measure by the median time past.
    #[tracing::instrument(skip(self))]
    async fn get_pending_requests(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        signer_btc_state: utxo::SignerBtcState,
        wallet: &SignerWallet,
    ) -> Result<utxo::SbtcRequests, Error> {
        let signatures_required = wallet.signatures_required();
        let aggregate_key = wallet.aggregate_key();

        let pending_deposit_requests = self
            .context
            .get_storage()
            .get_pending_accepted_deposit_requests(
                bitcoin_chain_tip,
                self.context_window,
                signatures_required,
            )
            .await?;

        let pending_withdraw_requests = self
            .context
            .get_storage()
            .get_pending_accepted_withdrawal_requests(
                bitcoin_chain_tip,
                self.context_window,
                signatures_required,
            )
            .await?;

        let signers_public_key = bitcoin::XOnlyPublicKey::from(aggregate_key);

        let mut deposits: Vec<utxo::DepositRequest> = Vec::new();

        for req in pending_deposit_requests {
            let votes = self
                .context
                .get_storage()
                .get_deposit_request_signer_votes(&req.txid, req.output_index, aggregate_key)
                .await?;

            let deposit = utxo::DepositRequest::from_model(req, signers_public_key, votes);
            deposits.push(deposit);
        }

        let mut withdrawals: Vec<utxo::WithdrawalRequest> = Vec::new();

        for req in pending_withdraw_requests {
            let votes = self
                .context
                .get_storage()
                .get_withdrawal_request_signer_votes(&req.qualified_id(), aggregate_key)
                .await?;

            let withdrawal = utxo::WithdrawalRequest::from_model(req, votes);
            withdrawals.push(withdrawal);
        }

        Ok(utxo::SbtcRequests {
            deposits,
            withdrawals,
            signer_state: signer_btc_state,
            signatures_required,
            num_signers: wallet.num_signers(),
        })
    }

    fn pub_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.private_key)
    }

    #[tracing::instrument(skip(self, msg))]
    async fn send_message(
        &mut self,
        msg: impl Into<message::Payload>,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(), Error> {
        let msg = msg
            .into()
            .to_message(*bitcoin_chain_tip)
            .sign_ecdsa(&self.private_key)?;

        self.network.broadcast(msg).await?;

        Ok(())
    }
}

/// Check if the provided public key is the coordinator for the provided chain tip
pub fn given_key_is_coordinator(
    pub_key: PublicKey,
    bitcoin_chain_tip: &model::BitcoinBlockHash,
    signer_public_keys: &BTreeSet<PublicKey>,
) -> Result<bool, Error> {
    Ok(
        coordinator_public_key(bitcoin_chain_tip, signer_public_keys)?
            .map(|coordinator_pub_key| coordinator_pub_key == pub_key)
            .unwrap_or(false),
    )
}

/// Find the coordinator public key
pub fn coordinator_public_key(
    bitcoin_chain_tip: &model::BitcoinBlockHash,
    signer_public_keys: &BTreeSet<PublicKey>,
) -> Result<Option<PublicKey>, Error> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bitcoin_chain_tip.into_bytes());
    let digest = hasher.finalize();
    let index = usize::from_be_bytes(*digest.first_chunk().ok_or(Error::TypeConversion)?);

    Ok(signer_public_keys
        .iter()
        .nth(index % signer_public_keys.len())
        .copied())
}

#[cfg(test)]
mod tests {
    use crate::bitcoin::MockBitcoinInteract;
    use crate::testing;
    use crate::testing::context::{TestContext, WrappedMock};
    use crate::testing::transaction_coordinator::TestEnvironment;

    fn test_environment() -> TestEnvironment<TestContext<WrappedMock<MockBitcoinInteract>>> {
        let test_model_parameters = testing::storage::model::Params {
            num_bitcoin_blocks: 20,
            num_stacks_blocks_per_bitcoin_block: 3,
            num_deposit_requests_per_block: 5,
            num_withdraw_requests_per_block: 5,
            num_signers_per_request: 7,
        };

        let context = TestContext::new(WrappedMock::<MockBitcoinInteract>::default());

        TestEnvironment {
            context,
            context_window: 5,
            num_signers: 7,
            signing_threshold: 5,
            test_model_parameters,
        }
    }

    #[tokio::test]
    async fn should_be_able_to_coordinate_signing_rounds() {
        test_environment()
            .assert_should_be_able_to_coordinate_signing_rounds()
            .await;
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
}
