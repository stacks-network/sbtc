//! # Transaction coordinator
//!
//! This module contains the transaction coordinator, which is the component of the sBTC signer
//! responsible for consctructing transactions and coordinating signing rounds.
//!
//! For more details, see the [`TxCoordinatorEventLoop`] documentation.

use std::collections::BTreeSet;

use sha2::Digest;

use crate::bitcoin::utxo;
use crate::bitcoin::BitcoinInteract;
use crate::error;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::network;
use crate::storage;
use crate::storage::model;
use crate::wsts_state_machine;

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
pub struct TxCoordinatorEventLoop<Network, Storage, BitcoinClient> {
    /// Interface to the signer network.
    pub network: Network,
    /// Database connection.
    pub storage: Storage,
    /// Bitcoin client
    pub bitcoin_client: BitcoinClient,
    /// Notification receiver from the block observer.
    pub block_observer_notifications: tokio::sync::watch::Receiver<()>,
    /// Private key of the coordinator for network communication.
    pub private_key: PrivateKey,
    /// The threshold for the signer
    pub threshold: u32,
    /// How many bitcoin blocks back from the chain tip the signer will look for requests.
    pub context_window: usize,
    /// The bitcoin network we're targeting
    pub bitcoin_network: bitcoin::Network,
}

impl<N, S, B> TxCoordinatorEventLoop<N, S, B>
where
    N: network::MessageTransfer,
    S: storage::DbRead + storage::DbWrite,
    B: BitcoinInteract,
    error::Error: From<N::Error>,
    error::Error: From<<S as storage::DbRead>::Error>,
    error::Error: From<<S as storage::DbWrite>::Error>,
    error::Error: From<B::Error>,
{
    /// Run the coordinator event loop
    #[tracing::instrument(skip(self))]
    pub async fn run(mut self) -> Result<(), error::Error> {
        loop {
            match self.block_observer_notifications.changed().await {
                Ok(()) => self.process_new_blocks().await?,
                Err(_) => {
                    tracing::info!("block observer notification channel closed");
                    break;
                }
            }
        }
        tracing::info!("shutting down transaction coordinator event loop");

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn process_new_blocks(&mut self) -> Result<(), error::Error> {
        let bitcoin_chain_tip = self
            .storage
            .get_bitcoin_canonical_chain_tip()
            .await?
            .ok_or(error::Error::NoChainTip)?;

        let (aggregate_key, signer_public_keys) = self
            .get_signer_public_keys_and_aggregate_key(&bitcoin_chain_tip)
            .await?;

        if self.is_coordinator(&bitcoin_chain_tip, &signer_public_keys)? {
            self.construct_and_sign_bitcoin_sbtc_transactions(
                &bitcoin_chain_tip,
                aggregate_key,
                &signer_public_keys,
            )
            .await?;

            self.construct_and_sign_stacks_sbtc_response_transactions(
                &bitcoin_chain_tip,
                aggregate_key,
                &signer_public_keys,
            )
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
        aggregate_key: PublicKey,
        signer_public_keys: &BTreeSet<PublicKey>,
    ) -> Result<(), error::Error> {
        let fee_rate = self.bitcoin_client.estimate_fee_rate().await?;

        let signer_btc_state = self.get_btc_state(fee_rate, &aggregate_key).await?;

        let pending_requests = self
            .get_pending_requests(
                bitcoin_chain_tip,
                signer_btc_state,
                aggregate_key,
                signer_public_keys,
            )
            .await?;

        let transaction_package = pending_requests.construct_transactions()?;

        for transaction in transaction_package {
            self.sign_and_broadcast(aggregate_key, signer_public_keys, transaction)
                .await?;
        }

        Ok(())
    }

    /// Construct and coordinate signing rounds for
    /// `deposit-accept`, `withdraw-accept` and `withdraw-reject` transactions.
    #[tracing::instrument(skip(self))]
    async fn construct_and_sign_stacks_sbtc_response_transactions(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        aggregate_key: PublicKey,
        signer_public_keys: &BTreeSet<PublicKey>,
    ) -> Result<(), error::Error> {
        // TODO(320): Implement
        todo!();
    }

    /// Coordinate a signing round for the given request
    /// and broadcast it once it's signed.
    #[tracing::instrument(skip(self))]
    async fn sign_and_broadcast(
        &mut self,
        aggregate_key: PublicKey,
        signer_public_keys: &BTreeSet<PublicKey>,
        transaction: utxo::UnsignedTransaction<'_>,
    ) -> Result<(), error::Error> {
        let _coordinator_state_machine = wsts_state_machine::CoordinatorStateMachine::load(
            &mut self.storage,
            aggregate_key,
            signer_public_keys.clone(),
            self.threshold,
            self.private_key,
        )
        .await?;
        // TODO(319): Coordinate signing round and broadcast result
        todo!();
    }

    // Determine if the current coordinator is the coordinator
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
    ) -> Result<bool, error::Error> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(bitcoin_chain_tip);
        let digest = hasher.finalize();
        let index =
            usize::from_be_bytes(*digest.first_chunk().ok_or(error::Error::TypeConversion)?);

        let pub_key = self.pub_key();

        Ok(signer_public_keys
            .iter()
            .nth(index % signer_public_keys.len())
            .map(|coordinator_pub_key| coordinator_pub_key == &pub_key)
            .unwrap_or(false))
    }

    #[tracing::instrument(skip(self))]
    async fn get_btc_state(
        &mut self,
        fee_rate: f64,
        aggregate_key: &PublicKey,
    ) -> Result<utxo::SignerBtcState, error::Error> {
        // TODO(319): Assemble the relevant information for the btc state
        todo!();
    }

    #[tracing::instrument(skip(self))]
    async fn get_pending_requests(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
        signer_btc_state: utxo::SignerBtcState,
        aggregate_key: PublicKey,
        signer_public_keys: &BTreeSet<PublicKey>,
    ) -> Result<utxo::SbtcRequests, error::Error> {
        let context_window = self
            .context_window
            .try_into()
            .map_err(|_| error::Error::TypeConversion)?;

        let threshold = self.threshold.into();

        let pending_deposit_requests = self
            .storage
            .get_pending_accepted_deposit_requests(bitcoin_chain_tip, context_window, threshold)
            .await?;

        let pending_withdraw_requests = self
            .storage
            .get_pending_accepted_withdraw_requests(bitcoin_chain_tip, context_window, threshold)
            .await?;

        let signers_public_key = bitcoin::XOnlyPublicKey::from(&aggregate_key);

        let convert_deposit =
            |request| utxo::DepositRequest::try_from_model(request, signers_public_key);

        let deposits: Vec<utxo::DepositRequest> = pending_deposit_requests
            .into_iter()
            .map(convert_deposit)
            .collect::<Result<_, _>>()?;

        let convert_withdraw =
            |request| utxo::WithdrawalRequest::try_from_model(request, self.bitcoin_network);

        let withdrawals = pending_withdraw_requests
            .into_iter()
            .map(convert_withdraw)
            .collect::<Result<_, _>>()?;

        let accept_threshold = self.threshold;
        let num_signers = signer_public_keys
            .len()
            .try_into()
            .map_err(|_| error::Error::TypeConversion)?;

        Ok(utxo::SbtcRequests {
            deposits,
            withdrawals,
            signer_state: signer_btc_state,
            accept_threshold,
            num_signers,
        })
    }

    #[tracing::instrument(skip(self))]
    async fn get_signer_public_keys_and_aggregate_key(
        &mut self,
        bitcoin_chain_tip: &model::BitcoinBlockHash,
    ) -> Result<(PublicKey, BTreeSet<PublicKey>), error::Error> {
        let last_key_rotation = self
            .storage
            .get_last_key_rotation(bitcoin_chain_tip)
            .await?
            .ok_or(error::Error::MissingKeyRotation)?;

        let aggregate_key = last_key_rotation.aggregate_key;
        let signer_set = last_key_rotation.signer_set.into_iter().collect();
        Ok((aggregate_key, signer_set))
    }

    // Return the public key of self.
    //
    // Technically not a fallible operation.
    fn pub_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.private_key)
    }
}
