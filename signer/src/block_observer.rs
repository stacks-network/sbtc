//! # Block observer
//!
//! This module contains the block observer implementation for the sBTC signer.
//! The block observer is responsible for populating the signer database with
//! information from the Bitcoin and Stacks blockchains, and notifying
//! the signer event loop whenever the state has been updated.
//!
//! The following information is extracted by the block observer:
//! - Bitcoin blocks
//! - Stacks blocks
//! - Deposit requests
//! - sBTC transactions
//! - Withdraw requests
//! - Deposit accept transactions
//! - Withdraw accept transactions
//! - Withdraw reject transactions
//! - Update signer set transactions
//! - Set aggregate key transactions

use std::future::Future;
use std::time::Duration;

use crate::bitcoin::rpc::BitcoinBlockHeader;
use crate::bitcoin::rpc::BitcoinTxInfo;
use crate::bitcoin::utxo::TxDeconstructor as _;
use crate::bitcoin::BitcoinInteract;
use crate::context::Context;
use crate::context::SbtcLimits;
use crate::context::SignerEvent;
use crate::emily_client::EmilyInteract;
use crate::error::Error;
use crate::metrics::Metrics;
use crate::metrics::BITCOIN_BLOCKCHAIN;
use crate::stacks::api::GetNakamotoStartHeight as _;
use crate::stacks::api::StacksInteract;
use crate::stacks::api::TenureBlocks;
use crate::storage;
use crate::storage::model;
use crate::storage::DbRead;
use crate::storage::DbWrite;
use bitcoin::hashes::Hash as _;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use futures::stream::Stream;
use futures::stream::StreamExt;
use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::DepositInfo;
use std::collections::HashSet;

/// Block observer
#[derive(Debug)]
pub struct BlockObserver<Context, BlockHashStream> {
    /// Signer context
    pub context: Context,
    /// Stream of blocks from the block notifier
    pub bitcoin_blocks: BlockHashStream,
}

/// A full "deposit", containing the bitcoin transaction and a fully
/// extracted and verified `scriptPubKey` from one of the transaction's
/// UTXOs.
#[derive(Debug, Clone)]
pub struct Deposit {
    /// The transaction spent to the signers as a deposit for sBTC.
    pub tx_info: BitcoinTxInfo,
    /// The deposit information included in one of the output
    /// `scriptPubKey`s of the above transaction.
    pub info: DepositInfo,
}

impl DepositRequestValidator for CreateDepositRequest {
    async fn validate<C>(&self, client: &C, is_mainnet: bool) -> Result<Option<Deposit>, Error>
    where
        C: BitcoinInteract,
    {
        // Fetch the transaction from either a block or from the mempool
        let Some(response) = client.get_tx(&self.outpoint.txid).await? else {
            return Ok(None);
        };

        // If the transaction has not been confirmed yet, then the block
        // hash will be None. The trasnaction has not failed validation,
        // let's try again when it gets confirmed.
        let Some(block_hash) = response.block_hash else {
            return Ok(None);
        };

        // The `get_tx_info` call here should not return None, we know that
        // it has been included in a block.
        let Some(tx_info) = client.get_tx_info(&self.outpoint.txid, &block_hash).await? else {
            return Ok(None);
        };

        // TODO(515): After the transaction passes validation, we need to
        // check whether we know about the public key in the deposit
        // script.

        Ok(Some(Deposit {
            info: self.validate_tx(&tx_info.tx, is_mainnet)?,
            tx_info,
        }))
    }
}

/// A trait to add validation functionality to the [`CreateDepositRequest`]
/// type.
pub trait DepositRequestValidator {
    /// Validate this deposit request from the transaction.
    ///
    /// This function fetches the transaction using the given client and
    /// checks that the transaction has been submitted. The transaction
    /// need not be confirmed.
    fn validate<C>(
        &self,
        client: &C,
        is_mainnet: bool,
    ) -> impl Future<Output = Result<Option<Deposit>, Error>>
    where
        C: BitcoinInteract;
}

impl<C, S> BlockObserver<C, S>
where
    C: Context,
    S: Stream<Item = Result<bitcoin::BlockHash, Error>> + Unpin,
{
    /// Run the block observer
    #[tracing::instrument(skip_all, name = "block-observer")]
    pub async fn run(mut self) -> Result<(), Error> {
        let term = self.context.get_termination_handle();

        loop {
            if term.shutdown_signalled() {
                break;
            }

            // Bitcoin blocks will generally arrive in ~10 minute intervals, so
            // we don't need to be so aggressive in our timeout here.
            let poll = tokio::time::timeout(Duration::from_millis(100), self.bitcoin_blocks.next());

            match poll.await {
                Ok(Some(Ok(block_hash))) => {
                    tracing::info!("observed new bitcoin block from stream");
                    metrics::counter!(
                        Metrics::BlocksObservedTotal,
                        "blockchain" => BITCOIN_BLOCKCHAIN,
                    )
                    .increment(1);

                    if let Err(error) = self.process_bitcoin_blocks_until(block_hash).await {
                        tracing::warn!(%error, %block_hash, "could not process bitcoin blocks");
                    }

                    if let Err(error) = self.process_stacks_blocks().await {
                        tracing::warn!(%error, "could not process stacks blocks");
                    }

                    if let Err(error) = self.update_sbtc_limits().await {
                        tracing::warn!(%error, "could not update sBTC limits");
                        continue;
                    }

                    tracing::info!("loading latest deposit requests from Emily");
                    if let Err(error) = self.load_latest_deposit_requests().await {
                        tracing::warn!(%error, "could not load latest deposit requests from Emily");
                    }

                    self.context
                        .signal(SignerEvent::BitcoinBlockObserved.into())?;
                }
                Ok(Some(Err(error))) => {
                    tracing::warn!(%error, "error decoding new bitcoin block hash from stream");
                    continue;
                }
                _ => continue,
            };
        }

        tracing::info!("block observer has stopped");

        Ok(())
    }
}

impl<C: Context, B> BlockObserver<C, B> {
    /// Fetch deposit requests from Emily and store the ones that pass
    /// validation into the database.
    #[tracing::instrument(skip_all)]
    async fn load_latest_deposit_requests(&self) -> Result<(), Error> {
        let requests = self.context.get_emily_client().get_deposits().await?;
        self.load_requests(&requests).await
    }

    /// Validate the given deposit requests and store the ones that pass
    /// validation into the database.
    ///
    /// There are three types of errors that can happen during validation
    /// 1. The transaction fails primary validation. This means the deposit
    ///    script itself does not align with what we expect. If probably
    ///    does not follow our protocol.
    /// 2. The transaction passes step (1), but we don't recognize the
    ///    x-only public key in the deposit script.
    /// 3. We cannot find the associated transaction confirmed on a bitcoin
    ///    block, or when we encountered some unexpected error when
    ///    reaching out to bitcoin-core or our database.
    #[tracing::instrument(skip_all)]
    pub async fn load_requests(&self, requests: &[CreateDepositRequest]) -> Result<(), Error> {
        let mut deposit_requests = Vec::new();
        let bitcoin_client = self.context.get_bitcoin_client();
        let is_mainnet = self.context.config().signer.network.is_mainnet();

        for request in requests {
            let deposit = request
                .validate(&bitcoin_client, is_mainnet)
                .await
                .inspect_err(|error| tracing::warn!(%error, "could not validate deposit request"));

            // We log the error above, so we just need to extract the
            // deposit now.
            let deposit_status = match deposit {
                Ok(Some(deposit)) => {
                    deposit_requests.push(deposit);
                    "success"
                }
                Ok(None) => "unconfirmed",
                Err(_) => "failed",
            };

            metrics::counter!(
                Metrics::DepositRequestsTotal,
                "blockchain" => BITCOIN_BLOCKCHAIN,
                "status" => deposit_status,
            )
            .increment(1);
        }

        self.store_deposit_requests(deposit_requests).await?;

        tracing::debug!("finished processing deposit requests");
        Ok(())
    }

    /// Set the sbtc start height, if it has not been set already.
    async fn set_sbtc_bitcoin_start_height(&self) -> Result<(), Error> {
        if self.context.state().is_sbtc_bitcoin_start_height_set() {
            return Ok(());
        }

        let pox_info = self.context.get_stacks_client().get_pox_info().await?;
        let nakamoto_start_height = pox_info
            .nakamoto_start_height()
            .ok_or(Error::MissingNakamotoStartHeight)?;

        self.context
            .state()
            .set_sbtc_bitcoin_start_height(nakamoto_start_height);

        Ok(())
    }

    /// Find the parent blocks from the given block that are also missing
    /// from our database.
    ///
    /// # Notes
    ///
    /// This function does two things:
    /// 1. Set the `sbtc_bitcoin_start_height` if it has not been set already. If
    ///    it is not set, then we fetch the stacks nakamoto start height
    ///    from stacks-core and use that value.
    /// 2. Continually fetches block headers from bitcoin-core until it
    ///    encounters a known block header or if the height of the block is
    ///    less than or equal to the `sbtc_bitcoin_start_height`.
    ///
    /// If there are many unknown blocks then this function can take some
    /// time. Since each header is 80 bytes, we should be able to fetch
    /// headers for the entire bitcoin blockchain (~900k blocks at the time
    /// of writing) into memory.
    #[tracing::instrument(skip_all, fields(%block_hash))]
    pub async fn next_headers_to_process(
        &self,
        mut block_hash: BlockHash,
    ) -> Result<Vec<BitcoinBlockHeader>, Error> {
        self.set_sbtc_bitcoin_start_height().await?;

        let start_height = self.context.state().get_sbtc_bitcoin_start_height();
        let mut headers = std::collections::VecDeque::new();
        let db = self.context.get_storage();
        let bitcoin_client = self.context.get_bitcoin_client();

        while !db.is_known_bitcoin_block_hash(&block_hash.into()).await? {
            let Some(header) = bitcoin_client.get_block_header(&block_hash).await? else {
                tracing::error!(%block_hash, "bitcoin-core does not know about block header");
                return Err(Error::BitcoinCoreUnknownBlockHeader(block_hash));
            };

            // We don't even try to write blocks to the database if the
            // height is less than the start height.
            if header.height < start_height {
                break;
            }

            let at_start_height = header.height == start_height;
            block_hash = header.previous_block_hash;
            headers.push_front(header);

            // We can write the block at the start height to the database.
            if at_start_height {
                break;
            }
        }

        Ok(headers.into())
    }

    /// Process bitcoin blocks until we get caught up to the given
    /// `block_hash`.
    ///
    /// This function starts at the given block hash and:
    /// 1. Works backwards, fetching block headers until it fetches one
    ///    that is already in the database or reaches a block that is at or
    ///    below the `sbtc_bitcoin_start_height`.
    /// 2. Starts from the header associated with the block with the least
    ///    height and writes the blocks and sweep transactions into the
    ///    database.
    /// 3. Bails if an error is encountered when fetching block headers or
    ///    when processing blocks.
    ///
    /// This means that if we stop processing blocks midway though,
    /// subsequent calls to this function will properly pick up from where
    /// we left off and update the database.
    async fn process_bitcoin_blocks_until(&self, block_hash: BlockHash) -> Result<(), Error> {
        let block_headers = self.next_headers_to_process(block_hash).await?;

        for block_header in block_headers {
            self.process_bitcoin_block(block_header).await?;
        }

        Ok(())
    }

    /// Write the bitcoin block and any transactions that spend to any of
    /// the signers `scriptPubKey`s to the database.
    #[tracing::instrument(skip_all, fields(block_hash = %block_header.hash))]
    async fn process_bitcoin_block(&self, block_header: BitcoinBlockHeader) -> Result<(), Error> {
        let block = self
            .context
            .get_bitcoin_client()
            .get_block(&block_header.hash)
            .await?
            .ok_or(Error::BitcoinCoreMissingBlock(block_header.hash))?;
        let db_block = model::BitcoinBlock::from(&block);

        self.context
            .get_storage_mut()
            .write_bitcoin_block(&db_block)
            .await?;
        self.extract_sbtc_transactions(block_header.hash, &block.txdata)
            .await?;

        tracing::debug!("finished processing bitcoin block");
        Ok(())
    }

    /// Process all recent stacks blocks.
    #[tracing::instrument(skip_all)]
    async fn process_stacks_blocks(&self) -> Result<(), Error> {
        tracing::info!("processing bitcoin block");
        let stacks_client = self.context.get_stacks_client();
        let tenure_info = stacks_client.get_tenure_info().await?;

        tracing::debug!("fetching unknown ancestral blocks from stacks-core");
        let stacks_blocks = crate::stacks::api::fetch_unknown_ancestors(
            &stacks_client,
            &self.context.get_storage(),
            tenure_info.tip_block_id,
        )
        .await?;

        self.write_stacks_blocks(&stacks_blocks).await?;

        tracing::debug!("finished processing stacks block");
        Ok(())
    }

    /// For each of the deposit requests, persist the corresponding
    /// transaction and the parsed deposit info into the database.
    ///
    /// This function does three things:
    /// 1. For all deposit requests, check to see if there are bitcoin
    ///    blocks that we do not have in our database.
    /// 2. If we do not have a record of the bitcoin block then write it
    ///    to the database.
    /// 3. Write the deposit transaction and the extracted deposit info
    ///    into the database.
    async fn store_deposit_requests(&self, requests: Vec<Deposit>) -> Result<(), Error> {
        // We need to check to see if we have a record of the bitcoin block
        // that contains the deposit request in our database. If we don't
        // then write them to our database.
        for deposit in requests.iter() {
            self.process_bitcoin_blocks_until(deposit.tx_info.block_hash)
                .await?;
        }

        // Okay now we write the deposit requests and the transactions to
        // the database.
        let (deposit_requests, deposit_request_txs) = requests
            .into_iter()
            .map(|deposit| {
                let tx = model::Transaction {
                    txid: deposit.tx_info.txid.to_byte_array(),
                    tx: bitcoin::consensus::serialize(&deposit.tx_info.tx),
                    tx_type: model::TransactionType::DepositRequest,
                    block_hash: deposit.tx_info.block_hash.to_byte_array(),
                };

                (model::DepositRequest::from(deposit), tx)
            })
            .collect::<Vec<_>>()
            .into_iter()
            .unzip();

        let db = self.context.get_storage_mut();
        db.write_bitcoin_transactions(deposit_request_txs).await?;
        db.write_deposit_requests(deposit_requests).await?;

        Ok(())
    }

    /// Extract all BTC transactions from the block where one of the UTXOs
    /// can be spent by the signers.
    ///
    /// # Note
    ///
    /// When using the postgres storage, we need to make sure that this
    /// function is called after the `Self::write_bitcoin_block` function
    /// because of the foreign key constraints.
    pub async fn extract_sbtc_transactions(
        &self,
        block_hash: BlockHash,
        txs: &[Transaction],
    ) -> Result<(), Error> {
        let db = self.context.get_storage_mut();
        // We store all the scriptPubKeys associated with the signers'
        // aggregate public key. Let's get the last years worth of them.
        let signer_script_pubkeys: HashSet<ScriptBuf> = db
            .get_signers_script_pubkeys()
            .await?
            .into_iter()
            .map(ScriptBuf::from_bytes)
            .collect();

        let btc_rpc = self.context.get_bitcoin_client();
        // Look through all the UTXOs in the given transaction slice and
        // keep the transactions where a UTXO is locked with a
        // `scriptPubKey` controlled by the signers.
        let mut sbtc_txs = Vec::new();
        for tx in txs {
            tracing::trace!(txid = %tx.compute_txid(), "attempting to extract sbtc transaction");
            // If any of the outputs are spent to one of the signers'
            // addresses, then we care about it
            let outputs_spent_to_signers = tx
                .output
                .iter()
                .any(|tx_out| signer_script_pubkeys.contains(&tx_out.script_pubkey));

            if !outputs_spent_to_signers {
                continue;
            }

            // This function is called after we have received a
            // notification of a bitcoin block, and we are iterating
            // through all of the transactions within that block. This
            // means the `get_tx_info` call below should not fail.
            let txid = tx.compute_txid();
            let tx_info = btc_rpc
                .get_tx_info(&txid, &block_hash)
                .await?
                .ok_or(Error::BitcoinTxMissing(txid, None))?;

            // sBTC transactions have as first txin a signers spendable output
            let tx_type = if tx_info.is_signer_created(&signer_script_pubkeys) {
                model::TransactionType::SbtcTransaction
            } else {
                model::TransactionType::Donation
            };

            let txid = tx.compute_txid();
            sbtc_txs.push(model::Transaction {
                txid: txid.to_byte_array(),
                tx: bitcoin::consensus::serialize(&tx),
                tx_type,
                block_hash: block_hash.to_byte_array(),
            });

            for prevout in tx_info.to_inputs(&signer_script_pubkeys) {
                db.write_tx_prevout(&prevout).await?;
                if prevout.prevout_type == model::TxPrevoutType::Deposit {
                    metrics::counter!(
                        Metrics::DepositsSweptTotal,
                        "blockchain" => BITCOIN_BLOCKCHAIN,
                    )
                    .increment(1);
                }
            }

            for output in tx_info.to_outputs(&signer_script_pubkeys) {
                db.write_tx_output(&output).await?;
            }
        }

        // Write these transactions into storage.
        db.write_bitcoin_transactions(sbtc_txs).await?;
        Ok(())
    }

    /// Write the given stacks blocks to the database.
    ///
    /// This function also extracts sBTC Stacks transactions from the given
    /// blocks and stores them into the database.
    async fn write_stacks_blocks(&self, tenures: &[TenureBlocks]) -> Result<(), Error> {
        let deployer = &self.context.config().signer.deployer;
        let txs = tenures
            .iter()
            .flat_map(|tenure| {
                storage::postgres::extract_relevant_transactions(tenure.blocks(), deployer)
            })
            .collect::<Vec<_>>();

        let headers = tenures
            .iter()
            .flat_map(TenureBlocks::as_stacks_blocks)
            .collect::<Vec<_>>();

        let storage = self.context.get_storage_mut();
        storage.write_stacks_block_headers(headers).await?;
        storage.write_stacks_transactions(txs).await?;
        Ok(())
    }

    /// Update the sBTC peg limits from Emily
    async fn update_sbtc_limits(&self) -> Result<(), Error> {
        let limits = self.context.get_emily_client().get_limits().await?;
        let sbtc_deployed = self.context.state().sbtc_contracts_deployed();

        let max_mintable = if limits.total_cap_exists() && sbtc_deployed {
            let sbtc_supply = self
                .context
                .get_stacks_client()
                .get_sbtc_total_supply(&self.context.config().signer.deployer)
                .await?;
            // The maximum amount of sBTC that can be minted is the total cap
            // minus the current supply.
            limits
                .total_cap()
                .checked_sub(sbtc_supply)
                .unwrap_or(Amount::ZERO)
        } else {
            Amount::MAX_MONEY
        };

        let limits = SbtcLimits::new(
            Some(limits.total_cap()),
            Some(limits.per_deposit_minimum()),
            Some(limits.per_deposit_cap()),
            Some(limits.per_withdrawal_cap()),
            Some(max_mintable),
        );

        let signer_state = self.context.state();
        if limits == signer_state.get_current_limits() {
            tracing::trace!(%limits, "sBTC limits have not changed");
        } else {
            tracing::debug!(%limits, "updated sBTC limits from Emily");
            signer_state.update_current_limits(limits);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;
    use bitcoin::BlockHash;
    use bitcoin::TxOut;
    use fake::Dummy;
    use fake::Fake;
    use model::BitcoinTxId;
    use model::ScriptPubKey;
    use rand::SeedableRng;
    use test_log::test;

    use crate::bitcoin::rpc::GetTxResponse;
    use crate::context::SignerSignal;
    use crate::keys::PublicKey;
    use crate::keys::SignerScriptPubKey as _;
    use crate::storage;
    use crate::testing::block_observer::TestHarness;
    use crate::testing::context::*;

    use super::*;

    #[test(tokio::test)]
    async fn should_be_able_to_extract_bitcoin_blocks_given_a_block_header_stream() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let storage = storage::in_memory::Store::new_shared();
        let test_harness = TestHarness::generate(&mut rng, 20, 0..5);
        let min_height = test_harness.min_block_height();
        let ctx = TestContext::builder()
            .with_storage(storage.clone())
            .with_stacks_client(test_harness.clone())
            .with_emily_client(test_harness.clone())
            .with_bitcoin_client(test_harness.clone())
            .modify_settings(|settings| settings.signer.sbtc_bitcoin_start_height = min_height)
            .build();

        // There must be at least one signal receiver alive when the block observer
        // later tries to send a signal, hence this line.
        let _signal_rx = ctx.get_signal_receiver();
        let block_hash_stream = test_harness.spawn_block_hash_stream();

        let block_observer = BlockObserver {
            context: ctx.clone(),
            bitcoin_blocks: block_hash_stream,
        };

        let handle = tokio::spawn(block_observer.run());
        ctx.wait_for_signal(Duration::from_secs(3), |signal| {
            matches!(
                signal,
                SignerSignal::Event(SignerEvent::BitcoinBlockObserved)
            )
        })
        .await
        .expect("block observer failed to complete within timeout");

        for block in test_harness.bitcoin_blocks() {
            let persisted = storage
                .get_bitcoin_block(&block.block_hash().into())
                .await
                .expect("storage error")
                .expect("block wasn't persisted");

            assert_eq!(persisted.block_hash, block.block_hash().into())
        }

        handle.abort();
    }

    /// Test that `BlockObserver::load_latest_deposit_requests` takes
    /// deposits from emily, validates them and only keeps the ones that
    /// pass validation and have been confirmed.
    #[tokio::test]
    async fn validated_confirmed_deposits_get_added_to_state() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let mut test_harness = TestHarness::generate(&mut rng, 20, 0..5);
        // We want the test harness to fetch a block from our
        // "bitcoin-core", which in this case is the test harness. So we
        // use a block hash that the test harness knows about.
        let block_hash = test_harness
            .bitcoin_blocks()
            .first()
            .map(|block| block.block_hash());

        let lock_time = 150;
        let max_fee = 32000;
        let amount = 500_000;

        // We're going to create two deposit requests, the first one valid
        // and the second one invalid. Emily will return both the valid and
        // invalid requests (even though it should've validated them) and
        // BitcoinClient will return the right transaction for both of
        // them.
        let tx_setup0 = sbtc::testing::deposits::tx_setup(lock_time, max_fee, amount);
        let deposit_request0 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup0.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: tx_setup0.deposit.deposit_script(),
            reclaim_script: tx_setup0.reclaim.reclaim_script(),
        };
        let req0 = deposit_request0.clone();
        // When we validate the deposit request, we fetch the transaction
        // from bitcoin-core's blockchain. The stubs out that response.
        let get_tx_resp0 = GetTxResponse {
            tx: tx_setup0.tx.clone(),
            block_hash,
            confirmations: None,
            block_time: None,
        };

        let tx_setup1 = sbtc::testing::deposits::tx_setup(300, 2000, amount);
        // This one is an invalid deposit request because the deposit
        // script is wrong
        let deposit_request1 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup1.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: bitcoin::ScriptBuf::new(),
            reclaim_script: tx_setup1.reclaim.reclaim_script(),
        };
        // The transaction is also in the mempool, even though it is an
        // invalid deposit.
        let get_tx_resp1 = GetTxResponse {
            tx: tx_setup1.tx.clone(),
            block_hash: None,
            confirmations: None,
            block_time: None,
        };

        // This deposit transaction is a fine deposit, it just hasn't been
        // confirmed yet.
        let tx_setup2 = sbtc::testing::deposits::tx_setup(400, 3000, amount);
        let get_tx_resp2 = GetTxResponse {
            tx: tx_setup2.tx.clone(),
            block_hash: None,
            confirmations: None,
            block_time: None,
        };

        let deposit_request2 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup2.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: tx_setup2.deposit.deposit_script(),
            reclaim_script: tx_setup2.reclaim.reclaim_script(),
        };

        // Let's add the "responses" to the field that feeds the
        // response to the `BitcoinClient::get_tx` call.
        test_harness.add_deposits(&[
            (get_tx_resp0.tx.compute_txid(), get_tx_resp0),
            (get_tx_resp1.tx.compute_txid(), get_tx_resp1),
            (get_tx_resp2.tx.compute_txid(), get_tx_resp2),
        ]);

        // Add the deposit requests to the pending deposits which
        // would be returned by Emily.
        test_harness.add_pending_deposits(&[deposit_request0, deposit_request1, deposit_request2]);
        let min_height = test_harness.min_block_height();

        // Now we finish setting up the block observer.
        let storage = storage::in_memory::Store::new_shared();
        let ctx = TestContext::builder()
            .with_storage(storage.clone())
            .with_stacks_client(test_harness.clone())
            .with_emily_client(test_harness.clone())
            .with_bitcoin_client(test_harness.clone())
            .modify_settings(|settings| settings.signer.sbtc_bitcoin_start_height = min_height)
            .build();

        let block_observer = BlockObserver {
            context: ctx,
            bitcoin_blocks: (),
        };

        {
            let db = storage.lock().await;
            assert_eq!(db.deposit_requests.len(), 0);
        }

        block_observer.load_latest_deposit_requests().await.unwrap();
        // Only the transaction from tx_setup0 was valid. Note that, since
        // we are not using a real block hash stored in the database. Our
        // DbRead function won't actually find it. And in prod we won't
        // actually store the deposit request transaction.
        let deposit = {
            let db = storage.lock().await;
            assert_eq!(db.deposit_requests.len(), 1);
            db.deposit_requests.values().next().cloned().unwrap()
        };

        assert_eq!(deposit.outpoint(), req0.outpoint);
    }

    /// Test that `BlockObserver::extract_deposit_requests` after
    /// `BlockObserver::load_latest_deposit_requests` stores validated
    /// deposit requests into "storage".
    #[tokio::test]
    async fn extract_deposit_requests_stores_validated_deposits() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(365);
        let mut test_harness = TestHarness::generate(&mut rng, 20, 0..5);

        // We want the test harness to fetch a block from our
        // "bitcoin-core", which in this case is the test harness. So we
        // use a block hash that the test harness knows about.
        let block_hash = test_harness
            .bitcoin_blocks()
            .first()
            .map(|block| block.block_hash());
        let lock_time = 150;
        let max_fee = 32000;
        let amount = 500_000;

        // We're going to create two deposit requests, the first one valid
        // and the second one invalid. Emily will return both the valid and
        // invalid requests (even though it should've validated them) and
        // BitcoinClient will return the right transaction for both of
        // them.
        let tx_setup0 = sbtc::testing::deposits::tx_setup(lock_time, max_fee, amount);
        let deposit_request0 = CreateDepositRequest {
            outpoint: bitcoin::OutPoint {
                txid: tx_setup0.tx.compute_txid(),
                vout: 0,
            },
            deposit_script: tx_setup0.deposit.deposit_script(),
            reclaim_script: tx_setup0.reclaim.reclaim_script(),
        };
        // When we validate the deposit request, we fetch the transaction
        // from bitcoin-core's blockchain. The stubs out that
        // response.
        let get_tx_resp0 = GetTxResponse {
            tx: tx_setup0.tx.clone(),
            block_hash,
            confirmations: None,
            block_time: None,
        };

        // Let's add the "responses" to the field that feeds the
        // response to the `BitcoinClient::get_tx` call.
        test_harness.add_deposit(get_tx_resp0.tx.compute_txid(), get_tx_resp0);
        // Add the deposit request to the pending deposits which
        // would be returned by Emily.
        test_harness.add_pending_deposit(deposit_request0);

        let min_height = test_harness.min_block_height();
        // Now we finish setting up the block observer.
        let storage = storage::in_memory::Store::new_shared();
        let ctx = TestContext::builder()
            .with_storage(storage.clone())
            .with_stacks_client(test_harness.clone())
            .with_emily_client(test_harness.clone())
            .with_bitcoin_client(test_harness.clone())
            .modify_settings(|settings| settings.signer.sbtc_bitcoin_start_height = min_height)
            .build();

        let block_observer = BlockObserver {
            context: ctx,
            bitcoin_blocks: (),
        };

        block_observer.load_latest_deposit_requests().await.unwrap();

        let storage = storage.lock().await;
        assert_eq!(storage.deposit_requests.len(), 1);
        let db_outpoint: (BitcoinTxId, u32) = (tx_setup0.tx.compute_txid().into(), 0);
        assert!(storage.deposit_requests.get(&db_outpoint).is_some());

        assert!(storage
            .bitcoin_transactions_to_blocks
            .get(&db_outpoint.0)
            .is_some());
        assert_eq!(
            storage
                .raw_transactions
                .get(db_outpoint.0.as_byte_array())
                .unwrap()
                .tx_type,
            model::TransactionType::DepositRequest
        );
    }

    /// Test that `BlockObserver::extract_sbtc_transactions` takes the
    /// stored signer `scriptPubKey`s and stores all transactions from a
    /// bitcoin block that match one of those `scriptPubkey`s.
    #[tokio::test]
    async fn sbtc_transactions_get_stored() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let mut test_harness = TestHarness::generate(&mut rng, 20, 0..5);

        let block_hash = BlockHash::from_byte_array([1u8; 32]);
        // We're going to do the following:
        // 1. pretend that the below bytes represent the signers
        //    `scriptPubKey`. We store it in our datastore along with some
        //    "DKG shares".
        // 2. We then create two transactions, one spending to our
        //    scriptPubKey and another not spending to it.
        // 3. We try "extracting" a block with one transaction that does
        //    not spend to the signers. This one transaction should not be
        //    extracted (we should not see it in storage).
        // 4. We try "extracting" a block with two transactions where one
        //    of them spends to the signers. The one transaction should be
        //    stored in our storage.
        let signers_script_pubkey: ScriptPubKey = fake::Faker.fake_with_rng(&mut rng);

        // We start by storing our `scriptPubKey`.
        let storage = storage::in_memory::Store::new_shared();
        let aggregate_key = PublicKey::dummy_with_rng(&fake::Faker, &mut rng);
        let shares = model::EncryptedDkgShares {
            aggregate_key,
            tweaked_aggregate_key: aggregate_key.signers_tweaked_pubkey().unwrap(),
            script_pubkey: signers_script_pubkey.clone(),
            encrypted_private_shares: Vec::new(),
            public_shares: Vec::new(),
            signer_set_public_keys: vec![aggregate_key],
            signature_share_threshold: 1,
        };
        storage.write_encrypted_dkg_shares(&shares).await.unwrap();

        // Now let's create two transactions, one spending to the signers
        // and another not spending to the signers. We use
        // sbtc::testing::deposits::tx_setup just to quickly create a
        // transaction; any one will do since we will be adding the UTXO
        // that spends to the signer afterward.
        let mut tx_setup0 = sbtc::testing::deposits::tx_setup(0, 0, 100);
        tx_setup0.tx.output.push(TxOut {
            value: Amount::ONE_BTC,
            script_pubkey: signers_script_pubkey.into(),
        });

        // This one does not spend to the signers :(
        let tx_setup1 = sbtc::testing::deposits::tx_setup(1, 10, 2000);
        let txid0 = tx_setup0.tx.compute_txid();
        let txid1 = tx_setup1.tx.compute_txid();

        let response0 = GetTxResponse {
            tx: tx_setup0.tx.clone(),
            block_hash: Some(block_hash),
            confirmations: None,
            block_time: None,
        };
        let response1 = GetTxResponse {
            tx: tx_setup1.tx.clone(),
            block_hash: Some(block_hash),
            confirmations: None,
            block_time: None,
        };
        test_harness.add_deposit(txid0, response0);
        test_harness.add_deposit(txid1, response1);

        let ctx = TestContext::builder()
            .with_storage(storage.clone())
            .with_stacks_client(test_harness.clone())
            .with_emily_client(test_harness.clone())
            .with_bitcoin_client(test_harness.clone())
            .build();

        let block_observer = BlockObserver {
            context: ctx,
            bitcoin_blocks: (),
        };

        // First we try extracting the transactions from a block that does
        // not contain any transactions spent to the signers
        let txs = [tx_setup1.tx.clone()];
        block_observer
            .extract_sbtc_transactions(block_hash, &txs)
            .await
            .unwrap();

        // We need to change the scope so that the mutex guard is dropped.
        {
            let store = storage.lock().await;
            // Under the hood, bitcoin transactions get stored in the
            // `bitcoin_block_to_transactions` field, so lets check there
            let stored_transactions = store.bitcoin_block_to_transactions.get(&block_hash.into());

            // Nothing should be stored so the map get call should return
            // None.
            assert!(stored_transactions.is_none());
        }

        // Now we try again, but we include the transaction that spends to
        // the signer. This one should turn out differently.
        let txs = [tx_setup0.tx.clone(), tx_setup1.tx.clone()];
        block_observer
            .extract_sbtc_transactions(block_hash, &txs)
            .await
            .unwrap();

        let store = storage.lock().await;
        let stored_transactions = store.bitcoin_block_to_transactions.get(&block_hash.into());

        // Is our one transaction stored? This block hash should now have
        // only one transaction with the expected txid.
        let tx_ids = stored_transactions.unwrap();
        let expected_tx_id = tx_setup0.tx.compute_txid().into();
        assert_eq!(tx_ids.len(), 1);
        assert_eq!(tx_ids[0], expected_tx_id);
    }
}
