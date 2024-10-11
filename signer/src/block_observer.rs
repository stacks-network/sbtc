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

use std::collections::HashMap;
use std::future::Future;

use crate::bitcoin::BitcoinInteract;
use crate::context::Context;
use crate::context::SignerEvent;
use crate::emily_client::EmilyInteract;
use crate::error::Error;
use crate::stacks::api::StacksInteract;
use crate::storage;
use crate::storage::model;
use crate::storage::DbRead;
use crate::storage::DbWrite;
use bitcoin::consensus::Encodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::BlockHash;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::Txid;
use blockstack_lib::chainstate::nakamoto;
use futures::stream::StreamExt;
use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::DepositInfo;
use std::collections::HashSet;

/// Block observer
#[derive(Debug)]
pub struct BlockObserver<Context, StacksClient, EmilyClient, BlockHashStream> {
    /// Signer context
    pub context: Context,
    /// Stacks client
    pub stacks_client: StacksClient,
    /// Emily client
    pub emily_client: EmilyClient,
    /// Stream of blocks from the block notifier
    pub bitcoin_blocks: BlockHashStream,
    /// How far back in time the observer should look
    pub horizon: usize,
    /// An in memory map of deposit requests that haven't been confirmed
    /// on bitcoin yet.
    pub deposit_requests: HashMap<Txid, Vec<Deposit>>,
    /// The bitcoin network
    pub network: bitcoin::Network,
}

/// A full "deposit", containing the bitcoin transaction and a fully
/// extracted and verified `scriptPubKey` from one of the transaction's
/// UTXOs.
#[derive(Debug, Clone)]
pub struct Deposit {
    /// The transaction spent to the signers as a deposit for sBTC.
    pub tx: Transaction,
    /// The deposit information included in one of the output
    /// `scriptPubKey`s of the above transaction.
    pub info: DepositInfo,
}

impl DepositRequestValidator for CreateDepositRequest {
    async fn validate<C>(&self, client: &C) -> Result<Deposit, Error>
    where
        C: BitcoinInteract,
    {
        // Fetch the transaction from either a block or from the mempool
        let Some(response) = client.get_tx(&self.outpoint.txid).await? else {
            return Err(Error::BitcoinTxMissing(self.outpoint.txid, None));
        };

        Ok(Deposit {
            info: self.validate_tx(&response.tx)?,
            tx: response.tx,
        })
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
    fn validate<C>(&self, client: &C) -> impl Future<Output = Result<Deposit, Error>>
    where
        C: BitcoinInteract;
}

impl<C, SC, EC, BHS> BlockObserver<C, SC, EC, BHS>
where
    C: Context,
    SC: StacksInteract,
    EC: EmilyInteract,
    BHS: futures::stream::Stream<Item = Result<bitcoin::BlockHash, Error>> + Unpin,
{
    /// Run the block observer
    #[tracing::instrument(skip(self))]
    pub async fn run(mut self) -> Result<(), Error> {
        let mut term = self.context.get_termination_handle();

        let run = async {
            while let Some(new_block_hash) = self.bitcoin_blocks.next().await {
                tracing::info!(
                    ?new_block_hash,
                    "new bitcoin block observed on bitcoin core block hash stream"
                );
                tracing::info!("loading latest deposit requests from Emily");
                if let Err(error) = self.load_latest_deposit_requests().await {
                    tracing::warn!(%error, "could not load latest deposit requests from Emily");
                }

                let new_block_hash = match new_block_hash {
                    Ok(hash) => hash,
                    Err(error) => {
                        tracing::warn!(%error, "error decoding new bitcoin block hash from stream");
                        continue;
                    }
                };

                tracing::info!(%new_block_hash, "observed new bitcoin block from stream");

                let next_blocks_to_process = match self.next_blocks_to_process(new_block_hash).await
                {
                    Ok(blocks) => blocks,
                    Err(error) => {
                        tracing::warn!(%error, block_hash = %new_block_hash, "could not get next blocks to process");
                        continue;
                    }
                };

                for block in next_blocks_to_process {
                    if let Err(error) = self.process_bitcoin_block(block).await {
                        tracing::warn!(%error, "could not process bitcoin block");
                    }
                }

                self.context
                    .signal(SignerEvent::BitcoinBlockObserved.into())?;
            }

            Ok::<_, Error>(())
        };

        tokio::select! {
            _ = term.wait_for_shutdown() => {
                tracing::info!("block observer received shutdown signal");
            },
            result = run => {
                result?;
            }
        }

        tracing::info!("shutting down block observer");

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn load_latest_deposit_requests(&mut self) -> Result<(), Error> {
        let deposit_requests = self.emily_client.get_deposits().await?;

        for request in deposit_requests {
            let deposit = request
                .validate(&self.context.get_bitcoin_client())
                .await
                .inspect_err(|error| tracing::warn!(%error, "could not validate deposit request"));

            if let Ok(deposit) = deposit {
                self.deposit_requests
                    .entry(deposit.info.outpoint.txid)
                    .or_default()
                    .push(deposit);
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn next_blocks_to_process(
        &mut self,
        mut block_hash: bitcoin::BlockHash,
    ) -> Result<Vec<bitcoin::Block>, Error> {
        let mut blocks = Vec::new();

        for _ in 0..self.horizon {
            if self.have_already_processed_block(block_hash).await? {
                tracing::debug!(?block_hash, "already processed block");
                break;
            }

            let block = self
                .context
                .get_bitcoin_client()
                .get_block(&block_hash)
                .await?
                .ok_or(Error::MissingBlock)?;

            block_hash = block.header.prev_blockhash;
            blocks.push(block);
        }

        // Make order chronological
        blocks.reverse();
        Ok(blocks)
    }

    #[tracing::instrument(skip(self))]
    async fn have_already_processed_block(
        &mut self,
        block_hash: bitcoin::BlockHash,
    ) -> Result<bool, Error> {
        Ok(self
            .context
            .get_storage()
            .get_bitcoin_block(&block_hash.to_byte_array().into())
            .await?
            .is_some())
    }

    #[tracing::instrument(skip(self))]
    async fn process_bitcoin_block(&mut self, block: bitcoin::Block) -> Result<(), Error> {
        let info = self.stacks_client.get_tenure_info().await?;
        let stacks_blocks = crate::stacks::api::fetch_unknown_ancestors(
            &self.stacks_client,
            &self.context.get_storage(),
            info.tip_block_id,
        )
        .await?;

        self.write_stacks_blocks(&stacks_blocks).await?;
        self.write_bitcoin_block(&block).await?;

        self.extract_deposit_requests(&block.txdata, block.block_hash())
            .await?;

        Ok(())
    }

    async fn extract_deposit_requests(
        &mut self,
        txs: &[Transaction],
        block_hash: BlockHash,
    ) -> Result<(), Error> {
        let (deposit_request, deposit_request_txs) = txs
            .iter()
            .filter_map(|tx| self.deposit_requests.remove(&tx.compute_txid()))
            .flatten()
            .map(|deposit| {
                let mut tx_bytes = Vec::new();
                deposit.tx.consensus_encode(&mut tx_bytes)?;

                let tx = model::Transaction {
                    txid: deposit.tx.compute_txid().to_byte_array(),
                    tx: tx_bytes,
                    tx_type: model::TransactionType::DepositRequest,
                    block_hash: block_hash.to_byte_array(),
                };

                Ok((model::DepositRequest::from(deposit), tx))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::BitcoinEncodeTransaction)?
            .into_iter()
            .unzip();

        self.context
            .get_storage_mut()
            .write_bitcoin_transactions(deposit_request_txs)
            .await?;
        self.context
            .get_storage_mut()
            .write_deposit_requests(deposit_request)
            .await?;

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
    async fn extract_sbtc_transactions(
        &self,
        block_hash: BlockHash,
        txs: &[Transaction],
    ) -> Result<(), Error> {
        // We store all the scriptPubKeys associated with the signers'
        // aggregate public key. Let's get the last years worth of them.
        let signer_script_pubkeys: HashSet<ScriptBuf> = self
            .context
            .get_storage()
            .get_signers_script_pubkeys()
            .await?
            .into_iter()
            .map(ScriptBuf::from_bytes)
            .collect();

        // Look through all the UTXOs in the given transaction slice and
        // keep the transactions where a UTXO is locked with a
        // `scriptPubKey` controlled by the signers.
        let mut sbtc_txs = Vec::new();
        for tx in txs {
            // If any of the outputs are spent to one of the signers'
            // addresses, then we care about it
            let outputs_spent_to_signers = tx
                .output
                .iter()
                .any(|tx_out| signer_script_pubkeys.contains(&tx_out.script_pubkey));

            if !outputs_spent_to_signers {
                continue;
            }

            let mut tx_bytes = Vec::new();
            tx.consensus_encode(&mut tx_bytes)
                .map_err(Error::BitcoinEncodeTransaction)?;

            // sBTC transactions have as first txin a signers spendable output
            let mut tx_type = model::TransactionType::Donation;
            if let Some(txin) = tx.input.first() {
                let tx_info = self
                    .context
                    .get_bitcoin_client()
                    .get_tx(&txin.previous_output.txid)
                    .await?
                    .ok_or(Error::BitcoinTxMissing(txin.previous_output.txid, None))?;

                let prevout = &tx_info
                    .tx
                    .tx_out(txin.previous_output.vout as usize)
                    .map_err(|_| Error::OutPointMissing(txin.previous_output))?
                    .script_pubkey;

                if signer_script_pubkeys.contains(prevout) {
                    tx_type = model::TransactionType::SbtcTransaction;
                }
            };

            sbtc_txs.push(model::Transaction {
                txid: tx.compute_txid().to_byte_array(),
                tx: tx_bytes,
                tx_type,
                block_hash: block_hash.to_byte_array(),
            });
        }

        // Write these transactions into storage.
        self.context
            .get_storage_mut()
            .write_bitcoin_transactions(sbtc_txs)
            .await?;
        Ok(())
    }

    async fn write_stacks_blocks(
        &mut self,
        blocks: &[nakamoto::NakamotoBlock],
    ) -> Result<(), Error> {
        let deployer = &self.context.config().signer.deployer;
        let txs = storage::postgres::extract_relevant_transactions(blocks, deployer);
        let headers = blocks
            .iter()
            .map(model::StacksBlock::try_from)
            .collect::<Result<_, _>>()?;

        let storage = self.context.get_storage_mut();
        storage.write_stacks_block_headers(headers).await?;
        storage.write_stacks_transactions(txs).await?;
        Ok(())
    }

    /// Write the bitcoin block to the database. We also write any
    /// transactions that are spend to any of the signers `scriptPubKey`s
    async fn write_bitcoin_block(&mut self, block: &bitcoin::Block) -> Result<(), Error> {
        let db_block = model::BitcoinBlock {
            block_hash: block.block_hash().into(),
            block_height: block
                .bip34_block_height()
                .expect("Failed to get block height"),
            parent_hash: block.header.prev_blockhash.into(),
            confirms: Vec::new(),
        };

        self.context
            .get_storage_mut()
            .write_bitcoin_block(&db_block)
            .await?;
        self.extract_sbtc_transactions(block.block_hash(), &block.txdata)
            .await?;

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

    use crate::bitcoin::rpc::GetTxResponse;
    use crate::config::Settings;
    use crate::context::SignerContext;
    use crate::keys::PublicKey;
    use crate::keys::SignerScriptPubKey as _;
    use crate::storage;
    use crate::testing::block_observer::TestHarness;

    use super::*;

    #[tokio::test]
    async fn should_be_able_to_extract_bitcoin_blocks_given_a_block_header_stream() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let storage = storage::in_memory::Store::new_shared();
        let test_harness = TestHarness::generate(&mut rng, 20, 0..5);
        let ctx = SignerContext::new(
            Settings::new_from_default_config().unwrap(),
            storage.clone(),
            test_harness.clone(),
            test_harness.clone(),
            test_harness.clone(),
        );
        // There must be at least one signal receiver alive when the block observer
        // later tries to send a signal, hence this line.
        let _signal_rx = ctx.get_signal_receiver();
        let block_hash_stream = test_harness.spawn_block_hash_stream();

        let block_observer = BlockObserver {
            context: ctx,
            stacks_client: test_harness.clone(),
            emily_client: test_harness.clone(),
            bitcoin_blocks: block_hash_stream,
            horizon: 1,
            deposit_requests: HashMap::new(),
            network: bitcoin::Network::Regtest,
        };

        block_observer.run().await.expect("block observer failed");

        for block in test_harness.bitcoin_blocks() {
            let persisted = storage
                .get_bitcoin_block(&block.block_hash().into())
                .await
                .expect("storage error")
                .expect("block wasn't persisted");

            assert_eq!(persisted.block_hash, block.block_hash().into())
        }
    }

    /// Test that `BlockObserver::load_latest_deposit_requests` takes
    /// deposits from emily, validates them and only keeps the ones that
    /// pass validation.
    #[tokio::test]
    async fn validated_deposits_get_added_to_state() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let mut test_harness = TestHarness::generate(&mut rng, 20, 0..5);

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
        // from bitcoin-core's mempool or blockchain. The stubs out that
        // response.
        let get_tx_resp0 = GetTxResponse {
            tx: tx_setup0.tx.clone(),
            block_hash: None,
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

        // Let's add the "responses" to the field that feeds the
        // response to the `BitcoinClient::get_tx` call.
        test_harness.add_deposits(&[
            (get_tx_resp0.tx.compute_txid(), get_tx_resp0),
            (get_tx_resp1.tx.compute_txid(), get_tx_resp1),
        ]);

        // Add the deposit requests to the pending deposits which
        // would be returned by Emily.
        test_harness.add_pending_deposits(&[deposit_request0, deposit_request1]);

        // Now we finish setting up the block observer.
        let storage = storage::in_memory::Store::new_shared();
        let block_hash_stream = test_harness.spawn_block_hash_stream();
        let ctx = SignerContext::new(
            Settings::new_from_default_config().unwrap(),
            storage.clone(),
            test_harness.clone(),
            test_harness.clone(),
            test_harness.clone(),
        );

        let mut block_observer = BlockObserver {
            context: ctx,
            stacks_client: test_harness.clone(),
            emily_client: test_harness.clone(),
            bitcoin_blocks: block_hash_stream,
            horizon: 1,
            deposit_requests: HashMap::new(),
            network: bitcoin::Network::Regtest,
        };

        block_observer.load_latest_deposit_requests().await.unwrap();
        // Only the transaction from tx_setup0 was valid.
        assert_eq!(block_observer.deposit_requests.len(), 1);

        let deposit = block_observer
            .deposit_requests
            .get(&tx_setup0.tx.compute_txid())
            .cloned()
            .unwrap();
        assert_eq!(deposit.len(), 1);
        assert_eq!(deposit[0].tx, tx_setup0.tx);
    }

    /// Test that `BlockObserver::extract_deposit_requests` after
    /// `BlockObserver::load_latest_deposit_requests` stores validated
    /// deposit requests into "storage".
    #[tokio::test]
    async fn extract_deposit_requests_stores_validated_deposits() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(365);
        let mut test_harness = TestHarness::generate(&mut rng, 20, 0..5);

        let block_hash = BlockHash::from_byte_array([1u8; 32]);
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
        // from bitcoin-core's mempool or blockchain. The stubs out that
        // response.
        let get_tx_resp0 = GetTxResponse {
            tx: tx_setup0.tx.clone(),
            block_hash: Some(block_hash.clone()),
            confirmations: None,
            block_time: None,
        };

        // Let's add the "responses" to the field that feeds the
        // response to the `BitcoinClient::get_tx` call.
        test_harness.add_deposit(get_tx_resp0.tx.compute_txid(), get_tx_resp0);
        // Add the deposit request to the pending deposits which
        // would be returned by Emily.
        test_harness.add_pending_deposit(deposit_request0);

        // Now we finish setting up the block observer.
        let storage = storage::in_memory::Store::new_shared();
        let block_hash_stream = test_harness.spawn_block_hash_stream();
        let ctx = SignerContext::new(
            Settings::new_from_default_config().unwrap(),
            storage.clone(),
            test_harness.clone(),
            test_harness.clone(),
            test_harness.clone(),
        );

        let mut block_observer = BlockObserver {
            context: ctx,
            stacks_client: test_harness.clone(),
            emily_client: test_harness.clone(),
            bitcoin_blocks: block_hash_stream,
            horizon: 1,
            deposit_requests: HashMap::new(),
            network: bitcoin::Network::Regtest,
        };

        block_observer.load_latest_deposit_requests().await.unwrap();
        // The transaction from tx_setup0 was valid.
        assert_eq!(block_observer.deposit_requests.len(), 1);

        block_observer
            .extract_deposit_requests(&[tx_setup0.tx.clone()], block_hash)
            .await
            .unwrap();
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

        // Now the deposit_requests thing should be empty now, since we stored the things.
        assert!(block_observer.deposit_requests.is_empty());
    }

    /// Test that `BlockObserver::extract_sbtc_transactions` takes the
    /// stored signer `scriptPubKey`s and stores all transactions from a
    /// bitcoin block that match one of those `scriptPubkey`s.
    #[tokio::test]
    async fn sbtc_transactions_get_stored() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(46);
        let test_harness = TestHarness::generate(&mut rng, 20, 0..5);

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
        };
        storage.write_encrypted_dkg_shares(&shares).await.unwrap();

        let ctx = SignerContext::new(
            Settings::new_from_default_config().unwrap(),
            storage.clone(),
            test_harness.clone(),
            test_harness.clone(),
            test_harness.clone(),
        );

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

        let block_observer = BlockObserver {
            context: ctx,
            stacks_client: test_harness.clone(),
            emily_client: test_harness.clone(),
            bitcoin_blocks: test_harness.spawn_block_hash_stream(),
            horizon: 1,
            deposit_requests: HashMap::new(),
            network: bitcoin::Network::Regtest,
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
