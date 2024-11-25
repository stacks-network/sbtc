use std::collections::HashSet;
use std::ops::Deref;
use std::sync::atomic::Ordering;

use bitcoin::hashes::Hash as _;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::SeedableRng as _;

use sbtc::testing::regtest;
use signer::bitcoin::utxo::Fees;
use signer::bitcoin::utxo::SbtcRequests;
use signer::bitcoin::utxo::SignerBtcState;
use signer::bitcoin::validation::BitcoinTxContext;
use signer::bitcoin::validation::BitcoinTxValidationData;
use signer::bitcoin::validation::InputValidationResult;
use signer::bitcoin::validation::TxRequestIds;
use signer::context::Context;
use signer::error::Error;
use signer::keys::PublicKey;
use signer::storage::model::BitcoinBlockHash;
use signer::storage::model::TxPrevoutType;
use signer::storage::DbRead as _;
use signer::testing;
use signer::testing::context::TestContext;
use signer::testing::context::*;

use crate::setup::{backfill_bitcoin_blocks, TestSignerSet};
use crate::setup::{DepositAmounts, TestSweepSetup2};
use crate::DATABASE_NUM;

pub struct TestSignerState {
    /// This signer's current view of the chain tip of the canonical
    /// bitcoin blockchain. It is the block hash of the block on the
    /// bitcoin blockchain with the greatest height.
    pub chain_tip: BitcoinBlockHash,
    /// How many bitcoin blocks back from the chain tip the signer will
    /// look for requests.
    pub context_window: u16,
    /// The current market fee rate in sat/vByte.
    pub fee_rate: f64,
    /// The total fee amount and the fee rate for the last transaction that
    /// used this UTXO as an input.
    pub last_fee: Option<Fees>,
    /// The current aggregate key that was the output of DKG.
    pub aggregate_key: PublicKey,
    /// Two byte prefix for BTC transactions that are related to the Stacks
    /// blockchain.
    pub magic_bytes: [u8; 2],
}

impl TestSignerState {
    fn with_defaults(chain_tip: BitcoinBlockHash, aggregate_key: PublicKey) -> Self {
        Self {
            chain_tip,
            context_window: 1000,
            fee_rate: 10.0,
            last_fee: None,
            aggregate_key,
            magic_bytes: [b'T', b'3'],
        }
    }
    /// Fetch the signers' BTC state and the aggregate key.
    ///
    /// The returned state is the essential information for the signers
    /// UTXO, and information about the current fees and any fees paid for
    /// transactions currently in the mempool.
    pub async fn get_btc_state<C>(&self, ctx: &C) -> Result<SignerBtcState, Error>
    where
        C: Context + Send + Sync,
    {
        // We need to know the signers UTXO, so let's fetch that.
        let db = ctx.get_storage();
        let utxo = db
            .get_signer_utxo(&self.chain_tip, self.context_window)
            .await?
            .ok_or(Error::MissingSignerUtxo)?;

        let btc_state = SignerBtcState {
            fee_rate: self.fee_rate,
            utxo,
            public_key: bitcoin::XOnlyPublicKey::from(self.aggregate_key),
            last_fees: self.last_fee,
            magic_bytes: self.magic_bytes,
        };

        Ok(btc_state)
    }
}

pub trait AssertConstantInvariants {
    fn packages(&self) -> &[BitcoinTxValidationData];
    fn assert_invariants(&self) {
        for package in self.packages() {
            let input_rows = package.to_input_rows();
            let withdrawal_rows = package.to_withdrawal_rows();
            let txids: HashSet<_> = input_rows
                .iter()
                .map(|row| row.txid)
                .chain(withdrawal_rows.iter().map(|row| row.txid))
                .collect();
            let is_valid_tx: HashSet<_> = input_rows
                .iter()
                .map(|row| row.is_valid_tx)
                .chain(withdrawal_rows.iter().map(|row| row.is_valid_tx))
                .collect();
            let chain_tip: HashSet<_> = input_rows
                .iter()
                .map(|row| row.chain_tip)
                .chain(withdrawal_rows.iter().map(|row| row.chain_tip))
                .collect();

            assert_eq!(txids.len(), 1);
            assert_eq!(is_valid_tx.len(), 1);
            assert_eq!(chain_tip.len(), 1);
        }
    }
}

impl AssertConstantInvariants for Vec<BitcoinTxValidationData> {
    fn packages(&self) -> &[BitcoinTxValidationData] {
        &self
    }
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn one_tx_per_request_set() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let signers = TestSignerSet::new(&mut rng);
    let amounts = [DepositAmounts {
        amount: 1_000_000,
        max_fee: 500_000,
    }];

    let mut setup = TestSweepSetup2::new_setup(signers, &faucet, &amounts);
    setup.deposits.sort_by_key(|(x, _, _)| x.outpoint);
    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_dkg_shares(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let chain_tip_block = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();

    let aggregate_key = setup.signers.signer.keypair.public_key().into();

    let test_state = TestSignerState::with_defaults(chain_tip, aggregate_key);

    let btc_ctx = BitcoinTxContext {
        chain_tip: chain_tip_block.block_hash,
        chain_tip_height: chain_tip_block.block_height,
        request_packages: vec![TxRequestIds {
            deposits: setup.deposit_outpoints(),
            withdrawals: Vec::new(),
        }],
        signer_public_key: setup.signers.keys[0],
        aggregate_key,
        signer_state: test_state.get_btc_state(&ctx).await.unwrap(),
    };

    let validation_data = btc_ctx.construct_package_sighashes(&ctx).await.unwrap();
    // There are a few invariants that we uphold for our validation data.
    // These are things like "the transaction ID per package must be the
    // same", we check for them here.
    validation_data.assert_invariants();
    // We only had a package with one set of requests that were being
    // handled.
    assert_eq!(validation_data.len(), 1);

    // We didn't give any withdrawals so the outputs vector should be
    // empty (it only has signer outputs).
    let set = &validation_data[0];
    assert!(set.to_withdrawal_rows().is_empty());

    // This transaction package
    let input_rows = set.to_input_rows();
    let [signer, deposit] = input_rows.last_chunk().unwrap();
    assert_eq!(signer.prevout_type, TxPrevoutType::SignersInput);
    assert_eq!(signer.validation_result, InputValidationResult::Ok);
    assert_eq!(signer.prevout_txid.deref(), &setup.donation.txid);
    assert_eq!(signer.prevout_output_index, setup.donation.vout);
    assert!(signer.will_sign);
    assert!(signer.is_valid_tx);

    let deposit_outpoint = setup.deposits[0].0.outpoint;
    assert_eq!(deposit.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(deposit.validation_result, InputValidationResult::Ok);
    assert_eq!(deposit.prevout_txid.deref(), &deposit_outpoint.txid);
    assert_eq!(deposit.prevout_output_index, deposit_outpoint.vout);
    assert!(deposit.will_sign);
    assert!(deposit.is_valid_tx);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn one_invalid_deposit_invalidates_tx() {
    let low_fee = 10;

    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let signers = TestSignerSet::new(&mut rng);
    let amounts = [
        DepositAmounts {
            amount: 1_000_000,
            max_fee: low_fee,
        },
        DepositAmounts {
            amount: 1_000_000,
            max_fee: 500_000,
        },
    ];

    // When making assertions below, we need to make sure that we're
    // comparing the right deposits transaction outputs, so we sort.
    let mut setup = TestSweepSetup2::new_setup(signers, &faucet, &amounts);
    setup.deposits.sort_by_key(|(x, _, _)| x.outpoint);
    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_dkg_shares(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let chain_tip_block = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();

    let aggregate_key = setup.signers.signer.keypair.public_key().into();

    let test_state = TestSignerState::with_defaults(chain_tip, aggregate_key);

    let btc_ctx = BitcoinTxContext {
        chain_tip: chain_tip_block.block_hash,
        chain_tip_height: chain_tip_block.block_height,
        request_packages: vec![TxRequestIds {
            deposits: setup.deposit_outpoints(),
            withdrawals: Vec::new(),
        }],
        signer_public_key: setup.signers.keys[0],
        aggregate_key,
        signer_state: test_state.get_btc_state(&ctx).await.unwrap(),
    };

    let validation_data = btc_ctx.construct_package_sighashes(&ctx).await.unwrap();
    // There are a few invariants that we uphold for our validation data.
    // These are things like "the transaction ID per package must be the
    // same", we check for them here.
    validation_data.assert_invariants();
    // We only had a package with one set of requests that were being
    // handled.
    assert_eq!(validation_data.len(), 1);

    // We didn't give any withdrawals so the outputs vector should be
    // empty (it only has signer outputs).
    let set = &validation_data[0];
    assert!(set.to_withdrawal_rows().is_empty());

    // The signer won't sign any of the sighashes, even though only one of
    // the deposits have failed validation.
    let input_rows = set.to_input_rows();
    let signer = input_rows.first().unwrap();
    assert_eq!(signer.prevout_type, TxPrevoutType::SignersInput);
    assert_eq!(signer.validation_result, InputValidationResult::Ok);
    assert_eq!(signer.prevout_txid.deref(), &setup.donation.txid);
    assert_eq!(signer.prevout_output_index, setup.donation.vout);
    assert!(!signer.will_sign);
    assert!(!signer.is_valid_tx);

    let [deposit1, deposit2] = input_rows.last_chunk().unwrap();

    let (validation_result1, validation_result2) = if setup.deposits[0].0.max_fee == low_fee {
        (InputValidationResult::FeeTooHigh, InputValidationResult::Ok)
    } else {
        (InputValidationResult::Ok, InputValidationResult::FeeTooHigh)
    };

    let outpoint = setup.deposits[0].0.outpoint;
    assert_eq!(deposit1.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(deposit1.validation_result, validation_result1);
    assert_eq!(deposit1.prevout_txid.deref(), &outpoint.txid);
    assert_eq!(deposit1.prevout_output_index, outpoint.vout);
    assert!(!deposit1.will_sign);
    assert!(!deposit1.is_valid_tx);

    let outpoint = setup.deposits[1].0.outpoint;
    assert_eq!(deposit2.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(deposit2.validation_result, validation_result2);
    assert_eq!(deposit2.prevout_txid.deref(), &outpoint.txid);
    assert_eq!(deposit2.prevout_output_index, outpoint.vout);
    assert!(!deposit2.will_sign);
    assert!(!deposit2.is_valid_tx);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn one_withdrawal_errors_validation() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let signers = TestSignerSet::new(&mut rng);
    let amounts = [
        DepositAmounts {
            amount: 700_000,
            max_fee: 500_000,
        },
        DepositAmounts {
            amount: 1_000_000,
            max_fee: 500_000,
        },
    ];

    // When making assertions below, we need to make sure that we're
    // comparing the right deposits transaction outputs, so we sort.
    let mut setup = TestSweepSetup2::new_setup(signers, &faucet, &amounts);
    setup.deposits.sort_by_key(|(x, _, _)| x.outpoint);
    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_dkg_shares(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;
    // For the withdrawal
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let chain_tip_block = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();

    let aggregate_key = setup.signers.signer.keypair.public_key().into();

    let test_state = TestSignerState::with_defaults(chain_tip, aggregate_key);

    let btc_ctx = BitcoinTxContext {
        chain_tip: chain_tip_block.block_hash,
        chain_tip_height: chain_tip_block.block_height,
        request_packages: vec![TxRequestIds {
            deposits: setup.deposit_outpoints(),
            withdrawals: setup.withdrawal_ids(),
        }],
        signer_public_key: setup.signers.keys[0],
        aggregate_key,
        signer_state: test_state.get_btc_state(&ctx).await.unwrap(),
    };

    let result = btc_ctx.construct_package_sighashes(&ctx).await;
    assert!(result.is_err());
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn cannot_sign_deposit_is_ok() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let signers = TestSignerSet::new(&mut rng);
    let amounts = [
        DepositAmounts {
            amount: 700_000,
            max_fee: 500_000,
        },
        DepositAmounts {
            amount: 1_000_000,
            max_fee: 500_000,
        },
    ];

    // When making assertions below, we need to make sure that we're
    // comparing the right deposits transaction outputs, so we sort.
    let mut setup = TestSweepSetup2::new_setup(signers, &faucet, &amounts);
    setup.deposits.sort_by_key(|(x, _, _)| x.outpoint);
    // Let's suppose that signer 0 cannot sign for the deposit, but that
    // they still accept the deposit. That means the bitmap at signer 0
    // will have a 1, since that means the signer did not sign for all
    // the inputs in the transaction.
    setup.deposits[0].1.signer_bitmap.set(0, true);

    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_dkg_shares(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Here we update the database to specifically say that we cannot sign,
    // but we accept the deposit, so we would if we could.
    sqlx::query(
        "
        UPDATE sbtc_signer.deposit_signers
           SET can_sign = FALSE
             , can_accept = TRUE          
         WHERE txid = $1
           AND output_index = $2
           AND signer_pub_key = $3
    ",
    )
    .bind(setup.deposits[0].0.outpoint.txid.to_byte_array())
    .bind(setup.deposits[0].0.outpoint.vout as i32)
    .bind(setup.signers.keys[0])
    .execute(db.pool())
    .await
    .unwrap();

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let chain_tip_block = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();

    // Now we construct the validation data, including the sighashes.
    let aggregate_key = setup.signers.signer.keypair.public_key().into();
    let test_state = TestSignerState::with_defaults(chain_tip, aggregate_key);

    let btc_ctx = BitcoinTxContext {
        chain_tip: chain_tip_block.block_hash,
        chain_tip_height: chain_tip_block.block_height,
        request_packages: vec![TxRequestIds {
            deposits: setup.deposit_outpoints(),
            withdrawals: Vec::new(),
        }],
        signer_public_key: setup.signers.keys[0],
        aggregate_key,
        signer_state: test_state.get_btc_state(&ctx).await.unwrap(),
    };

    let validation_data = btc_ctx.construct_package_sighashes(&ctx).await.unwrap();
    // There are a few invariants that we uphold for our validation data.
    // These are things like "the transaction ID per package must be the
    // same", we check for them here.
    validation_data.assert_invariants();
    // We only had a package with one set of requests that were being
    // handled.
    assert_eq!(validation_data.len(), 1);

    // We didn't give any withdrawals so the outputs vector should be
    // empty (it only has signer outputs).
    let set = &validation_data[0];
    assert!(set.to_withdrawal_rows().is_empty());

    // The signer won't sign the sighashes where they cannot sign, but the
    // transaction is still valid, so they will sign the other sighashes.
    let input_rows = set.to_input_rows();
    let signer = input_rows.first().unwrap();
    assert_eq!(input_rows.len(), 3);
    assert_eq!(signer.prevout_type, TxPrevoutType::SignersInput);
    assert_eq!(signer.validation_result, InputValidationResult::Ok);
    assert_eq!(signer.prevout_txid.deref(), &setup.donation.txid);
    assert_eq!(signer.prevout_output_index, setup.donation.vout);
    assert!(signer.will_sign);
    assert!(signer.is_valid_tx);

    let [deposit1, deposit2] = input_rows.last_chunk().unwrap();
    let outpoint = setup.deposits[0].0.outpoint;
    assert_eq!(deposit1.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(
        deposit1.validation_result,
        InputValidationResult::CannotSignUtxo
    );
    assert_eq!(deposit1.prevout_txid.deref(), &outpoint.txid);
    assert_eq!(deposit1.prevout_output_index, outpoint.vout);
    assert!(!deposit1.will_sign);
    assert!(deposit1.is_valid_tx);

    let outpoint = setup.deposits[1].0.outpoint;
    assert_eq!(deposit2.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(deposit2.validation_result, InputValidationResult::Ok);
    assert_eq!(deposit2.prevout_txid.deref(), &outpoint.txid);
    assert_eq!(deposit2.prevout_output_index, outpoint.vout);
    assert!(deposit2.will_sign);
    assert!(deposit2.is_valid_tx);

    // Let's make sure the sighashes still match
    let sbtc_requests = SbtcRequests {
        deposits: setup
            .deposits
            .iter()
            .map(|(_, req, _)| req.clone())
            .collect(),
        withdrawals: Vec::new(),
        signer_state: btc_ctx.signer_state,
        accept_threshold: 2,
        num_signers: 3,
    };
    let txs = sbtc_requests.construct_transactions().unwrap();
    assert_eq!(txs.len(), 1);

    let tx = &txs[0];
    let sighashes = tx.construct_digests().unwrap();
    assert_eq!(sighashes.signers, signer.sighash);

    assert_eq!(sighashes.deposits.len(), 2);
    assert_eq!(sighashes.deposits[0].1, deposit1.sighash);
    assert_eq!(sighashes.deposits[1].1, deposit2.sighash);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn sighashes_match_from_sbtc_requests_object() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let signers = TestSignerSet::new(&mut rng);
    let amounts = [
        DepositAmounts {
            amount: 700_000,
            max_fee: 500_000,
        },
        DepositAmounts {
            amount: 1_000_000,
            max_fee: 500_000,
        },
    ];

    let mut setup = TestSweepSetup2::new_setup(signers, &faucet, &amounts);
    setup.deposits.sort_by_key(|(x, _, _)| x.outpoint);
    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_dkg_shares(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let chain_tip_block = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();

    let aggregate_key = setup.signers.signer.keypair.public_key().into();

    let test_state = TestSignerState::with_defaults(chain_tip, aggregate_key);

    let btc_ctx = BitcoinTxContext {
        chain_tip: chain_tip_block.block_hash,
        chain_tip_height: chain_tip_block.block_height,
        request_packages: vec![TxRequestIds {
            deposits: setup.deposit_outpoints(),
            withdrawals: Vec::new(),
        }],
        signer_public_key: setup.signers.keys[0],
        aggregate_key,
        signer_state: test_state.get_btc_state(&ctx).await.unwrap(),
    };

    let validation_data = btc_ctx.construct_package_sighashes(&ctx).await.unwrap();
    // There are a few invariants that we uphold for our validation data.
    // These are things like "the transaction ID per package must be the
    // same", we check for them here.
    validation_data.assert_invariants();
    // We only had a package with one set of requests that were being
    // handled.
    assert_eq!(validation_data.len(), 1);

    // We didn't give any withdrawals so the outputs vector should be
    // empty (it only has signer outputs).
    let set = &validation_data[0];
    assert!(set.to_withdrawal_rows().is_empty());

    // The signer won't sign any of the sighashes, even though all deposits
    // have passed validation. The withdrawal will fail validation,
    // invalidating the transaction.
    let input_rows = set.to_input_rows();
    let signer = input_rows.first().unwrap();
    assert_eq!(input_rows.len(), 3);
    assert_eq!(signer.prevout_type, TxPrevoutType::SignersInput);
    assert_eq!(signer.validation_result, InputValidationResult::Ok);
    assert_eq!(signer.prevout_txid.deref(), &setup.donation.txid);
    assert_eq!(signer.prevout_output_index, setup.donation.vout);
    assert!(signer.will_sign);
    assert!(signer.is_valid_tx);

    let [deposit1, deposit2] = input_rows.last_chunk().unwrap();
    let outpoint = setup.deposits[0].0.outpoint;
    assert_eq!(deposit1.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(deposit1.validation_result, InputValidationResult::Ok);
    assert_eq!(deposit1.prevout_txid.deref(), &outpoint.txid);
    assert_eq!(deposit1.prevout_output_index, outpoint.vout);
    assert!(deposit1.will_sign);
    assert!(deposit1.is_valid_tx);

    let outpoint = setup.deposits[1].0.outpoint;
    assert_eq!(deposit2.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(deposit2.validation_result, InputValidationResult::Ok);
    assert_eq!(deposit2.prevout_txid.deref(), &outpoint.txid);
    assert_eq!(deposit2.prevout_output_index, outpoint.vout);
    assert!(deposit2.will_sign);
    assert!(deposit2.is_valid_tx);

    let sbtc_requests = SbtcRequests {
        deposits: setup
            .deposits
            .iter()
            .map(|(_, req, _)| req.clone())
            .collect(),
        withdrawals: Vec::new(),
        signer_state: btc_ctx.signer_state,
        accept_threshold: 2,
        num_signers: 3,
    };
    let txs = sbtc_requests.construct_transactions().unwrap();
    assert_eq!(txs.len(), 1);

    let tx = &txs[0];
    let sighashes = tx.construct_digests().unwrap();
    assert_eq!(sighashes.signers, signer.sighash);

    assert_eq!(sighashes.deposits.len(), 2);
    assert_eq!(sighashes.deposits[0].1, deposit1.sighash);
    assert_eq!(sighashes.deposits[1].1, deposit2.sighash);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn outcome_is_independent_of_input_order() {
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = OsRng;
    let (rpc, faucet) = regtest::initialize_blockchain();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let signers = TestSignerSet::new(&mut rng);
    let amounts = [
        DepositAmounts {
            amount: 1_500_000,
            max_fee: 500_000,
        },
        DepositAmounts {
            amount: 700_000,
            max_fee: 500_000,
        },
        DepositAmounts {
            amount: 1_000_000,
            max_fee: 500_000,
        },
        DepositAmounts {
            amount: 2_000_000,
            max_fee: 500_000,
        },
    ];

    let mut setup = TestSweepSetup2::new_setup(signers, &faucet, &amounts);
    setup.deposits.sort_by_key(|(x, _, _)| x.outpoint);
    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;

    setup.store_dkg_shares(&db).await;
    setup.store_donation(&db).await;
    setup.store_deposit_txs(&db).await;
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    let chain_tip = db.get_bitcoin_canonical_chain_tip().await.unwrap().unwrap();
    let chain_tip_block = db.get_bitcoin_block(&chain_tip).await.unwrap().unwrap();

    let aggregate_key = setup.signers.signer.keypair.public_key().into();

    let test_state = TestSignerState::with_defaults(chain_tip, aggregate_key);
    let mut btc_ctx = BitcoinTxContext {
        chain_tip: chain_tip_block.block_hash,
        chain_tip_height: chain_tip_block.block_height,
        request_packages: vec![TxRequestIds {
            deposits: setup.deposit_outpoints(),
            withdrawals: Vec::new(),
        }],
        signer_public_key: setup.signers.keys[0],
        aggregate_key,
        signer_state: test_state.get_btc_state(&ctx).await.unwrap(),
    };

    // The outcome is independent of the ordering of the input IDs.
    let validation_data1 = btc_ctx.construct_package_sighashes(&ctx).await.unwrap();
    let set1 = &validation_data1[0];
    let input_rows1 = set1.to_input_rows();

    btc_ctx.request_packages[0].deposits.shuffle(&mut rng);
    let validation_data2 = btc_ctx.construct_package_sighashes(&ctx).await.unwrap();
    let set2 = &validation_data2[0];
    let input_rows2 = set2.to_input_rows();

    assert_eq!(input_rows1, input_rows2);
}