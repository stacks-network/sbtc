use std::collections::HashSet;
use std::ops::Deref;
use std::sync::atomic::Ordering;

use rand::SeedableRng as _;
use sbtc::testing::regtest;
use signer::bitcoin::utxo::{Fees, SignerBtcState};
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
    /// bitcoin blockchain with the greatest height. On ties, we sort by
    /// the block hash descending and take the first one.
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
            let txids: HashSet<_> = input_rows.iter().map(|row| row.txid).collect();
            let is_valid_tx: HashSet<_> = input_rows.iter().map(|row| row.is_valid_tx).collect();
            let chain_tip: HashSet<_> = input_rows.iter().map(|row| row.chain_tip).collect();

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
    let amounts = DepositAmounts {
        amount: 1_000_000,
        max_fee: 500_000,
    };

    let setup = TestSweepSetup2::new_setup(signers, &faucet, &[amounts]);
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

    let valadation_data = btc_ctx.construct_package_sighashes(&ctx).await.unwrap();
    // There a re a few invariants that we uphold for our validation data.
    // These are things like "the transaction ID per package must be the
    // same", we check for them here.
    valadation_data.assert_invariants();
    // We only had a package with one set of requests that were being
    // handled.
    assert_eq!(valadation_data.len(), 1);

    // We didn't give any withdrawals so the outputs vector should be
    // empty (it only has withdrawal outputs).
    let set = &valadation_data[0];
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
        DepositAmounts { amount: 1_000_000, max_fee: 10 },
        DepositAmounts {
            amount: 1_000_000,
            max_fee: 500_000,
        },
    ];

    let setup = TestSweepSetup2::new_setup(signers, &faucet, &amounts);
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

    let valadation_data = btc_ctx.construct_package_sighashes(&ctx).await.unwrap();
    // There a re a few invariants that we uphold for our validation data.
    // These are things like "the transaction ID per package must be the
    // same", we check for them here.
    valadation_data.assert_invariants();
    // We only had a package with one set of requests that were being
    // handled.
    assert_eq!(valadation_data.len(), 1);

    // We didn't give any withdrawals so the outputs vector should be
    // empty (it only has withdrawal outputs).
    let set = &valadation_data[0];
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
    let outpoint = setup.deposits[0].0.outpoint;
    assert_eq!(deposit1.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(
        deposit1.validation_result,
        InputValidationResult::FeeTooHigh
    );
    assert_eq!(deposit1.prevout_txid.deref(), &outpoint.txid);
    assert_eq!(deposit1.prevout_output_index, outpoint.vout);
    assert!(!deposit1.will_sign);
    assert!(!deposit1.is_valid_tx);

    let outpoint = setup.deposits[1].0.outpoint;
    assert_eq!(deposit2.prevout_type, TxPrevoutType::Deposit);
    assert_eq!(deposit2.validation_result, InputValidationResult::Ok);
    assert_eq!(deposit2.prevout_txid.deref(), &outpoint.txid);
    assert_eq!(deposit2.prevout_output_index, outpoint.vout);
    assert!(!deposit2.will_sign);
    assert!(!deposit2.is_valid_tx);
}

#[tokio::test]
async fn one_invalid_withdrawal_invalidates_tx() {}

#[tokio::test]
async fn cannot_sign_deposit_is_ok() {}

#[tokio::test]
async fn sighashes_match_from_sbtc_requests_object() {}
