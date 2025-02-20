use std::collections::BTreeSet;

use bitcoin::hashes::Hash;
use bitcoincore_rpc::RpcApi;
use blockstack_lib::types::chainstate::StacksAddress;
use rand::rngs::OsRng;
use sbtc::testing::regtest;
use sbtc::testing::regtest::Faucet;
use signer::error::Error;
use signer::keys::PublicKey;
use signer::stacks::contracts::AsContractCall as _;
use signer::stacks::contracts::RejectWithdrawalV1;
use signer::stacks::contracts::ReqContext;
use signer::stacks::contracts::WithdrawalRejectErrorMsg;
use signer::storage::model;
use signer::storage::model::BitcoinTxSigHash;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead;
use signer::storage::DbWrite;
use signer::testing;

use fake::Fake;
use rand::SeedableRng;
use signer::context::Context;
use signer::testing::context::*;
use signer::WITHDRAWAL_BLOCKS_EXPIRY;

use crate::setup::backfill_bitcoin_blockchain;
use crate::setup::set_withdrawal_completed;
use crate::setup::set_withdrawal_incomplete;
use crate::setup::SweepAmounts;
use crate::setup::TestSignerSet;
use crate::setup::TestSweepSetup2;

/// Create a "proper" [`RejectWithdrawalV1`] object and context with the
/// given information. If the information here is correct then the returned
/// [`RejectWithdrawalV1`] object will pass validation with the given
/// context.
async fn make_withdrawal_reject(
    data: &TestSweepSetup2,
    db: &PgStore,
) -> (RejectWithdrawalV1, ReqContext) {
    // Okay now we get ready to create the transaction using the
    // `RejectWithdrawalV1` type.
    let complete_withdrawal_tx = RejectWithdrawalV1 {
        // This points to the withdrawal request transaction.
        id: data.withdrawals[0].request.qualified_id(),
        signer_bitmap: data.withdrawals[0].request.signer_bitmap,
        // The deployer must match what is in the signers' context.
        deployer: StacksAddress::burn_address(false),
    };

    let chain_tip = db
        .get_bitcoin_canonical_chain_tip_ref()
        .await
        .unwrap()
        .unwrap();

    // This is what the current signer thinks is the state of things.
    let req_ctx = ReqContext {
        chain_tip,
        // This value means that the signer will go back 20 blocks when
        // looking for pending and rejected withdrawal requests.
        context_window: 20,
        // The value here doesn't matter.
        origin: fake::Faker.fake_with_rng(&mut OsRng),
        // When checking whether the transaction is from the signer, we
        // check that the first "prevout" has a `scriptPubKey` that the
        // signers control.
        aggregate_key: data.signers.aggregate_key(),
        // This value affects whether a withdrawal request is considered
        // "rejected". During validation, a signer won't sign a transaction
        // if it is not considered rejected but the collection of signers.
        signatures_required: 4,
        // This is who the current signer thinks deployed the sBTC
        // contracts.
        deployer: StacksAddress::burn_address(false),
    };

    (complete_withdrawal_tx, req_ctx)
}

fn new_sweep_setup(signers: &TestSignerSet, faucet: &Faucet) -> TestSweepSetup2 {
    let amount = 1_000_000;
    let deposit_amounts = SweepAmounts {
        amount,
        max_fee: amount / 2,
        is_deposit: true,
    };
    let withdraw_amounts = SweepAmounts {
        amount,
        max_fee: amount / 2,
        is_deposit: false,
    };

    TestSweepSetup2::new_setup(
        signers.clone(),
        &faucet,
        &[deposit_amounts, withdraw_amounts],
    )
}

/// For this test we check that the `RejectWithdrawalV1::validate` function
/// returns okay when everything matches the way that it is supposed to.
#[tokio::test]
async fn reject_withdrawal_validation_happy_path() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request. This is just setup
    // and should be essentially the same between tests.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let test_signer_set = TestSignerSet::new(&mut rng);
    let setup = new_sweep_setup(&test_signer_set, &faucet);

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Normal: the request has not been marked as completed in the smart
    // contract.
    set_withdrawal_incomplete(&mut ctx).await;

    let public_keys = test_signer_set
        .keys
        .iter()
        .cloned()
        .collect::<BTreeSet<PublicKey>>();
    ctx.state().update_current_signer_set(public_keys);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observered since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Generate the transaction and corresponding request context.
    let (reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;

    reject_withdrawal_tx.validate(&ctx, &req_ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `RejectWithdrawalV1::validate` function
/// returns fails validation when the withdrawal request is NOT expired
#[tokio::test]
async fn reject_withdrawal_validation_not_final() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request. This is just setup
    // and should be essentially the same between tests.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let test_signer_set = TestSignerSet::new(&mut rng);
    let setup = new_sweep_setup(&test_signer_set, &faucet);

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Normal: the request has not been marked as completed in the smart
    // contract.
    set_withdrawal_incomplete(&mut ctx).await;

    let public_keys = test_signer_set
        .keys
        .iter()
        .cloned()
        .collect::<BTreeSet<PublicKey>>();
    ctx.state().update_current_signer_set(public_keys);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Different: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observered since the smart
    // contract that created the withdrawal request has bene observed. We
    // are generating one too few blocks.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY);
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Generate the transaction and corresponding request context.
    let (reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;

    let validate_future = reject_withdrawal_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::WithdrawalRejectValidation(ref err) => {
            assert_eq!(err.error, WithdrawalRejectErrorMsg::RequestNotFinal)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    // Generate more block then backfill the DB
    faucet.generate_blocks(1);
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Generate the transaction and corresponding request context.
    let (reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;

    reject_withdrawal_tx.validate(&ctx, &req_ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `RejectWithdrawalV1::validate` function
/// returns a withdrawal validation error with a DeployerMismatch message
/// when the deployer doesn't match but everything else is okay.
#[tokio::test]
async fn reject_withdrawal_validation_deployer_mismatch() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let test_signer_set = TestSignerSet::new(&mut rng);
    let setup = new_sweep_setup(&test_signer_set, &faucet);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut reject_withdrawal_tx, mut req_ctx) = make_withdrawal_reject(&setup, &db).await;
    // Different: Okay, let's make sure the deployers do not match.
    reject_withdrawal_tx.deployer = StacksAddress::p2pkh(false, &setup.signers.keys[0].into());
    req_ctx.deployer = StacksAddress::p2pkh(false, &setup.signers.keys[1].into());

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Normal: the request has not been marked as completed in the smart
    // contract.
    set_withdrawal_incomplete(&mut ctx).await;

    let validate_future = reject_withdrawal_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::WithdrawalRejectValidation(ref err) => {
            assert_eq!(err.error, WithdrawalRejectErrorMsg::DeployerMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `RejectWithdrawalV1::validate` function
/// returns a withdrawal validation error with a RequestMissing message
/// when the signer does not have a record of the withdrawal request
/// doesn't match but everything else is okay.
#[tokio::test]
async fn reject_withdrawal_validation_missing_withdrawal_request() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    
    let test_signer_set = TestSignerSet::new(&mut rng);
    let setup = new_sweep_setup(&test_signer_set, &faucet);
    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observered since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Generate the transaction and corresponding request context.
    let (mut reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;
    // Different: Let's use a request_id that does not exist in our
    // database. In these tests, the withdrawal id starts at 0 and
    // increments by 1 for each withdrawal request generated.
    reject_withdrawal_tx.id.request_id = i64::MAX as u64;

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Normal: the request has not been marked as completed in the smart
    // contract.
    set_withdrawal_incomplete(&mut ctx).await;

    let validation_result = reject_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalRejectValidation(ref err) => {
            assert_eq!(err.error, WithdrawalRejectErrorMsg::RequestMissing)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `RejectWithdrawalV1::validate` function
/// returns a withdrawal validation error with a BitmapMismatch message
/// when bitmap in the transaction does not match what our records would
/// create for the bitmap.
#[tokio::test]
async fn reject_withdrawal_validation_bitmap_mismatch() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let test_signer_set = TestSignerSet::new(&mut rng);
    let setup = new_sweep_setup(&test_signer_set, &faucet);

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Normal: the request has not been marked as completed in the smart
    // contract.
    set_withdrawal_incomplete(&mut ctx).await;

    let public_keys = test_signer_set
        .keys
        .iter()
        .cloned()
        .collect::<BTreeSet<PublicKey>>();
    ctx.state().update_current_signer_set(public_keys);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observered since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Generate the transaction and corresponding request context.
    let (mut reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;

    // Different: We're going to get the bitmap that is a little different
    // from what is expected.
    let first_vote = *reject_withdrawal_tx.signer_bitmap.get(0).unwrap();
    reject_withdrawal_tx.signer_bitmap.set(0, !first_vote);

    let validation_result = reject_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalRejectValidation(ref err) => {
            assert_eq!(err.error, WithdrawalRejectErrorMsg::BitmapMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `RejectWithdrawalV1::validate` function
/// returns a withdrawal validation error with a RequestCompleted message
/// when the stacks node returns that the withdrawal request has been
/// completed.
#[tokio::test]
async fn reject_withdrawal_validation_request_completed() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request. This is just setup
    // and should be essentially the same between tests.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let test_signer_set = TestSignerSet::new(&mut rng);
    let setup = new_sweep_setup(&test_signer_set, &faucet);

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Different: the request has been marked as completed in the smart
    // contract.
    set_withdrawal_completed(&mut ctx).await;

    let public_keys = test_signer_set
        .keys
        .iter()
        .cloned()
        .collect::<BTreeSet<PublicKey>>();
    ctx.state().update_current_signer_set(public_keys);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observered since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);
    backfill_bitcoin_blockchain(&db, rpc).await;

    // Generate the transaction and corresponding request context.
    let (reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;

    let validation_result = reject_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalRejectValidation(ref err) => {
            assert_eq!(err.error, WithdrawalRejectErrorMsg::RequestCompleted)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}


    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate more blocks then backfill the DB
    let mut hashes = faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY);
    let last = hashes.pop().unwrap();
    backfill_bitcoin_blocks(&db, rpc, &last).await;

    // Generate the transaction and corresponding request context.
    let (reject_withdrawal_tx, req_ctx) = make_withdrawal_reject2(&setup, &db).await;

    let validation_result = reject_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalRejectValidation(ref err) => {
            assert_eq!(err.error, WithdrawalRejectErrorMsg::RequestCompleted)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}
