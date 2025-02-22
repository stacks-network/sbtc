use bitcoin::hashes::Hash;
use blockstack_lib::types::chainstate::StacksAddress;
use rand::rngs::OsRng;
use sbtc::testing::regtest;
use sbtc::testing::regtest::Faucet;
use signer::error::Error;
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
use signer::testing::context::*;
use signer::WITHDRAWAL_BLOCKS_EXPIRY;

use crate::setup::fetch_canonical_bitcoin_blockchain;
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
        stacks_chain_tip: data.withdrawals[0].request.block_hash,
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
    let withdraw_amounts = SweepAmounts {
        amount,
        max_fee: amount / 2,
        is_deposit: false,
    };

    TestSweepSetup2::new_setup(signers.clone(), &faucet, &[withdraw_amounts])
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

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observed since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // Normal: The signers normally have a UTXO, so we add one here too. It
    // is necessary when checking for whether the withdrawal being
    // fulfilled by a sweep transaction that is in the mempool.
    setup.store_donation(&db).await;

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

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Different: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observed since the smart
    // contract that created the withdrawal request has bene observed. We
    // are generating one too few blocks.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // Normal: The signers normally have a UTXO, so we add one here too. It
    // is necessary when checking for whether the withdrawal being
    // fulfilled by a sweep transaction that is in the mempool.
    setup.store_donation(&db).await;

    // Generate the transaction and corresponding request context.
    let (reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;

    let validate_future = reject_withdrawal_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::WithdrawalRejectValidation(ref err) => {
            assert_eq!(err.error, WithdrawalRejectErrorMsg::RequestNotFinal)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    // Generate more blocks and backfill the DB
    faucet.generate_blocks(1);
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

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

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Normal: the request has not been marked as completed in the smart
    // contract.
    set_withdrawal_incomplete(&mut ctx).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observed since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // Normal: The signers normally have a UTXO, so we add one here too. It
    // is necessary when checking for whether the withdrawal being
    // fulfilled by a sweep transaction that is in the mempool.
    setup.store_donation(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut reject_withdrawal_tx, mut req_ctx) = make_withdrawal_reject(&setup, &db).await;
    // Different: Okay, let's make sure the deployers do not match.
    reject_withdrawal_tx.deployer = StacksAddress::p2pkh(false, &setup.signers.keys[0].into());
    req_ctx.deployer = StacksAddress::p2pkh(false, &setup.signers.keys[1].into());

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

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Normal: the request has not been marked as completed in the smart
    // contract.
    set_withdrawal_incomplete(&mut ctx).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observed since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // Normal: The signers normally have a UTXO, so we add one here too. It
    // is necessary when checking for whether the withdrawal being
    // fulfilled by a sweep transaction that is in the mempool.
    setup.store_donation(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;
    // Different: Let's use a request_id that does not exist in our
    // database. In these tests, the withdrawal id starts at 0 and
    // increments by 1 for each withdrawal request generated.
    reject_withdrawal_tx.id.request_id = i64::MAX as u64;

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

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observed since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // Normal: The signers normally have a UTXO, so we add one here too. It
    // is necessary when checking for whether the withdrawal being
    // fulfilled by a sweep transaction that is in the mempool.
    setup.store_donation(&db).await;

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

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observed since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // Normal: The signers normally have a UTXO, so we add one here too. It
    // is necessary when checking for whether the withdrawal being
    // fulfilled by a sweep transaction that is in the mempool.
    setup.store_donation(&db).await;

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

/// For this test we check that the `RejectWithdrawalV1::validate` function
/// returns a withdrawal validation error with a RequestBeingFulfilled
/// message when the database indicates that it is possible that the
/// withdrawal request is being fulfilled by a sweep transaction in the
/// mempool.
#[tokio::test]
async fn reject_withdrawal_validation_request_being_fulfilled() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request. This is just setup
    // and should be essentially the same between tests.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let test_signer_set = TestSignerSet::new(&mut rng);
    let mut setup = new_sweep_setup(&test_signer_set, &faucet);

    let mut ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Normal: the request has not been marked as completed in the smart
    // contract.
    set_withdrawal_incomplete(&mut ctx).await;

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    let chain_tip = fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // Different: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control. We need
    // this so that the donation gets picked up correctly below.
    setup.store_dkg_shares(&db).await;

    // Normal: The signers normally have a UTXO, so we add one here too. It
    // is necessary when checking for whether the withdrawal being
    // fulfilled by a sweep transaction that is in the mempool.
    setup.store_donation(&db).await;

    // Different: We submit a sweep transaction into the mempool so that
    // the TestSweepSetup2 struct has the sweep_tx_info set. We also need
    // to submit the transaction in order for
    // `TestSweepSetup2::store_bitcoin_withdrawals_outputs` to work as
    // expected.
    setup.submit_sweep_tx(rpc, faucet);

    let sweep = setup.sweep_tx_info.as_ref().unwrap();

    // Different: We're adding a row that let the signer know that someone
    // may have tried to fulfill the withdrawal request. If that
    // transaction is spending the current signer UTXO, then it could
    // possibly be in the mempool. Since the signers' UTXO is a donation,
    // we're saying that the coordinator may have tried to fulfill the
    // withdrawal.
    setup.store_bitcoin_withdrawals_outputs(&db).await;

    let signer_tx_sighash = BitcoinTxSigHash {
        txid: sweep.tx_info.txid.into(),
        prevout_type: model::TxPrevoutType::SignersInput,
        prevout_txid: setup.donation.txid.into(),
        prevout_output_index: setup.donation.vout,
        validation_result: signer::bitcoin::validation::InputValidationResult::Ok,
        aggregate_key: setup.signers.aggregate_key().into(),
        is_valid_tx: false,
        will_sign: false,
        chain_tip,
        sighash: bitcoin::TapSighash::from_byte_array([23; 32]).into(),
    };
    db.write_bitcoin_txs_sighashes(&[signer_tx_sighash])
        .await
        .unwrap();

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_requests(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Normal: We do not reject a withdrawal requests until more than
    // WITHDRAWAL_BLOCKS_EXPIRY blocks have been observed since the smart
    // contract that created the withdrawal request has bene observed.
    faucet.generate_blocks(WITHDRAWAL_BLOCKS_EXPIRY + 1);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    fetch_canonical_bitcoin_blockchain(&db, rpc).await;

    // Generate the transaction and corresponding request context.
    let (reject_withdrawal_tx, req_ctx) = make_withdrawal_reject(&setup, &db).await;

    let validation_result = reject_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalRejectValidation(ref err) => {
            assert_eq!(err.error, WithdrawalRejectErrorMsg::RequestBeingFulfilled)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}
