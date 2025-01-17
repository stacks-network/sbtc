use bitcoin::OutPoint;
use blockstack_lib::types::chainstate::StacksAddress;
use rand::rngs::OsRng;
use sbtc::testing::regtest;
use signer::error::Error;
use signer::stacks::contracts::AcceptWithdrawalV1;
use signer::stacks::contracts::AsContractCall as _;
use signer::stacks::contracts::ReqContext;
use signer::stacks::contracts::WithdrawalErrorMsg;
use signer::storage::model::BitcoinBlockRef;
use signer::storage::model::BitcoinTxId;
use signer::testing;

use fake::Fake;
use rand::SeedableRng;
use signer::testing::context::*;

use crate::setup::backfill_bitcoin_blocks;
use crate::setup::TestSweepSetup;

/// Create a "proper" [`AcceptWithdrawalV1`] object and context with the
/// given information. If the information here is correct then the returned
/// [`AcceptWithdrawalV1`] object will pass validation with the given
/// context.
fn make_withdrawal_accept(data: &TestSweepSetup) -> (AcceptWithdrawalV1, ReqContext) {
    // Okay now we get ready to create the transaction using the
    // `AcceptWithdrawalV1` type.
    let fee = data.sweep_tx_info.assess_output_fee(2).unwrap().to_sat();
    let complete_withdrawal_tx = AcceptWithdrawalV1 {
        // This OutPoint points to the withdrawal UTXO. We look up our
        // record of the actual withdrawal to make sure that the amount
        // matches the one in the withdrawal request.
        outpoint: OutPoint {
            txid: data.sweep_tx_info.txid,
            // The sweep transaction has exactly 3 outputs, where the first
            // two are about the signers and the third one is for the
            // withdrawal request.
            vout: 2,
        },
        // This points to the withdrawal request transaction.
        request_id: data.withdrawal_request.request_id,
        // This is the assessed transaction fee for fulfilling the withdrawal
        // request.
        tx_fee: fee,
        //
        signer_bitmap: data.withdrawal_request.signer_bitmap,
        // The deployer must match what is in the signers' context.
        deployer: StacksAddress::burn_address(false),
        // The block hash of the block that includes the above sweep
        // transaction. It must be on the canonical bitcoin blockchain.
        sweep_block_hash: data.sweep_block_hash.into(),
        // This must be the height of the above block.
        sweep_block_height: data.sweep_block_height,
    };

    // This is what the current signer thinks is the state of things.
    let req_ctx = ReqContext {
        chain_tip: BitcoinBlockRef {
            block_hash: data.sweep_block_hash.into(),
            block_height: data.sweep_block_height,
        },
        // This value means that the signer will go back 20 blocks when
        // looking for pending and accepted withdrawal requests.
        context_window: 20,
        // The value here doesn't matter.
        origin: fake::Faker.fake_with_rng(&mut OsRng),
        // When checking whether the transaction is from the signer, we
        // check that the first "prevout" has a `scriptPubKey` that the
        // signers control.
        aggregate_key: data.aggregated_signer.keypair.public_key().into(),
        // This value affects whether a withdrawal request is considered
        // "accepted". During validation, a signer won't sign a transaction
        // if it is not considered accepted but the collection of signers.
        signatures_required: 2,
        // This is who the current signer thinks deployed the sBTC
        // contracts.
        deployer: StacksAddress::burn_address(false),
    };

    (complete_withdrawal_tx, req_ctx)
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns okay when everything matches the way that it is supposed to.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_happy_path() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request. This is just setup
    // and should be essentially the same between tests.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);

    // This should not return an Err.
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    accept_withdrawal_tx.validate(&ctx, &req_ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a DeployerMismatch message
/// when the deployer doesn't match but everything else is okay.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_deployer_mismatch() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut accept_withdrawal_tx, mut req_ctx) = make_withdrawal_accept(&setup);
    // Different: Okay, let's make sure the deployers do not match.
    accept_withdrawal_tx.deployer = StacksAddress::p2pkh(false, &setup.signer_keys[0].into());
    req_ctx.deployer = StacksAddress::p2pkh(false, &setup.signer_keys[1].into());

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validate_future = accept_withdrawal_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::DeployerMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a RequestMissing message
/// when the signer does not have a record of the withdrawal request
/// doesn't match but everything else is okay.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_missing_withdrawal_request() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);
    // Different: Let's use a request_id that does not exist in our
    // database. In these tests, the withdrawal id starts at 0 and
    // increments by 1 for each withdrawal request generated.
    accept_withdrawal_tx.request_id = u64::MAX;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::RequestMissing)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a RecipientMismatch message
/// when the recipient in the complete-withdrawal transaction does not
/// match the recipient in our records.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_recipient_mismatch() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let mut setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Different: the sweep transaction has already taken place, but our
    // records of the recipient does not match the actual recipient on
    // chain.
    setup.withdrawal_request.script_pubkey = fake::Faker.fake_with_rng(&mut rng);
    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::RecipientMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a InvalidAmount message
/// when the amount of sBTC to mint exceeds the amount in the signer's
/// withdrawal request record.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_invalid_amount() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let mut setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Different: the request amount and the amount on chain do not match.
    setup.withdrawal_request.amount += 1;
    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::InvalidAmount)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a InvalidFee message when
/// the amount of sBTC to mint is less than the `amount - max-fee` from in
/// the signer's withdrawal request record.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_invalid_fee() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let mut setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Different: The fee cannot exceed the max fee. As usual, we still
    // need to store the withdrawal request and how the signers voted.
    let assessed_fee = setup.sweep_tx_info.assess_output_fee(2).unwrap().to_sat();
    setup.withdrawal_request.max_fee = assessed_fee - 1;
    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validate_future = accept_withdrawal_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::FeeTooHigh)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a SweepTransactionMissing
/// message when the signer does not have a record of the sweep
/// transaction.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_sweep_tx_missing() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);

    // Different: there is supposed to be sweep transaction in
    // bitcoin-core, but we make sure that such a transaction does not
    // exist.
    let fake_txid: BitcoinTxId = fake::Faker.fake_with_rng(&mut rng);
    accept_withdrawal_tx.outpoint.txid = fake_txid.into();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::SweepTransactionMissing)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a SweepTransactionReorged
/// message when the sweep transaction is in our records but is not on what
/// the signer thinks is the canonical bitcoin blockchain.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_sweep_reorged() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, mut req_ctx) = make_withdrawal_accept(&setup);

    // Different: the transaction that sweeps in the withdrawal has been
    // confirmed, but let's suppose that it gets confirmed on a bitcoin
    // blockchain that is not the canonical one. To test that we set a
    // chain tip to be some other blockchain. The important part is that
    // our sweep transaction is not on the canonical one.
    req_ctx.chain_tip = BitcoinBlockRef {
        block_hash: fake::Faker.fake_with_rng(&mut rng),
        // This value kind of matters, but that's more of an implementation
        // detail. All that should matter is that the block_hash does not
        // identify the bitcoin blockchain that includes the sweep
        // transaction.
        block_height: 30000,
    };

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::SweepTransactionReorged)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a UtxoMissingFromSweep
/// message when the sweep transaction is in our records, is on what the
/// signer thinks is the canonical bitcoin blockchain, but it does not have
/// an input that that matches the withdrawal request outpoint.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_withdrawal_not_in_sweep() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);
    // Different: the outpoint here is supposed to be the outpoint of the
    // UTXO in the sweep transactions that spends to the desired recipient.
    // Here we give an outpoint that doesn't exist in the transaction,
    // triggering the desired error. We use 3 for the vout, but any number
    // greater than 2 will do.
    accept_withdrawal_tx.outpoint = OutPoint::new(setup.sweep_tx_info.txid, 3);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::UtxoMissingFromSweep)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a BitmapMismatch message
/// when bitmap in the transaction does not match what our records would
/// create for the bitmap.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_bitmap_mismatch() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);
    // Different: We're going to get the bitmap that is a little different
    // from what is expected.
    let first_vote = *accept_withdrawal_tx.signer_bitmap.get(0).unwrap();
    accept_withdrawal_tx.signer_bitmap.set(0, !first_vote);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::BitmapMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a IncorrectFee message when
/// the sweep transaction is in our records, is on what the signer thinks
/// is the canonical bitcoin blockchain, but the supplied transaction
/// object does not have what we think should be the correct fee.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_withdrawal_incorrect_fee() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (mut accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);
    // Different: the fee here is less than we would think that it
    // should be.
    accept_withdrawal_tx.tx_fee -= 1;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::IncorrectFee)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a InvalidSweep message when
/// the sweep transaction does not have a prevout with a scriptPubKey that
/// the signers control.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_withdrawal_invalid_sweep() {
    // Normal: this generates the blockchain as well as a transaction
    // sweeping out the funds for a withdrawal request.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signer follows the bitcoin blockchain and event observer
    // should be getting new block events from bitcoin-core. We haven't
    // hooked up our block observer, so we need to manually update the
    // database with new bitcoin block headers.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Different: we normally add a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control. Here we
    // exclude it, so it looks like the first UTXO in the transaction is not
    // controlled by the signers.

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the withdrawal request object
    // corresponds to how the signers voted.
    setup.store_withdrawal_request(&db).await;
    setup.store_withdrawal_decisions(&db).await;

    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, req_ctx) = make_withdrawal_accept(&setup);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = accept_withdrawal_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::InvalidSweep)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}
