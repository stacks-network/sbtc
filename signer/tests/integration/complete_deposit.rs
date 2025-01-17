use blockstack_lib::types::chainstate::StacksAddress;
use rand::rngs::OsRng;
use rand::SeedableRng;

use sbtc::testing::regtest;
use signer::error::Error;
use signer::stacks::contracts::AsContractCall as _;
use signer::stacks::contracts::CompleteDepositV1;
use signer::stacks::contracts::DepositErrorMsg;
use signer::stacks::contracts::ReqContext;
use signer::storage::model::BitcoinBlockRef;
use signer::storage::model::BitcoinTxId;
use signer::storage::model::StacksPrincipal;
use signer::testing;
use signer::testing::context::*;

use fake::Fake;

use crate::setup::backfill_bitcoin_blocks;
use crate::setup::DepositAmounts;
use crate::setup::TestSignerSet;
use crate::setup::TestSweepSetup;
use crate::setup::TestSweepSetup2;

/// Create a "proper" [`CompleteDepositV1`] object and context with the
/// given information. If the information here is correct then the returned
/// [`CompleteDepositV1`] object will pass validation with the given
/// context.
pub fn make_complete_deposit(data: &TestSweepSetup) -> (CompleteDepositV1, ReqContext) {
    // The fee assessed for a deposit is subtracted from the minted amount.
    let fee = data
        .sweep_tx_info
        .assess_input_fee(&data.deposit_request.outpoint)
        .unwrap()
        .to_sat();
    let complete_deposit_tx = CompleteDepositV1 {
        // This OutPoint points to the deposit UTXO.
        outpoint: data.deposit_request.outpoint,
        // This amount must not exceed the amount in the deposit request.
        amount: data.deposit_request.amount - fee,
        // The recipient must match what was indicated in the deposit
        // request.
        recipient: data.deposit_recipient.clone(),
        // The deployer must match what is in the signers' context.
        deployer: StacksAddress::burn_address(false),
        // The sweep transaction ID must point to a transaction on
        // the canonical bitcoin blockchain.
        sweep_txid: data.sweep_tx_info.txid.into(),
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
        // This value means that the signer will go back 10 blocks when
        // looking for pending and accepted deposit requests.
        context_window: 10,
        // The value here doesn't matter.
        origin: fake::Faker.fake_with_rng(&mut OsRng),
        // When checking whether the transaction is from the signer, we
        // check that the first "prevout" has a `scriptPubKey` that the
        // signers control.
        aggregate_key: data.aggregated_signer.keypair.public_key().into(),
        // This value affects how many deposit transactions are consider
        // accepted. During validation, a signer won't sign a transaction
        // if it is not considered accepted but the collection of signers.
        signatures_required: 2,
        // This is who the current signer thinks deployed the sBTC
        // contracts.
        deployer: StacksAddress::burn_address(false),
    };

    (complete_deposit_tx, req_ctx)
}

/// Create a "proper" [`CompleteDepositV1`] object and context with the
/// given information. If the information here is correct then the returned
/// [`CompleteDepositV1`] object will pass validation with the given
/// context.
pub fn make_complete_deposit2(data: &TestSweepSetup2) -> (CompleteDepositV1, ReqContext) {
    let deposit = &data.deposits[0];
    let sweep_tx_info = data.sweep_tx_info.clone().unwrap();
    // The fee assessed for a deposit is subtracted from the minted amount.
    let fee = sweep_tx_info
        .tx_info
        .assess_input_fee(&deposit.1.outpoint)
        .unwrap()
        .to_sat();
    let complete_deposit_tx = CompleteDepositV1 {
        // This OutPoint points to the deposit UTXO.
        outpoint: deposit.1.outpoint,
        // This amount must not exceed the amount in the deposit request.
        amount: deposit.1.amount - fee,
        // The recipient must match what was indicated in the deposit
        // request.
        recipient: deposit.0.recipient.clone(),
        // The deployer must match what is in the signers' context.
        deployer: StacksAddress::burn_address(false),
        // The sweep transaction ID must point to a transaction on
        // the canonical bitcoin blockchain.
        sweep_txid: sweep_tx_info.tx_info.txid.into(),
        // The block hash of the block that includes the above sweep
        // transaction. It must be on the canonical bitcoin blockchain.
        sweep_block_hash: sweep_tx_info.block_hash,
        // This must be the height of the above block.
        sweep_block_height: sweep_tx_info.block_height,
    };

    // This is what the current signer thinks is the state of things.
    let req_ctx = ReqContext {
        chain_tip: BitcoinBlockRef {
            block_hash: sweep_tx_info.block_hash,
            block_height: sweep_tx_info.block_height,
        },
        // This value means that the signer will go back 10 blocks when
        // looking for pending and accepted deposit requests.
        context_window: 10,
        // The value here doesn't matter.
        origin: fake::Faker.fake_with_rng(&mut OsRng),
        // When checking whether the transaction is from the signer, we
        // check that the first "prevout" has a `scriptPubKey` that the
        // signers control.
        aggregate_key: data.signers.aggregate_key(),
        // This value affects how many deposit transactions are consider
        // accepted. During validation, a signer won't sign a transaction
        // if it is not considered accepted by enough signers.
        signatures_required: data.signatures_required,
        // This is who the current signer thinks deployed the sBTC
        // contracts.
        deployer: StacksAddress::burn_address(false),
    };

    (complete_deposit_tx, req_ctx)
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_happy_path() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    // This is just setup and should be essentially the same between tests.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit(&setup);

    // Create a context object for reaching out to the database and bitcoin
    // core. This will create a bitcoin core client that connects to the
    // bitcoin-core at the [bitcoin].endpoints[0] endpoint from the default
    // toml config file.
    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    // Check to see if validation passes.
    complete_deposit_tx.validate(&ctx, &req_ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a DeployerMismatch message when
/// the deployer doesn't match but everything else is okay.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_deployer_mismatch() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (mut complete_deposit_tx, mut req_ctx) = make_complete_deposit(&setup);
    // Different: Okay, let's make sure we get the deployers do not match.
    complete_deposit_tx.deployer = StacksAddress::p2pkh(false, &setup.signer_keys[0].into());
    req_ctx.deployer = StacksAddress::p2pkh(false, &setup.signer_keys[1].into());

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validate_future = complete_deposit_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::DeployerMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a DepositRequestMissing message
/// when the signer does not have a record of the deposit request doesn't
/// match but everything else is okay.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_missing_deposit_request() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Different: We do not store the deposit request and the associated
    // decisions in the database.

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit(&setup);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = complete_deposit_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::RequestMissing)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a RecipientMismatch message
/// when the recipient in the complete-deposit transaction does not match
/// the recipient in our records.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_recipient_mismatch() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (mut complete_deposit_tx, req_ctx) = make_complete_deposit(&setup);
    // Different: Okay, let's make sure we the recipients do not match.
    complete_deposit_tx.recipient = fake::Faker
        .fake_with_rng::<StacksPrincipal, _>(&mut rng)
        .into();

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validate_future = complete_deposit_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::RecipientMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a AmountBelowDustLimit message
/// when the sweep transaction does not have a prevout with a scriptPubKey
/// that the signers control.
///
/// Unfortunately, this test is a bit opaque and complex. We try to set
/// things so that the mint amount is less than the dust amount, but for
/// that we need to take into consideration fees. The fee rate for these
/// tests are 10 sats per vbyte, and this test constructs a sweep
/// transaction that is 235 bytes. Adding more deposits, including
/// withdrawals outputs, and changing the fee rate would change the
/// calculation specified in this test, so that's why we use the magic
/// deposit amount here.
///
/// Moreover, our testing apparatus goes through code that filters deposits
/// based off of the DUST amount, so we need custom code to trigger this
/// error.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_fee_too_low() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();

    let signers = TestSignerSet::new(&mut rng);
    // We are trying to trigger the AmountBelowDustLimit error.
    // Specifically, we want to choose a deposit amount that is still
    // positive after fees but below the dust limit. But our test code goes
    // through the production code that refuses to construct transactions
    // where we could hit the dust limit. So we construct a deposit with a
    // certain high amount, and then modify the database to store an amount
    // that would trigger the limit. This is tricky because we reach out to
    // bitcoin core for some things and rely on the database for others.
    // Hopefully this test does not become an issue down the line due to a
    // refactor.
    let amounts = DepositAmounts { amount: 50000, max_fee: 80_000 };
    let mut setup = TestSweepSetup2::new_setup(signers, faucet, &[amounts]);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.deposit_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_txs(&db).await;

    // Normal: we submit the transaction sweeping the funds. It gets
    // confirmed; this generates a new bitcoin block behind the scene.
    setup.submit_sweep_tx(rpc, faucet, false);

    // Normal: When a new bitcoin block is generated, we need to update the
    // signer's database with blockchain data.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash().unwrap()).await;
    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Different: We need to update the amount to be something that
    // validation would reject. To do that we update our database.
    //
    // The fee rate in this test is fixed at 10.0 sats per vbyte and the tx
    // size is 235 bytes, so we lose 2350 sats to fees. The amount here is
    // chosen so that 2350 + 546 is greater than it.
    let deposit_amount = 2895;
    sqlx::query(
        r#"
        UPDATE deposit_requests AS dr
        SET amount = $1
        WHERE dr.txid = $2
          AND dr.output_index = $3;
    "#,
    )
    .bind(deposit_amount as i32)
    .bind(BitcoinTxId::from(setup.deposits[0].0.outpoint.txid))
    .bind(setup.deposits[0].0.outpoint.vout as i32)
    .execute(db.pool())
    .await
    .unwrap();
    setup.deposits[0].1.amount = deposit_amount;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit2(&setup);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = complete_deposit_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::AmountBelowDustLimit)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    // Now a sanity check to see what happens if we are at the limit.
    let deposit_amount = deposit_amount + 1;
    sqlx::query(
        r#"
        UPDATE deposit_requests AS dr
        SET amount = $1
        WHERE dr.txid = $2
          AND dr.output_index = $3;
    "#,
    )
    .bind(deposit_amount as i32)
    .bind(BitcoinTxId::from(setup.deposits[0].0.outpoint.txid))
    .bind(setup.deposits[0].0.outpoint.vout as i32)
    .execute(db.pool())
    .await
    .unwrap();
    setup.deposits[0].1.amount = deposit_amount;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit2(&setup);
    assert!(complete_deposit_tx.validate(&ctx, &req_ctx).await.is_ok());

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a FeeTooHigh message when the
/// amount of sBTC to mint is less than the `amount - max-fee` from in the
/// signer's deposit request record.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_fee_too_high() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let mut setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Different: the actual assessed fee cannot be greater than the
    // max-fee, so here we adjust the max fee to pretend what would happen
    // during validation if assessed transaction fee exceeded that amount.
    let assessed_fee = setup
        .sweep_tx_info
        .assess_input_fee(&setup.deposit_request.outpoint);
    setup.deposit_info.max_fee = assessed_fee.unwrap().to_sat() - 1;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit(&setup);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validate_future = complete_deposit_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::FeeTooHigh)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a SweepTransactionMissing
/// message when the signer does not have a record of the sweep
/// transaction.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_sweep_tx_missing() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (mut complete_deposit_tx, req_ctx) = make_complete_deposit(&setup);

    // Different: there is supposed to be sweep transaction in
    // bitcoin-core, but we make sure that such a transaction does not
    // exist.
    complete_deposit_tx.sweep_txid = fake::Faker.fake_with_rng(&mut rng);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = complete_deposit_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::SweepTransactionMissing)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a SweepTransactionReorged
/// message when the sweep transaction is in our records but is not on what
/// the signer thinks is the canonical bitcoin blockchain.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_sweep_reorged() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (complete_deposit_tx, mut req_ctx) = make_complete_deposit(&setup);

    // Different: the transaction that sweeps in the deposit has been
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

    let validation_result = complete_deposit_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::SweepTransactionReorged)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a MissingFromSweep
/// message when the sweep transaction is in our records, is on what the
/// signer thinks is the canonical bitcoin blockchain, but it does not have
/// an input that that matches the deposit request outpoint.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_deposit_not_in_sweep() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (mut complete_deposit_tx, req_ctx) = make_complete_deposit(&setup);

    // Different: We want to simulate what would happen if the sweep
    // transaction did not include the deposit request UTXO as an input. To
    // do that we set the outpoint of the deposit to be different from any
    // of the prevout outpoints in the sweep transaction.
    complete_deposit_tx.outpoint.vout = 5000;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = complete_deposit_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::MissingFromSweep)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a IncorrectFee message when the
/// sweep transaction is in our records, is on what the signer thinks is
/// the canonical bitcoin blockchain, but the fee assessed differs from
/// what we would expect.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_deposit_incorrect_fee() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Normal: we need to store a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control.
    setup.store_dkg_shares(&db).await;

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (mut complete_deposit_tx, req_ctx) = make_complete_deposit(&setup);
    // Different: the amount here is less than we would think that it
    // should be, implying that the assessed fee is greater than what we
    // would have thought.
    complete_deposit_tx.amount -= 1;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = complete_deposit_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::IncorrectFee)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a InvalidSweep message when the
/// sweep transaction does not have a prevout with a scriptPubKey that the
/// signers control.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_deposit_invalid_sweep() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions and a transaction sweeping in the deposited funds.
    let db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let (rpc, faucet) = regtest::initialize_blockchain();
    let setup = TestSweepSetup::new_setup(&rpc, &faucet, 1_000_000, &mut rng);

    // Normal: the signers' block observer should be getting new block
    // events from bitcoin-core. We haven't hooked up our block observer,
    // so we need to manually update the database with new bitcoin block
    // headers and at least one stacks block.
    backfill_bitcoin_blocks(&db, rpc, &setup.sweep_block_hash).await;
    // Normal: This stores a genesis stacks block anchored to the bitcoin
    // blockchain identified by setup.sweep_block_hash.
    setup.store_stacks_genesis_block(&db).await;

    // Normal: we take the deposit transaction as is from the test setup
    // and store it in the database. This is necessary for when we fetch
    // outstanding unfulfilled deposit requests.
    setup.store_deposit_tx(&db).await;

    // Normal: we take the sweep transaction as is from the test setup and
    // store it in the database.
    setup.store_sweep_tx(&db).await;

    // Different: we normally add a row in the dkg_shares table so that we
    // have a record of the scriptPubKey that the signers control. Here we
    // exclude it, so it looks like the first UTXO in the transaction is not
    // controlled by the signers.

    // Normal: the request and how the signers voted needs to be added to
    // the database. Here the bitmap in the deposit request object
    // corresponds to how the signers voted.
    setup.store_deposit_request(&db).await;
    setup.store_deposit_decisions(&db).await;

    // Normal: create a properly formed complete-deposit transaction object
    // and the corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit(&setup);

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();

    let validation_result = complete_deposit_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::InvalidSweep)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}
