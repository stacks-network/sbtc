use std::sync::atomic::Ordering;

use bitcoin::hashes::Hash as _;
use bitcoin::OutPoint;
use blockstack_lib::types::chainstate::StacksAddress;

use rand::rngs::OsRng;
use signer::error::Error;
use signer::keys::PublicKey;
use signer::stacks::contracts::AsContractCall as _;
use signer::stacks::contracts::CompleteDepositV1;
use signer::stacks::contracts::DepositErrorMsg;
use signer::stacks::contracts::ReqContext;
use signer::storage::model;
use signer::storage::model::BitcoinBlock;
use signer::storage::model::BitcoinTxRef;
use signer::storage::model::DepositRequest;
use signer::storage::model::StacksPrincipal;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::testing;
use signer::testing::dummy::SweepTxConfig;
use signer::testing::storage::model::TestData;

use fake::Fake;
use rand::SeedableRng;
use signer::testing::TestSignerContext;

use crate::DATABASE_NUM;

/// Create a "proper" [`CompleteDepositV1`] object and context with the
/// given information. If the information here is correct then the returned
/// [`CompleteDepositV1`] object will pass validation with the given
/// context.
fn make_complete_deposit(
    req: &DepositRequest,
    sweep_tx: &model::Transaction,
    chain_tip: &BitcoinBlock,
) -> (CompleteDepositV1, ReqContext) {
    // Okay now we get ready to create the transaction using the
    // `CompleteDepositV1` type.
    let complete_deposit_tx = CompleteDepositV1 {
        // This OutPoint points to the deposit UTXO.
        outpoint: req.outpoint(),
        // This amount must not exceed the amount in the deposit request.
        amount: req.amount,
        // The recipient must match what was indicated in the deposit
        // request.
        recipient: req.recipient.clone().into(),
        // The deployer must match what is in the signers' context.
        deployer: StacksAddress::burn_address(false),
        // The sweep transaction ID must point to a transaction on
        // the canonical bitcoin blockchain.
        sweep_txid: sweep_tx.txid.into(),
        // The block hash of the block that includes the above sweep
        // transaction. It must be on the canonical bitcoin blockchain.
        sweep_block_hash: chain_tip.block_hash,
        // This must be the height of the above block.
        sweep_block_height: chain_tip.block_height,
    };

    // This is what the current signer things of the state of things.
    let req_ctx = ReqContext {
        chain_tip: chain_tip.into(),
        // This value means that the signer will go back 10 blocks when
        // looking for pending and accepted deposit requests.
        context_window: 10,
        // The value here doesn't matter.
        origin: fake::Faker.fake_with_rng(&mut OsRng),
        // This value doesn't matter here.
        aggregate_key: fake::Faker.fake_with_rng(&mut OsRng),
        // This value affects how many deposit transactions are consider
        // accepted.
        signatures_required: 2,
        // This is who the current signer thinks deployed the sBTC
        // contracts.
        deployer: StacksAddress::burn_address(false),
    };

    (complete_deposit_tx, req_ctx)
}

/// Generate a signer set, deposit requests and store them into the
/// database.
async fn deposit_setup<R>(rng: &mut R, db: &PgStore) -> Vec<PublicKey>
where
    R: rand::RngCore + rand::CryptoRng,
{
    // This is just a sql test, where we use the `TestData` struct to help
    // populate the database with test data. We set all the other
    // unnecessary parameters to zero.
    let num_signers = 7;
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 0,
        num_deposit_requests_per_block: 2,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: num_signers,
    };

    // Normal: this generates the blockchain as well as deposit request
    // transactions in each bitcoin block.
    let signer_set = testing::wsts::generate_signer_set_public_keys(rng, num_signers);
    let test_data = TestData::generate(rng, &signer_set, &test_model_params);
    test_data.write_to(db).await;
    signer_set
}

/// Get the full block
async fn get_bitcoin_canonical_chain_tip_block(db: &PgStore) -> BitcoinBlock {
    sqlx::query_as::<_, BitcoinBlock>(
        "SELECT
            block_hash
            , block_height
            , parent_hash
            , confirms
            FROM sbtc_signer.bitcoin_blocks
            ORDER BY block_height DESC, block_hash DESC
            LIMIT 1",
    )
    .fetch_optional(db.pool())
    .await
    .unwrap()
    .unwrap()
}

/// Get an existing deposit request that has been confirmed on the
/// canonical bitcoin blockchain.
///
/// The signatures required field affects which deposit requests are
/// eligible for being accepted. In these tests, we just need any old
/// deposit request so this value doesn't matter so long as we get one
/// deposit request that meets these requirements.
async fn get_pending_accepted_deposit_requests(
    db: &PgStore,
    chain_tip: &BitcoinBlock,
    signatures_required: u16,
) -> DepositRequest {
    // The context window limits how far back we look in the blockchain for
    // accepted and pending deposit requests. For these tests, this value
    // is fine.
    db.get_pending_accepted_deposit_requests(&chain_tip.block_hash, 20, signatures_required)
        .await
        .unwrap()
        .last()
        .cloned()
        .unwrap()
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns okay when everything matches the way that it is supposed to.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_happy_path() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 2;

    let signer_set = deposit_setup(&mut rng, &db).await;
    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing deposit request on the canonical bitcoin
    // blockchain.
    let deposit_req =
        get_pending_accepted_deposit_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps in the deposit.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![deposit_req.outpoint()],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    sweep_tx.block_hash = chain_tip.block_hash.into_bytes();
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Generate the transaction and corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip);

    // This should not return an Err.
    let ctx = TestSignerContext::from_db(db.clone());

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
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 2;

    let signer_set = deposit_setup(&mut rng, &db).await;

    // Get the chain tip
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing deposit request on the canonical bitcoin
    // blockchain.
    let deposit_req =
        get_pending_accepted_deposit_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps in the deposit.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![deposit_req.outpoint()],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    sweep_tx.block_hash = chain_tip.block_hash.into_bytes();
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Generate the transaction and corresponding request context.
    let (mut complete_deposit_tx, mut req_ctx) =
        make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip);
    // Different: Okay, let's make sure we get the deployers do not match.
    complete_deposit_tx.deployer = StacksAddress::p2pkh(false, &signer_set[0].into());
    req_ctx.deployer = StacksAddress::p2pkh(false, &signer_set[1].into());
    let ctx = TestSignerContext::from_db(db.clone());

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
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let signer_set = deposit_setup(&mut rng, &db).await;

    // Normal: Get the chain tip and any pending deposit request in the blockchain
    // identified by the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Different: Let's use a random deposit request instead of one that
    // exists in the database.
    let deposit_req: DepositRequest = fake::Faker.fake_with_rng(&mut rng);

    // Normal: we generate a transaction that sweeps in the deposit.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![deposit_req.outpoint()],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    sweep_tx.block_hash = chain_tip.block_hash.into_bytes();
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    let (complete_deposit_tx, req_ctx) = make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip);
    let ctx = TestSignerContext::from_db(db.clone());

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
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 2;

    let signer_set = deposit_setup(&mut rng, &db).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing deposit request on the canonical bitcoin
    // blockchain.
    let deposit_req =
        get_pending_accepted_deposit_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps in the deposit.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![deposit_req.outpoint()],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    sweep_tx.block_hash = chain_tip.block_hash.into_bytes();
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Generate the transaction and corresponding request context.
    let (mut complete_deposit_tx, req_ctx) =
        make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip);
    // Different: Okay, let's make sure we the recipients do not match.
    complete_deposit_tx.recipient = fake::Faker
        .fake_with_rng::<StacksPrincipal, _>(&mut rng)
        .into();
    let ctx = TestSignerContext::from_db(db.clone());

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
/// returns a deposit validation error with a InvalidMintAmount message
/// when the amount of sBTC to mint exceeds the amount in the signer's
/// deposit request record.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_invalid_mint_amount() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 2;

    let signer_set = deposit_setup(&mut rng, &db).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing deposit request on the canonical bitcoin
    // blockchain.
    let deposit_req =
        get_pending_accepted_deposit_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps in the deposit.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![deposit_req.outpoint()],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    sweep_tx.block_hash = chain_tip.block_hash.into_bytes();
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Generate the transaction and corresponding request context.
    let (mut complete_deposit_tx, req_ctx) =
        make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip);
    // Different: The amount cannot exceed the amount in the deposit
    // request.
    complete_deposit_tx.amount = deposit_req.amount + 1;
    let ctx = TestSignerContext::from_db(db.clone());

    let validate_future = complete_deposit_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::InvalidMintAmount)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `CompleteDepositV1::validate` function
/// returns a deposit validation error with a InvalidFee message when the
/// amount of sBTC to mint is less than the `amount - max-fee` from in the
/// signer's deposit request record.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_invalid_fee() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 2;

    let signer_set = deposit_setup(&mut rng, &db).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing deposit request on the canonical bitcoin
    // blockchain.
    let deposit_req =
        get_pending_accepted_deposit_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps in the deposit.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![deposit_req.outpoint()],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    sweep_tx.block_hash = chain_tip.block_hash.into_bytes();
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Generate the transaction and corresponding request context.
    let (mut complete_deposit_tx, req_ctx) =
        make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip);
    // Different: The amount cannot be less than the deposit amount less
    // the max-fee.
    complete_deposit_tx.amount = deposit_req.amount - deposit_req.max_fee - 1;
    let ctx = TestSignerContext::from_db(db.clone());

    let validate_future = complete_deposit_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::InvalidFee)
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
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 2;

    let signer_set = deposit_setup(&mut rng, &db).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing deposit request on the canonical bitcoin
    // blockchain.
    let deposit_req =
        get_pending_accepted_deposit_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps in the deposit.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![deposit_req.outpoint()],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    sweep_tx.block_hash = chain_tip.block_hash.into_bytes();

    // Different: we are supposed to store a sweep transaction, but we do
    // not do that here.

    // Generate the transaction and corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip);
    let ctx = TestSignerContext::from_db(db.clone());

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
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 2;

    let signer_set = deposit_setup(&mut rng, &db).await;
    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing deposit request on the canonical bitcoin
    // blockchain.
    let deposit_req =
        get_pending_accepted_deposit_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps in the deposit.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![deposit_req.outpoint()],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Different: the transaction that sweeps in the deposit gets
    // confirmed, but on a bitcoin blockchain that is not the canonical
    // one. We generate a new blockchain and put it there.
    //
    // Note that this blockchain might actually have a greater height,
    // but we get to say which one is the canonical one in our context so
    // that fact doesn't matter in this test.
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 10,
        num_stacks_blocks_per_bitcoin_block: 0,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data2 = TestData::generate(&mut rng, &signer_set, &test_model_params);
    test_data2.write_to(&db).await;
    let chain_tip2 = test_data2
        .bitcoin_blocks
        .iter()
        .max_by_key(|x| (x.block_height, x.block_hash))
        .unwrap();
    sweep_tx.block_hash = chain_tip2.block_hash.into_bytes();
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Generate the transaction and corresponding request context.
    let (complete_deposit_tx, mut req_ctx) =
        make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip2);
    req_ctx.chain_tip = chain_tip.into();
    let ctx = TestSignerContext::from_db(db.clone());

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
/// returns a deposit validation error with a DepositMissingFromSweep
/// message when the sweep transaction is in our records, is on what the
/// signer thinks is the canonical bitcoin blockchain, but it does not have
/// an input that that matches the deposit request outpoint.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn complete_deposit_validation_deposit_not_in_sweep() {
    // Normal: this generates the blockchain as well as deposit request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 2;

    let signer_set = deposit_setup(&mut rng, &db).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing deposit request on the canonical bitcoin
    // blockchain.
    let deposit_req =
        get_pending_accepted_deposit_requests(&db, &chain_tip, signatures_required).await;

    // Different: The sweep transaction does not include the deposit
    // request UTXO as an input.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: vec![OutPoint {
            txid: bitcoin::Txid::from_byte_array(fake::Faker.fake_with_rng(&mut rng)),
            vout: 0,
        }],
        outputs: Vec::new(),
    };
    let mut sweep_tx: model::Transaction = sweep_config.fake_with_rng(&mut rng);
    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    sweep_tx.block_hash = chain_tip.block_hash.into_bytes();
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Generate the transaction and corresponding request context.
    let (complete_deposit_tx, req_ctx) = make_complete_deposit(&deposit_req, &sweep_tx, &chain_tip);
    let ctx = TestSignerContext::from_db(db.clone());

    let validation_result = complete_deposit_tx.validate(&ctx, &req_ctx).await;
    match validation_result.unwrap_err() {
        Error::DepositValidation(ref err) => {
            assert_eq!(err.error, DepositErrorMsg::MissingFromSweep)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}
