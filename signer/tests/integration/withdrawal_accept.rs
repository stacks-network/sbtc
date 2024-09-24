use std::sync::atomic::Ordering;

use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash as _;
use bitcoin::OutPoint;
use bitvec::array::BitArray;
use blockstack_lib::types::chainstate::StacksAddress;

use rand::rngs::OsRng;
use signer::error::Error;
use signer::keys::PublicKey;
use signer::stacks::contracts::AcceptWithdrawalV1;
use signer::stacks::contracts::AsContractCall as _;
use signer::stacks::contracts::ReqContext;
use signer::stacks::contracts::WithdrawalErrorMsg;
use signer::storage::model;
use signer::storage::model::BitcoinBlock;
use signer::storage::model::BitcoinTx;
use signer::storage::model::BitcoinTxRef;
use signer::storage::model::RotateKeysTransaction;
use signer::storage::model::WithdrawalRequest;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::testing;
use signer::testing::dummy::SweepTxConfig;
use signer::testing::storage::model::TestData;

use fake::Fake;
use rand::SeedableRng;

use crate::DATABASE_NUM;

/// Create a "proper" [`AcceptWithdrawalV1`] object and context with the
/// given information. If the information here is correct then the returned
/// [`AcceptWithdrawalV1`] object will pass validation with the given
/// context.
fn make_withdrawal_accept(
    req: &WithdrawalRequest,
    outpoint: OutPoint,
    aggregate_key: PublicKey,
    chain_tip: &BitcoinBlock,
    bitmap: BitArray<[u8; 16]>,
) -> (AcceptWithdrawalV1, ReqContext) {
    // Creating `AcceptWithdrawalV1` transactions are tricky. They are a
    //  mix of data from the bitcoin transaction sweeping out the funds,
    //  the withdrawal request itself, and how the signers voted.
    let complete_withdrawal_tx = AcceptWithdrawalV1 {
        // This OutPoint points to the withdrawal UTXO. We look up our
        // record of the actual withdrawal to make sure that the amount
        // matches the one in the withdrawal request.
        outpoint,
        // This amount must not exceed the amount in the withdrawal request.
        request_id: req.request_id,
        // The recipient must match what was indicated in the withdrawal
        // request.
        tx_fee: 0,
        //
        signer_bitmap: bitmap,
        // The deployer must match what is in the signers' context.
        deployer: StacksAddress::burn_address(false),
        // The block hash of the block that includes the above sweep
        // transaction. It must be on the canonical bitcoin blockchain.
        sweep_block_hash: chain_tip.block_hash,
        // This must be the height of the above block.
        sweep_block_height: chain_tip.block_height,
    };

    // This is what the current signer things of the state of things.
    let ctx = ReqContext {
        chain_tip: chain_tip.into(),
        // This value means that the signer will go back 10 blocks when
        // looking for pending and accepted withdrawal requests.
        context_window: 10,
        // The value here doesn't matter.
        origin: fake::Faker.fake_with_rng(&mut OsRng),
        // The value here doesn't matter either.
        aggregate_key,
        // This value affects how many withdrawal transactions are consider
        // accepted.
        signatures_required: 2,
        // This is who the current signer thinks deployed the sBTC
        // contracts.
        deployer: StacksAddress::burn_address(false),
    };

    (complete_withdrawal_tx, ctx)
}

/// Generate a signer set, withdrawal requests and store them into the
/// database.
async fn withdrawal_setup<R>(
    rng: &mut R,
    db: &PgStore,
    signatures_required: u16,
) -> (PublicKey, Vec<PublicKey>)
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
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 2,
        num_signers_per_request: num_signers,
    };

    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let signer_set = testing::wsts::generate_signer_set_public_keys(rng, num_signers);
    let test_data = TestData::generate(rng, &signer_set, &test_model_params);
    test_data.write_to(db).await;

    let aggregate_key = PublicKey::combine_keys(&signer_set).unwrap();
    let rotate_keys = RotateKeysTransaction {
        txid: fake::Faker.fake_with_rng(rng),
        aggregate_key,
        signer_set: signer_set.clone(),
        signatures_required,
    };
    // Before we can write the rotate keys into the postgres database, we
    // need to have a transaction in the transactions table.
    let rotate_keys_tx = model::Transaction {
        txid: rotate_keys.txid.into_bytes(),
        tx: Vec::new(),
        tx_type: model::TransactionType::RotateKeys,
        block_hash: fake::Faker.fake_with_rng(rng),
    };
    db.write_transaction(&rotate_keys_tx).await.unwrap();
    db.write_rotate_keys_transaction(&rotate_keys)
        .await
        .unwrap();

    (aggregate_key, signer_set)
}

/// Get the full block
async fn get_bitcoin_canonical_chain_tip_block(store: &PgStore) -> BitcoinBlock {
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
    .fetch_one(store.pool())
    .await
    .unwrap()
}

/// Get an existing pending and accepted withdrawal request that has been
/// confirmed on the canonical bitcoin blockchain.
///
/// The signatures required field affects which deposit requests are
/// eligible for being accepted. In these tests, we just need any old
/// deposit request so this value doesn't matter so long as we get one
/// deposit request that meets these requirements.
async fn get_pending_accepted_withdrawal_requests(
    db: &PgStore,
    chain_tip: &BitcoinBlock,
    signatures_required: u16,
) -> WithdrawalRequest {
    // The context window limits how far back we look in the blockchain for
    // accepted and pending deposit requests. For these tests, this value
    // is fine.
    db.get_pending_accepted_withdrawal_requests(&chain_tip.block_hash, 20, signatures_required)
        .await
        .unwrap()
        .pop()
        .unwrap()
}

/// Get how the signers voted for a particular withdrawal request
async fn get_withdrawal_request_signer_votes(
    db: &PgStore,
    req: &WithdrawalRequest,
    aggregate_key: &PublicKey,
) -> BitArray<[u8; 16]> {
    db.get_withdrawal_request_signer_votes(&req.qualified_id(), &aggregate_key)
        .await
        .map(BitArray::<[u8; 16]>::from)
        .unwrap()
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns okay when everything matches the way that it is supposed to.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_happy_path() {
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;
    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps out the withdrawal.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip.block_hash.into_bytes(),
    };

    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Normal: get the signer bitmap for how they voted.
    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);

    // This should not return an Err.
    accept_withdrawal_tx.validate(&db, &ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a DeployerMismatch message
/// when the deployer doesn't match but everything else is okay.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_deployer_mismatch() {
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;

    // Get the chain tip
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps out the withdrawal.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip.block_hash.into_bytes(),
    };
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Normal: get the signer bitmap for how they voted.
    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    // Generate the transaction and corresponding request context.
    let (mut accept_withdrawal_tx, mut ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);
    // Different: Okay, let's make sure the deployers do not match.
    accept_withdrawal_tx.deployer = StacksAddress::p2pkh(false, &signer_set[0].into());
    ctx.deployer = StacksAddress::p2pkh(false, &signer_set[1].into());

    let validate_future = accept_withdrawal_tx.validate(&db, &ctx);
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
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, 3).await;

    // Normal: Get the chain tip and any pending withdrawal request in the blockchain
    // identified by the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Different: Let's use a random withdrawal request instead of one that
    // exists in the database.
    let req: WithdrawalRequest = fake::Faker.fake_with_rng(&mut rng);

    // Normal: we generate a transaction that sweeps out the withdrawal.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip.block_hash.into_bytes(),
    };
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    let (accept_withdrawal_tx, ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);

    let validation_result = accept_withdrawal_tx.validate(&db, &ctx).await;
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
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Different: we generate a transaction that sweeps out the withdrawal,
    // but the recipient of the funds does not match.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, fake::Faker.fake_with_rng(&mut rng))],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip.block_hash.into_bytes(),
    };
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Normal: get the signer bitmap for how they voted.
    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);

    let validation_result = accept_withdrawal_tx.validate(&db, &ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::RecipientMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

/// For this test we check that the `AcceptWithdrawalV1::validate` function
/// returns a withdrawal validation error with a InvalidMintAmount message
/// when the amount of sBTC to mint exceeds the amount in the signer's
/// withdrawal request record.
#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn accept_withdrawal_validation_invalid_mint_amount() {
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Different: we generate a transaction that sweeps out the withdrawal,
    // but the amount is off.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount + 1, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip.block_hash.into_bytes(),
    };
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Normal: get the signer bitmap for how they voted.
    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);

    let validation_result = accept_withdrawal_tx.validate(&db, &ctx).await;
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
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps out the withdrawal.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip.block_hash.into_bytes(),
    };

    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Normal: get the signer bitmap for how they voted.
    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    // Generate the transaction and corresponding request context.
    let (mut accept_withdrawal_tx, ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);
    // Different: The fee cannot exceed the max fee. Setting the `tx_fee`
    // to `max_fee + 1` here will result in the validation validating
    // `req.value - (req.max_fee + 1)`, which will then be less than
    // `req.value - req.max_fee` and thus invalid.
    accept_withdrawal_tx.tx_fee = req.max_fee + 1;

    let validate_future = accept_withdrawal_tx.validate(&db, &ctx);
    match validate_future.await.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::InvalidFee)
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
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps out the withdrawal.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Different: we are supposed to store a sweep transaction, but we do
    // not do that here. Now this signer does not have a record of the
    // sweep transaction.

    // Normal: get the signer bitmap for how they voted.
    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);

    let validation_result = accept_withdrawal_tx.validate(&db, &ctx).await;
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
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;
    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps out the withdrawal.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Different: In this case the transaction that sweeps in the
    // withdrawal gets confirmed, but on a bitcoin blockchain that is not
    // the canonical one. So we generate a new blockchain and put it there.
    //
    // Note that this blockchain might actually have a greater height, but
    // we get to say which one is the canonical one in our context so that
    // fact doesn't matter in this test.
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
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip2.block_hash.into_bytes(),
    };
    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Normal: get the signer bitmap for how they voted.
    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, mut ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip2, bitmap);
    // Different: We already created the BTC transaction that swept out the
    // users funds and confirmed it on a bitcoin blockchain identified by
    // `chain_tip2`. Here we set the canonical chain tip on the context to
    // be `chain_tip1`.
    ctx.chain_tip = chain_tip.into();

    let validation_result = accept_withdrawal_tx.validate(&db, &ctx).await;
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
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;

    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps out the withdrawal.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Different: the outpoint here is supposed to be the outpoint of the
    // UTXO in the sweep transactions that spends to the desired recipient.
    // Here we give an outpoint that doesn't exist in the transaction,
    // triggering the desired error. We use 3 for the vout, but any number
    // greater than 2 will do.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 3);

    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip.block_hash.into_bytes(),
    };

    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Normal: get the signer bitmap for how they voted.
    let bitmap = get_withdrawal_request_signer_votes(&db, &req, &aggregate_key).await;
    // Generate the transaction and corresponding request context.
    // Different: using the "invalid" `sweep_outpoint` we created above.
    let (accept_withdrawal_tx, ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);

    let validation_result = accept_withdrawal_tx.validate(&db, &ctx).await;
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
    // Normal: this generates the blockchain as well as withdrawal request
    // transactions in each bitcoin block.
    let db_num = DATABASE_NUM.fetch_add(1, Ordering::SeqCst);
    let db = testing::storage::new_test_database(db_num, true).await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let signatures_required = 3;

    let (aggregate_key, signer_set) = withdrawal_setup(&mut rng, &db, signatures_required).await;
    // Get the chain tip.
    let chain_tip = get_bitcoin_canonical_chain_tip_block(&db).await;
    // Normal: Get an existing withdrawal request on the canonical bitcoin
    // blockchain.
    let req = get_pending_accepted_withdrawal_requests(&db, &chain_tip, signatures_required).await;

    // Normal: we generate a transaction that sweeps out the withdrawal.
    let sweep_config = SweepTxConfig {
        aggregate_key: PublicKey::combine_keys(&signer_set).unwrap(),
        amounts: 3000..1_000_000_000,
        inputs: Vec::new(),
        outputs: vec![(req.amount, req.recipient.clone())],
    };
    let sweep_btc_tx: BitcoinTx = sweep_config.fake_with_rng(&mut rng);
    let mut tx_bytes = Vec::new();
    sweep_btc_tx.consensus_encode(&mut tx_bytes).unwrap();
    // Normal: we get the outpoint of the UTXO in the sweep transactions.
    // Sweep transactions start withdrawal UTXOs at the third output.
    let sweep_outpoint = OutPoint::new(sweep_btc_tx.compute_txid(), 2);

    // Normal: make sure the sweep transaction is on the canonical bitcoin
    // blockchain and is in our database.
    let sweep_tx = model::Transaction {
        txid: sweep_btc_tx.compute_txid().to_byte_array(),
        tx: tx_bytes,
        tx_type: model::TransactionType::SbtcTransaction,
        block_hash: chain_tip.block_hash.into_bytes(),
    };

    // Normal: make sure that we have a record of the sweep transaction in
    // our database.
    let bitcoin_tx_ref = BitcoinTxRef {
        txid: sweep_tx.txid.into(),
        block_hash: sweep_tx.block_hash.into(),
    };
    db.write_transaction(&sweep_tx).await.unwrap();
    db.write_bitcoin_transaction(&bitcoin_tx_ref).await.unwrap();

    // Different: We're going to get the bitmap that is a little different
    // from what is expected.
    let mut bitmap = db
        .get_withdrawal_request_signer_votes(&req.qualified_id(), &aggregate_key)
        .await
        .map(BitArray::<[u8; 16]>::from)
        .unwrap();
    let first_vote = *bitmap.get(0).unwrap();
    bitmap.set(0, !first_vote);
    // Generate the transaction and corresponding request context.
    let (accept_withdrawal_tx, ctx) =
        make_withdrawal_accept(&req, sweep_outpoint, aggregate_key, &chain_tip, bitmap);

    let validation_result = accept_withdrawal_tx.validate(&db, &ctx).await;
    match validation_result.unwrap_err() {
        Error::WithdrawalAcceptValidation(ref err) => {
            assert_eq!(err.error, WithdrawalErrorMsg::BitmapMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}
