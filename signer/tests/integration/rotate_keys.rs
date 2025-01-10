use blockstack_lib::types::chainstate::StacksAddress;
use rand::rngs::OsRng;
use rand::SeedableRng;

use sbtc::testing::regtest;
use signer::error::Error;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::stacks::contracts::AsContractCall;
use signer::stacks::contracts::ReqContext;
use signer::stacks::contracts::RotateKeysErrorMsg;
use signer::stacks::contracts::RotateKeysV1;
use signer::stacks::wallet::SignerWallet;
use signer::storage::model::BitcoinBlock;
use signer::storage::model::EncryptedDkgShares;
use signer::storage::model::RotateKeysTransaction;
use signer::storage::model::StacksPrincipal;
use signer::storage::model::Transaction;
use signer::storage::model::TransactionType;
use signer::storage::postgres::PgStore;
use signer::storage::DbRead;
use signer::storage::DbWrite as _;
use signer::testing;
use signer::testing::context::*;

use fake::Fake;
use signer::testing::storage::model::TestData;

struct TestRotateKeySetup {
    /// The signer object. It's public key represents the group of signers'
    /// public keys, allowing us to abstract away the fact that there are
    /// many signers needed to sign a transaction.
    pub aggregated_signer: regtest::Recipient,
    /// The public keys of the signer set. It is effectively controlled by
    /// the above signer's private key.
    pub signer_keys: Vec<PublicKey>,
    /// This value affects whether a request is considered "accepted".
    pub signatures_required: u16,
    /// Raw transaction
    pub raw_tx: Transaction,
    /// Signers wallet
    pub wallet: SignerWallet,
    /// Bitcoin chain tip used when generating current setup
    pub chain_tip: BitcoinBlock,
}
impl TestRotateKeySetup {
    pub async fn new<R>(
        db: &PgStore,
        signatures_required: u16,
        num_signers: usize,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng,
    {
        let aggregated_signer = regtest::Recipient::new(bitcoin::AddressType::P2tr);
        let signer_keys =
            signer::testing::wallet::create_signers_keys(rng, &aggregated_signer, num_signers);

        let wallet = SignerWallet::new(
            &signer_keys,
            signatures_required,
            signer::config::NetworkKind::Regtest,
            0,
        )
        .unwrap();

        // Create the transaction as if included in the current stacks chain tip
        let bitcoin_chain_tip = db
            .get_bitcoin_canonical_chain_tip()
            .await
            .expect("failed to get bitcoin chain tip")
            .expect("no bitcoin chain tip");
        let bitcoin_chain_tip_block = db
            .get_bitcoin_block(&bitcoin_chain_tip)
            .await
            .expect("failed to get bitcoin chain tip block")
            .expect("no bitcoin chain tip block");
        let stacks_chain_tip = db
            .get_stacks_chain_tip(&bitcoin_chain_tip)
            .await
            .expect("failed to get stacks chain tip")
            .expect("no stacks chain tip");

        let raw_tx = Transaction {
            txid: fake::Faker.fake_with_rng(rng),
            tx: Vec::new(),
            tx_type: TransactionType::RotateKeys,
            block_hash: stacks_chain_tip.block_hash.into_bytes(),
        };

        TestRotateKeySetup {
            aggregated_signer,
            signer_keys,
            signatures_required,
            raw_tx,
            wallet,
            chain_tip: bitcoin_chain_tip_block,
        }
    }

    /// Get setup aggregate key
    pub fn aggregate_key(&self) -> PublicKey {
        self.aggregated_signer.keypair.public_key().into()
    }

    /// Store mocked shares in dkg_shares table.
    pub async fn store_dkg_shares(&self, db: &PgStore) {
        let aggregate_key: PublicKey = self.aggregate_key();
        let shares = EncryptedDkgShares {
            script_pubkey: aggregate_key.signers_script_pubkey().into(),
            tweaked_aggregate_key: aggregate_key.signers_tweaked_pubkey().unwrap(),
            encrypted_private_shares: Vec::new(),
            public_shares: Vec::new(),
            aggregate_key,
            signer_set_public_keys: self.signer_keys.clone(),
            signature_share_threshold: self.signatures_required,
        };
        db.write_encrypted_dkg_shares(&shares).await.unwrap();
    }

    /// Store rotate key tx.
    pub async fn store_rotate_keys(&self, db: &PgStore) {
        db.write_stacks_transactions(vec![self.raw_tx.clone()])
            .await
            .unwrap();

        let aggregate_key: PublicKey = self.aggregate_key();
        let address = StacksPrincipal::from(clarity::vm::types::PrincipalData::from(
            self.wallet.address().clone(),
        ));
        let rotate_key_tx = RotateKeysTransaction {
            address: address,
            txid: self.raw_tx.txid.into(),
            aggregate_key,
            signer_set: self.signer_keys.clone(),
            signatures_required: self.signatures_required,
        };
        db.write_rotate_keys_transaction(&rotate_key_tx)
            .await
            .unwrap();
    }
}

fn make_rotate_key(setup: &TestRotateKeySetup) -> (RotateKeysV1, ReqContext) {
    let rotate_key = RotateKeysV1::new(
        &setup.wallet,
        StacksAddress::burn_address(false),
        &setup.aggregate_key(),
    );

    // This is what the current signer thinks is the state of things.
    let req_ctx = ReqContext {
        chain_tip: setup.chain_tip.clone().into(),
        context_window: 10,
        origin: fake::Faker.fake_with_rng(&mut OsRng),
        aggregate_key: setup.aggregate_key(),
        signatures_required: setup.signatures_required,
        deployer: StacksAddress::burn_address(false),
    };

    (rotate_key, req_ctx)
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn rotate_key_validation_happy_path() {
    // Normal: preamble
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&mut db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Check to see if validation passes.
    rotate_key_tx.validate(&ctx, &req_ctx).await.unwrap();

    // Check that, if we run another dkg, the new tx pass validation
    let setup_other = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    let (rotate_key_tx_other, _) = make_rotate_key(&setup_other);

    // No DKG yet
    rotate_key_tx_other
        .validate(&ctx, &req_ctx)
        .await
        .unwrap_err();

    setup_other.store_dkg_shares(&db).await;
    // Now we have the new DKG in db
    rotate_key_tx_other.validate(&ctx, &req_ctx).await.unwrap();

    testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn rotate_key_validation_no_dkg() {
    // Normal: preamble
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&mut db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Differnt: we do NOT store setup dkg shares

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    let validate_future = rotate_key_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::NoDkgShares => {}
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn rotate_key_validation_wrong_deployer() {
    // Normal: preamble
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&mut db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, mut req_ctx) = make_rotate_key(&setup);

    // Different: use a different (expected) deployer
    req_ctx.deployer = StacksAddress::p2pkh(false, &setup.signer_keys[0].into());

    let validate_future = rotate_key_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::DeployerMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn rotate_key_validation_wrong_signing_set() {
    // Normal: preamble
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&mut db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Different: create another setup, resulting in different public keys, and try to use
    // those as public keys in rotate keys tx
    let setup_other = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    let rotate_key_tx_other = RotateKeysV1::new(
        &setup_other.wallet,
        rotate_key_tx.deployer_address(),
        &setup.aggregate_key(),
    );

    let validate_future = rotate_key_tx_other.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::SignerSetMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn rotate_key_validation_wrong_aggregate_key() {
    // Normal: preamble
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&mut db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Different: create another setup, resulting in different aggregate key, and try to use
    // that as aggregate key in rotate keys tx
    let setup_other = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;
    let rotate_key_tx_other = RotateKeysV1::new(
        &setup.wallet,
        rotate_key_tx.deployer_address(),
        &setup_other.aggregate_key(),
    );

    let validate_future = rotate_key_tx_other.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::AggregateKeyMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn rotate_key_validation_wrong_signatures_required() {
    // Normal: preamble
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&mut db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Different: we change the signature threshold
    let wallet_other = SignerWallet::new(
        setup.wallet.public_keys(),
        setup.wallet.signatures_required() + 1,
        signer::config::NetworkKind::Regtest,
        0,
    )
    .unwrap();
    let rotate_key_tx_other = RotateKeysV1::new(
        &wallet_other,
        rotate_key_tx.deployer_address(),
        &setup.aggregate_key(),
    );

    let validate_future = rotate_key_tx_other.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::SignaturesRequiredMismatch)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    testing::storage::drop_db(db).await;
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[tokio::test]
async fn rotate_key_validation_replay() {
    // Normal: preamble
    let mut db = testing::storage::new_test_database().await;
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);

    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 20,
        num_stacks_blocks_per_bitcoin_block: 3,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&mut db).await;

    let ctx = TestContext::builder()
        .with_storage(db.clone())
        .with_mocked_clients()
        .build();

    let setup = TestRotateKeySetup::new(&db, 2, 3, &mut rng).await;

    // Normal: we store setup dkg shares
    setup.store_dkg_shares(&db).await;

    // Normal: we get the rotate key from the setup
    let (rotate_key_tx, req_ctx) = make_rotate_key(&setup);

    // Check to see if validation passes.
    rotate_key_tx.validate(&ctx, &req_ctx).await.unwrap();

    // Different: store the rotate key tx
    setup.store_rotate_keys(&db).await;

    let validate_future = rotate_key_tx.validate(&ctx, &req_ctx);
    match validate_future.await.unwrap_err() {
        Error::RotateKeysValidation(ref err) => {
            assert_eq!(err.error, RotateKeysErrorMsg::KeyRotationExists)
        }
        err => panic!("unexpected error during validation {err}"),
    }

    // Check that, if we exclude the rotate key from the canonical chain, validation passes
    let test_model_params = testing::storage::model::Params {
        num_bitcoin_blocks: 2,
        num_stacks_blocks_per_bitcoin_block: 1,
        num_deposit_requests_per_block: 0,
        num_withdraw_requests_per_block: 0,
        num_signers_per_request: 0,
    };
    let test_data = TestData::generate(&mut rng, &[], &test_model_params);
    test_data.write_to(&mut db).await;

    let mut req_ctx_fork = req_ctx.clone();
    req_ctx_fork.chain_tip.block_hash = test_data.bitcoin_blocks[0].block_hash;
    req_ctx_fork.chain_tip.block_height = test_data.bitcoin_blocks[0].block_height;

    rotate_key_tx.validate(&ctx, &req_ctx_fork).await.unwrap();

    testing::storage::drop_db(db).await;
}
