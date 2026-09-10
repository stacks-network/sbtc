use std::{
    num::{NonZero, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use assert_matches::assert_matches;
use bitcoin::{AddressType, Amount, consensus::encode::serialize_hex};
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc_json::Utxo;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use clarity::{
    types::chainstate::StacksAddress,
    vm::{
        ContractName, Value,
        types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions as _},
    },
};
use emily_client::{apis::deposit_api, models::CreateDepositRequestBody};
use futures::stream::StreamExt as _;
use lru::LruCache;
use more_asserts::{assert_ge, assert_le};
use rand::rngs::OsRng;
use sbtc::{
    WITHDRAWAL_MIN_CONFIRMATIONS,
    events::RegistryEvent,
    testing::{
        containers::TestContainersBuilder,
        regtest::{BITCOIN_CORE_FALLBACK_FEE, Recipient, get_btc_balance},
    },
};
use secp256k1::Keypair;
use signer::{
    api::new_block,
    bitcoin::{
        BitcoinBlockHashStreamProvider as _, poller::BitcoinChainTipPoller, rpc::BitcoinCoreClient,
    },
    block_observer::BlockObserver,
    config::NetworkKind,
    context::Context as _,
    emily_client::EmilyClient,
    error::Error,
    keys::{PublicKey, SignerScriptPubKey as _},
    network::in_memory2::WanNetwork,
    request_decider::RequestDeciderEventLoop,
    stacks::{
        api::{ClarityName, StacksClient, StacksInteract as _, SubmitTxResponse},
        contracts::{AsContractCall as _, SmartContract},
        wallet::SignerWallet,
    },
    storage::{DbRead as _, postgres::PgStore},
    testing::{self, context::*, wallet::InitiateWithdrawalRequest},
    transaction_coordinator::TxCoordinatorEventLoop,
    transaction_signer::{STACKS_SIGN_REQUEST_LRU_SIZE, TxSignerEventLoop},
    util::{FutureExt as _, Sleep},
};

use crate::{
    containers::{BitcoinContainerExt as _, StacksContainerExt as _},
    setup::{clean_emily_setup, new_emily_setup},
    stacks::{
        BlockReplay, BlockReplayTransaction, address_to_clarity_arg, block_replay,
        create_stacks_tx, fund_stx, get_block_by_height, principal_to_address, wait_for_new_nonce,
        wait_for_stx_balance,
    },
    transaction_coordinator::{IntegrationTestContext, wait_for_tenure_completed},
    utxo_construction::make_deposit_request_to,
};

const SIMULATED_EVENT_OBSERVER_POLLING: Duration = Duration::from_millis(200);

async fn start_signers(
    bitcoin_client: &BitcoinCoreClient,
    bitcoin_chain_tip_poller: &BitcoinChainTipPoller,
    stacks_client: &StacksClient,
    emily_client: &EmilyClient,
    network: &WanNetwork,
    num_signers: usize,
    signatures_required: u16,
) -> Vec<(
    IntegrationTestContext<StacksClient>,
    PgStore,
    Keypair,
    signer::network::in_memory2::SignerNetwork,
)> {
    let keypairs = std::iter::repeat_with(|| Keypair::new_global(&mut OsRng))
        .take(num_signers)
        .collect::<Vec<_>>();

    let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public_key().into()).collect();
    let wallet =
        SignerWallet::new(&public_keys, signatures_required, NetworkKind::Testnet, 0).unwrap();

    let tx = fund_stx(
        stacks_client,
        &wallet.address().to_account_principal(),
        100 * 1_000_000,
    )
    .await;
    stacks_client
        .submit_tx(&tx)
        .await
        .expect("failed to send stacks transaction");

    wait_for_stx_balance(stacks_client, wallet.address(), |ustx| ustx > 0).await;

    // We fetch for a period longer than the poller interval so it sets the last
    // seen block to current chain tip and will not notify the signers yet.
    let mut stream = bitcoin_chain_tip_poller.get_block_hash_stream();
    let polling_fut = async {
        loop {
            let _ = stream.next().with_timeout(Duration::from_millis(100)).await;
        }
    };
    let _ = polling_fut.with_timeout(Duration::from_millis(500)).await;

    let mut signers = Vec::new();
    for kp in keypairs.iter() {
        let db = testing::storage::new_test_database().await;
        let ctx = TestContext::builder()
            .with_storage(db.clone())
            .with_bitcoin_client(bitcoin_client.clone())
            .with_emily_client(emily_client.clone())
            .with_stacks_client(stacks_client.clone())
            .modify_settings(|settings| {
                settings.signer.bootstrap_signing_set = public_keys.iter().cloned().collect();
                settings.signer.bootstrap_signatures_required = signatures_required;
                settings.signer.bitcoin_processing_delay = Duration::from_millis(500);
                settings.signer.deployer = wallet.address().clone();
                settings.signer.stacks_fees_max_ustx = NonZero::new(1_000_000).unwrap();
            })
            .build();

        let network = network.connect(&ctx);

        signers.push((ctx, db, *kp, network));
    }

    let start_count = Arc::new(AtomicU8::new(0));
    for (ctx, _, kp, network) in signers.iter() {
        let ev = TxCoordinatorEventLoop {
            network: network.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            private_key: kp.secret_key().into(),
            signing_round_max_duration: Duration::from_secs(10),
            bitcoin_presign_request_max_duration: Duration::from_secs(10),
            dkg_max_duration: Duration::from_secs(10),
            is_epoch3: true,
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });

        let ev = TxSignerEventLoop {
            network: network.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
            signer_private_key: kp.secret_key().into(),
            last_presign_block: None,
            dkg_begin_pause: None,
            dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
            stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });

        let ev = RequestDeciderEventLoop {
            network: network.spawn(),
            context: ctx.clone(),
            context_window: 10000,
            deposit_decisions_retry_window: 1,
            withdrawal_decisions_retry_window: 1,
            blocklist_checker: Some(()),
            signer_private_key: kp.secret_key().into(),
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            ev.run().await
        });

        let block_observer = BlockObserver {
            context: ctx.clone(),
            bitcoin_block_source: bitcoin_chain_tip_poller.clone(),
        };
        let counter = start_count.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            block_observer.run().await
        });

        // Since we don't have an event observer wired for the tests, we need
        // to simulate it
        let counter = start_count.clone();
        let ctx_ = ctx.clone();
        tokio::spawn(async move {
            counter.fetch_add(1, Ordering::Relaxed);
            simulate_event_observer(ctx_).await
        });
    }

    while start_count.load(Ordering::SeqCst) < 5 * num_signers as u8 {
        Sleep::for_millis(10).await;
    }

    signers
}

async fn simulate_event_observer(ctx: IntegrationTestContext<StacksClient>) {
    let stacks_client = ctx.stacks_client.clone();

    let mut last_block = stacks_client
        .get_node_info()
        .await
        .unwrap()
        .stacks_tip_height;

    loop {
        let current_block = stacks_client
            .get_node_info()
            .await
            .unwrap()
            .stacks_tip_height;

        for block_height in (*last_block + 1)..=(*current_block) {
            let block_hash = get_block_by_height(&stacks_client, block_height)
                .await
                .expect("failed to get block")
                .block_id();

            let block_replay = block_replay(&stacks_client, block_hash.into())
                .await
                .expect("failed to replay block");

            new_block_handler(&ctx, block_replay).await;
        }

        last_block = current_block;
        tokio::time::sleep(SIMULATED_EVENT_OBSERVER_POLLING).await;
    }
}

enum SbtcBalance {
    Total,
    Available,
    Locked,
}

async fn get_sbtc_balance(
    stacks_client: &StacksClient,
    deployer: &StacksAddress,
    address: &PrincipalData,
    balance: SbtcBalance,
) -> Result<Amount, Error> {
    let fn_name = match balance {
        SbtcBalance::Total => "get-balance",
        SbtcBalance::Available => "get-balance-available",
        SbtcBalance::Locked => "get-balance-locked",
    };
    let result = stacks_client
        .call_read(
            deployer,
            SmartContract::SbtcToken,
            ClarityName(fn_name),
            deployer,
            &[Value::Principal(address.clone())],
        )
        .await?;

    match result {
        Value::Response(response) => match *response.data {
            Value::UInt(total_supply) => Ok(Amount::from_sat(
                u64::try_from(total_supply)
                    .map_err(|_| Error::InvalidStacksResponse("invalid u64"))?,
            )),
            _ => Err(Error::InvalidStacksResponse(
                "expected a uint but got something else",
            )),
        },
        _ => Err(Error::InvalidStacksResponse(
            "expected a response but got something else",
        )),
    }
}

/// Simulates `new_block_handler` in the sBTC signer API. We can't use that
/// directly because we don't get exactly the same data from the block replay.
async fn new_block_handler(ctx: &IntegrationTestContext<StacksClient>, block: BlockReplay) {
    let PrincipalData::Standard(deployer) = ctx.config().signer.deployer.to_account_principal()
    else {
        panic!("unexpected deployer")
    };

    let registry_address = QualifiedContractIdentifier::new(
        deployer,
        ContractName::from(SmartContract::SbtcRegistry.contract_name()),
    );

    for BlockReplayTransaction { events } in block.transactions {
        let events = events
            .into_iter()
            .filter(|x| x.committed)
            .filter_map(|x| x.contract_event.map(|ev| (ev, x.txid)))
            .filter(|(ev, _)| ev.contract_identifier == registry_address && ev.topic == "print")
            .collect::<Vec<_>>();

        for (ev, txid) in events {
            let tx_info = sbtc::events::TxInfo {
                txid: sbtc::events::StacksTxid(txid.0),
                block_id: block.block_id.into(),
            };
            match RegistryEvent::try_new(ev.raw_value, tx_info) {
                Ok(RegistryEvent::CompletedDeposit(event)) => {
                    new_block::handle_completed_deposit(ctx, event.into()).await
                }
                Ok(RegistryEvent::WithdrawalAccept(event)) => {
                    new_block::handle_withdrawal_accept(ctx, event.into()).await
                }
                Ok(RegistryEvent::WithdrawalReject(event)) => {
                    new_block::handle_withdrawal_reject(ctx, event.into()).await
                }
                Ok(RegistryEvent::WithdrawalCreate(event)) => {
                    new_block::handle_withdrawal_create(ctx, event.into()).await
                }
                Ok(RegistryEvent::KeyRotation(event)) => {
                    new_block::handle_key_rotation(ctx, event.into()).await
                }
                Err(error) => {
                    panic!("unknown event: {error}");
                }
            }
            .expect("failed to handle event");
        }
    }
}

/// End to end test for deposit and withdrawal:
///  - the sBTC signers bootstrap
///  - a deposit is created on Emily
///  - the signers fulfill it (with a controlled chain progression) and mint sBTC
///  - the recipient creates a withdrawal request
///  - the signers fulfill it (with a controlled chain progression) and pegout BTC
#[test_log::test(tokio::test)]
async fn deposit_and_withdrawal() {
    let stack = TestContainersBuilder::start_stacks().await;
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;

    let rpc = bitcoin.rpc();
    let faucet = &bitcoin.get_faucet();

    let stacks_client = stacks.get_client();

    let (emily_client, emily_tables) = new_emily_setup().await;

    let network = WanNetwork::default();

    // Ensure we can estimate fees
    faucet.generate_fee_data();

    let num_signers = 3;
    let signatures_required = 2;

    let bitcoin_chain_tip_poller = bitcoin.start_chain_tip_poller().await;

    let signers = start_signers(
        &bitcoin.get_client(),
        &bitcoin_chain_tip_poller,
        &stacks_client,
        &emily_client,
        &network,
        num_signers,
        signatures_required,
    )
    .await;

    let deployer = signers[0].0.config().signer.deployer.clone();

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now we should have contracts deployed

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now we should have a key rotation

    let aggregate_key = stacks_client
        .get_current_signers_aggregate_key(&deployer)
        .await
        .unwrap()
        .expect("no aggregate key in contract");
    let aggregate_key_bitcoin = (*aggregate_key).into();

    // Signers require a donation
    let donation_amount = 10_000;
    faucet.send_to_script(donation_amount, aggregate_key.signers_script_pubkey());

    let depositor = Recipient::new(AddressType::P2tr);
    let deposit_amount = 100_000;

    let tx_fee = BITCOIN_CORE_FALLBACK_FEE.to_sat();
    let deposit_max_fee = deposit_amount / 2;
    let depositor_fund_amount = deposit_amount + tx_fee;
    let depositor_fund_outpoint = faucet.send_to(depositor_fund_amount, &depositor.address);

    assert_eq!(depositor.get_balance(rpc), Amount::ZERO);

    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    // Now the funding txs should be confirmed, we can submit the deposit
    let peg_balance = get_btc_balance(rpc, &aggregate_key_bitcoin, AddressType::P2tr).to_sat();
    assert_eq!(peg_balance, donation_amount);

    assert_eq!(depositor.get_balance(rpc).to_sat(), depositor_fund_amount);

    let recipient = depositor.stacks_address().to_account_principal();

    // Check that recipient doesn't hold any sBTC yet
    let sbtc_balance = get_sbtc_balance(&stacks_client, &deployer, &recipient, SbtcBalance::Total)
        .await
        .expect("cannot get sbtc balance");
    assert_eq!(sbtc_balance, Amount::ZERO);

    let depositor_utxo = Utxo {
        txid: depositor_fund_outpoint.txid,
        vout: depositor_fund_outpoint.vout,
        script_pub_key: depositor.address.script_pubkey(),
        descriptor: "".to_string(),
        amount: Amount::from_sat(depositor_fund_amount),
        height: 0,
    };
    let (deposit_tx, deposit_request, deposit_info) = make_deposit_request_to(
        &depositor,
        deposit_amount,
        depositor_utxo,
        deposit_max_fee,
        aggregate_key.into(),
        recipient.clone(),
    );
    rpc.send_raw_transaction(&deposit_tx)
        .expect("cannot submit deposit tx");

    let emily_request = CreateDepositRequestBody {
        bitcoin_tx_output_index: deposit_request.outpoint.vout,
        bitcoin_txid: deposit_request.outpoint.txid.to_string(),
        deposit_script: deposit_request.deposit_script.to_hex_string(),
        reclaim_script: deposit_info.reclaim_script.to_hex_string(),
        transaction_hex: serialize_hex(&deposit_tx),
    };

    deposit_api::create_deposit(emily_client.config(), emily_request.clone())
        .await
        .expect("cannot create emily deposit");

    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    // Now we should have a sweep transaction submitted

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now we should have sBTC minted

    assert_eq!(depositor.get_balance(rpc), Amount::ZERO);

    let peg_new_balance = get_btc_balance(rpc, &aggregate_key_bitcoin, AddressType::P2tr).to_sat();
    let fee_paid = peg_balance + deposit_amount - peg_new_balance;
    assert_ge!(fee_paid, 1);
    assert_le!(fee_paid, deposit_max_fee);
    let peg_balance = peg_new_balance;

    let sbtc_balance = get_sbtc_balance(
        &stacks_client,
        &deployer,
        &recipient,
        SbtcBalance::Available,
    )
    .await
    .expect("cannot get sbtc balance");

    assert_eq!(sbtc_balance.to_sat(), deposit_amount - fee_paid);

    // Now lets withdraw those sBTC

    let recipient_principal = principal_to_address(&recipient);
    let stx_fund_tx = fund_stx(&stacks_client, &recipient, 1_000_000).await;
    stacks_client
        .submit_tx(&stx_fund_tx)
        .await
        .expect("failed to send stacks transaction");
    wait_for_stx_balance(&stacks_client, &recipient_principal, |ustx| ustx > 0).await;

    let withdrawal_recipient = Recipient::new(AddressType::P2tr);
    let withdrawal_max_fee = 2_000;
    let withdrawal_amount = sbtc_balance.to_sat() - withdrawal_max_fee;

    assert_eq!(withdrawal_recipient.get_balance(rpc), Amount::ZERO);

    let withdrawal_request = InitiateWithdrawalRequest {
        amount: withdrawal_amount,
        recipient: address_to_clarity_arg(&withdrawal_recipient.address),
        max_fee: withdrawal_max_fee,
        deployer: deployer.clone(),
    };

    let payload = TransactionPayload::ContractCall(withdrawal_request.as_contract_call());
    let depositor_sk = depositor.keypair.secret_key().into();
    let withdrawal_init_tx = create_stacks_tx(&stacks_client, payload, &depositor_sk).await;

    let withdrawal_init_result = stacks_client
        .submit_tx(&withdrawal_init_tx)
        .await
        .expect("failed to init withdrawal");
    assert_matches!(withdrawal_init_result, SubmitTxResponse::Acceptance(_));

    wait_for_new_nonce(
        &stacks_client,
        &recipient_principal,
        withdrawal_init_tx.get_origin_nonce(),
    )
    .await;
    // Now the withdrawal request should exists on Stacks

    let sbtc_balance_available = get_sbtc_balance(
        &stacks_client,
        &deployer,
        &recipient,
        SbtcBalance::Available,
    )
    .await
    .expect("cannot get sbtc balance");
    assert_eq!(sbtc_balance_available, Amount::ZERO);

    let sbtc_balance_locked =
        get_sbtc_balance(&stacks_client, &deployer, &recipient, SbtcBalance::Locked)
            .await
            .expect("cannot get sbtc balance");
    assert_eq!(
        sbtc_balance_locked.to_sat(),
        withdrawal_amount + withdrawal_max_fee
    );

    // Sleep for a bit to ensure the event observer catches up
    tokio::time::sleep(3 * SIMULATED_EVENT_OBSERVER_POLLING).await;

    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    // Now the signers should know about the withdrawal and voted for it

    let mut withdrawal_id = 0;
    for (ctx, db, _, _) in &signers {
        let stacks_chain_tip = ctx.state().stacks_chain_tip().unwrap();

        let accepted_withdrawals = db
            .get_pending_accepted_withdrawal_requests(
                &chain_tip,
                &stacks_chain_tip.block_hash,
                0u64.into(),
                signatures_required,
            )
            .await
            .unwrap();

        assert_eq!(accepted_withdrawals.len(), 1);
        let withdrawal = accepted_withdrawals.first().unwrap();

        assert_eq!(withdrawal.amount, withdrawal_amount);
        assert_eq!(withdrawal.max_fee, withdrawal_max_fee);
        if withdrawal_id != 0 {
            assert_eq!(withdrawal.request_id, withdrawal_id);
        } else {
            withdrawal_id = withdrawal.request_id;
        }
    }
    assert_ne!(withdrawal_id, 0);

    // Generate enough blocks to make the withdrawal valid; the minus one is
    // because we already generated one block above to check for signers votes
    for _ in 0..WITHDRAWAL_MIN_CONFIRMATIONS - 1 {
        let chain_tip = faucet.generate_block().into();
        wait_for_tenure_completed(&signers, chain_tip).await;
    }
    // Now the withdrawal should be swept (in mempool)

    let peg_new_balance = get_btc_balance(rpc, &aggregate_key_bitcoin, AddressType::P2tr).to_sat();
    assert_eq!(peg_balance, peg_new_balance);

    let is_withdrawal_completed = stacks_client
        .is_withdrawal_completed(&deployer, withdrawal_id)
        .await
        .unwrap();
    assert!(!is_withdrawal_completed);

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;
    wait_for_new_nonce(&stacks_client, &deployer, old_nonce).await;
    // Now the withdrawal sweep should be confirmed and the withdrawal completed

    let peg_new_balance = get_btc_balance(rpc, &aggregate_key_bitcoin, AddressType::P2tr).to_sat();
    assert_le!(peg_new_balance, peg_balance - withdrawal_amount);
    assert_ge!(
        peg_new_balance,
        peg_balance - withdrawal_amount - withdrawal_max_fee
    );
    assert_eq!(
        withdrawal_recipient.get_balance(rpc).to_sat(),
        withdrawal_amount
    );

    let is_withdrawal_completed = stacks_client
        .is_withdrawal_completed(&deployer, withdrawal_id)
        .await
        .unwrap();
    assert!(is_withdrawal_completed);

    let sbtc_balance_locked =
        get_sbtc_balance(&stacks_client, &deployer, &recipient, SbtcBalance::Locked)
            .await
            .expect("cannot get sbtc balance");
    assert_eq!(sbtc_balance_locked, Amount::ZERO);

    let sbtc_balance_available = get_sbtc_balance(
        &stacks_client,
        &deployer,
        &recipient,
        SbtcBalance::Available,
    )
    .await
    .expect("cannot get sbtc balance");
    let fee_paid = withdrawal_max_fee - sbtc_balance_available.to_sat();

    assert_eq!(peg_new_balance, peg_balance - withdrawal_amount - fee_paid);

    for (_, db, _, _) in signers {
        testing::storage::drop_db(db).await;
    }
    clean_emily_setup(emily_tables).await;
}
