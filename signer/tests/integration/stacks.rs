use std::borrow::Cow;
use std::str::FromStr as _;
use std::time::Duration;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::SinglesigHashMode;
use blockstack_lib::chainstate::stacks::SinglesigSpendingCondition;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TokenTransferMemo;
use blockstack_lib::chainstate::stacks::TransactionAnchorMode;
use blockstack_lib::chainstate::stacks::TransactionAuth;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use blockstack_lib::chainstate::stacks::TransactionPublicKeyEncoding;
use blockstack_lib::chainstate::stacks::TransactionSpendingCondition;
use blockstack_lib::chainstate::stacks::TransactionVersion;
use blockstack_lib::chainstate::stacks::address::PoxAddressType20;
use blockstack_lib::chainstate::stacks::address::PoxAddressType32;
use clarity::codec::StacksMessageCodec as _;
use clarity::consts::CHAIN_ID_TESTNET;
use clarity::types::chainstate::StacksAddress;
use clarity::util::secp256k1::MessageSignature;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::QualifiedContractIdentifier;
use sbtc::webhooks::TransactionEvent;
use signer::error::Error;
use signer::signature::RecoverableEcdsaSignature as _;
use signer::stacks::api::StacksClient;
use signer::stacks::api::update_db_with_unknown_ancestors;
use signer::stacks::contracts::AsTxPayload as _;
use signer::storage::model::ConsensusHash;
use signer::storage::model::StacksBlockHash;
use signer::testing::stacks::assert_db_contains_stacks_headers;
use signer::util::FutureExt as _;
use stacks_common::address::AddressHashMode;
use stacks_common::address::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;

// This is one of the generic accounts defined in the stacks miner config used
// for tests.
// Address: ST1YEHRRYJ4GF9CYBFFN0ZVCXX1APSBEEQ5KEDN7M
const FAUCET_PRIVATE_KEY: &str = "e26e611fc92fe535c5e2e58a6a446375bb5e3b471440af21bbe327384befb50a";

// Authorization token for tests Stacks client protected endpoints
const STACKS_NODE_AUTH_TOKEN: &str = "12345";

/// Timeout used when waiting for something to happen on Stacks
const STACKS_NODE_TIMEOUT: Duration = Duration::from_secs(10);
/// Polling used when waiting for something to happen on Stacks
const STACKS_NODE_POLLING: Duration = Duration::from_millis(200);

// Wait until the uSTX balance of an address satisfies a predicate, or panic on timeout
pub async fn wait_for_stx_balance<F>(
    stacks_client: &StacksClient,
    address: &StacksAddress,
    predicate: F,
) where
    F: Fn(u128) -> bool,
{
    let polling_fut = async {
        while !predicate(stacks_client.get_account(address).await.unwrap().balance) {
            tokio::time::sleep(STACKS_NODE_POLLING).await;
        }
    };
    polling_fut
        .with_timeout(STACKS_NODE_TIMEOUT)
        .await
        .expect("failed to wait for stx balance");
}

// Wait until the nonce of an address changes, or panic on timeout
pub async fn wait_for_new_nonce(
    stacks_client: &StacksClient,
    address: &StacksAddress,
    old_nonce: u64,
) {
    let polling_fut = async {
        while stacks_client.get_account(address).await.unwrap().nonce <= old_nonce {
            tokio::time::sleep(STACKS_NODE_POLLING).await;
        }
    };
    polling_fut
        .with_timeout(STACKS_NODE_TIMEOUT)
        .await
        .expect("failed to wait for new nonce");
}

/// Get a Nakamoto Stacks block by block height
pub async fn get_block_by_height(
    stacks_client: &StacksClient,
    block_height: u64,
) -> Result<NakamotoBlock, Error> {
    let path = format!("/v3/blocks/height/{block_height}");
    let url = stacks_client
        .endpoint
        .join(&path)
        .map_err(|err| Error::PathJoin(err, stacks_client.endpoint.clone(), Cow::Owned(path)))?;

    let block_bytes = stacks_client
        .client
        .get(url)
        .send()
        .await
        .map_err(Error::StacksNodeRequest)?
        .error_for_status()
        .map_err(Error::StacksNodeResponse)?
        .bytes()
        .await
        .map_err(Error::UnexpectedStacksResponse)?;

    NakamotoBlock::consensus_deserialize(&mut &*block_bytes).map_err(Error::StacksCodec)
}

/// Response model for `/v3/blocks/replay/{block_id}`, omitting unused fields
#[derive(Debug, serde::Deserialize)]
pub struct BlockReplay {
    pub block_id: StacksBlockHash,
    pub transactions: Vec<BlockReplayTransaction>,
}

#[derive(Debug, serde::Deserialize)]
pub struct BlockReplayTransaction {
    pub events: Vec<TransactionEvent>,
}

/// Replay a Nakamoto block and return its effects
pub async fn block_replay(
    stacks_client: &StacksClient,
    block_id: StacksBlockHash,
) -> Result<BlockReplay, Error> {
    let path = format!("/v3/blocks/replay/{block_id}");
    let url = stacks_client
        .endpoint
        .join(&path)
        .map_err(|err| Error::PathJoin(err, stacks_client.endpoint.clone(), Cow::Owned(path)))?;

    stacks_client
        .client
        .get(url)
        .header("authorization", STACKS_NODE_AUTH_TOKEN)
        .send()
        .await
        .map_err(Error::StacksNodeRequest)?
        .error_for_status()
        .map_err(Error::StacksNodeResponse)?
        .json()
        .await
        .map_err(Error::UnexpectedStacksResponse)
}

pub fn principal_to_address(principal: &PrincipalData) -> StacksAddress {
    let principal = match principal {
        PrincipalData::Standard(addr) => addr.clone(),
        PrincipalData::Contract(QualifiedContractIdentifier { issuer, .. }) => issuer.clone(),
    };
    StacksAddress::from(principal)
}

pub async fn fund_stx(
    stacks_client: &StacksClient,
    recipient: &PrincipalData,
    ustx: u64,
) -> StacksTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), ustx, TokenTransferMemo([0u8; 34]));
    let secret_key = signer::keys::PrivateKey::from_str(FAUCET_PRIVATE_KEY).unwrap();
    create_stacks_tx(stacks_client, payload, &secret_key).await
}

pub async fn create_stacks_tx(
    stacks_client: &StacksClient,
    payload: TransactionPayload,
    sender_sk: &signer::keys::PrivateKey,
) -> StacksTransaction {
    let public_key = signer::keys::PublicKey::from_private_key(sender_sk);

    let sender_addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![public_key.into()],
    )
    .expect("failed to construct the stacks address");

    let nonce = stacks_client
        .get_account(&sender_addr)
        .await
        .expect("cannot get account nonce")
        .nonce;

    let conditions = payload.post_conditions();

    let auth = SinglesigSpendingCondition {
        signer: sender_addr.bytes().clone(),
        nonce,
        tx_fee: 1000,
        hash_mode: SinglesigHashMode::P2PKH,
        key_encoding: TransactionPublicKeyEncoding::Compressed,
        signature: MessageSignature::empty(),
    };

    let mut tx = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(auth)),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: conditions.post_condition_mode,
        post_conditions: conditions.post_conditions,
        payload: payload.tx_payload(),
    };

    let signature = signer::signature::sign_stacks_tx(&tx, sender_sk).as_stacks_sig();
    match tx.auth {
        TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(ref mut auth)) => {
            auth.set_signature(signature)
        }
        _ => panic!("unexpected tx auth"),
    }

    tx
}

/// Convert a Bitcoin address to the clarity representation
pub fn address_to_clarity_arg(addr: &bitcoin::Address) -> (u8, Vec<u8>) {
    // We cannot use `PoxAddress::from_b58` as it doesn't support regtest addresses
    let addr_data = addr.to_address_data();
    let bytes: &[u8] = match addr_data {
        bitcoin::address::AddressData::P2pkh { ref pubkey_hash } => pubkey_hash.as_ref(),
        bitcoin::address::AddressData::P2sh { ref script_hash } => script_hash.as_ref(),
        bitcoin::address::AddressData::Segwit { ref witness_program } => {
            witness_program.program().as_bytes()
        }
        _ => panic!("unexpected addr"),
    };
    let version: u8 = match addr.address_type().expect("unknown addr type") {
        bitcoin::AddressType::P2pkh => AddressHashMode::SerializeP2PKH as u8,
        bitcoin::AddressType::P2sh => AddressHashMode::SerializeP2SH as u8,
        bitcoin::AddressType::P2wpkh => PoxAddressType20::P2WPKH as u8,
        bitcoin::AddressType::P2wsh => PoxAddressType32::P2WSH as u8,
        bitcoin::AddressType::P2tr => PoxAddressType32::P2TR as u8,
        _ => todo!(),
    };
    (version, bytes.to_vec())
}

#[tokio::test]
async fn update_db_with_unknown_ancestors_process_first_nakamoto_block() {
    // get_epoch_status actually calls get_pox_info under the hood.
    // Block 232 is the first Nakamoto block.
    let raw_json_response_get_epoch_status =
        include_str!("../fixtures/stacksapi-get-pox-info-test-data.json");

    // Two tenure header mocks were obtained by curling the Hiro API for
    // mainnet consensus hashes ch_1 and ch_2 (which correspond to blocks
    // 900_000 and 899_999), and tweaking anchor heights, such that ch_1 is
    // the second Nakamoto block, ch_2 is the first Nakamoto block,
    // according to stacksapi-get-pox-info-test-data.json
    let raw_json_response_get_tenure_headers_1 =
        include_str!("../fixtures/stacksapi-v3-tenures-blocks-1.json");
    let raw_json_response_get_tenure_headers_2 =
        include_str!("../fixtures/stacksapi-v3-tenures-blocks-2.json");

    let ch_1 = ConsensusHash::from_hex("d9f1486525e738d818fee87c4739b87e03bf35e4").unwrap();
    let ch_2 = ConsensusHash::from_hex("3f30756abe6808071ecdf94f7485cee10624667d").unwrap();

    let mut stacks_node_server = mockito::Server::new_async().await;
    let mock_get_epoch_status = stacks_node_server
        .mock("GET", "/v2/pox")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_epoch_status)
        .expect(1)
        .create();

    let mock_get_tenure_headers_1 = stacks_node_server
        .mock("GET", format!("/v3/tenures/blocks/{ch_1}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_tenure_headers_1)
        .expect(1)
        .create();
    let mock_get_tenure_headers_2 = stacks_node_server
        .mock("GET", format!("/v3/tenures/blocks/{ch_2}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_tenure_headers_2)
        .expect(1)
        .create();

    let client =
        StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

    let storage = signer::testing::storage::new_test_database().await;

    update_db_with_unknown_ancestors(&client, &storage, ch_1)
        .await
        .unwrap();

    // These values equal the smallest height in mock 2 and the biggest in mock 1.
    let actual_start_height = 1507180;
    let actual_end_height = 1507233;

    assert_db_contains_stacks_headers(&storage, actual_start_height, actual_end_height).await;

    mock_get_epoch_status.assert();
    mock_get_tenure_headers_1.assert();
    mock_get_tenure_headers_2.assert();

    signer::testing::storage::drop_db(storage).await;
}

#[tokio::test]
async fn update_db_with_unknown_ancestors_process_stops_when_fetches_seen_block() {
    // get_epoch_status actually calls get_pox_info under the hood.
    // Block 232 is the first Nakamoto block.
    let raw_json_response_get_epoch_status =
        include_str!("../fixtures/stacksapi-get-pox-info-test-data.json");

    // Two tenure header mocks were obtained by curling the Hiro API for
    // mainnet consensus hashes ch_1 and ch_2 (which correspond to blocks
    // 900_000 and 899_999), and tweaking anchor heights, such that ch_1 is
    // the second Nakamoto block, ch_2 is the first Nakamoto block,
    // according to stacksapi-get-pox-info-test-data.json
    let raw_json_response_get_tenure_headers_1 =
        include_str!("../fixtures/stacksapi-v3-tenures-blocks-1.json");
    let raw_json_response_get_tenure_headers_2 =
        include_str!("../fixtures/stacksapi-v3-tenures-blocks-2.json");

    let ch_1 = ConsensusHash::from_hex("d9f1486525e738d818fee87c4739b87e03bf35e4").unwrap();
    let ch_2 = ConsensusHash::from_hex("3f30756abe6808071ecdf94f7485cee10624667d").unwrap();

    let mut stacks_node_server = mockito::Server::new_async().await;
    let mock_get_epoch_status = stacks_node_server
        .mock("GET", "/v2/pox")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_epoch_status)
        .expect(2)
        .create();

    let mock_get_tenure_headers_1 = stacks_node_server
        .mock("GET", format!("/v3/tenures/blocks/{ch_1}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_tenure_headers_1)
        .expect(1)
        .create();
    let mock_get_tenure_headers_2 = stacks_node_server
        .mock("GET", format!("/v3/tenures/blocks/{ch_2}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_tenure_headers_2)
        .expect(1)
        .create();

    let client =
        StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

    let storage = signer::testing::storage::new_test_database().await;

    // First, call update ancestors for ch_2, such that blocks
    // corresponding to ch_2 will be present in the db. This should trigger
    // mock_get_epoch_status once, and mock_get_tenure_headers_2, but not
    // mock_get_tenure_headers_1
    update_db_with_unknown_ancestors(&client, &storage, ch_2)
        .await
        .unwrap();

    // At this point we have only blocks corresponding to ch_2 in the db.

    // These values equal the smallest height in mock 2 and the biggest in
    // mock 2.
    let actual_start_height_ch2 = 1507180;
    let actual_end_height_ch2 = 1507194;

    assert_db_contains_stacks_headers(&storage, actual_start_height_ch2, actual_end_height_ch2)
        .await;

    // Now, we call update_db_with_unknown_ancestors again for ch_1, and
    // the mocks ensure that it calls mock_get_epoch_status once and
    // mock_get_tenure_headers_1, avoiding calling
    // mock_get_tenure_headers_2
    update_db_with_unknown_ancestors(&client, &storage, ch_1)
        .await
        .unwrap();

    // At this point we have blocks corresponding to both ch_1 and ch_2 in
    // the db. The written block heights should equal the smallest height
    // in mock 2 and the biggest in mock 1.
    let actual_end_height_ch1 = 1507233;

    assert_db_contains_stacks_headers(&storage, actual_start_height_ch2, actual_end_height_ch1)
        .await;

    mock_get_epoch_status.assert();
    mock_get_tenure_headers_1.assert();
    mock_get_tenure_headers_2.assert();

    signer::testing::storage::drop_db(storage).await;
}

#[tokio::test]
async fn update_db_with_unknown_ancestors_works_with_empty_tenures() {
    // get_epoch_status actually calls get_pox_info under the hood.
    // Block 232 is the first Nakamoto block.
    let raw_json_response_get_epoch_status =
        include_str!("../fixtures/stacksapi-get-pox-info-test-data.json");

    // We are setting up the mocks as follows:
    // mock1 -- height 234, empty block
    // mock2 -- height 233, non-empty block
    // mock3 -- height 232, empty block. Also, it's the nakamoto start height
    // --------------------------------
    let raw_json_response_get_tenure_headers_1 = r#"{
        "consensus_hash": "1230756abe6808071ecdf94f7485cee10624667d",
        "last_sortition_ch": "d9f1486525e738d818fee87c4739b87e03bf35e4",
        "burn_block_height": 234,
        "burn_block_hash": "0000000000000000000196400396be46d0816dc462df4c3450972f589f4d7d24",
        "stacks_blocks": []
    }"#;

    let raw_json_response_get_tenure_headers_2 =
        include_str!("../fixtures/stacksapi-v3-tenures-blocks-1.json");

    let raw_json_response_get_tenure_headers_3 = r#"{
        "consensus_hash": "3f30756abe6808071ecdf94f7485cee10624667d",
        "last_sortition_ch": "39fa0bf52fbe50fccd43ba9ffcacae39793231bc",
        "burn_block_height": 232,
        "burn_block_hash": "0000000000000000000196400396be46d0816dc462df4c3450972f589f4d7d24",
        "stacks_blocks": []
    }"#;

    let ch_1 = ConsensusHash::from_hex("1230756abe6808071ecdf94f7485cee10624667d").unwrap();
    let ch_2 = ConsensusHash::from_hex("d9f1486525e738d818fee87c4739b87e03bf35e4").unwrap();
    let ch_3 = ConsensusHash::from_hex("3f30756abe6808071ecdf94f7485cee10624667d").unwrap();

    let mut stacks_node_server = mockito::Server::new_async().await;
    let mock_get_epoch_status = stacks_node_server
        .mock("GET", "/v2/pox")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_epoch_status)
        .expect(1)
        .create();

    let mock_get_tenure_headers_1 = stacks_node_server
        .mock("GET", format!("/v3/tenures/blocks/{ch_1}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_tenure_headers_1)
        .expect(1)
        .create();
    let mock_get_tenure_headers_2 = stacks_node_server
        .mock("GET", format!("/v3/tenures/blocks/{ch_2}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_tenure_headers_2)
        .expect(1)
        .create();
    let mock_get_tenure_headers_3 = stacks_node_server
        .mock("GET", format!("/v3/tenures/blocks/{ch_3}").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(raw_json_response_get_tenure_headers_3)
        .expect(1)
        .create();

    let client =
        StacksClient::new(url::Url::parse(stacks_node_server.url().as_str()).unwrap()).unwrap();

    let storage = signer::testing::storage::new_test_database().await;

    // Now, let's call update_db_with_unknown_ancestors and ensure that it
    // correctly fetched all blocks corresponding to ch_1 but no other
    // blocks
    update_db_with_unknown_ancestors(&client, &storage, ch_1)
        .await
        .unwrap();

    let actual_start_height = 1507195;
    let actual_end_height = 1507233;

    assert_db_contains_stacks_headers(&storage, actual_start_height, actual_end_height).await;

    mock_get_epoch_status.assert();
    mock_get_tenure_headers_1.assert();
    mock_get_tenure_headers_2.assert();
    mock_get_tenure_headers_3.assert();

    signer::testing::storage::drop_db(storage).await;
}
