use bitcoin::{absolute::LockTime, hashes::Hash as _, transaction::Version, BlockHash};
use bitcoincore_rpc::RpcApi as _;
use sbtc::{rpc::BitcoinCoreClient, testing::regtest};
use signer::{bitcoin::BitcoinInteract, util::ApiFallbackClient};
use url::Url;

#[tokio::test]
async fn test_get_block_not_found() {
    let url: Url = "http://devnet:devnet@localhost:18443".parse().unwrap();
    let client = BitcoinCoreClient::try_from(url).unwrap();
    let result = client.inner_client().get_block(&BlockHash::all_zeros());

    // This will return: JsonRpc(Rpc(RpcError { code: -5, message: "Block not found", data: None }))
    assert!(matches!(
        result.unwrap_err(),
        bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(rpc_error))
            if rpc_error.code == -5
    ))
}

// TODO: Figure out how to let this (and similar tests) run against the wallet
// generated by `initialize_blockchain()`. See comment in the test below.
//#[ignore = "This test needs to be run against a 'fresh' bitcoin core instance"]
#[tokio::test]
async fn test_get_block_works() {
    let (_, faucet) = regtest::initialize_blockchain();
    let blocks = faucet.generate_blocks(5);

    let url: Url = "http://devnet:devnet@localhost:18443".parse().unwrap();

    let client =
        ApiFallbackClient::<BitcoinCoreClient>::new(vec![
            BitcoinCoreClient::try_from(url.clone()).unwrap()
        ])
        .unwrap();

    // Double-check that an all-zero block doesn't return an error or something else unexpected.
    let block = client.get_block(&BlockHash::all_zeros()).await;
    assert!(block.is_ok_and(|x| x.is_none()));

    for block in blocks.iter() {
        let b = client
            .get_block(block)
            .await
            .expect("failed to get block")
            .expect("expected to receive a block, not None");

        assert_eq!(b.header.block_hash(), *block);
    }
}

// TODO: Complete this test with inputs/outputs (it currently fails as the
// transaction is invalid). I didn't do this for now as it takes time, but I
// wanted to get a skeleton in place.
#[ignore = "This test needs to be completed (i.e. with inputs/outputs"]
#[tokio::test]
async fn broadcast_tx_works() {
    let url: Url = "http://devnet:devnet@localhost:18443".parse().unwrap();
    let client = ApiFallbackClient::<BitcoinCoreClient>::try_from([url].as_slice()).unwrap();

    let tx = bitcoin::Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    client.broadcast_transaction(&tx).await.unwrap();
}
