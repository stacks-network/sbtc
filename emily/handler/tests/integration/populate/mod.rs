//! Populates the Emily database with entries.
//!
//! Note: This whole file is tech debt; there should be a command line method for
//! populating the database.
//!
//! TODO(370): Move this functionality to a CLI command.

use emily_handler::api::models::{
    chainstate::Chainstate,
    deposit::{requests::CreateDepositRequestBody, responses::CreateDepositResponse, Deposit},
    withdrawal::{
        requests::CreateWithdrawalRequestBody, responses::CreateWithdrawalResponse,
        WithdrawalParameters,
    },
};
use rand::Rng;
use reqwest::Client;

const EMILY_ENDPOINT: &'static str = "http://localhost:3000";
const NUM_ENTRIES: u32 = 1000;

/// Populates emily.
#[cfg_attr(not(feature = "populate"), ignore)]
#[tokio::test]
pub async fn populate_emily() {
    let client = Client::new();
    create_deposits(&client).await;
    create_withdrawals(&client).await;
    create_chainstates(&client).await;
}

async fn create_deposits(client: &Client) {
    let mut rng = rand::thread_rng();
    for i in 0..NUM_ENTRIES {
        let n = rng.gen_range(1..=3);
        for j in 0..n {
            let offset = rng.gen_range(1..=4);
            let create_request = CreateDepositRequestBody {
                bitcoin_txid: format!("txid-{i}"),
                bitcoin_tx_output_index: j + offset,
                reclaim: format!("reclaim-script-{i}"),
                deposit: format!("deposit-script-{i}"),
            };
            create_deposit(client, create_request).await;
        }
    }
}

async fn create_deposit(
    client: &Client,
    request: CreateDepositRequestBody,
) -> CreateDepositResponse {
    client
        .post(format!("{EMILY_ENDPOINT}/deposit"))
        .json(&request)
        .send()
        .await
        .expect("Create deposit request should succeed")
        .json()
        .await
        .expect("Failed to deserialize create deposit request response")
}

async fn create_withdrawals(client: &Client) {
    let mut rng = rand::thread_rng();
    for i in 0..NUM_ENTRIES {
        let create_request = CreateWithdrawalRequestBody {
            request_id: i as u64,
            stacks_block_hash: format!("stacks-block-hash-{i}"),
            recipient: format!("recipient-{i}"),
            amount: rng.gen_range(1000..=1000000) as u64,
            parameters: WithdrawalParameters {
                max_fee: rng.gen_range(100..=300),
            },
        };
        create_withdrawal(client, create_request).await;
    }
}

async fn create_withdrawal(
    client: &Client,
    request: CreateWithdrawalRequestBody,
) -> CreateWithdrawalResponse {
    client
        .post(format!("{EMILY_ENDPOINT}/withdrawal"))
        .json(&request)
        .send()
        .await
        .expect("Create withdrawal request should succeed")
        .json()
        .await
        .expect("Failed to deserialize create withdrawal request response")
}

async fn create_chainstates(client: &Client) {
    for i in 0..NUM_ENTRIES {
        let create_request = Chainstate {
            stacks_block_height: i as u64,
            stacks_block_hash: format!("stacks-block-hash-{i}"),
        };
        create_chainstate(client, create_request).await;
    }
}

async fn create_chainstate(client: &Client, request: Chainstate) -> Chainstate {
    client
        .post(format!("{EMILY_ENDPOINT}/chainstate"))
        .json(&request)
        .send()
        .await
        .expect("Create chainstate request should succeed")
        .json()
        .await
        .expect("Failed to deserialize create chainstate request response")
}
