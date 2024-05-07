use std::collections::HashMap;

use emily::models;
use crate::common;
use crate::errors;

pub fn handle_create_deposit(
    body:  Option<String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    common::deserialize_request::<models::CreateDepositRequestContent>(body).map(|request| models::CreateDepositResponseContent {
                bitcoin_txid: request.bitcoin_txid.to_string(),
                bitcoin_tx_output_index: request.bitcoin_tx_output_index,
                recipient: "MOCK_RECIPIENT".to_string(),
                amount: 11111.0,
                status: emily::models::OpStatus::Pending,
                status_message: "MOCK_CREATE_DEPOSIT_RESPONSE".to_string(),
                parameters: Box::new(models::DepositParameters {
                    lock_time:22222.0,
                    max_fee: 33333.0,
                    reclaim_script: "MOCK_RECLAIM_SCRIPT".to_string()
                }),
                last_update_block_hash: None, // Unknown at creation
                last_update_height: None, // Unknown at creation
                fulfillment: None, // Unknown at creation
            })
        .and_then(|response| {
            common::package_response(response, 201)
        })
}

pub fn handle_get_txn_deposits(
    _path_parameters:  HashMap<String, String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    Ok(models::GetTxnDepositsResponseContent {
        next_token: Some("Cassandra".to_string()),
        deposits: Some(vec![
            models::DepositData {
                bitcoin_txid: "Bongo".to_string(),
                bitcoin_tx_output_index: 1.0,
                recipient: "Refrigerator".to_string(),
                amount: 1000000000.0,
                last_update_height: Some(3.0),
                last_update_block_hash: Some("TheRefrigeratorIsRunnin".to_string()),
                status: models::OpStatus::Failed,
                status_message: "Soup is for the soul".to_string(),
                parameters: Box::new(models::DepositParameters {
                    lock_time: 22222.0,
                    max_fee: 33333.0,
                    reclaim_script: "Chicken".to_string(),
                }),
                fulfillment: None, // Unknown at creation
            },
            models::DepositData {
                bitcoin_txid: "Chicken?".to_string(),
                bitcoin_tx_output_index: 1.0,
                recipient: "Churro".to_string(),
                amount: 500000000.0,
                last_update_height: Some(3.0),
                last_update_block_hash: Some("aSmallDog".to_string()),
                status: models::OpStatus::Accepted,
                status_message: "Uzumaki, Naruto will be Hokage".to_string(),
                parameters: Box::new(models::DepositParameters {
                    lock_time: 22222.0,
                    max_fee: 33333.0,
                    reclaim_script: "SometimesIwonderWhoElmoReallyIs.AreTheyHappy?".to_string(),
                }),
                fulfillment: None, // Unknown at creation
            },
        ])
    })
    .and_then(|response| {
        common::package_response(response, 200)
    })
}

pub fn handle_get_deposit(
    _path_parameters:  HashMap<String, String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    Ok(models::GetDepositResponseContent {
        bitcoin_txid: "Samuel".to_string(),
        bitcoin_tx_output_index: 22.0,
        recipient: "George".to_string(),
        amount: 2.0,
        last_update_height: Some(3.0),
        last_update_block_hash: Some("Widdershins".to_string()),
        status: models::OpStatus::Accepted,
        status_message: "Moisturize me!".to_string(),
        parameters: Box::new(models::DepositParameters {
            lock_time: 22222.0,
            max_fee: 33333.0,
            reclaim_script: "Barbara".to_string(),
        }),
        fulfillment: None, // Unknown at creation
    })
    .and_then(|response| {
        common::package_response(response, 200)
    })
}

pub fn handle_get_deposits(
    _path_parameters:  HashMap<String, String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    Ok(models::GetDepositsResponseContent {
        next_token: Some("cheese-coin".to_string()),
        deposits: Some(vec![
            models::DepositBasicInfo {
                bitcoin_txid: "Blood".to_string(),
                bitcoin_tx_output_index: 1.0,
                recipient: "Greg".to_string(),
                amount: 1000000000.0,
                last_update_height: 3.0,
                last_update_block_hash: "Stompy".to_string(),
                status: models::OpStatus::Failed
            },
            models::DepositBasicInfo {
                bitcoin_txid: "Brittany".to_string(),
                bitcoin_tx_output_index: 1.0,
                recipient: "GregAgain".to_string(),
                amount: 300.0,
                last_update_height: 5.0,
                last_update_block_hash: "Adam".to_string(),
                status: models::OpStatus::Accepted
            },
        ])
    })
    .and_then(|response| {
        common::package_response(response, 200)
    })
}


// TODO: Handle Update Deposit
pub fn handle_update_deposits(
    body:  Option<String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    common::deserialize_request::<models::UpdateDepositsRequestContent>(body).map(|_request| models::UpdateDepositsResponseContent {
                deposits: Some(vec![
                    models::DepositData {
                        bitcoin_txid: "Voldemort".to_string(),
                        bitcoin_tx_output_index: 1.0,
                        recipient: "GalileoTheCat".to_string(),
                        amount: 1000000000.0,
                        last_update_height: Some(3.0),
                        last_update_block_hash: Some("HashBrowns".to_string()),
                        status: models::OpStatus::Failed,
                        status_message: "Cortage!".to_string(),
                        parameters: Box::new(models::DepositParameters {
                            lock_time: 22222.0,
                            max_fee: 33333.0,
                            reclaim_script: "iDidntGetMeMoneyGiveMeBakMeMoneyNow".to_string(),
                        }),
                        fulfillment: None,
                    },
                    models::DepositData {
                        bitcoin_txid: "Frederick".to_string(),
                        bitcoin_tx_output_index: 1.0,
                        recipient: "GregAgain".to_string(),
                        amount: 500000000.0,
                        last_update_height: Some(3.0),
                        last_update_block_hash: Some("Candle".to_string()),
                        status: models::OpStatus::Accepted,
                        status_message: "Oh no me arm!".to_string(),
                        parameters: Box::new(models::DepositParameters {
                            lock_time: 22222.0,
                            max_fee: 33333.0,
                            reclaim_script: "Osmosis".to_string()
                        }),
                        fulfillment: None,
                    },
                ])
            })
        .and_then(|response| {
            // Return 202 because this PUT operation won't be reflected in GET calls
            // until the change is consistent in DynamoDB (<1 second).
            common::package_response(response, 202)
        })
}

// Tested in `bin/entrypoint.rs`. Tests will be added here when these outputs no longer mock.
