//! Handlers for sBTC withdrawal API operations

use std::collections::HashMap;

use emily::models;
use crate::common;
use crate::errors;

/// Handles the creation of a withdrawal request
pub fn handle_create_withdrawal(
    body:  Option<String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    common::deserialize_request::<models::CreateWithdrawalRequestContent>(body).map(|_request| models::CreateWithdrawalResponseContent {
                request_id: "BitcoinTxIdHere".to_string(),
                block_height: 124452.0,
                block_hash: "CountryStyle".to_string(),
                recipient: "Michael Jackson".to_string(),
                amount: 11111.0,
                status: emily::models::OpStatus::Pending,
                status_message: "Heehee".to_string(),
                parameters: Box::new(models::WithdrawalParameters {
                    max_fee: 33333.0,
                }),
                last_update_block_hash: "LastUpdateBlockHash".to_string(),
                last_update_height: 1234888.0,
                fulfillment: None, // Unknown at creation
            })
        .and_then(|response| {
            common::package_response(response, 201)
        })
}

/// Handles the retrieval of a single withdrawal transaction
pub fn handle_get_withdrawal(
    _path_parameters:  HashMap<String, String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    Ok(models::GetWithdrawalResponseContent {
        request_id: "BitcoinTxIdHere".to_string(),
        block_height: 124452.0,
        block_hash: "CountryStyle".to_string(),
        recipient: "Michael Jackson".to_string(),
        amount: 11111.0,
        status: emily::models::OpStatus::Confirmed,
        status_message: "Heehee".to_string(),
        parameters: Box::new(models::WithdrawalParameters {
            max_fee: 33333.0,
        }),
        last_update_block_hash: "LastUpdateBlockHash".to_string(),
        last_update_height: 1234888.0,
        fulfillment: Some(Box::new(models::Fulfillment {
            bitcoin_txid: Some("fulfillment-bitcoin-txid".to_string()),
            bitcoin_tx_index: Some(0.0),
            bitcoin_block_hash: Some("BitcoinBlockHashHerere".to_string()),
            bitcoin_block_height: Some(421.0),
            txid: Some("fulfillment-stacks-txid".to_string()),
            btc_fee: Some(234.0),
        })),
    })
    .and_then(|response| {
        common::package_response(response, 200)
    })
}

/// Handles the retrieval of a multiple withdrawal transaction
pub fn handle_get_withdrawals(
    _path_parameters:  HashMap<String, String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    Ok(models::GetWithdrawalsResponseContent {
        next_token: Some("Cassandra".to_string()),
        withdrawals: Some(vec![
            models::WithdrawalBasicInfo {
                request_id: "BitcoinTxIdHere".to_string(),
                block_hash: "CountryStyle".to_string(),
                recipient: "Michael Jackson".to_string(),
                amount: 11111.0,
                status: emily::models::OpStatus::Confirmed,
                last_update_block_hash: "Michael Jackson".to_string(), // Unknown at creation
                last_update_height: 256.0, // Unknown at creation
            },
            models::WithdrawalBasicInfo {
                request_id: "SecondBitcoinTxIdHere".to_string(),
                block_hash: "iLikeTurtles".to_string(),
                recipient: "YourFriendBarneyTheDinosaur".to_string(),
                amount: 111142.0,
                status: emily::models::OpStatus::Failed,
                last_update_block_hash: "Rejected by Signers".to_string(), // Unknown at creation
                last_update_height: 512.0, // Unknown at creation
            },
        ])
    })
    .and_then(|response| {
        common::package_response(response, 200)
    })
}

/// Handles the update of withdrawal transactions
pub fn handle_update_withdrawals(
    body:  Option<String>
) -> Result<common::SimpleApiResponse, errors::EmilyApiError> {
    common::deserialize_request::<models::UpdateWithdrawalsRequestContent>(body).map(|_request| models::UpdateWithdrawalsResponseContent {
                withdrawals: Some(vec![
                    models::WithdrawalData {
                        request_id: "BitcoinTxIdHere".to_string(),
                        block_height: 124452.0,
                        block_hash: "CountryStyle".to_string(),
                        recipient: "Michael Jackson".to_string(),
                        amount: 11111.0,
                        status: emily::models::OpStatus::Pending,
                        status_message: "Heehee".to_string(),
                        parameters: Box::new(models::WithdrawalParameters {
                            max_fee: 33333.0,
                        }),
                        last_update_block_hash: "LastUpdateBlockHash".to_string(),
                        last_update_height: 1234888.0,
                        fulfillment: None, // Unknown at creation
                    },
                    models::WithdrawalData {
                        request_id: "BitcoinTxIdHere".to_string(),
                        block_height: 124452.0,
                        block_hash: "CountryStyle".to_string(),
                        recipient: "Michael Jackson".to_string(),
                        amount: 11111.0,
                        status: emily::models::OpStatus::Pending,
                        status_message: "Heehee".to_string(),
                        parameters: Box::new(models::WithdrawalParameters {
                            max_fee: 33333.0,
                        }),
                        last_update_block_hash: "LastUpdateBlockHash".to_string(),
                        last_update_height: 1234888.0,
                        fulfillment: None, // Unknown at creation
                    }
                ])
            })
        .and_then(|response| {
            // Return 202 because this PUT operation won't be reflected in GET calls
            // until the change is consistent in DynamoDB (<1 second).
            common::package_response(response, 202)
        })
}

// Tested in `bin/entrypoint.rs`. Tests will be added here when these outputs no longer mock.
