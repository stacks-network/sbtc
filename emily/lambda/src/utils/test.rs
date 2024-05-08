use serde::{Deserialize, Serialize};
use serde_json::json;

pub static BAD_JSON: &str = "{bad json}";

// Structure that will always fail serialization so we can test serialization failures.
pub struct AlwaysFailSerialization;
impl Serialize for AlwaysFailSerialization {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom("deliberate serialization failure"))
    }
}

pub enum RequestType {
    FULL,
    MINIMAL,
    MALFORMED,
    MISSING,
    EMPTY,
}

// Define test specific structure for deserialization tests so changes to external
// structures don't require that these tests change.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct TestResponse {
    pub message: String,
}

pub fn create_deposit_request_body(request_type: RequestType) -> Option<String> {
    match request_type {
        RequestType::FULL | RequestType::MINIMAL => Some(json!({
            "bitcoinTxid": "123abc",
            "bitcoinTxOutputIndex": 1,
            "reclaim": "TEST_RECLAIM_SCRIPT",
            "deposit": "TEST_DEPOSIT_SCRIPT",
        })),
        RequestType::MALFORMED => Some(json!({
            "bitcoinTxid": "123abc",
            "bitcoinTxOutputIndex": "Not a Number", // <-- malformed.
            "reclaim": "TEST_RECLAIM_SCRIPT",
            "deposit": "TEST_DEPOSIT_SCRIPT",
        })),
        RequestType::MISSING => Some(json!({
            "bitcoinTxid": "123abc",
            "bitcoinTxOutputIndex": 1,
            "reclaim": "TEST_RECLAIM_SCRIPT",
        })),
        RequestType::EMPTY => None
    }.and_then(|value| Some(value.to_string()))
}

pub fn update_deposits_request_body(request_type: RequestType) -> Option<String> {
    match request_type {
        RequestType::FULL => Some(json!({
            "deposits": [
                {
                    "bitcoinTxid": "123abc",
                    "bitcoinTxOutputIndex": 1,
                    "recipient": "TEST_RECIPIENT",
                    "amount": 2134,
                    "lastUpdateHeight": 2415253,
                    "lastUpdateBlockHash": "TEST_BLOCK_HASH",
                    "status": "ACCEPTED",
                    "statusMessage": "TEST_STATUS_MESSAGE",
                    "parameters": {
                        "maxFee": 123,
                        "lockTime": 1253524,
                        "reclaimScript": "TEST_RECLAIM_SCRIPT",
                    },
                    "fulfillment": {
                        "bitcoinTxid": "TEST_BITCOIN_FULFILLMENT_TXID",
                        "bitcoinTxIndex": 4,
                        "txid": "TEST_STACKS_FULFILLMENT_TXID",
                        "bitcoinBlockHash": "TEST_FULFILLMENT_BITCOIN_BLOCK_HASH",
                        "bitcoinBlockHeight": 567898765,
                        "btcFee": 22,
                    }
                }
            ]
        })),
        RequestType::MINIMAL => Some(json!({
            "deposits": [
                {
                    // This would be a silly update because no fields change.
                    "bitcoinTxid": "123abc",
                    "bitcoinTxOutputIndex": 1,
                }
            ]
        })),
        RequestType::MALFORMED => Some(json!({
            "deposits": [
                {
                    "not_a_valid_field": "123abc", // <-- malformed.
                    "bitcoinTxOutputIndex": 1,
                }
            ]
        })),
        RequestType::MISSING => Some(json!({})),
        RequestType::EMPTY => None
    }.and_then(|value| Some(value.to_string()))
}

pub fn create_withdrawal_request_body(request_type: RequestType) -> Option<String> {
    match request_type {
        RequestType::FULL | RequestType::MINIMAL => Some(json!({
            "requestId": "TEST_REQUEST_ID",
            "blockHash": "TEST_STACKS_BLOCK_HASH",
            "blockHeight": 222,
            "recipient": "TEST_RECIPIENT",
            "amount": 5882300,
            "parameters": {
                "maxFee": 1254,
            }
        })),
        RequestType::MALFORMED => Some(json!({
            "requestId": "TEST_REQUEST_ID",
            "blockHash": "TEST_STACKS_BLOCK_HASH",
            "blockHeight": 222,
            "recipient": "TEST_RECIPIENT",
            "amount": 5882300,
            "parameters": {
                "maxFee": "dogs", // <-- malformed.
            }
        })),
        RequestType::MISSING => Some(json!({
            "bitcoinTxid": "123abc",
            "bitcoinTxOutputIndex": 1,
            "reclaim": "TEST_RECLAIM_SCRIPT",
        })),
        RequestType::EMPTY => None
    }.and_then(|value| Some(value.to_string()))
}

pub fn update_withdrawals_request_body(request_type: RequestType) -> Option<String> {
    match request_type {
        RequestType::FULL => Some(json!({
            "withdrawals": [
                {
                    "requestId": "TEST_REQUEST_ID",
                    "blockHash": "TEST_BLOCK_HASH",
                    "recipient": "TEST_RECIPIENT",
                    "amount": 2134,
                    "lastUpdateHeight": 2415253,
                    "lastUpdateBlockHash": "TEST_BLOCK_HASH",
                    "status": "FAILED",
                    "statusMessage": "TEST_STATUS_MESSAGE",
                    "parameters": {
                        "maxFee": 123,
                        "lockTime": 1253524,
                        "reclaimScript": "TEST_RECLAIM_SCRIPT",
                    },
                    "fulfillment": {
                        "bitcoinTxid": "TEST_BITCOIN_FULFILLMENT_TXID",
                        "bitcoinTxIndex": 4,
                        "txid": "TEST_STACKS_FULFILLMENT_TXID",
                        "bitcoinBlockHash": "TEST_FULFILLMENT_BITCOIN_BLOCK_HASH",
                        "bitcoinBlockHeight": 567898765,
                        "btcFee": 22,
                    }
                }
            ]
        })),
        RequestType::MINIMAL => Some(json!({
            "withdrawals": [
                {
                    "requestId": "TEST_REQUEST_ID",
                    "blockHash": "TEST_STACKS_BLOCK_HASH",
                }
            ]
        })),
        RequestType::MALFORMED => Some(json!({
            "withdrawals": [
                {
                    "requestId": 84, // <-- malformed.
                    "blockHash": "TEST_STACKS_BLOCK_HASH",
                }
            ]
        })),
        RequestType::MISSING => Some(json!({})),
        RequestType::EMPTY => None
    }.and_then(|value| Some(value.to_string()))
}


pub fn create_chainstate_request_body(request_type: RequestType) -> Option<String> {
    match request_type {
        RequestType::FULL | RequestType::MINIMAL => Some(json!({
            "blockHash": "TEST_STACKS_BLOCK_HASH",
            "blockHeight": 222,
        })),
        RequestType::MALFORMED => Some(json!({
            "blockHash": 54321, // <-- malformed.
            "blockHeight": 222,
        })),
        RequestType::MISSING => Some(json!({
            "blockHeight": 222,
        })),
        RequestType::EMPTY => None
    }.and_then(|value| Some(value.to_string()))
}

pub fn update_chainstate_request_body(request_type: RequestType) -> Option<String> {
    // Create and update have the same requirements for chainstate.
    create_chainstate_request_body(request_type)
}
