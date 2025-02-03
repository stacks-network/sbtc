//! Request structures for deposit api calls.

use std::str::FromStr;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use sbtc::deposits::{CreateDepositRequest, DepositInfo};

use crate::api::models::common::{Fulfillment, Status};
use crate::api::models::limits::Limits;
use crate::common::error::Error;

/// Query structure for the GetDepositsQuery struct.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetDepositsForTransactionQuery {
    /// Next token for the search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    /// Maximum number of results to show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u16>,
}

/// Query structure for the GetDepositsQuery struct.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetDepositsQuery {
    /// Operation status.
    pub status: Status,
    /// Next token for the search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    /// Maximum number of results to show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u16>,
}

/// Query structure common for all paginated queries.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BasicPaginationQuery {
    /// Next token for the search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    /// Maximum number of results to show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u16>,
}

/// Request structure for create deposit request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateDepositRequestBody {
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub bitcoin_tx_output_index: u32,
    /// Reclaim script.
    pub reclaim_script: String,
    /// Deposit script.
    pub deposit_script: String,
    /// The raw transaction hex.
    pub transaction_hex: String,
}

/// This is the dust limit for deposits in the sBTC smart contracts.
/// Deposit amounts that is less than this amount will be rejected by the
/// smart contract.
pub const DEPOSIT_DUST_LIMIT: u64 = 546;

fn parse_hex<T, F, E>(input: &str, error_msg: &str, parser: F) -> Result<T, Error>
where
    F: Fn(&str) -> Result<T, E>,
{
    parser(input).map_err(|_| Error::HttpRequest(StatusCode::BAD_REQUEST, error_msg.to_string()))
}

impl CreateDepositRequestBody {
    /// Validates that the deposit request is valid.
    /// This includes validating the request fields, if their content matches the transaction
    /// and if the amount is within the limits.
    pub fn validate(&self, limits: &Limits, is_mainnet: bool) -> Result<DepositInfo, Error> {
        let deposit_req = CreateDepositRequest {
            outpoint: OutPoint {
                txid: parse_hex(&self.bitcoin_txid, "invalid bitcoin_txid", Txid::from_str)?,
                vout: self.bitcoin_tx_output_index,
            },
            reclaim_script: parse_hex(
                &self.reclaim_script,
                "invalid reclaim_script",
                ScriptBuf::from_hex,
            )?,
            deposit_script: parse_hex(
                &self.deposit_script,
                "invalid deposit_script",
                ScriptBuf::from_hex,
            )?,
        };

        let tx: Transaction = parse_hex(
            &self.transaction_hex,
            "invalid transaction_hex",
            encode::deserialize_hex,
        )?;

        let amount = tx
            .tx_out(self.bitcoin_tx_output_index as usize)
            .map_err(|_| {
                Error::HttpRequest(
                    StatusCode::BAD_REQUEST,
                    "invalid bitcoin_output_index".to_string(),
                )
            })?
            .value
            .to_sat();

        // Even if no limits are set, the deposit amount should be higher than the dust limit.
        let min = limits.per_deposit_minimum.unwrap_or(DEPOSIT_DUST_LIMIT);
        if amount < min {
            return Err(Error::HttpRequest(
                StatusCode::BAD_REQUEST,
                format!("deposit amount below minimum ({})", min),
            ));
        }

        let cap = limits.per_deposit_cap.unwrap_or(Amount::MAX_MONEY.to_sat());
        if amount > cap {
            return Err(Error::HttpRequest(
                StatusCode::BAD_REQUEST,
                format!("deposit amount exceeds cap ({})", cap),
            ));
        }

        deposit_req
            .validate_tx(&tx, is_mainnet)
            .map_err(|e| Error::HttpRequest(StatusCode::BAD_REQUEST, e.to_string()))
    }
}

/// A singular Deposit update that contains only the fields pertinent
/// to updating the status of a deposit. This includes the key related
/// data in addition to status history related data.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DepositUpdate {
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,
    /// Output index on the bitcoin transaction associated with this specific deposit.
    pub bitcoin_tx_output_index: u32,
    /// The most recent Stacks block height the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this height is the Stacks block height that contains that artifact.
    pub last_update_height: u64,
    /// The most recent Stacks block hash the API was aware of when the deposit was last
    /// updated. If the most recent update is tied to an artifact on the Stacks blockchain
    /// then this hash is the Stacks block hash that contains that artifact.
    pub last_update_block_hash: String,
    /// The status of the deposit.
    pub status: Status,
    /// The status message of the deposit.
    pub status_message: String,
    /// Details about the on chain artifacts that fulfilled the deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
}

/// Request structure for update deposit request.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDepositsRequestBody {
    /// Bitcoin transaction id.
    pub deposits: Vec<DepositUpdate>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    const CREATE_DEPOSIT_VALID: &str =
        include_str!("../../../../tests/fixtures/create-deposit-valid.json");

    const CREATE_DEPOSIT_INVALID_TXID: &str =
        include_str!("../../../../tests/fixtures/create-deposit-invalid-txid.json");

    const CREATE_DEPOSIT_INVALID_OUTPUT_INDEX: &str =
        include_str!("../../../../tests/fixtures/create-deposit-invalid-output-index.json");

    const CREATE_DEPOSIT_INVALID_RECLAIM_SCRIPT: &str =
        include_str!("../../../../tests/fixtures/create-deposit-invalid-reclaim-script.json");

    const CREATE_DEPOSIT_INVALID_DEPOSIT_SCRIPT: &str =
        include_str!("../../../../tests/fixtures/create-deposit-invalid-deposit-script.json");

    const CREATE_DEPOSIT_INVALID_TRANSACTION_HEX: &str =
        include_str!("../../../../tests/fixtures/create-deposit-invalid-transaction-hex.json");

    const CREATE_DEPOSIT_MISMATCH_TXID: &str =
        include_str!("../../../../tests/fixtures/create-deposit-mismatch-txid.json");

    const CREATE_DEPOSIT_MISMATCH_RECLAIM_SCRIPT: &str =
        include_str!("../../../../tests/fixtures/create-deposit-mismatch-reclaim-script.json");

    const CREATE_DEPOSIT_MISMATCH_DEPOSIT_SCRIPT: &str =
        include_str!("../../../../tests/fixtures/create-deposit-mismatch-deposit-script.json");

    mod helpers {
        use super::*;

        pub fn create_test_limits(min: Option<u64>, max: Option<u64>) -> Limits {
            Limits {
                per_deposit_minimum: min,
                per_deposit_cap: max,
                ..Default::default()
            }
        }

        pub fn parse_request(json: &str) -> CreateDepositRequestBody {
            serde_json::from_str(json).expect("failed to parse request")
        }
    }

    #[tokio::test]
    async fn test_deposit_validate_happy_path() {
        let deposit_request = helpers::parse_request(CREATE_DEPOSIT_VALID);
        let limits = helpers::create_test_limits(None, None);
        assert!(deposit_request.validate(&limits, true).is_ok());
    }

    #[test_case(CREATE_DEPOSIT_INVALID_TXID, "invalid bitcoin_txid"; "invalid_txid")]
    #[test_case(CREATE_DEPOSIT_INVALID_RECLAIM_SCRIPT, "invalid reclaim_script"; "invalid_reclaim_script")]
    #[test_case(CREATE_DEPOSIT_INVALID_DEPOSIT_SCRIPT, "invalid deposit_script"; "invalid_deposit_script")]
    #[test_case(CREATE_DEPOSIT_INVALID_TRANSACTION_HEX, "invalid transaction_hex"; "invalid_transaction_hex")]
    #[test_case(CREATE_DEPOSIT_INVALID_OUTPUT_INDEX, "invalid bitcoin_output_index"; "invalid_output_index")]
    #[test_case(CREATE_DEPOSIT_MISMATCH_TXID, "The txid of the transaction did not match the given txid"; "mismatch_txid")]
    #[test_case(
        CREATE_DEPOSIT_MISMATCH_RECLAIM_SCRIPT,
        "mismatch in expected and actual ScriptPubKeys. outpoint: f75cb869600c6a75ab90c872435da38d54d53c27afe5e03ac7dedae7822958de:0";
        "mismatch_reclaim_script")]
    #[test_case(
        CREATE_DEPOSIT_MISMATCH_DEPOSIT_SCRIPT,
        "mismatch in expected and actual ScriptPubKeys. outpoint: f75cb869600c6a75ab90c872435da38d54d53c27afe5e03ac7dedae7822958de:0";
        "mismatch_deposit_script")]
    #[tokio::test]
    async fn test_deposit_validate_errors(input: &str, expected_error: &str) {
        let deposit_request = helpers::parse_request(input);
        let limits = helpers::create_test_limits(Some(DEPOSIT_DUST_LIMIT), None);

        let result = deposit_request.validate(&limits, true);
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("HTTP request failed with status code 400 Bad Request: {expected_error}")
        );
    }

    // CREATE_DEPOSIT_VALID has a deposit amount of 1_000_000 satoshis.
    #[test_case(CREATE_DEPOSIT_VALID, None, None; "no_limits")]
    #[test_case(CREATE_DEPOSIT_VALID, Some(DEPOSIT_DUST_LIMIT), None; "min_limit")]
    #[test_case(CREATE_DEPOSIT_VALID, None, Some(1_000_000_000); "max_limit")]
    #[test_case(CREATE_DEPOSIT_VALID, Some(DEPOSIT_DUST_LIMIT), Some(1_000_000_000); "min_max_limit")]
    #[tokio::test]
    async fn test_deposit_validate_limits(input: &str, min: Option<u64>, max: Option<u64>) {
        let deposit_request = helpers::parse_request(input);
        let limits = helpers::create_test_limits(min, max);
        assert!(deposit_request.validate(&limits, true).is_ok());
    }

    #[test_case(CREATE_DEPOSIT_VALID, Some(1_000_000 + 1), None, "deposit amount below minimum (1000001)"; "below_min_limit")]
    #[test_case(CREATE_DEPOSIT_VALID, None, Some(999_999), "deposit amount exceeds cap (999999)"; "above_max_limit")]
    #[tokio::test]
    async fn test_deposit_validate_limits_errors(
        input: &str,
        min: Option<u64>,
        max: Option<u64>,
        expected_error: &str,
    ) {
        let deposit_request = helpers::parse_request(input);
        let limits = helpers::create_test_limits(min, max);

        let result = deposit_request.validate(&limits, true);

        assert_eq!(
            result.unwrap_err().to_string(),
            format!("HTTP request failed with status code 400 Bad Request: {expected_error}")
        );
    }
}
