//! Request structures for deposit api calls.

use std::str::FromStr;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode;
use bitcoin::params::Params;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Txid};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tracing;
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
    pub fn validate(
        &self,
        limits: &Limits,
        is_mainnet: bool,
    ) -> Result<ValidatedCreateDepositRequestData, Error> {
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

        let deposit_info = deposit_req
            .validate_tx(&tx, is_mainnet)
            .map_err(|e| Error::HttpRequest(StatusCode::BAD_REQUEST, e.to_string()))?;

        let txin = tx.tx_in(0).map_err(|_| {
            Error::HttpRequest(
                StatusCode::BAD_REQUEST,
                "invalid transaction input".to_string(),
            )
        })?;
        let input_address = {
            let params = if is_mainnet {
                Params::MAINNET
            } else {
                Params::REGTEST
            };
            Address::from_script(&txin.script_sig, params.clone())
                .inspect_err(|_| {
                    tracing::debug!(
                        "unrecognized ScriptBuf format for txid: {}",
                        self.bitcoin_txid
                    );
                })
                .ok()
        };

        Ok(ValidatedCreateDepositRequestData { deposit_info, input_address })
    }
}

/// Validated deposit request data.
#[derive(Debug)]
pub struct ValidatedCreateDepositRequestData {
    /// Deposit information.
    pub deposit_info: DepositInfo,
    /// Input address of the first input in the transaction.
    pub input_address: Option<Address>,
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
    use bitcoin::{AddressType, Network};
    use sbtc::testing;
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
    #[test_case("002065f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3", "bc1qvhu3557twysq2ldn6dut6rmaj3qk04p60h9l79wk4lzgy0ca8mfsnffz65", AddressType::P2wsh; "p2wsh")]
    #[test_case("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac", "132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM", AddressType::P2pkh; "p2pkh")]
    #[test_case("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087", "33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k", AddressType::P2sh; "p2sh")]
    #[test_case("0014841b80d2cc75f5345c482af96294d04fdd66b2b7", "bc1qssdcp5kvwh6nghzg9tuk99xsflwkdv4hgvq58q", AddressType::P2wpkh; "p2wpkh")]
    #[test_case("5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80", "bc1p7dmcmml9zuafhackj463zc3yl9suq0rjts8f3wx63u2a72gefwqqku46c7", AddressType::P2tr; "p2tr")]
    #[tokio::test]
    async fn test_deposit_validate_extracts_address(
        scriptbuf_hex: &str,
        address: &str,
        address_type: AddressType,
    ) {
        let input_sigscript = ScriptBuf::from_hex(scriptbuf_hex).unwrap();
        let mainnet = true;
        let deposit = testing::deposits::tx_setup_with_input_sigscript(
            14,
            8000,
            &[10000],
            input_sigscript,
            mainnet,
        );
        let deposit_request = CreateDepositRequestBody {
            bitcoin_txid: deposit.tx.compute_txid().to_string(),
            bitcoin_tx_output_index: 0,
            reclaim_script: deposit.reclaims[0].reclaim_script().to_hex_string(),
            deposit_script: deposit.deposits[0].deposit_script().to_hex_string(),
            transaction_hex: encode::serialize_hex(&deposit.tx),
        };
        let limits = helpers::create_test_limits(None, None);
        let result = deposit_request.validate(&limits, mainnet).unwrap();

        assert_eq!(
            result.input_address.unwrap().to_string(),
            address.to_string()
        );
        let address = Address::from_str(address).unwrap();
        assert!(address.is_valid_for_network(Network::Bitcoin));
        assert_eq!(
            address.assume_checked().address_type().unwrap(),
            address_type
        );
    }

    #[test_case("524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae"; "p2ms")]
    #[test_case("160014ea940f42d06dfe7ffffd0f8270bf83f3b3d2259d"; "nested-p2wpkh")]
    #[tokio::test]
    async fn test_deposit_validate_for_unsupported_pubscript(scriptbuf_hex: &str) {
        let input_sigscript = ScriptBuf::from_hex(scriptbuf_hex).unwrap();
        let mainnet = true;
        let deposit = testing::deposits::tx_setup_with_input_sigscript(
            14,
            8000,
            &[10000],
            input_sigscript,
            mainnet,
        );
        let deposit_request = CreateDepositRequestBody {
            bitcoin_txid: deposit.tx.compute_txid().to_string(),
            bitcoin_tx_output_index: 0,
            reclaim_script: deposit.reclaims[0].reclaim_script().to_hex_string(),
            deposit_script: deposit.deposits[0].deposit_script().to_hex_string(),
            transaction_hex: encode::serialize_hex(&deposit.tx),
        };
        let limits = helpers::create_test_limits(None, None);
        let result = deposit_request.validate(&limits, mainnet).unwrap();

        assert_eq!(result.input_address, None);
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
