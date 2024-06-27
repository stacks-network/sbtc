use std::convert::From;
use emily::models::{self, OpStatus};
use serde::{Deserialize, Serialize};

/// Deposit table entry key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DepositRequestKey {
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,

    /// Bitcoin transaction output index.
    pub bitcoin_tx_output_index: u16,
}

/// Deposit table entry.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DepositRequest {
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,

    /// Bitcoin transaction output index.
    pub bitcoin_tx_output_index: u16,

    /// Table entry version. Updated on each alteration.
    pub version: u64,

    /// Recipient of the deposit.
    pub recipient: String,

    /// Amount of the deposit.
    pub amount: u64,

    /// Max fee in satoshis to execute the deposit.
    pub max_fee: u64,

    /// Lock time.
    pub lock_time: u64,

    /// Reclaim script.
    pub reclaim_script: String,

    /// Operation status.
    pub op_status: OpStatus,

    /// Last update block height.
    pub last_update_height: u64,

    /// Last update block hash.
    pub last_update_block_hash: String,

    /// Bitcoin transaction id that fulfills the deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment_bitcoin_txid: Option<String>,

    /// Output index on the fulfilling Bitcoin transaction that fulfills the deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment_bitcoin_tx_index: Option<u16>,

    /// Fee on the fulfillment bitcoin transaction paid by this deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment_btc_fee: Option<u64>,

    /// Stacks transaction id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stacks_txid: Option<String>,

    /// History of this deposit transaction.
    pub history: Vec<DepositHistoryEntry>,
}

/// Deposit history entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DepositHistoryEntry {
    /// Status code.
    pub op_status: OpStatus,

    /// Status message.
    pub message: String,

    /// Stacks block heigh at the time of this update.
    pub stacks_block_height: u64,

    /// Stacks block hash associated with the height of this update.
    pub stacks_block_hash: String,
}

/// Deposit basic info key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DepositRequestBasicInfoKey {
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,

    /// Bitcoin transaction output index.
    pub bitcoin_tx_output_index: u16,

    /// Last update block height.
    pub last_update_height: u64,

    /// Operation status.
    pub op_status: OpStatus,
}

/// Deposit basic info resource.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DepositRequestBasicInfo {
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,

    /// Bitcoin transaction output index.
    pub bitcoin_tx_output_index: u16,

    /// Recipient of the deposit.
    pub recipient: String,

    /// Amount of the deposit.
    pub amount: u64,

    /// Last update block height.
    pub last_update_height: u64,

    /// Last update block hash.
    pub last_update_block_hash: String,

    /// Operation status.
    pub op_status: OpStatus,
}

/// Converts from the reduced table version of a Deposit request to the reduced
/// api version of the Deposit request.
impl From<DepositRequestBasicInfo> for models::DepositBasicInfo {
    fn from(deposit_request_basic_info: DepositRequestBasicInfo) -> Self {
        models::DepositBasicInfo {
            bitcoin_txid: deposit_request_basic_info.bitcoin_txid,
            bitcoin_tx_output_index: deposit_request_basic_info.bitcoin_tx_output_index as f64,
            recipient: deposit_request_basic_info.recipient,
            amount: deposit_request_basic_info.amount as f64,
            last_update_height: deposit_request_basic_info.last_update_height as f64,
            last_update_block_hash: deposit_request_basic_info.last_update_block_hash,
            status: deposit_request_basic_info.op_status.into(),
        }
    }
}

/// Converts from Deposit Table Entry to Deposit Resource.
///
/// TODO: [ticket link here once PR is approved]
/// Gracefully handle entry validation failures.
impl From<DepositRequest> for models::DepositData {
    fn from(deposit_request: DepositRequest) -> Self {

        // Get the latest event.
        let latest_event = deposit_request.history
            .last() // There must always be at least one entry.
            .expect(format!("Deposit request missing history: {:?}", &deposit_request).as_str());

        // Convert status to API version.
        let status: models::OpStatus = deposit_request.op_status.into();

        // Provide last update height if the fields have a tangible impact
        // on the status of the deposit.
        let mut last_update_height: Option<f64> = Some(deposit_request.last_update_height as f64);
        let mut last_update_block_hash: Option<String> = Some(deposit_request.last_update_block_hash);
        if status == models::OpStatus::Pending {
            last_update_height = None;
            last_update_block_hash = None;
        }

        // Package data.
        models::DepositData {
            bitcoin_txid: deposit_request.bitcoin_txid,
            bitcoin_tx_output_index: deposit_request.bitcoin_tx_output_index as f64,
            recipient: deposit_request.recipient,
            amount: deposit_request.amount as f64,
            last_update_height,
            last_update_block_hash,
            status,
            status_message: latest_event.message.clone(),
            parameters: Box::new(models::DepositParameters {
                max_fee: deposit_request.max_fee as f64,
                lock_time: deposit_request.lock_time as f64,
                reclaim_script: deposit_request.reclaim_script,
            }),
            fulfillment: match (
                deposit_request.fulfillment_bitcoin_txid,
                deposit_request.fulfillment_bitcoin_tx_index,
                deposit_request.fulfillment_btc_fee,
                deposit_request.stacks_txid,
            ) {
                // Only create the fulfillment struct if all necessary data is present.
                (
                    Some(fulfillment_bitcoin_txid),
                    Some(fulfillment_bitcoin_tx_index),
                    Some(fulfillment_btc_fee),
                    Some(stacks_txid),
                ) => Some(Box::new(models::Fulfillment {
                    bitcoin_txid: Some(fulfillment_bitcoin_txid),
                    bitcoin_tx_index: Some(fulfillment_bitcoin_tx_index as f64),
                    txid: Some(stacks_txid),
                    btc_fee: Some(fulfillment_btc_fee as f64),
                    // TODO: [ticket link here once PR is approved]
                    // Alter API spec so that these fields are accessible to the API database.
                    bitcoin_block_hash: None,
                    bitcoin_block_height: None,
                })),
                _ => None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::DepositParameters;
    use serde_json;

    #[test]
    fn test_deposit_request_serialization() {
        let deposit_request = DepositRequest {
            bitcoin_txid: "abc123".to_string(),
            bitcoin_tx_output_index: 1,
            version: 1,
            recipient: "recipient1".to_string(),
            amount: 1000,
            max_fee: 10,
            lock_time: 0,
            reclaim_script: "script".to_string(),
            op_status: OpStatus::Pending,
            last_update_height: 0,
            last_update_block_hash: "hash".to_string(),
            fulfillment_bitcoin_txid: Some("fulfillment_txid".to_string()),
            fulfillment_bitcoin_tx_index: Some(0),
            fulfillment_btc_fee: Some(5),
            stacks_txid: Some("stacks_txid".to_string()),
            history: vec![DepositHistoryEntry {
                op_status: OpStatus::Pending,
                message: "status_message".to_string(),
                stacks_block_height: 0,
                stacks_block_hash: "block_hash".to_string(),
            }],
        };

        // Serialize to JSON
        let json = serde_json::to_string(&deposit_request).unwrap();

        // Deserialize back to struct
        let deserialized: DepositRequest = serde_json::from_str(&json).unwrap();

        // Verify that the deserialized struct matches the original
        assert_eq!(deposit_request, deserialized);
    }

    #[test]
    fn test_deposit_request_basic_info_serialization() {
        let basic_info = DepositRequestBasicInfo {
            bitcoin_txid: "abc123".to_string(),
            bitcoin_tx_output_index: 1,
            recipient: "recipient1".to_string(),
            amount: 1000,
            last_update_height: 0,
            last_update_block_hash: "hash".to_string(),
            op_status: OpStatus::Pending,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&basic_info).unwrap();

        // Deserialize back to struct
        let deserialized: DepositRequestBasicInfo = serde_json::from_str(&json).unwrap();

        // Verify that the deserialized struct matches the original
        assert_eq!(basic_info, deserialized);
    }

    #[test]
    fn test_from_deposit_request_basic_info() {
        let basic_info = DepositRequestBasicInfo {
            bitcoin_txid: "abc123".to_string(),
            bitcoin_tx_output_index: 1,
            recipient: "recipient1".to_string(),
            amount: 1000,
            last_update_height: 0,
            last_update_block_hash: "hash".to_string(),
            op_status: OpStatus::Pending,
        };

        let deposit_basic_info: models::DepositBasicInfo = basic_info.into();

        assert_eq!(deposit_basic_info.bitcoin_txid, "abc123");
        assert_eq!(deposit_basic_info.bitcoin_tx_output_index, 1.0);
        assert_eq!(deposit_basic_info.recipient, "recipient1");
        assert_eq!(deposit_basic_info.amount, 1000.0);
        assert_eq!(deposit_basic_info.last_update_height, 0.0);
        assert_eq!(deposit_basic_info.last_update_block_hash, "hash");
        // Convert OpStatus to the appropriate type and compare
        assert_eq!(deposit_basic_info.status, models::OpStatus::Pending);
    }

    #[test]
    fn test_from_deposit_request() {
        let deposit_request = DepositRequest {
            bitcoin_txid: "abc123".to_string(),
            bitcoin_tx_output_index: 1,
            version: 1,
            recipient: "recipient1".to_string(),
            amount: 1000,
            max_fee: 10,
            lock_time: 0,
            reclaim_script: "script".to_string(),
            op_status: OpStatus::Pending,
            last_update_height: 0,
            last_update_block_hash: "hash".to_string(),
            fulfillment_bitcoin_txid: Some("fulfillment_txid".to_string()),
            fulfillment_bitcoin_tx_index: Some(0),
            fulfillment_btc_fee: Some(5),
            stacks_txid: Some("stacks_txid".to_string()),
            history: vec![DepositHistoryEntry {
                op_status: OpStatus::Pending,
                message: "status_message".to_string(),
                stacks_block_height: 0,
                stacks_block_hash: "block_hash".to_string(),
            }],
        };

        let deposit_data: models::DepositData = deposit_request.into();

        assert_eq!(deposit_data.bitcoin_txid, "abc123");
        assert_eq!(deposit_data.bitcoin_tx_output_index, 1.0);
        assert_eq!(deposit_data.recipient, "recipient1");
        assert_eq!(deposit_data.amount, 1000.0);
        assert_eq!(deposit_data.status, models::OpStatus::Pending);
        assert_eq!(deposit_data.status_message, "status_message");

        let parameters: &DepositParameters = deposit_data.parameters.as_ref();
        assert_eq!(parameters.max_fee, 10.0);
        assert_eq!(parameters.lock_time, 0.0);
        assert_eq!(parameters.reclaim_script, "script");

        if let Some(fulfillment) = deposit_data.fulfillment.as_ref() {
            assert_eq!(fulfillment.bitcoin_txid.as_ref().unwrap(), "fulfillment_txid");
            assert_eq!(fulfillment.bitcoin_tx_index.as_ref().unwrap(), &0.0);
            assert_eq!(fulfillment.txid.as_ref().unwrap(), "stacks_txid");
            assert_eq!(fulfillment.btc_fee.as_ref().unwrap(), &5.0);
        } else {
            panic!("Fulfillment should be present");
        }
    }
}
