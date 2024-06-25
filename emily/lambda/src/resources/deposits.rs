use std::{collections::HashMap, convert::{From, TryFrom}, fmt::format, str::FromStr};

use aws_sdk_dynamodb::types::AttributeValue;
use emily::models::{self, DepositBasicInfo, OpStatus};

use crate::errors::EmilyApiError;

// ------------------------------------------------------------------
// Api resources.
// ------------------------------------------------------------------

/// Deposit resource.
#[derive(Clone)]
pub struct DepositResource {
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
    /// Status message.
    pub status_message: String,
    /// Deposit parameters.
    pub parameters: DepositParameters,
    /// Fulfillment information about this deposit.
    pub fulfillment: Option<DepositFulfillment>,
}

/// Deposit basic info resource.
#[derive(Clone)]
pub struct DepositBasicInfoResource {
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,
    /// Bitcoin transaction output index.
    pub bitcoin_tx_output_index: f64,
    /// Recipient of the deposit.
    pub recipient: String,
    /// Amount of the deposit.
    pub amount: u64,
    /// Last update block height.
    pub last_update_height: u64,
    /// Last update block hash.
    pub last_update_block_hash: String,
    /// Operation status.
    pub status: OpStatus,
}

/// Parameters to the deposit operation.
#[derive(Clone)]
pub struct DepositParameters {
    /// The maximum total BTC fee in satoshis that the deposit initiator is comfortable with
    /// being taken out of their BTC to pay for the BTC fee of the despot fulfillment transaction.
    pub max_fee: u64,
    /// The block height at which the depositor can reclaim their transaction.
    pub lock_time: u64,
    /// The script with which the depositor can reclaim their deposit after the lock time.
    pub reclaim_script: String,
}

/// Fulfillment data for a deposit.
#[derive(Clone)]
pub struct DepositFulfillment {
    /// Bitcoin txid that fulfilled the deposit.
    pub bitcoin_txid: String,
    /// Index of the Bitcoin transaction that fulfilled this specific deposit.
    pub bitcoin_tx_index: u16,
    /// Stacks transaction id that fulfilled the deposit.
    pub txid:String,
    /// Bitcoin block hash of the transaction that fulfilled the deposit.
    pub bitcoin_block_hash: String,
    /// Block height of the bitcoin block that fulfilled this deposit.
    pub bitcoin_block_height: u64,
    /// Bitcoin fee used to fulfill the deposit.
    pub btc_fee: u64,
}

// Conversions ------------------------------------------------------

/// Convert from resource definition of deposit parameters to the api model version
/// of the struct.
impl From<DepositParameters> for Box<models::DepositParameters> {
    fn from(value: DepositParameters) -> Self {
        Box::new(models::DepositParameters {
            max_fee: value.max_fee as f64,
            lock_time: value.lock_time as f64,
            reclaim_script: value.reclaim_script,
        })
    }
}

// ------------------------------------------------------------------
// DynamoDB table entry resources.
// ------------------------------------------------------------------

/// Deposit table entry key.
#[derive(Debug)]
pub struct DepositTableEntryKey {
    /// Bitcoin transaction id.
    pub bitcoin_txid: String,
    /// Bitcoin transaction output index.
    pub bitcoin_tx_output_index: u16,
}

/// Deposit table entry.
#[derive(Debug)]
pub struct DepositTableEntry {
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
    pub op_status: models::OpStatus,
    /// Last update block height.
    pub last_update_height: u64,
    /// Last update block hash.
    pub last_update_block_hash: String,
    /// Bitcoin transaction id that fulfills the deposit.
    pub fulfillment_bitcoin_txid: Option<String>,
    /// Output index on the fulfilling Bitcoin transaction that fulfills the deposit.
    pub fulfillment_bitcoin_tx_index: Option<u16>,
    /// Fee on the fulfillment bitcoin transaction paid by this deposit.
    pub fulfillment_btc_fee: Option<u64>,
    /// Stacks transaction id.
    pub stacks_txid: Option<String>,
    /// History of this deposit transaction.
    pub history: Vec<DepositHistoryEntry>,
}

/// Deposit history entry.
#[derive(Debug)]
pub struct DepositHistoryEntry {
    /// Status code.
    pub op_status: models::OpStatus,
    /// Status message.
    pub message: String,
    /// Stacks block heigh at the time of this update.
    pub stacks_block_height: u64,
    /// Stacks block hash associated with the height of this update.
    pub stacks_block_hash: String,
}

// Conversions ------------------------------------------------------

/// Converts from the deposit key to a hashmap that can be used as a key
/// for searching a DynamoDB table.
impl From<DepositTableEntryKey> for HashMap<String, AttributeValue> {
    fn from(key_struct: DepositTableEntryKey) -> Self {
        return (&key_struct).into();
    }
}

/// Converts from the deposit key to a hashmap that can be used as a key
/// for searching a DynamoDB table.
impl From<&DepositTableEntryKey> for HashMap<String, AttributeValue> {
    fn from(key_struct: &DepositTableEntryKey) -> Self {
        let mut key: HashMap<String, AttributeValue> = HashMap::new();
        key.insert(
            "BitcoinTxid".to_string(),
            AttributeValue::S(key_struct.bitcoin_txid.clone()),
        );
        key.insert(
            "BitcoinTxOutputIndex".to_string(),
            AttributeValue::N((key_struct.bitcoin_tx_output_index).to_string()),
        );
        return key;
    }
}

/// Converts from the deposit resource to a table entry.
impl From<DepositTableEntry> for HashMap<String, AttributeValue> {
    fn from(deposit_table_entry: DepositTableEntry) -> Self {
        (&deposit_table_entry).into()
    }
}

/// Converts from the deposit resource to a table entry.
impl From<&DepositTableEntry> for HashMap<String, AttributeValue> {
    fn from(deposit_table_entry: &DepositTableEntry) -> Self {
        let mut item: HashMap<String, AttributeValue> = HashMap::new();
        item.insert("BitcoinTxid".to_string(), AttributeValue::S(deposit_table_entry.bitcoin_txid.clone()));
        item.insert("BitcoinTxOutputIndex".to_string(), AttributeValue::N(deposit_table_entry.bitcoin_tx_output_index.to_string()));
        item.insert("Version".to_string(), AttributeValue::N(0.to_string()));
        item.insert("Recipient".to_string(), AttributeValue::S(deposit_table_entry.recipient.clone()));
        item.insert("Amount".to_string(), AttributeValue::N(deposit_table_entry.amount.to_string()));
        item.insert("MaxFee".to_string(), AttributeValue::N(deposit_table_entry.max_fee.to_string()));
        item.insert("LockTime".to_string(), AttributeValue::S(deposit_table_entry.lock_time.to_string()));
        item.insert("ReclaimScript".to_string(), AttributeValue::S(deposit_table_entry.reclaim_script.clone()));
        item.insert("OpStatus".to_string(), AttributeValue::N(status_to_id(deposit_table_entry.op_status).to_string()));
        item.insert("LastUpdateHeight".to_string(), AttributeValue::N(deposit_table_entry.last_update_height.to_string()));
        item.insert("LastUpdateBlockHash".to_string(), AttributeValue::S(deposit_table_entry.last_update_block_hash.clone().to_string()));
        if let Some(fulfillment_bitcoin_txid) = deposit_table_entry.fulfillment_bitcoin_txid.clone() {
            item.insert("FulfillmentBitcoinTxid".to_string(), AttributeValue::S(fulfillment_bitcoin_txid.to_string()));
        }
        if let Some(fulfillment_bitcoin_tx_index) = deposit_table_entry.fulfillment_bitcoin_tx_index {
            item.insert("FulfillmentBitcoinTxIndex".to_string(), AttributeValue::N(fulfillment_bitcoin_tx_index.to_string()));
        }
        if let Some(fulfillment_btc_fee) = deposit_table_entry.fulfillment_btc_fee {
            item.insert("FulfillmentBtcFee".to_string(), AttributeValue::N(fulfillment_btc_fee.to_string()));
        }
        if let Some(stacks_txid) = deposit_table_entry.stacks_txid.clone() {
            item.insert("StacksTxid".to_string(), AttributeValue::S(stacks_txid.to_string()));
        }
        item.insert("History".to_string(), AttributeValue::L(
            deposit_table_entry.history.iter().map(|history_entry|
            history_entry.into()
        ).collect()));
        item
    }
}

/// Converts from Deposit Table Entry to Deposit Resource.
impl From<DepositTableEntry> for DepositResource {
    fn from(deposit_table_entry: DepositTableEntry) -> Self {
        (&deposit_table_entry).into()
    }
}

/// Converts from Deposit Table Entry to Deposit Resource.
impl From<&DepositTableEntry> for DepositResource {
    fn from(deposit_table_entry: &DepositTableEntry) -> Self {
        let latest_history_entry = deposit_table_entry.history
            .last() // There must always be at least one entry.
            .unwrap();

        DepositResource {
            bitcoin_txid: deposit_table_entry.bitcoin_txid.clone(),
            bitcoin_tx_output_index: deposit_table_entry.bitcoin_tx_output_index,
            recipient: deposit_table_entry.recipient.clone(),
            amount: deposit_table_entry.amount,
            last_update_height: deposit_table_entry.last_update_height,
            last_update_block_hash: deposit_table_entry.last_update_block_hash.clone(),
            op_status: deposit_table_entry.op_status,
            status_message: latest_history_entry.message.clone(),
            parameters: DepositParameters {
                max_fee: deposit_table_entry.max_fee,
                lock_time: deposit_table_entry.lock_time,
                reclaim_script: deposit_table_entry.reclaim_script.clone(),
            },
            // TODO
            fulfillment: None,
        }
    }
}

/// Converts from Deposit History Entry to a DynamoDB Table Attribute.
impl From<&DepositHistoryEntry> for AttributeValue {
    fn from(deposit_history_entry: &DepositHistoryEntry) -> Self {
        let mut item: HashMap<String, AttributeValue> = HashMap::new();
        item.insert("OpStatus".to_string(), AttributeValue::N(status_to_id(deposit_history_entry.op_status).to_string()));
        item.insert("Message".to_string(), AttributeValue::S(deposit_history_entry.message.clone()));
        item.insert("StacksBlockHeight".to_string(), AttributeValue::N(deposit_history_entry.stacks_block_height.to_string()));
        item.insert("StacksBlockHash".to_string(), AttributeValue::S(deposit_history_entry.stacks_block_hash.to_string()));
        AttributeValue::M(item)
    }
}

/// Converts from Deposit History Entry to a DynamoDB Table Attribute.
impl From<DepositHistoryEntry> for AttributeValue {
    fn from(deposit_history_entry: DepositHistoryEntry) -> Self {
        (&deposit_history_entry).into()
    }
}

// Deposit Resource

impl TryFrom<HashMap<String, AttributeValue>> for DepositTableEntry {
    type Error = EmilyApiError;
    fn try_from(deposit_table_entry: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        return (&deposit_table_entry).try_into();
    }
}


fn extract_attribute<T: FromStr>(
    table_entry: &HashMap<String, AttributeValue>,
    attribute_name: &str,
) -> Result<T, EmilyApiError>
where
    <T as FromStr>::Err: std::error::Error + 'static,
{
    let attribute_value = table_entry
        .get(attribute_name)
        .ok_or(EmilyApiError::InternalService(
            format!("Table entry is missing field: {}.", attribute_name)))?;

    let attribute_str = match attribute_value {
        AttributeValue::N(value) => Ok(value),
        AttributeValue::S(value) => Ok(value),
        _ => Err(EmilyApiError::InternalService("Error".to_string())),
    }?;

    let attribute: T = attribute_str
        .parse::<T>()
        .map_err(|e| EmilyApiError::UnhandledService(Box::new(e)))?;

    Ok(attribute)
}

fn extract_optional_attribute<T: FromStr>(
    table_entry: &HashMap<String, AttributeValue>,
    attribute_name: &str,
) -> Result<Option<T>, EmilyApiError>
where
    <T as FromStr>::Err: std::error::Error + 'static,
{
    let maybe_attribute = table_entry
        .get(attribute_name);
    if let Some(attribute_value) = maybe_attribute {

        let attribute_str = match attribute_value {
            AttributeValue::N(value) => Ok(value),
            AttributeValue::S(value) => Ok(value),
            _ => Err(EmilyApiError::InternalService("Error".to_string())),
        }?;

        let attribute = attribute_str
            .parse::<T>()
            .map_err(|e| EmilyApiError::UnhandledService(Box::new(e)))?;

        return Ok(Some(attribute))
    } else {
        return Ok(None)
    }
}

impl TryFrom<&HashMap<String, AttributeValue>> for DepositTableEntry {
    type Error = EmilyApiError;
    fn try_from(deposit_table_entry: &HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {

        let history_result: Result<Vec<DepositHistoryEntry>, EmilyApiError> = deposit_table_entry.get("History")
            .ok_or(EmilyApiError::InternalService(
                format!("Failed to get \"History from entry\" {:?}", deposit_table_entry)
            ))?
            .as_l()
            .map_err(|e| EmilyApiError::InternalService(
                format!("Failed to get deposit history list from attribute: {:?}", e)
            ))?
            .iter()
            .map(|history_entry| {
                let history_blip: Result<DepositHistoryEntry, EmilyApiError> = history_entry
                    .try_into()
                    .map_err(|e| {
                        EmilyApiError::InternalService(
                            format!("Failed to convert history entry: {:?}", e),
                        )
                    });
                history_blip
            })
            .collect();

        let history = history_result?;

        Ok(DepositTableEntry {
            bitcoin_txid: extract_attribute(deposit_table_entry, "BitcoinTxid")?,
            bitcoin_tx_output_index: extract_attribute(deposit_table_entry, "BitcoinTxOutputIndex")?,
            version: extract_attribute(deposit_table_entry, "Version")?,
            recipient: extract_attribute(deposit_table_entry, "Recipient")?,
            amount: extract_attribute(deposit_table_entry, "Amount")?,
            max_fee: extract_attribute(deposit_table_entry, "MaxFee")?,
            lock_time: extract_attribute(deposit_table_entry, "LockTime")?,
            reclaim_script: extract_attribute(deposit_table_entry, "ReclaimScript")?,
            op_status: id_to_status(extract_attribute(deposit_table_entry, "OpStatus")?)?,
            last_update_height: extract_attribute(deposit_table_entry, "LastUpdateHeight")?,
            last_update_block_hash: extract_attribute(deposit_table_entry, "LastUpdateBlockHash")?,
            fulfillment_bitcoin_txid: extract_optional_attribute(deposit_table_entry, "FulfillmentBitcoinTxid")?,
            fulfillment_bitcoin_tx_index: extract_optional_attribute(deposit_table_entry, "FulfillmentBitcoinTxIndex")?,
            fulfillment_btc_fee: extract_optional_attribute(deposit_table_entry, "FulfillmentBtcFee")?,
            stacks_txid: extract_optional_attribute(deposit_table_entry, "StacksTxid")?,
            history,
        })
    }
}


// Deposit History Entry
impl TryFrom<AttributeValue> for DepositHistoryEntry {
    type Error = EmilyApiError;
    fn try_from(deposit_history_table_entry: AttributeValue) -> Result<Self, Self::Error> {
        (&deposit_history_table_entry).try_into()
    }
}

impl TryFrom<&AttributeValue> for DepositHistoryEntry {
    type Error = EmilyApiError;
    fn try_from(deposit_history_table_entry: &AttributeValue) -> Result<Self, Self::Error> {
        deposit_history_table_entry
            .as_m()
            .map_err(|e| EmilyApiError::InternalService(
                format!("Failed to get deposit history hashmap from attribute: {:?}", e)
            ))?
            .try_into()
    }
}

impl TryFrom<HashMap<String, AttributeValue>> for DepositHistoryEntry {
    type Error = EmilyApiError;
    fn try_from(deposit_history_table_entry: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        return (&deposit_history_table_entry).try_into();
    }
}

impl TryFrom<&HashMap<String, AttributeValue>> for DepositHistoryEntry {
    type Error = EmilyApiError;
    fn try_from(deposit_history_table_entry: &HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        Ok(DepositHistoryEntry {
            op_status: id_to_status(
                extract_attribute(deposit_history_table_entry, "OpStatus")?
            )?,
            message: extract_attribute(deposit_history_table_entry, "Message")?,
            stacks_block_height: extract_attribute(deposit_history_table_entry, "StacksBlockHeight")?,
            stacks_block_hash: extract_attribute(deposit_history_table_entry, "StacksBlockHash")?,
        })
    }
}

impl TryFrom<&HashMap<String, AttributeValue>> for DepositBasicInfoResource {
    type Error = EmilyApiError;
    fn try_from(deposit_basic_info_table_entry: &HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
        Ok(DepositBasicInfoResource {
            bitcoin_txid: extract_attribute(deposit_basic_info_table_entry, "BitcoinTxid")?,
            bitcoin_tx_output_index: extract_attribute(deposit_basic_info_table_entry, "BitcoinTxOutputIndex")?,
            recipient: extract_attribute(deposit_basic_info_table_entry, "Recipient")?,
            amount: extract_attribute(deposit_basic_info_table_entry, "Amount")?,
            last_update_height: extract_attribute(deposit_basic_info_table_entry, "LastUpdateHeight")?,
            last_update_block_hash: extract_attribute(deposit_basic_info_table_entry, "LastUpdateBlockHash")?,
            status: id_to_status(extract_attribute(deposit_basic_info_table_entry, "OpStatus")?)?,
        })
    }
}

impl From<DepositBasicInfoResource> for DepositBasicInfo {
    fn from(deposit_basic_info: DepositBasicInfoResource) -> Self {
        DepositBasicInfo {
            bitcoin_txid: deposit_basic_info.bitcoin_txid,
            bitcoin_tx_output_index: deposit_basic_info.bitcoin_tx_output_index,
            recipient: deposit_basic_info.recipient,
            amount: deposit_basic_info.amount as f64,
            last_update_height: deposit_basic_info.last_update_height as f64,
            last_update_block_hash: deposit_basic_info.last_update_block_hash,
            status: deposit_basic_info.status,
        }
    }
}

// ------------------------------------------------------------------
// Conversions.
// ------------------------------------------------------------------

/// Converts status to id for table entry.
pub fn status_to_id(op_status: OpStatus) -> u16 {
    match op_status {
        OpStatus::Pending => 0,
        OpStatus::Accepted => 1,
        OpStatus::Confirmed => 2,
        OpStatus::Failed => 3,
    }
}

fn id_to_status(status_id: u16) -> Result<OpStatus, EmilyApiError> {
    match status_id {
        0 => Ok(OpStatus::Pending),
        1 => Ok(OpStatus::Accepted),
        2 => Ok(OpStatus::Confirmed),
        3 => Ok(OpStatus::Failed),
        _ => Err(EmilyApiError::InternalService(format!("Invalid op status {}", status_id))),
    }
}

// impl DepositTableEntry {
//     pub fn validate (&self) -> Result<(), EmilyApiError> {
//         // Verify consistency.
//         let listed_current_status: OpStatus = id_to_status(self.op_status)?;
//         let inferred_current_status: OpStatus = match self.history.last() {
//             Some(history) => {
//                 id_to_status(history.op_status)
//             },
//             None => Err(EmilyApiError::InternalService(format!("Internal service error").to_string()))
//         }?;

//         match inferred_current_status == listed_current_status {
//             true => Ok(()),
//             false => Err(EmilyApiError::InternalService(
//                 format!("Inconsistent historical data for deposit {}:{}",
//                 self.bitcoin_txid,
//                 self.bitcoin_tx_output_index,
//             ).to_string()))
//         }
//     }
// }

// impl TryFrom<DepositTableEntry> for DepositResource {
//     type Error = EmilyApiError;
//     fn try_from(value: DepositTableEntry) -> Result<Self, Self::Error> {

//         // Validate.
//         value.validate()?;

//         // Current status.
//         let current_status: OpStatus = id_to_status(value.op_status)?;
//         let latest_update: &DepositHistoryEntry= value.history.last()
//             .ok_or(EmilyApiError::InternalService("Incomplete history".to_string()))?;

//         //
//         let fulfillment: Option<DepositFulfillment> = match current_status {
//             OpStatus::Confirmed => Some(DepositFulfillment {
//                 bitcoin_txid: value.fulfillment_bitcoin_txid,
//                 bitcoin_tx_index: value.fulfillment_bitcoin_tx_index,
//                 txid: value.stacks_txid,
//                 bitcoin_block_hash: "DUMMY".to_string(),
//                 bitcoin_block_height: 0,
//                 btc_fee: value.fulfillment_btc_fee.,
//             }),
//             _ => None
//         };

//         return Ok(DepositResource {
//             bitcoin_txid: value.bitcoin_txid,
//             bitcoin_tx_output_index: value.bitcoin_tx_output_index,
//             recipient: value.recipient,
//             amount: value.amount,
//             last_update_height: value.last_update_height,
//             last_update_block_hash: value.last_update_block_hash,
//             op_status: id_to_status(value.op_status),
//             status_message: value.history.last()
//                 .and_then(|h| Some(h.message.clone()))
//                 .unwrap_or("Unknown status.".to_string()),
//             parameters: DepositParameters {
//                 max_fee: value.max_fee,
//                 lock_time: value.lock_time,
//                 reclaim_script: value.reclaim_script,
//             },
//             fulfillment: DepositFulfillment {
//                 bitcoin_txid: value.fulfillment_bitcoin_txid,
//                 bitcoin_tx_index: value.fulfillment_bitcoin_tx_index,
//                 txid: value.stacks_txid,
//                 bitcoin_block_hash: match,
//                 bitcoin_block_height: u64,
//                 btc_fee: u64,
//             },
//         });
//     }
// }

// impl TryFrom<DepositTableEntry> for DepositResource {
//     type Error = EmilyApiError;
//     fn try_from(value: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
//         return Ok(DepositResource {

//         });
//     }
// }

// impl TryFrom<DepositResource> for DepositTableEntry {
//     type Error = EmilyApiError;
//     fn try_from(value: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
//         return Ok(DepositResource {

//         });
//     }
// }


// impl TryFrom<HashMap<String, AttributeValue>> for DepositResource {
//     type Error = EmilyApiError;
//     fn try_from(value: HashMap<String, AttributeValue>) -> Result<Self, Self::Error> {
//         return Ok(DepositResource {

//         });
//     }
// }
