use std::{collections::HashMap, str::FromStr};

use aws_sdk_dynamodb::types::AttributeValue;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize};
use serde_dynamo::Item;

use crate::errors::{self, EmilyApiError};

// Compile the test utils iff the crate is being compiled for testing.
#[cfg(test)]
pub mod test;

/// Deserializes a string to number. Useful as a serde deserialization annotation where
/// a hashmap encodes a number as a string.
pub fn deserialize_string_to_number<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<T>().map_err(serde::de::Error::custom)
}

/// A generic function that serializes an object to a JSON string and then encodes
/// it in Base64. This function is intended to be used to serialize "next token" like
/// values for paginated queries.
///
/// TODO: [ticket link here once PR is approved]
/// Refine token serialization and deserialization to be a shorter string.
pub fn serialize_key_to_token<T>(
    key: HashMap<String, AttributeValue>
) -> Result<String, EmilyApiError>
where
    T: Serialize,
    T: for<'de> Deserialize<'de>,
{
    // Deserialize into the key struct.
    let key_struct: T = serde_dynamo::from_item(key)
        .map_err(errors::to_emily_api_error)?;

    // Serialize the object to a JSON string
    let json_string = serde_json::to_string(&key_struct)
        .map_err(errors::to_emily_api_error)?;

    // Encode the JSON string in Base64
    let base64_string = STANDARD.encode(json_string);

    // Return the Base64 encoded string
    Ok(base64_string)
}

/// A generic function that serializes an object to a JSON string and then encodes
/// it in Base64. This function is intended to be used to deserialze "next token" like
/// values for paginated queries.
///
/// TODO: [ticket link here once PR is approved]
/// Refine token serialization and deserialization to be a shorter string.
pub fn deserialize_token_to_key<T>(
    encoded_key: &str
) -> Result<HashMap<String, AttributeValue>, EmilyApiError>
where
    T: Serialize,
    T: for<'de> Deserialize<'de>,
{
    // Decode the Base64 string
    let decoded_bytes = STANDARD.decode(encoded_key)
        .map_err(errors::to_emily_api_error)?;

    // Deserialize the JSON string back into an object
    let key: T = serde_json::from_slice(&decoded_bytes)
        .map_err(errors::to_emily_api_error)?;

    // Convert into item that can be converted into a the HashMap.
    let dynamodb_item: Item = serde_dynamo::to_item(key)
        .map_err(errors::to_emily_api_error)?;

    // Return the deserialized object
    Ok(dynamodb_item.into())
}
