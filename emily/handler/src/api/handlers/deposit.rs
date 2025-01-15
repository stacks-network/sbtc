//! Handlers for Deposit endpoints.
use crate::api::models::common::Status;
use crate::api::models::deposit::requests::BasicPaginationQuery;
use crate::api::models::deposit::responses::{
    GetDepositsForTransactionResponse, UpdateDepositsResponse,
};
use crate::database::entries::StatusEntry;
use stacks_common::codec::StacksMessageCodec as _;
use tracing::{debug, instrument};
use warp::reply::{json, with_status, Reply};

use crate::api::models::deposit::{Deposit, DepositInfo};
use crate::api::models::{
    deposit::requests::{
        CreateDepositRequestBody, GetDepositsForTransactionQuery, GetDepositsQuery,
        UpdateDepositsRequestBody,
    },
    deposit::responses::GetDepositsResponse,
};
use crate::common::error::Error;
use crate::context::EmilyContext;
use crate::database::accessors;
use crate::database::entries::deposit::{
    DepositEntry, DepositEntryKey, DepositEvent, DepositParametersEntry,
    ValidatedUpdateDepositsRequest,
};
use bitcoin::ScriptBuf;
use warp::http::StatusCode;

/// Get deposit handler.
#[utoipa::path(
    get,
    operation_id = "getDeposit",
    path = "/deposit/{txid}/{index}",
    params(
        ("txid" = String, Path, description = "txid associated with the Deposit."),
        ("index" = String, Path, description = "output index associated with the Deposit."),
    ),
    tag = "deposit",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Deposit retrieved successfully", body = Deposit),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn get_deposit(
    context: EmilyContext,
    bitcoin_txid: String,
    bitcoin_tx_output_index: u32,
) -> impl warp::reply::Reply {
    debug!("In get deposit");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        bitcoin_txid: String,
        bitcoin_tx_output_index: u32,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Make key.
        let key = DepositEntryKey {
            bitcoin_txid,
            bitcoin_tx_output_index,
        };
        // Get deposit.
        let deposit: Deposit = accessors::get_deposit_entry(&context, &key)
            .await?
            .try_into()?;

        // Respond.
        Ok(with_status(json(&deposit), StatusCode::OK))
    }

    // Handle and respond.
    handler(context, bitcoin_txid, bitcoin_tx_output_index)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Get deposits for transaction handler.
#[utoipa::path(
    get,
    operation_id = "getDepositsForTransaction",
    path = "/deposit/{txid}",
    params(
        ("txid" = String, Path, description = "txid associated with the Deposit."),
        ("nextToken" = Option<String>, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = Option<i32>, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "deposit",
    responses(
        (status = 200, description = "Deposits retrieved successfully", body = GetDepositsForTransactionResponse),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn get_deposits_for_transaction(
    context: EmilyContext,
    bitcoin_txid: String,
    query: GetDepositsForTransactionQuery,
) -> impl warp::reply::Reply {
    debug!("In get deposits for transaction");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        bitcoin_txid: String,
        query: GetDepositsForTransactionQuery,
    ) -> Result<impl warp::reply::Reply, Error> {
        // TODO(506): Reverse this order of deposits so that the transactions are returned
        // in ascending index order.
        let (entries, next_token) = accessors::get_deposit_entries_for_transaction(
            &context,
            &bitcoin_txid,
            query.next_token,
            query.page_size,
        )
        .await?;
        // Get deposits as the right type.
        let deposits: Vec<Deposit> = entries
            .into_iter()
            .map(|entry| entry.try_into())
            .collect::<Result<_, _>>()?;
        // Create response.
        let response = GetDepositsForTransactionResponse { deposits, next_token };
        // Respond.
        Ok(with_status(json(&response), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, bitcoin_txid, query)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Get deposits handler.
#[utoipa::path(
    get,
    operation_id = "getDeposits",
    path = "/deposit",
    params(
        ("status" = Status, Query, description = "the status to search by when getting all deposits."),
        ("nextToken" = Option<String>, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = Option<i32>, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "deposit",
    responses(
        (status = 200, description = "Deposits retrieved successfully", body = GetDepositsResponse),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn get_deposits(
    context: EmilyContext,
    query: GetDepositsQuery,
) -> impl warp::reply::Reply {
    debug!("In get deposits");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        query: GetDepositsQuery,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Deserialize next token into the exclusive start key if present/
        let (entries, next_token) = accessors::get_deposit_entries(
            &context,
            &query.status,
            query.next_token,
            query.page_size,
        )
        .await?;
        // Convert data into resource types.
        let deposits: Vec<DepositInfo> = entries.into_iter().map(|entry| entry.into()).collect();
        // Create response.
        let response = GetDepositsResponse { deposits, next_token };
        // Respond.
        Ok(with_status(json(&response), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, query)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Get deposits by recipient handler.
#[utoipa::path(
    get,
    operation_id = "getDepositsForRecipient",
    path = "/deposit/recipient/{recipient}",
    params(
        ("recipient" = String, Path, description = "the status to search by when getting all deposits."),
        ("nextToken" = Option<String>, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = Option<i32>, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "deposit",
    responses(
        (status = 200, description = "Deposits retrieved successfully", body = GetDepositsResponse),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn get_deposits_for_recipient(
    context: EmilyContext,
    recipient: String,
    query: BasicPaginationQuery,
) -> impl warp::reply::Reply {
    debug!("In get deposits for recipient");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        recipient: String,
        query: BasicPaginationQuery,
    ) -> Result<impl warp::reply::Reply, Error> {
        let (entries, next_token) = accessors::get_deposit_entries_by_recipient(
            &context,
            &recipient,
            query.next_token,
            query.page_size,
        )
        .await?;
        // Convert data into resource types.
        let deposits: Vec<DepositInfo> = entries.into_iter().map(|entry| entry.into()).collect();
        // Create response.
        let response = GetDepositsResponse { deposits, next_token };
        // Respond.
        Ok(with_status(json(&response), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, recipient, query)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Create deposit handler.
#[utoipa::path(
    post,
    operation_id = "createDeposit",
    path = "/deposit",
    tag = "deposit",
    request_body = CreateDepositRequestBody,
    responses(
        (status = 201, description = "Deposit created successfully", body = Deposit),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 409, description = "Duplicate request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn create_deposit(
    context: EmilyContext,
    body: CreateDepositRequestBody,
) -> impl warp::reply::Reply {
    debug!("In create deposit");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        body: CreateDepositRequestBody,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Set variables.
        let api_state = accessors::get_api_state(&context).await?;
        api_state.error_if_reorganizing()?;

        let chaintip = api_state.chaintip();
        let mut stacks_block_hash: String = chaintip.key.hash;
        let mut stacks_block_height: u64 = chaintip.key.height;

        // Check if deposit with such txid and outindex already exists.
        let entry = accessors::get_deposit_entry(
            &context,
            &DepositEntryKey {
                bitcoin_txid: body.bitcoin_txid.clone(),
                bitcoin_tx_output_index: body.bitcoin_tx_output_index,
            },
        )
        .await;
        // Reject if we already have a deposit with the same txid and output index and it is NOT pending or reprocessing.
        match entry {
            Ok(deposit) => {
                if deposit.status != Status::Pending && deposit.status != Status::Reprocessing {
                    return Err(Error::Conflict);
                } else {
                    // If the deposit is pending or reprocessing, we should keep height and hash same as in the old deposit
                    stacks_block_hash = deposit.last_update_block_hash;
                    stacks_block_height = deposit.last_update_height;
                }
            }
            Err(Error::NotFound) => {}
            Err(e) => return Err(e),
        }

        let status = Status::Pending;

        // Get parameters from scripts.
        let script_parameters =
            scripts_to_resource_parameters(&body.deposit_script, &body.reclaim_script)?;

        // Make table entry.
        let deposit_entry: DepositEntry = DepositEntry {
            key: DepositEntryKey {
                bitcoin_txid: body.bitcoin_txid,
                bitcoin_tx_output_index: body.bitcoin_tx_output_index,
            },
            recipient: script_parameters.recipient,
            parameters: DepositParametersEntry {
                max_fee: script_parameters.max_fee,
                lock_time: script_parameters.lock_time,
            },
            history: vec![DepositEvent {
                status: StatusEntry::Pending,
                message: "Just received deposit".to_string(),
                stacks_block_hash: stacks_block_hash.clone(),
                stacks_block_height,
            }],
            status,
            last_update_block_hash: stacks_block_hash,
            last_update_height: stacks_block_height,
            amount: script_parameters.amount,
            reclaim_script: body.reclaim_script,
            deposit_script: body.deposit_script,
            ..Default::default()
        };
        // Validate deposit entry.
        deposit_entry.validate()?;
        // Add entry to the table.
        accessors::add_deposit_entry(&context, &deposit_entry).await?;
        // Respond.
        let response: Deposit = deposit_entry.try_into()?;
        Ok(with_status(json(&response), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, body)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Parameters from the deposit and reclaim scripts.
struct ScriptParameters {
    amount: u64,
    max_fee: u64,
    recipient: String,
    lock_time: u32,
}

/// Convert scripts to resource parameters.
///
/// This function is used to convert the deposit and reclaim scripts into the
/// parameters that are stored in the database.
fn scripts_to_resource_parameters(
    deposit_script: &str,
    reclaim_script: &str,
) -> Result<ScriptParameters, Error> {
    let deposit_script_buf = ScriptBuf::from_hex(deposit_script)?;
    let deposit_script_inputs = sbtc::deposits::DepositScriptInputs::parse(&deposit_script_buf)?;

    let reclaim_script_buf = ScriptBuf::from_hex(reclaim_script)?;
    let reclaim_script_inputs = sbtc::deposits::ReclaimScriptInputs::parse(&reclaim_script_buf)?;

    let recipient_bytes = deposit_script_inputs.recipient.serialize_to_vec();
    let recipient_hex_string = hex::encode(&recipient_bytes);

    Ok(ScriptParameters {
        // TODO(TBD): Get the amount from some script related data somehow.
        amount: 0,
        max_fee: deposit_script_inputs.max_fee,
        recipient: recipient_hex_string,
        lock_time: reclaim_script_inputs.lock_time(),
    })
}

/// Update deposits handler.
#[utoipa::path(
    put,
    operation_id = "updateDeposits",
    path = "/deposit",
    tag = "deposit",
    request_body = UpdateDepositsRequestBody,
    responses(
        (status = 201, description = "Deposits updated successfully", body = UpdateDepositsResponse),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn update_deposits(
    context: EmilyContext,
    api_key: String,
    body: UpdateDepositsRequestBody,
) -> impl warp::reply::Reply {
    debug!("In update deposits");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        api_key: String,
        body: UpdateDepositsRequestBody,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Get the api state and error if the api state is claimed by a reorg.
        //
        // Note: This may not be necessary due to the implied order of events
        // that the API can receive from stacks nodes, but it's being added here
        // in order to enforce added stability to the API during a reorg.
        let api_state = accessors::get_api_state(&context).await?;
        api_state.error_if_reorganizing()?;
        // Validate request.
        let validated_request: ValidatedUpdateDepositsRequest = body.try_into()?;

        // Infer the new chainstates that would come from these deposit updates and then
        // attempt to update the chainstates.
        let inferred_chainstates = validated_request.inferred_chainstates()?;
        let can_reorg = context.settings.trusted_reorg_api_key == api_key;
        for chainstate in inferred_chainstates {
            // TODO(TBD): Determine what happens if this occurs in multiple lambda
            // instances at once.
            crate::api::handlers::chainstate::add_chainstate_entry_or_reorg(
                &context,
                can_reorg,
                &chainstate,
            )
            .await?;
        }

        // Create aggregator.
        let mut updated_deposits: Vec<(usize, Deposit)> =
            Vec::with_capacity(validated_request.deposits.len());

        // Loop through all updates and execute.
        for (index, update) in validated_request.deposits {
            let updated_deposit =
                accessors::pull_and_update_deposit_with_retry(&context, update, 15).await?;
            updated_deposits.push((index, updated_deposit.try_into()?));
        }

        updated_deposits.sort_by_key(|(index, _)| *index);
        let deposits = updated_deposits
            .into_iter()
            .map(|(_, deposit)| deposit)
            .collect();
        let response = UpdateDepositsResponse { deposits };
        Ok(with_status(json(&response), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, api_key, body)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

// TODO(393): Add handler unit tests.

// Test module
#[cfg(test)]
mod tests {

    use super::*;
    use sbtc::testing::{self, deposits::TxSetup};
    use test_case::test_case;

    #[test_case(15000, 500_000, 150; "All parameters are normal numbers")]
    #[test_case(0, 0, 0; "All parameters are zeros")]
    fn test_scripts_to_resource_parameters(max_fee: u64, amount_sats: u64, lock_time: u32) {
        let setup: TxSetup = testing::deposits::tx_setup(lock_time, max_fee, amount_sats);

        let deposit_script = setup.deposit.deposit_script().to_hex_string();
        let reclaim_script = setup.reclaim.reclaim_script().to_hex_string();

        let script_parameters: ScriptParameters =
            scripts_to_resource_parameters(&deposit_script, &reclaim_script).unwrap();

        assert_eq!(script_parameters.max_fee, max_fee);
        assert_eq!(script_parameters.lock_time, lock_time);

        // TODO: Test the recipient with an input value.
        assert!(script_parameters.recipient.len() > 0);
    }
}
