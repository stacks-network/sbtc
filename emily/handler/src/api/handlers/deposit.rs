//! Handlers for Deposit endpoints.
use crate::api::models::common::Status;
use crate::api::models::deposit::requests::BasicPaginationQuery;
use crate::api::models::deposit::responses::{
    GetDepositsForTransactionResponse, UpdateDepositsResponse,
};
use crate::database::entries::StatusEntry;
use bitcoin::opcodes::all as opcodes;
use bitcoin::ScriptBuf;
use sbtc::deposits::ReclaimScriptInputs;
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
use stacks_common::codec::StacksMessageCodec as _;
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
        ("recipient" = String, Path, description = "the recipient to search by when getting all deposits."),
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
    debug!("in get deposits for recipient: {recipient}");
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

/// Get deposits by recipient handler.
#[utoipa::path(
    get,
    operation_id = "getDepositsForReclaimPubkey",
    path = "/deposit/reclaim-pubkey/{reclaimPubkey}",
    params(
        ("reclaimPubkey" = String, Path, description = "the reclaim schnorr public key to search by when getting all deposits."),
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
pub async fn get_deposits_for_reclaim_pubkey(
    context: EmilyContext,
    reclaim_pubkey: String,
    query: BasicPaginationQuery,
) -> impl warp::reply::Reply {
    debug!("in get deposits for reclaim pubkey: {reclaim_pubkey}");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        reclaim_pubkey: String,
        query: BasicPaginationQuery,
    ) -> Result<impl warp::reply::Reply, Error> {
        let (entries, next_token) = accessors::get_deposit_entries_by_reclaim_pubkey(
            &context,
            &reclaim_pubkey,
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
    handler(context, reclaim_pubkey, query)
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
    debug!(
        "Creating deposit with txid: {}, output index: {}",
        body.bitcoin_txid, body.bitcoin_tx_output_index
    );
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

        let limits = accessors::get_limits(&context).await?;
        let deposit_info = body.validate(&limits, context.settings.is_mainnet)?;

        // Make table entry.
        let deposit_entry: DepositEntry = DepositEntry {
            key: DepositEntryKey {
                bitcoin_txid: body.bitcoin_txid,
                bitcoin_tx_output_index: body.bitcoin_tx_output_index,
            },
            recipient: hex::encode(deposit_info.recipient.serialize_to_vec()),
            parameters: DepositParametersEntry {
                max_fee: deposit_info.max_fee,
                lock_time: deposit_info.lock_time.to_consensus_u32(),
            },
            history: vec![DepositEvent {
                status: StatusEntry::Pending,
                message: "Just received deposit".to_string(),
                stacks_block_hash: stacks_block_hash.clone(),
                stacks_block_height,
            }],
            status: Status::Pending,
            last_update_block_hash: stacks_block_hash,
            last_update_height: stacks_block_height,
            amount: deposit_info.amount,
            reclaim_script: body.reclaim_script,
            deposit_script: body.deposit_script,
            reclaim_pubkey: parse_reclaim_pubkey(&deposit_info.reclaim_script),
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

const OP_DROP: u8 = opcodes::OP_DROP.to_u8();
const OP_CHECKSIG: u8 = opcodes::OP_CHECKSIG.to_u8();

/// Parse the reclaim script to extract the pubkey.
/// Currently only supports the sBTC Bridge and Leather Wallet reclaim scripts.
fn parse_reclaim_pubkey(reclaim_script: &ScriptBuf) -> Option<String> {
    let reclaim = ReclaimScriptInputs::parse(reclaim_script).ok()?;

    match reclaim.user_script().as_bytes() {
        [OP_DROP, _key_len, pubkey @ .., OP_CHECKSIG] => Some(hex::encode(pubkey)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        key::rand::rngs::OsRng,
        secp256k1::{SecretKey, SECP256K1},
    };

    #[tokio::test]
    async fn test_parse_reclaim_pubkey_two_ways() {
        let secret_key = SecretKey::new(&mut OsRng);
        let pubkey = secret_key.x_only_public_key(SECP256K1).0.serialize();
        let user_script = ScriptBuf::builder()
            .push_opcode(opcodes::OP_DROP)
            .push_slice(pubkey)
            .push_opcode(opcodes::OP_CHECKSIG)
            .into_script();
        let reclaim_script = ReclaimScriptInputs::try_new(14, user_script)
            .unwrap()
            .reclaim_script();
        let pubkey_from_script = parse_reclaim_pubkey(&reclaim_script).unwrap();
        assert_eq!(pubkey_from_script, hex::encode(pubkey));
    }
}

// TODO(393): Add handler unit tests.
