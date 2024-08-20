//! Handlers for Deposit endpoints.
use crate::api::models::common::{BlockHeight, StacksBlockHash, Status};
use crate::api::models::deposit::responses::{
    GetDepositsForTransactionResponse, UpdateDepositsResponse,
};
use crate::database::entries::StatusEntry;
use warp::reply::{json, with_status, Reply};

use warp::http::StatusCode;

use crate::api::models::deposit::{Deposit, DepositInfo};
use crate::api::models::{
    common::{BitcoinTransactionId, BitcoinTransactionOutputIndex},
    deposit::requests::{
        CreateDepositRequestBody, GetDepositsForTransactionQuery, GetDepositsQuery,
        UpdateDepositsRequestBody,
    },
    deposit::responses::{CreateDepositResponse, GetDepositResponse, GetDepositsResponse},
};
use crate::common::error::Error;
use crate::context::EmilyContext;
use crate::database::accessors;
use crate::database::entries::deposit::{
    DepositEntry, DepositEntryKey, DepositEvent, DepositParametersEntry, DepositUpdatePackage,
    ValidatedUpdateDepositsRequest,
};

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
        (status = 200, description = "Deposit retrieved successfully", body = GetDepositResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_deposit(
    context: EmilyContext,
    bitcoin_txid: BitcoinTransactionId,
    bitcoin_tx_output_index: BitcoinTransactionOutputIndex,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        bitcoin_txid: BitcoinTransactionId,
        bitcoin_tx_output_index: BitcoinTransactionOutputIndex,
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
        Ok(with_status(
            json(&(deposit as GetDepositResponse)),
            StatusCode::OK,
        ))
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
        ("nextToken" = String, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = String, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "deposit",
    responses(
        (status = 200, description = "Deposits retrieved successfully", body = GetDepositsForTransactionResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_deposits_for_transaction(
    context: EmilyContext,
    bitcoin_txid: BitcoinTransactionId,
    query: GetDepositsForTransactionQuery,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        bitcoin_txid: BitcoinTransactionId,
        query: GetDepositsForTransactionQuery,
    ) -> Result<impl warp::reply::Reply, Error> {
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
        ("nextToken" = String, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = String, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "deposit",
    responses(
        (status = 200, description = "Deposits retrieved successfully", body = GetDepositsResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_deposits(
    context: EmilyContext,
    query: GetDepositsQuery,
) -> impl warp::reply::Reply {
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

/// Create deposit handler.
#[utoipa::path(
    post,
    operation_id = "createDeposit",
    path = "/deposit",
    tag = "deposit",
    request_body = CreateDepositRequestBody,
    responses(
        (status = 201, description = "Deposit created successfully", body = CreateDepositResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn create_deposit(
    context: EmilyContext,
    body: CreateDepositRequestBody,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        body: CreateDepositRequestBody,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Set variables.
        let stacks_block_hash: StacksBlockHash = "DUMMY_HASH".into();
        let stacks_block_height: BlockHeight = 0;
        let status = Status::Pending;
        // Make table entry.
        let deposit_entry: DepositEntry = DepositEntry {
            key: DepositEntryKey {
                bitcoin_txid: body.bitcoin_txid,
                bitcoin_tx_output_index: body.bitcoin_tx_output_index,
            },
            parameters: DepositParametersEntry {
                reclaim_script: body.reclaim,
                ..Default::default()
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
            ..Default::default()
        };
        // Validate deposit entry.
        deposit_entry.validate()?;
        // Add entry to the table.
        accessors::add_deposit_entry(&context, &deposit_entry).await?;
        // Respond.
        let response: CreateDepositResponse = deposit_entry.try_into()?;
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
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn update_deposits(
    context: EmilyContext,
    body: UpdateDepositsRequestBody,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        body: UpdateDepositsRequestBody,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Validate request.
        let validated_request: ValidatedUpdateDepositsRequest = body.try_into()?;
        // Create aggregator.
        let mut updated_deposits: Vec<Deposit> =
            Vec::with_capacity(validated_request.deposits.len());
        // Loop through all updates and execute.
        for update in validated_request.deposits {
            // Get original deposit entry.
            let deposit_entry = accessors::get_deposit_entry(&context, &update.key).await?;
            // Make the update package.
            let update_package = DepositUpdatePackage::try_from(&deposit_entry, update)?;
            let updated_deposit = accessors::update_deposit(&context, &update_package)
                .await?
                .try_into()?;
            // Append the updated deposit to the list.
            updated_deposits.push(updated_deposit);
        }
        let response = UpdateDepositsResponse { deposits: updated_deposits };
        Ok(with_status(json(&response), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, body)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

// TODO(393): Add handler unit tests.
