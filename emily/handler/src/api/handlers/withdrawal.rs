//! Handlers for withdrawal endpoints.
use warp::reply::{json, with_status, Reply};

use crate::api::models::common::Status;
use crate::api::models::withdrawal::{
    requests::{CreateWithdrawalRequestBody, GetWithdrawalsQuery, UpdateWithdrawalsRequestBody},
    responses::{GetWithdrawalsResponse, UpdateWithdrawalsResponse},
};
use crate::api::models::withdrawal::{Withdrawal, WithdrawalInfo};
use crate::common::error::Error;
use crate::context::EmilyContext;
use crate::database::accessors;
use crate::database::entries::withdrawal::{
    ValidatedUpdateWithdrawalRequest, WithdrawalEntry, WithdrawalEntryKey, WithdrawalEvent,
    WithdrawalParametersEntry,
};
use crate::database::entries::StatusEntry;
use warp::http::StatusCode;

/// Get withdrawal handler.
#[utoipa::path(
    get,
    operation_id = "getWithdrawal",
    path = "/withdrawal/{id}",
    params(
        ("id" = u64, Path, description = "id associated with the Withdrawal"),
    ),
    tag = "withdrawal",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Withdrawal retrieved successfully", body = Withdrawal),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_withdrawal(context: EmilyContext, request_id: u64) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        request_id: u64,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Get withdrawal.
        let withdrawal: Withdrawal = accessors::get_withdrawal_entry(&context, &request_id)
            .await?
            .try_into()?;

        // Respond.
        Ok(with_status(json(&withdrawal), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, request_id)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Get withdrawals handler.
#[utoipa::path(
    get,
    operation_id = "getWithdrawals",
    path = "/withdrawal",
    params(
        ("status" = Status, Query, description = "the status to search by when getting all deposits."),
        ("nextToken" = Option<String>, Query, description = "the next token value from the previous return of this api call."),
        ("pageSize" = Option<i32>, Query, description = "the maximum number of items in the response list.")
    ),
    tag = "withdrawal",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Withdrawals retrieved successfully", body = GetWithdrawalsResponse),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_withdrawals(
    context: EmilyContext,
    query: GetWithdrawalsQuery,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        query: GetWithdrawalsQuery,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Deserialize next token into the exclusive start key if present.
        let (entries, next_token) = accessors::get_withdrawal_entries(
            &context,
            &query.status,
            query.next_token,
            query.page_size,
        )
        .await?;
        // Convert data into resource types.
        let withdrawals: Vec<WithdrawalInfo> =
            entries.into_iter().map(|entry| entry.into()).collect();
        // Create response.
        let response = GetWithdrawalsResponse { withdrawals, next_token };
        // Respond.
        Ok(with_status(json(&response), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, query)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Create withdrawal handler.
#[utoipa::path(
    post,
    operation_id = "createWithdrawal",
    path = "/withdrawal",
    tag = "withdrawal",
    request_body = CreateWithdrawalRequestBody,
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Withdrawal created successfully", body = Withdrawal),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
pub async fn create_withdrawal(
    context: EmilyContext,
    body: CreateWithdrawalRequestBody,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        body: CreateWithdrawalRequestBody,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Get the api state and error if the api state is claimed by a reorg.
        //
        // Note: This may not be necessary due to the implied order of events
        // that the API can receive from stacks nodes, but it's being added here
        // in order to enforce added stability to the API during a reorg.
        let api_state = accessors::get_api_state(&context).await?;
        api_state.error_if_reorganizing()?;

        let CreateWithdrawalRequestBody {
            request_id,
            stacks_block_hash,
            stacks_block_height,
            recipient,
            amount,
            parameters,
        } = body;

        let status = Status::Pending;

        // Make table entry.
        let withdrawal_entry: WithdrawalEntry = WithdrawalEntry {
            key: WithdrawalEntryKey {
                request_id,
                // TODO(396): Remove dummy hash.
                stacks_block_hash: stacks_block_hash.clone(),
            },
            recipient,
            amount,
            parameters: WithdrawalParametersEntry { max_fee: parameters.max_fee },
            history: vec![WithdrawalEvent {
                status: StatusEntry::Pending,
                message: "Just received withdrawal".to_string(),
                stacks_block_hash: stacks_block_hash.clone(),
                stacks_block_height,
            }],
            status,
            last_update_block_hash: stacks_block_hash,
            last_update_height: stacks_block_height,
            ..Default::default()
        };
        // Validate withdrawal entry.
        withdrawal_entry.validate()?;
        // Add entry to the table.
        accessors::add_withdrawal_entry(&context, &withdrawal_entry).await?;
        // Respond.
        let response: Withdrawal = withdrawal_entry.try_into()?;
        Ok(with_status(json(&response), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, body)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Update withdrawals handler.
#[utoipa::path(
    put,
    operation_id = "updateWithdrawals",
    path = "/withdrawal",
    tag = "withdrawal",
    request_body = UpdateWithdrawalsRequestBody,
    responses(
        (status = 201, description = "Withdrawals updated successfully", body = UpdateWithdrawalsResponse),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
pub async fn update_withdrawals(
    context: EmilyContext,
    body: UpdateWithdrawalsRequestBody,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        body: UpdateWithdrawalsRequestBody,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Get the api state and error if the api state is claimed by a reorg.
        //
        // Note: This may not be necessary due to the implied order of events
        // that the API can receive from stacks nodes, but it's being added here
        // in order to enforce added stability to the API during a reorg.
        let api_state = accessors::get_api_state(&context).await?;
        api_state.error_if_reorganizing()?;
        // Validate request.
        let validated_request: ValidatedUpdateWithdrawalRequest = body.try_into()?;

        // Infer the new chainstates that would come from these deposit updates and then
        // attempt to update the chainstates.
        let inferred_chainstates = validated_request.inferred_chainstates()?;
        for chainstate in inferred_chainstates {
            // TODO(TBD): Determine what happens if this occurs in multiple lambda
            // instances at once.
            crate::api::handlers::chainstate::add_chainstate_entry_or_reorg(&context, &chainstate)
                .await?;
        }

        // Create aggregator.
        let mut updated_withdrawals: Vec<(usize, Withdrawal)> =
            Vec::with_capacity(validated_request.withdrawals.len());

        // Loop through all updates and execute.
        for (index, update) in validated_request.withdrawals {
            let updated_withdrawal =
                accessors::pull_and_update_withdrawal_with_retry(&context, update, 15).await?;
            updated_withdrawals.push((index, updated_withdrawal.try_into()?));
        }

        updated_withdrawals.sort_by_key(|(index, _)| *index);
        let withdrawals = updated_withdrawals
            .into_iter()
            .map(|(_, withdrawal)| withdrawal)
            .collect();
        let response = UpdateWithdrawalsResponse { withdrawals };
        Ok(with_status(json(&response), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, body)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

// TODO(393): Add handler unit tests.
