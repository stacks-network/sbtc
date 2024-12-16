//! Handlers for limits endpoints.
use std::time::SystemTime;

use crate::{
    api::models::limits::{AccountLimits, Limits},
    common::error::Error,
    context::EmilyContext,
    database::{
        accessors,
        entries::limits::{LimitEntry, GLOBAL_CAP_ACCOUNT},
    },
};
use tracing::instrument;
use warp::http::StatusCode;
use warp::reply::{json, with_status, Reply};

/// Get the global limits.
#[utoipa::path(
    get,
    operation_id = "getLimits",
    path = "/limits",
    tag = "limits",
    responses(
        (status = 200, description = "Limits retrieved successfully", body = Limits),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
#[instrument(skip(context))]
pub async fn get_limits(context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(context: EmilyContext) -> Result<impl warp::reply::Reply, Error> {
        let global_limits = accessors::get_limits(&context).await?;
        Ok(with_status(json(&global_limits), StatusCode::OK))
    }
    // Handle and respond.
    handler(context)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Get limits handler.
#[utoipa::path(
    post,
    operation_id = "setLimits",
    path = "/limits",
    tag = "limits",
    request_body = Limits,
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Limits updated successfully", body = Limits),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn set_limits(context: EmilyContext, limits: Limits) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        limits: Limits,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Set the global limits.
        accessors::set_limit_for_account(
            &context,
            &LimitEntry::from_account_limit(
                GLOBAL_CAP_ACCOUNT.to_string(),
                SystemTime::now(),
                &AccountLimits {
                    peg_cap: limits.peg_cap,
                    per_deposit_minimum: limits.per_deposit_minimum,
                    per_deposit_cap: limits.per_deposit_cap,
                    per_withdrawal_cap: limits.per_withdrawal_cap,
                },
            ),
        )
        .await?;
        // Get account cap entries.
        let account_cap_entries = limits
            .account_caps
            .into_iter()
            .map(|(account, account_limits)| {
                LimitEntry::from_account_limit(account, SystemTime::now(), &account_limits)
            })
            .collect::<Vec<LimitEntry>>();
        // Put each entry into the table.
        for entry in account_cap_entries {
            accessors::set_limit_for_account(&context, &entry).await?;
        }
        // Get the limits from the database confirming that the updates were done.
        let global_limits = accessors::get_limits(&context).await?;
        // Respond.
        Ok(with_status(json(&global_limits), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, limits)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Get limits for account handler.
#[utoipa::path(
    get,
    operation_id = "getLimitsForAccount",
    path = "/limits/{account}",
    params(
        ("account" = String, Path, description = "The account for which to get the limits."),
    ),
    tag = "limits",
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Account limits retrieved successfully", body = AccountLimits),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
)]
#[instrument(skip(context))]
pub async fn get_limits_for_account(
    context: EmilyContext,
    account: String,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        account: String,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Get the entry.
        let account_limit: AccountLimits = accessors::get_limit_for_account(&context, &account)
            .await?
            .into();
        // Respond.
        Ok(with_status(json(&account_limit), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, account)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Set limits for account handler.
#[utoipa::path(
    post,
    operation_id = "setLimitsForAccount",
    path = "/limits/{account}",
    params(
        ("account" = String, Path, description = "The account for which to set the limits."),
    ),
    tag = "limits",
    request_body = AccountLimits,
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Set account limits successfully", body = AccountLimits),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context))]
pub async fn set_limits_for_account(
    context: EmilyContext,
    account: String,
    body: crate::api::models::limits::AccountLimits,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        account: String,
        account_limit: crate::api::models::limits::AccountLimits,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Create the limit entry.
        let limit_entry =
            LimitEntry::from_account_limit(account, SystemTime::now(), &account_limit);
        // Put entry into the table.
        accessors::set_limit_for_account(&context, &limit_entry).await?;
        // Respond.
        Ok(with_status(json(&account_limit), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, account, body)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}
