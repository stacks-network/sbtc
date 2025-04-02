//! Handlers for chainstate endpoints.
use crate::{
    api::{
        handlers::internal::{ExecuteReorgRequest, execute_reorg_handler},
        models::chainstate::Chainstate,
    },
    common::error::{Error, Inconsistency},
    context::EmilyContext,
    database::{accessors, entries::chainstate::ChainstateEntry},
};
use tracing::{debug, info, instrument, warn};
use warp::http::StatusCode;
use warp::reply::{Reply, json, with_status};

// TODO(TBD): Add conflict handling to the chainstate endpoint.

/// Get chain tip handler.
#[utoipa::path(
    get,
    operation_id = "getChainTip",
    path = "/chainstate",
    tag = "chainstate",
    responses(
        (status = 200, description = "Chain tip retrieved successfully", body = Chainstate),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn get_chain_tip(context: EmilyContext) -> impl warp::reply::Reply {
    debug!("Attempting to get chain tip");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(context: EmilyContext) -> Result<impl warp::reply::Reply, Error> {
        // TODO(390): Handle multiple being in the tip list here.
        let api_state = accessors::get_api_state(&context).await?;
        let chaintip: Chainstate = api_state.chaintip().into();
        Ok(with_status(json(&chaintip), StatusCode::OK))
    }
    // Handle and respond.
    handler(context)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Get chainstate handler.
#[utoipa::path(
    get,
    operation_id = "getChainstateAtHeight",
    path = "/chainstate/{height}",
    params(
        ("height" = u64, Path, description = "Height of the blockchain data to receive."),
    ),
    tag = "chainstate",
    responses(
        (status = 200, description = "Chainstate retrieved successfully", body = Chainstate),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
#[instrument(skip(context))]
pub async fn get_chainstate_at_height(
    context: EmilyContext,
    height: u64,
) -> impl warp::reply::Reply {
    debug!("Attempting to get chainstate at height: {height:?}");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(context: EmilyContext, height: u64) -> Result<impl warp::reply::Reply, Error> {
        // Get chainstate at height.
        let chainstate: Chainstate = accessors::get_chainstate_entry_at_height(&context, &height)
            .await?
            .into();
        // Respond.
        Ok(with_status(json(&chainstate), StatusCode::OK))
    }
    // Handle and respond.
    handler(context, height)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Set chainstate handler.
#[utoipa::path(
    post,
    operation_id = "setChainstate",
    path = "/chainstate",
    tag = "chainstate",
    request_body = Chainstate,
    responses(
        (status = 201, description = "Chainstate updated successfully", body = Chainstate),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context, api_key))]
pub async fn set_chainstate(
    context: EmilyContext,
    api_key: String,
    body: Chainstate,
) -> impl warp::reply::Reply {
    debug!("Attempting to set chainstate: {body:?}");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        api_key: String,
        body: Chainstate,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Convert body to the correct type.
        let chainstate: Chainstate = body;
        let can_reorg = context.settings.trusted_reorg_api_key == api_key;
        add_chainstate_entry_or_reorg(&context, can_reorg, &chainstate).await?;
        // Respond.
        Ok(with_status(json(&chainstate), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, api_key, body)
        .await
        .map_err(|error| {
            warn!("Failed to set chainstate with error: {}", error);
            error
        })
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Update chainstate handler.
#[utoipa::path(
    put,
    operation_id = "updateChainstate",
    path = "/chainstate",
    tag = "chainstate",
    request_body = Chainstate,
    responses(
        (status = 201, description = "Chainstate updated successfully", body = Chainstate),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("ApiGatewayKey" = []))
)]
#[instrument(skip(context, api_key))]
pub async fn update_chainstate(
    context: EmilyContext,
    api_key: String,
    request: Chainstate,
) -> impl warp::reply::Reply {
    debug!("Attempting to update chainstate: {request:?}");
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        api_key: String,
        body: Chainstate,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Convert body to the correct type.
        let chainstate: Chainstate = body;
        let can_reorg = context.settings.trusted_reorg_api_key == api_key;
        add_chainstate_entry_or_reorg(&context, can_reorg, &chainstate).await?;
        // Respond.
        Ok(with_status(json(&chainstate), StatusCode::CREATED))
    }
    // Handle and respond.
    handler(context, api_key, request)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Adds the chainstate to the table, and reorganizes the API if there's a
/// conflict that suggests it needs a reorg in order for this entry to be
/// consistent.
///
/// TODO(TBD): Consider moving this logic into database accessor structures.
pub async fn add_chainstate_entry_or_reorg(
    context: &EmilyContext,
    can_reorg: bool,
    chainstate: &Chainstate,
) -> Result<(), Error> {
    // Get chainstate as entry.
    let entry: ChainstateEntry = chainstate.clone().into();
    debug!("Attempting to add chainstate: {entry:?}");
    match accessors::add_chainstate_entry_with_retry(context, &entry, 15).await {
        Err(Error::InconsistentState(Inconsistency::Chainstates(conflicting_chainstates))) => {
            if can_reorg {
                info!("Inconsistent chainstate found; attempting reorg for {entry:?}");
                let execute_reorg_request = ExecuteReorgRequest {
                    canonical_tip: chainstate.clone(),
                    conflicting_chainstates,
                };
                // Execute the reorg.
                execute_reorg_handler(context, execute_reorg_request)
                    .await
                    .inspect_err(|e| warn!("Failed executing reorg with error {}", e))?;
            // Log error.
            } else {
                debug!("Inconsistent chainstate found for {entry:?} but we pretend it's okay.");
            }
        }
        e @ Err(_) => return e,
        _ => {}
    };
    // Return.
    Ok(())
}

// TODO(393): Add handler unit tests.
