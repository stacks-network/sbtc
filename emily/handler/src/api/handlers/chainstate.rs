//! Handlers for chainstate endpoints.
use crate::{
    api::{
        handlers::internal::{execute_reorg_handler, ExecuteReorgRequest},
        models::{
            chainstate::{
                requests::{SetChainstateRequestBody, UpdateChainstateRequestBody},
                responses::{GetChainstateResponse, SetChainstateResponse},
                Chainstate,
            },
            common::BlockHeight,
        },
    },
    common::error::{Error, Inconsistency},
    context::EmilyContext,
    database::{accessors, entries::chainstate::ChainstateEntry},
};
use tracing::warn;
use warp::http::StatusCode;
use warp::reply::{json, with_status, Reply};

// TODO(TBD): Add conflict handling to the chainstate endpoint.

/// Get chain tip handler.
#[utoipa::path(
    get,
    operation_id = "getChainTip",
    path = "/chainstate",
    tag = "chainstate",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Chain tip retrieved successfully", body = GetChainstateResponse),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_chain_tip(context: EmilyContext) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(context: EmilyContext) -> Result<impl warp::reply::Reply, Error> {
        // TODO(390): Handle multiple being in the tip list here.
        let api_state = accessors::get_api_state(&context).await?;
        let chaintip: Chainstate = api_state.chaintip().into();
        Ok(with_status(
            json(&(chaintip as GetChainstateResponse)),
            StatusCode::OK,
        ))
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
        // TODO(271): Add success body.
        (status = 200, description = "Chainstate retrieved successfully", body = GetChainstateResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_chainstate_at_height(
    context: EmilyContext,
    height: BlockHeight,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        height: BlockHeight,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Get chainstate at height.
        let chainstate: Chainstate = accessors::get_chainstate_entry_at_height(&context, &height)
            .await?
            .into();
        // Respond.
        Ok(with_status(
            json(&(chainstate as GetChainstateResponse)),
            StatusCode::OK,
        ))
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
    request_body = SetChainstateRequestBody,
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Chainstate updated successfully", body = SetChainstateResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn set_chainstate(
    context: EmilyContext,
    body: SetChainstateRequestBody,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        body: SetChainstateRequestBody,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Convert body to the correct type.
        let chainstate: Chainstate = body;
        add_chainstate_entry_or_reorg(&context, &chainstate).await?;
        // Respond.
        Ok(with_status(
            json(&(chainstate as SetChainstateResponse)),
            StatusCode::CREATED,
        ))
    }
    // Handle and respond.
    handler(context, body)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Update chainstate handler.
#[utoipa::path(
    put,
    operation_id = "updateChainstate",
    path = "/chainstate",
    tag = "chainstate",
    request_body = UpdateChainstateRequestBody,
    responses(
        // TODO(271): Add success body.
        (status = 201, description = "Chainstate updated successfully", body = UpdateChainstateResponse),
        (status = 400, description = "Invalid request body"),
        (status = 404, description = "Address not found"),
        (status = 405, description = "Method not allowed"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn update_chainstate(
    context: EmilyContext,
    request: UpdateChainstateRequestBody,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a reply.
    async fn handler(
        context: EmilyContext,
        body: SetChainstateRequestBody,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Convert body to the correct type.
        let chainstate: Chainstate = body;
        add_chainstate_entry_or_reorg(&context, &chainstate).await?;
        // Respond.
        Ok(with_status(
            json(&(chainstate as SetChainstateResponse)),
            StatusCode::CREATED,
        ))
    }
    // Handle and respond.
    handler(context, request)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// Adds the chainstate to the table, and reorganizes the API if there's a
/// conflict that suggests it needs a reorg in order for this entry to be
/// consistent.
async fn add_chainstate_entry_or_reorg(
    context: &EmilyContext,
    chainstate: &Chainstate,
) -> Result<(), Error> {
    // Get chainstate as entry.
    let entry: ChainstateEntry = chainstate.clone().into();
    match accessors::add_chainstate_entry(context, &entry).await {
        Err(Error::InconsistentState(Inconsistency::Chainstate(conflicting_chainstates))) => {
            let execute_reorg_request = ExecuteReorgRequest {
                canonical_tip: chainstate.clone(),
                conflicting_chainstates,
            };
            // Execute the reorg.
            execute_reorg_handler(context, execute_reorg_request)
                .await
                .inspect_err(|e| warn!("Failed executing reorg with error {}", e))?;
        }
        e @ Err(_) => return e,
        _ => {}
    };
    // Return.
    Ok(())
}

// TODO(393): Add handler unit tests.
