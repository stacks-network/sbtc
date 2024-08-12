//! Handlers for chainstate endpoints.
use crate::{
    api::models::{
        chainstate::{
            requests::{SetChainstateRequestBody, UpdateChainstateRequestBody},
            responses::{GetChainstateResponse, SetChainstateResponse},
            Chainstate,
        },
        common::BlockHeight,
    },
    common::error::Error,
    context::EmilyContext,
    database::{accessors, entries::chainstate::ChainstateEntry},
};
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
        let chaintip: Chainstate = api_state.chaintip.into();
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
        // Get chainstate at height - hopefully just one.
        //
        // If there is more than one then there is a state inconsistency. This is potentially
        // okay but the hope then is that the database is actively being repaired.
        let num_to_retrieve_if_multiple = 5;
        let (entries, _) = accessors::get_chainstate_entries_for_height(
            &context,
            &height,
            None,
            Some(num_to_retrieve_if_multiple),
        )
        .await?;
        // Convert data into resource types.
        let chainstates: Vec<Chainstate> = entries.into_iter().map(|entry| entry.into()).collect();
        // Respond.
        match &chainstates[..] {
            [] => Err(Error::NotFound),
            [chainstate] => Ok(with_status(
                json(chainstate as &GetChainstateResponse),
                StatusCode::OK,
            )),
            _ => Err(Error::Debug(format!(
                "Found too many withdrawals: {chainstates:?}"
            ))),
        }
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
        let chainstate_entry: ChainstateEntry = chainstate.clone().into();
        // TODO(TBD): handle a conflicting internal state error.
        accessors::add_chainstate_entry(&context, &chainstate_entry).await?;
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
    _context: EmilyContext,
    _request: UpdateChainstateRequestBody,
) -> impl warp::reply::Reply {
    Error::NotImplemented
}

// TODO(393): Add handler unit tests.
