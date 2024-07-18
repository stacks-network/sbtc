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
    database::{
        accessors,
        entries::chainstate::{ChainstateEntry, ChainstateEntryKey},
    },
};
use warp::http::StatusCode;
use warp::reply::{json, with_status, Reply};

// TODO(TBD): Add conflict handling to the chainstate endpoint.

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
            height,
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
        // Create new chainstate table entry.
        let new_chainstate_entry: ChainstateEntry = ChainstateEntry {
            key: ChainstateEntryKey {
                height: body.stacks_block_height,
                hash: body.stacks_block_hash,
            },
        };

        // TODO(TBD): Tactfully handle state inconsistencies and race conditions across
        // multiple requests.
        //
        // - chain tip is ahead.
        // - chain tip is far behind.
        // - two chain tips are proposed at the same time for conflicting hashes
        // - etc.
        //
        // `get_chain_tip_or_set_if_absent` is inappropriate in the long run and should be
        // deleted.

        accessors::add_chainstate_entry(&context, &new_chainstate_entry).await?;
        let response: Chainstate = new_chainstate_entry.into();
        Ok(with_status(
            json(&(response as SetChainstateResponse)),
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

// TODO(TBD): Add handler unit tests.
