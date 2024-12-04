//! Handlers for Deposit endpoints.
use std::time::SystemTime;

use bitcoin::ScriptBuf;
use stacks_common::codec::StacksMessageCodec as _;
use warp::http::StatusCode;
use warp::reply::json;
use warp::reply::with_status;
use warp::reply::Reply;

use crate::api::models::common::Status;
use crate::api::models::deposit::requests::CreateDepositRequestBody;
use crate::api::models::deposit::requests::GetDepositsForTransactionQuery;
use crate::api::models::deposit::requests::GetDepositsQuery;
use crate::api::models::deposit::requests::UpdateDepositsRequestBody;
use crate::api::models::deposit::responses::GetDepositsForTransactionResponse;
use crate::api::models::deposit::responses::GetDepositsResponse;
use crate::api::models::deposit::responses::UpdateDepositsResponse;
use crate::api::models::deposit::Deposit;
use crate::api::models::deposit::DepositInfo;
use crate::api::models::signer::Signer;
use crate::api::models::signer::SignerInfo;
use crate::common::error::Error;
use crate::context::EmilyContext;
use crate::database::accessors;
use crate::database::entries::deposit::DepositEntry;
use crate::database::entries::deposit::DepositEntryKey;
use crate::database::entries::deposit::DepositEvent;
use crate::database::entries::deposit::DepositParametersEntry;
use crate::database::entries::deposit::ValidatedUpdateDepositsRequest;
use crate::database::entries::signers::SignerEntry;
use crate::database::entries::signers::SignerInfoEntry;
use crate::database::entries::StatusEntry;

const API_KEY: &str = "api_key";

/// The register signer handler.
#[utoipa::path(
    post,
    operation_id = "registerSigner",
    path = "/signer",
    request_body = RegisterSignerRequestBody,
    tag = "signer",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Successfully registered signer", body = FullSigner),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn register_signer(
    context: EmilyContext, request: Signer,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a
    // reply.
    async fn handler(
        context: EmilyContext, full_signer: Signer,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Set variables.
        let signer_entry = SignerEntry::from_full_signer(
            API_KEY.to_string(),
            full_signer,
            SystemTime::now(),
        );
        // Set the signer.
        accessors::set_signer_entry(&context, &signer_entry).await?;
        // Get signer.
        let full_signer: Signer = accessors::get_signer_entry_from_api_key(
            &context,
            API_KEY.to_string(),
        )
        .await?
        .into();
        // Respond.
        Ok(with_status(json(&full_signer), StatusCode::OK))
    }

    // Handle and respond.
    handler(context, request)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}

/// The register signer handler.
#[utoipa::path(
    post,
    operation_id = "getSigner",
    path = "/signer/{public_key}",
    request_body = RegisterSignerRequestBody,
    params(
        ("public_key" = String, Path, description = "The public key of the signer."),
    ),
    tag = "signer",
    responses(
        // TODO(271): Add success body.
        (status = 200, description = "Successfully got the signer infor", body = FullSigner),
        (status = 400, description = "Invalid request body", body = ErrorResponse),
        (status = 404, description = "Address not found", body = ErrorResponse),
        (status = 405, description = "Method not allowed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_signer(
    context: EmilyContext, public_key: String,
) -> impl warp::reply::Reply {
    // Internal handler so `?` can be used correctly while still returning a
    // reply.
    async fn handler(
        context: EmilyContext, public_key: String,
    ) -> Result<impl warp::reply::Reply, Error> {
        // Get signer.
        let signer: SignerInfo =
            accessors::get_signer_entry_from_public_key(&context, public_key)
                .await?
                .into();
        // Respond.
        Ok(with_status(json(&signer), StatusCode::OK))
    }

    // Handle and respond.
    handler(context, public_key)
        .await
        .map_or_else(Reply::into_response, Reply::into_response)
}
