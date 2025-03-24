//! Requests for withdrawal api calls.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::models::chainstate::Chainstate;
use crate::api::models::common::{Fulfillment, Status};
use crate::api::models::withdrawal::WithdrawalParameters;
use crate::common::error::{self, ValidationError};
use crate::database::entries::withdrawal::{
    ValidatedUpdateWithdrawalRequest, ValidatedWithdrawalUpdate, WithdrawalEvent,
};
use crate::database::entries::StatusEntry;

/// Query structure for the get withdrawals request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetWithdrawalsQuery {
    /// Operation status.
    pub status: Status,
    /// Next token for the search.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_token: Option<String>,
    /// Maximum number of results to show.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u16>,
}

/// Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateWithdrawalRequestBody {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: u64,
    /// The stacks block hash in which this request id was initiated.
    pub stacks_block_hash: String,
    /// The stacks block hash in which this request id was initiated.
    pub stacks_block_height: u64,
    /// The recipient's Bitcoin hex-encoded scriptPubKey.
    pub recipient: String,
    /// The sender's Stacks principal.
    pub sender: String,
    /// Amount of BTC being withdrawn in satoshis.
    pub amount: u64,
    /// Withdrawal request parameters.
    pub parameters: WithdrawalParameters,
}

/// A singular Withdrawal update that contains only the fields pertinent
/// to updating the status of a withdrawal. This includes the key related
/// data in addition to status history related data.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalUpdate {
    /// The id of the Stacks withdrawal request that initiated the sBTC operation.
    pub request_id: u64,
    /// The status of the withdrawal.
    pub status: Status,
    /// The status message of the withdrawal.
    pub status_message: String,
    /// Details about the on chain artifacts that fulfilled the withdrawal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fulfillment: Option<Fulfillment>,
}

impl WithdrawalUpdate {
    /// Try to convert the withdrawal update into a validated withdrawal update.
    ///
    /// # Errors
    ///
    /// - `ValidationError::WithdrawalMissingFulfillment`: If the withdrawal update is missing a fulfillment.
    pub fn try_into_validated_withdrawal_update(
        self,
        chainstate: Chainstate,
    ) -> Result<ValidatedWithdrawalUpdate, error::Error> {
        // Make status entry.
        let status_entry: StatusEntry = match self.status {
            Status::Confirmed => {
                let fulfillment =
                    self.fulfillment
                        .ok_or(ValidationError::WithdrawalMissingFulfillment(
                            self.request_id,
                        ))?;
                StatusEntry::Confirmed(fulfillment)
            }
            Status::Accepted => StatusEntry::Accepted,
            Status::Pending => StatusEntry::Pending,
            Status::Reprocessing => StatusEntry::Reprocessing,
            Status::Failed => StatusEntry::Failed,
        };
        // Make the new event.
        let event = WithdrawalEvent {
            status: status_entry,
            message: self.status_message,
            stacks_block_height: chainstate.stacks_block_height,
            stacks_block_hash: chainstate.stacks_block_hash,
        };
        // Return the validated update.
        Ok(ValidatedWithdrawalUpdate {
            request_id: self.request_id,
            event,
        })
    }
}

/// Request structure for the create withdrawal request.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWithdrawalsRequestBody {
    /// Withdrawal updates to execute.
    pub withdrawals: Vec<WithdrawalUpdate>,
}

impl UpdateWithdrawalsRequestBody {
    /// Try to convert the request body into a validated update request.
    ///
    /// # Errors
    ///
    /// - `ValidationError::WithdrawalsMissingFulfillment`: If any of the withdrawal updates are missing a fulfillment.
    pub fn try_into_validated_update_request(
        self,
        chainstate: Chainstate,
    ) -> Result<ValidatedUpdateWithdrawalRequest, error::Error> {
        // Validate all the withdrawal updates.
        let mut withdrawals: Vec<(usize, ValidatedWithdrawalUpdate)> = vec![];
        let mut failed_ids: Vec<u64> = vec![];

        for (index, update) in self.withdrawals.into_iter().enumerate() {
            match update
                .clone()
                .try_into_validated_withdrawal_update(chainstate.clone())
            {
                Ok(validated_update) => withdrawals.push((index, validated_update)),
                Err(_) => failed_ids.push(update.request_id),
            }
        }

        // If there are failed conversions, return an error.
        if !failed_ids.is_empty() {
            return Err(ValidationError::WithdrawalsMissingFulfillment(failed_ids).into());
        }

        // Sort updates by stacks_block_height to process them in chronological order.
        withdrawals.sort_by_key(|(_, update)| update.event.stacks_block_height);

        Ok(ValidatedUpdateWithdrawalRequest { withdrawals })
    }
}
