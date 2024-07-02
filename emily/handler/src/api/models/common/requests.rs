//! Requests module that contains all request types for different API calls.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Generic paginated query representation.
#[derive(Clone, Default, Debug, PartialEq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedQuery<T> {
    /// Next token for the search.
    pub next_token: Option<T>,
    /// Maximum number of results to show.
    pub page_size: Option<u32>,
}
