//! Requests module that contains all request types for different API calls.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Generic paginated query representation.
#[derive(Serialize, Deserialize, Debug, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedQuery<T> {
    /// Next token for search.
    #[serde(default)]
    pub page: Option<T>,
    /// Maximum number of results to show.
    #[serde(default)]
    pub page_size: Option<u32>,
}
