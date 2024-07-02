use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Struct that represents the current status of the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HealthData {
    /// Whether the API is okay.
    pub is_okay: bool,
}
