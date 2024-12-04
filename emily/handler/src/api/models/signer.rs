//! Request structures for signer api calls.

use serde::Deserialize;
use serde::Serialize;
use utoipa::ToResponse;
use utoipa::ToSchema;

/// The health of the signer.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
pub enum SignerHealth {
    /// The signer is inactive.
    Healthy,
    /// The signer is unhealthy.
    Unhealthy(String),
    /// The signer is dead.
    Dead(String),
    /// The status of the signer is unknown.
    #[default]
    Unknown,
}

/// The full information about the signer. This includes some private
/// information that only select users should have access to.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
pub struct Signer {
    /// The "name" of the signer being registered.
    pub name: String,
    /// Public key.
    pub public_key: String,
    /// Approximate location.
    pub location: String,
    /// Signer health.
    pub health: SignerHealth,
    /// Contact information for the signer. This is private information.
    pub contact: String,
}

/// The representation of the signer.
#[derive(
    Clone,
    Default,
    Debug,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ToSchema,
    ToResponse,
)]
pub struct SignerInfo {
    /// The "name" of the signer being registered.
    pub name: String,
    /// Public key.
    pub public_key: String,
    /// Approximate location.
    pub location: String,
    /// Signer health.
    pub health: SignerHealth,
}
