//! This module defines the common data types and methods used by the Blocklist client

use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;

pub mod error;

/// The BlocklistStatus of a user address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BlocklistStatus {
    /// Whether the address is blocklisted or not
    pub is_blocklisted: bool,
    /// The risk severity associated with an address
    pub severity: RiskSeverity,
    /// Blocklist client's acceptance decision based on the risk severity of the address
    pub accept: bool,
    /// Reason for the acceptance decision
    pub reason: Option<String>,
}

/// Risk severity linked to an address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum RiskSeverity {
    /// Low risk
    Low,
    /// Medium risk
    Medium,
    /// High risk
    High,
    /// Severe risk
    Severe,
}

impl fmt::Display for RiskSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RiskSeverity::Low => write!(f, "Low"),
            RiskSeverity::Medium => write!(f, "Moderate"),
            RiskSeverity::High => write!(f, "High"),
            RiskSeverity::Severe => write!(f, "Severe"),
        }
    }
}

impl RiskSeverity {
    /// Checks if the risk severity is considered severe.
    ///
    /// # Returns
    ///
    /// `true` if the risk severity is `Severe`, otherwise `false`.
    pub fn is_severe(&self) -> bool {
        matches!(self, RiskSeverity::Severe)
    }
}
