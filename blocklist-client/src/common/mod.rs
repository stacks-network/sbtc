use serde::{Deserialize, Serialize};
use std::fmt;

pub mod error;

/// The BlocklistStatus of a user address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistStatus {
    // Whether the address is blocklisted or not
    pub is_blocklisted: bool,
    // The risk severity associated with an address
    pub severity: RiskSeverity,
    // Blocklist client's acceptance decision based on the risk severity of the address
    pub accept: bool,
    // Reason for the acceptance decision
    pub reason: Option<String>,
}

/// Risk severity linked to an address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
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
    pub fn is_severe(&self) -> bool {
        matches!(self, RiskSeverity::Severe)
    }
}
