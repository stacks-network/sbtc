use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub risk_analysis: RiskAnalysisConfig,
}

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Deserialize, Clone)]
pub struct RiskAnalysisConfig {
    pub api_url: String,
    pub api_key: String,
}
