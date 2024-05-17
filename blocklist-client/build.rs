use std::fs::File;
use std::io::Write;
use utoipa::OpenApi;

#[path = "src/api/mod.rs"]
mod api;
#[path = "src/client/mod.rs"]
mod client;
#[path = "src/common/mod.rs"]
mod common;
#[path = "src/config.rs"]
mod config;

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(api::handlers::check_address_handler,),
    components(schemas(
        common::BlocklistStatus,
        common::RiskSeverity,
        common::error::ErrorResponse
    ))
)]
struct ApiDoc;

fn main() {
    let api_doc = ApiDoc::openapi();
    let spec_json =
        serde_json::to_string_pretty(&api_doc).expect("Failed to serialize OpenAPI spec");
    let mut file =
        File::create("./src/openapi/openapi.json").expect("Failed to create OpenAPI spec file");
    file.write_all(spec_json.as_bytes())
        .expect("Failed to write OpenAPI spec file");
}
