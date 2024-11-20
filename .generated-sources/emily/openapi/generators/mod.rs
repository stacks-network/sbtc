//! Api specs for each type of API

use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use utoipa::openapi::security::ApiKey;
use utoipa::openapi::security::ApiKeyValue;
use utoipa::openapi::security::SecurityScheme;
use utoipa::Modify;
use utoipa::OpenApi;

/// The admin api definition.
pub mod admin;
/// The public api definition.
pub mod public;
/// The signer api definition.
pub mod signer;
/// The test api definition.
pub mod testing;

/// Write all the API specs to the output files.
pub fn write_all(relative_dir: &'static str) {
    write_openapi_spec(
        relative_dir,
        "admin-emily-openapi-spec.json",
        admin::ApiDoc::openapi(),
    );
    write_openapi_spec(
        relative_dir,
        "public-emily-openapi-spec.json",
        public::ApiDoc::openapi(),
    );
    write_openapi_spec(
        relative_dir,
        "testing-emily-openapi-spec.json",
        testing::ApiDoc::openapi(),
    );
    write_openapi_spec(
        relative_dir,
        "signer-emily-openapi-spec.json",
        signer::ApiDoc::openapi(),
    );
}

/// Creates the spec file and writes it to the output file path.
fn write_openapi_spec(
    relative_directory_path: &str,
    file_name: &str,
    spec: utoipa::openapi::OpenApi,
) {
    // Generate string for api doc.
    let spec_json = spec
        .to_pretty_json()
        .expect(format!("Failed to serialize {file_name} OpenAPI spec file").as_str());
    // Open and write to file.
    let output_file_path = format!("{relative_directory_path}/{file_name}");
    File::create(output_file_path)
        .expect(format!("Failed to create {file_name} OpenAPI spec file").as_str())
        .write_all(spec_json.as_bytes())
        .expect(format!("Failed to write {file_name} OpenAPI spec file").as_str());
}

/// Openapi spec modifier that adds the API Gateway API key to the OpenAPI specification.
/// This adds the key as a schema type but is referenced by name in the paths need to
/// require authentication.
struct AwsApiKey;
impl Modify for AwsApiKey {
    /// Modify the OpenAPI specification to include the AWS API Gateway key.
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(schema) = openapi.components.as_mut() {
            schema.add_security_scheme(
                "ApiGatewayKey",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "x-api-key",
                    "AWS Apigateway key",
                ))),
            );
        }
    }
}

/// Attaches the AWS Lambda integration to the OpenAPI specification. This is necessary
/// for the AWS CDK to attach the lambda to the API Gateway.
///
/// TODO(269): Change Emily API Lambda Integrations to use cdk constructs if possible
/// instead of specification alteration.
struct AwsLambdaIntegration;
impl Modify for AwsLambdaIntegration {
    /// Add AWS extension to openapi specification so AWS CDK can attach the appropriate lambda endpoint.
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        // Gather the extensions to be added to each operation.
        let mut lambda_integration: HashMap<String, serde_json::Value> = HashMap::new();
        lambda_integration.insert(
            "x-amazon-apigateway-integration".to_string(),
            json!({
                "type": "aws_proxy",
                // Note that it's always meant to be POST regardless of the verb in the api spec.
                "httpMethod": "POST",
                "uri": {
                    "Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${OperationLambda}/invocations"
                }
            })
        );
        // Add extensions to each operation.
        openapi
            .paths
            .paths
            .iter_mut()
            .flat_map(|(_, path_item)| path_item.operations.iter_mut())
            .for_each(|(_, operation)| {
                operation
                    .extensions
                    .get_or_insert(Default::default())
                    .extend(lambda_integration.clone())
            });
    }
}
