/// Specification generator module.
mod generators;

/// The relative directory for the specifications.
const RELATIVE_SPEC_DIRECTORY: &str = "./generated-specs";

/// Main function.
fn main() {
    // Ensure that we rerun if the API spec changes.
    println!("cargo:rerun-if-changed=../handler/src/api");
    // Ensure that we rerun if the scripts responsible for building change.
    println!("cargo:rerun-if-changed=generators");
    println!("cargo:rerun-if-changed=api-config");
    println!("cargo:rerun-if-changed=build.rs");
    // Generate the OpenAPI specification based on the selected specification.
    generators::write_all(RELATIVE_SPEC_DIRECTORY);
}
