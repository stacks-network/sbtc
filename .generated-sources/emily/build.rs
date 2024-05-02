use std::process::Command;
use std::env;

fn main() {

    // Ensure that we rerun if the API changes.
    println!("cargo:rerun-if-changed=../../emily/api-definition/models");
    println!("cargo:rerun-if-changed=build.rs");

    // Go to the api directory.
    let root_dir = env::current_dir().unwrap();
    let emily_api_dir = root_dir
        .join("..")
        .join("..")
        .join("emily")
        .join("api-definition");

    // Move execution location.
    assert!(
        env::set_current_dir(&emily_api_dir).is_ok(),
        "Couldn't change to the emily/api-definition directory.",
    );

    // Run `npm install`.
    let npm_install = Command::new("npm")
        .args(["install"])
        .status()
        .expect("Failed to run `npm install`.");

    // Fail if the install command failed.
    assert!(
        npm_install.success(),
        "npm install failed.",
    );

    // Run `npm run build`.
    let npm_build = Command::new("npm")
        .args(["run", "build"])
        .status()
        .expect("Failed to run `npm run build`.");

    // Fail if the build command failed.
    assert!(
        npm_build.success(),
        "npm run build failed.",
    );
}
