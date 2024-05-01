use std::process::Command;
use std::env;

fn main() {

    // Ensure that we rerun if the API changes.
    println!("cargo:rerun-if-changed=../../emily/api-definition");
    println!("cargo:rerun-if-changed=build.rs");

    let root_dir = env::current_dir().unwrap();
    let emily_api_dir = root_dir
        .join("..")
        .join("..")
        .join("emily")
        .join("api-definition");

    assert!(
        env::set_current_dir(&emily_api_dir).is_ok(),
        "Couldn't change to the emily/api-definition directory",
    );

    // Run `npm run build`
    let npm_build = Command::new("npm")
        .args(["run", "build"])
        .status()
        .expect("Failed to run `npm run build`");

    assert!(
        npm_build.success(),
        "npm run build failed",
    );
    env::set_current_dir(root_dir).expect("Couldn't change back to the original directory");
}
