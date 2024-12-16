use std::env;

fn main() {
    set_up_build_info();
    // compile_protos();
}

pub fn set_up_build_info() {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .expect("Failed to execute rustc");

    let version = String::from_utf8_lossy(&output.stdout);

    let git_output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output();

    let git_hash = match git_output {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            String::from_utf8_lossy(&output.stdout).to_string()
        }
        _ => std::env::var("GIT_COMMIT").unwrap_or_default(),
    };

    let env_abi = std::env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    // We capture these variables in our binary and use them in the
    // build_info metric.
    println!("cargo:rustc-env=CARGO_CFG_TARGET_ENV={}", env_abi.trim());
    println!("cargo:rustc-env=CARGO_CFG_TARGET_ARCH={}", arch.trim());
    println!("cargo:rustc-env=GIT_COMMIT={}", git_hash.trim());
    println!("cargo:rustc-env=RUSTC_VERSION={}", version.trim());
}

pub fn compile_protos() {
    let workingdir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();

    let protos = [
        "protobufs/bitcoin/bitcoin.proto",
        "protobufs/crypto/common.proto",
        "protobufs/crypto/wsts/state.proto",
        "protobufs/crypto/wsts/wsts.proto",
        "protobufs/stacks/common.proto",
        "protobufs/stacks/signer/v1/decisions.proto",
        "protobufs/stacks/signer/v1/requests.proto",
        "protobufs/stacks/signer/v1/messages.proto",
    ]
    .map(|path| workingdir.join(path));

    println!("cargo:rerun-if-changed=protobufs/");

    // Compile protocol buffers
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .btree_map(["."])
        .out_dir(workingdir.join("signer/src/proto/generated/"))
        .include_file("mod.rs")
        .type_attribute("crypto.Uint256", "#[derive(Copy)]")
        .compile(&protos, &[workingdir.join("protobufs")])
        .expect("Unable to compile protocol buffers");
}
