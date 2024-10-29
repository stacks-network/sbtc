fn main() {
    compile_protos();
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
    ]
    .map(|path| workingdir.join(path));

    println!("cargo:rerun-if-changed=protobufs/");

    // Compile protocol buffers
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(workingdir.join("signer/src/proto/generated/"))
        .include_file("mod.rs")
        .type_attribute("crypto.Uint256", "#[derive(Copy)]")
        .compile(&protos, &[workingdir.join("protobufs")])
        .expect("Unable to compile protocol buffers");
}
