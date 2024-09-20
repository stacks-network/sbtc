fn main() {
    compile_protos();
}

pub fn compile_protos() {
    let workingdir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();

    let protos = ["protobufs/stacks/signer/message_relay.proto"].map(|path| workingdir.join(path));

    println!("cargo:rerun-if-changed=protobufs/stacks/signer/");

    // Compile protocol buffers
    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .out_dir(workingdir.join("signer/src/proto/generated/"))
        .include_file("mod.rs")
        .compile(&protos, &[workingdir.join("protobufs")])
        .expect("Unable to compile protocol buffers");
}
