fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../protobufs/stacks/signer/message_relay.proto")?;
    Ok(())
}
