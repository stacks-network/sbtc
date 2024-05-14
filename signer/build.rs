fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("src/network/message.proto")?;
    Ok(())
}
