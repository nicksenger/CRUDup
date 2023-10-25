fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().out_dir("src/proto").compile(
        &[
            "proto/gateway.proto",
            "proto/auth.proto",
        ],
        &["proto/"],
    )?;
    Ok(())
}
