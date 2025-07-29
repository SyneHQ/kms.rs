fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure the proto directory exists
    std::fs::create_dir_all("proto")?;
    
    tonic_build::configure()
        .build_server(true)
        .build_client(true) // Build both server and client for testing
        .compile(
            &["proto/synekms.proto"], // files to compile
            &["proto"],                   // include path
        )?;
    Ok(())
}