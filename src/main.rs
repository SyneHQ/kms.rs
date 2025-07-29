use std::env;
use tonic::transport::Server;

use syne_kms::{
    SyneKmsService,
    synekms::kms_service_server::KmsServiceServer,
};

// --- Main Server Entrypoint ---
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file if it exists
    dotenv::dotenv().ok();

    let addr = env::var("GRPC_SERVER_ADDRESS")
        .unwrap_or_else(|_| "[::1]:50051".to_string())
        .parse()?;
    
    let kms_service = SyneKmsService::new()?;

    println!("gRPC Server listening on {}", addr);

    Server::builder()
        .add_service(KmsServiceServer::new(kms_service))
        .serve(addr)
        .await?;

    Ok(())
}
