// --- Generated Protobuf Code ---
// This module is created by tonic-build in build.rs
pub mod synekms {
    tonic::include_proto!("synekms");
}

pub mod error;
pub mod models;
pub mod service;

// Re-export commonly used types
pub use error::ServiceError;
pub use service::SyneKmsService;
pub use synekms::{
    kms_service_server::{KmsService, KmsServiceServer},
    kms_service_client::KmsServiceClient,
    CreateKeyRequest, CreateKeyResponse,
    DecryptRequest, DecryptResponse,
    EncryptRequest, EncryptResponse,
    SignRequest, SignResponse,
    VerifyRequest, VerifyResponse,
};