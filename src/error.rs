use reqwest::StatusCode;
use tonic::Status;

// --- Error Handling ---
// Custom error type to wrap different kinds of errors
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Infisical API Error: {status} - {message}")]
    InfisicalApi { status: StatusCode, message: String },
    
    #[error("Network or request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("JSON parsing error: {0}")]
    JsonParseError(#[from] serde_json::Error),
}

// Convert our custom ServiceError into a gRPC Status
impl From<ServiceError> for Status {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::InfisicalApi { status, message } => {
                let code = match status {
                    StatusCode::BAD_REQUEST => tonic::Code::InvalidArgument,
                    StatusCode::UNAUTHORIZED => tonic::Code::Unauthenticated,
                    StatusCode::FORBIDDEN => tonic::Code::PermissionDenied,
                    StatusCode::NOT_FOUND => tonic::Code::NotFound,
                    _ => tonic::Code::Internal,
                };
                Status::new(code, message)
            }
            ServiceError::RequestError(e) => Status::internal(e.to_string()),
            ServiceError::MissingEnvVar(e) => Status::failed_precondition(e),
            ServiceError::JsonParseError(e) => Status::internal(format!("JSON parsing error: {}", e)),
        }
    }
}