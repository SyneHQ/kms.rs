use serde::{Deserialize, Serialize};

// --- Infisical API Request/Response Models ---

// Create Key Request
#[derive(Debug, Serialize)]
pub struct InfisicalCreateKeyRequest<'a> {
    #[serde(rename = "projectId")]
    pub project_id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    #[serde(rename = "encryptionAlgorithm")]
    pub encryption_algorithm: &'a str,
}

// Create Key Response
#[derive(Debug, Deserialize)]
pub struct InfisicalCreateKeyResponse {
    pub key: InfisicalKeyDetails,
}

#[derive(Debug, Deserialize)]
pub struct InfisicalKeyDetails {
    pub id: String,
    pub description: String,
    #[serde(default = "default_false")]
    pub is_disabled: bool,
    #[serde(default = "default_false")]
    pub is_reserved: bool,
    #[serde(default = "default_empty_string")]
    pub org_id: String,
    pub name: String,
    #[serde(default = "default_empty_string")]
    pub created_at: String,
    #[serde(default = "default_empty_string")]
    pub updated_at: String,
    pub project_id: String,
}

fn default_false() -> bool {
    false
}

fn default_empty_string() -> String {
    String::new()
}

// Encrypt Request
#[derive(Debug, Serialize)]
pub struct InfisicalEncryptRequest<'a> {
    pub plaintext: &'a str,
}

// Encrypt Response
#[derive(Debug, Deserialize)]
pub struct InfisicalEncryptResponse {
    pub ciphertext: String,
}

// Decrypt Request
#[derive(Debug, Serialize)]
pub struct InfisicalDecryptRequest<'a> {
    pub ciphertext: &'a str,
}

// Decrypt Response
#[derive(Debug, Deserialize)]
pub struct InfisicalDecryptResponse {
    pub plaintext: String,
}

// Sign Request
#[derive(Debug, Serialize)]
pub struct InfisicalSignRequest<'a> {
    pub data: &'a str,
    pub signing_algorithm: Option<&'a str>,
    pub is_digest: Option<bool>,
}

// Sign Response
#[derive(Debug, Deserialize)]
pub struct InfisicalSignResponse {
    pub signature: String,
    pub key_id: String,
    pub signing_algorithm: String,
}

// Verify Request
#[derive(Debug, Serialize)]
pub struct InfisicalVerifyRequest<'a> {
    pub data: &'a str,
    pub signature: &'a str,
    pub signing_algorithm: Option<&'a str>,
    pub is_digest: Option<bool>,
}

// Verify Response
#[derive(Debug, Deserialize)]
pub struct InfisicalVerifyResponse {
    pub signature_valid: bool,
    pub key_id: String,
    pub signing_algorithm: String,
}

// Error Response
#[derive(Debug, Deserialize)]
pub struct InfisicalErrorResponse {
    pub message: String,
}