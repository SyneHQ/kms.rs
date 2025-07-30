use tonic::transport::Channel;
use base64::Engine;
use syne_kms::{
    KmsServiceClient,
    CreateKeyRequest, EncryptRequest, DecryptRequest, SignRequest, VerifyRequest,
};

// Test configuration
const TEST_SERVER_ADDR: &str = "http://[::1]:50051";

// Helper function to create a client
async fn create_client() -> Result<KmsServiceClient<Channel>, Box<dyn std::error::Error>> {
    let channel = Channel::from_shared(TEST_SERVER_ADDR.to_string())?
        .connect()
        .await?;
    Ok(KmsServiceClient::new(channel))
}

// Helper function to encode data as base64
fn encode_b64(data: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(data.as_bytes())
}

// Helper function to decode base64 data
fn decode_b64(data: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
    Ok(String::from_utf8(bytes)?)
}

// #[tokio::test]
// async fn test_create_key() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = create_client().await?;
    
//     let request = tonic::Request::new(CreateKeyRequest {
//         name: "test-key".to_string(), // Changed to lowercase with hyphens
//         description: "A test key for unit testing".to_string(),
//         slug: "test-key-001".to_string(),
//         encryption_algorithm: "aes-256-gcm".to_string(), // Changed to lowercase
//     });

//     let response = client.create_key(request).await?;
//     let key_response = response.into_inner();

//     // Verify the response contains expected fields
//     assert!(!key_response.key_id.is_empty());
//     assert_eq!(key_response.name, "test-key"); // Updated expectation
//     assert_eq!(key_response.description, "A test key for unit testing");
//     assert_eq!(key_response.slug, "test-key-001");

//     println!("✅ CreateKey test passed - Key ID: {}", key_response.key_id);
//     Ok(())
// }

// #[tokio::test]
// async fn test_encrypt_decrypt_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = create_client().await?;
    
//     // First, create a key
//     let create_request = tonic::Request::new(CreateKeyRequest {
//         name: "encrypt-test-key".to_string(), // Changed to lowercase with hyphens
//         description: "Key for encryption/decryption testing".to_string(),
//         slug: "encrypt-test-key".to_string(),
//         encryption_algorithm: "aes-256-gcm".to_string(),
//     });

//     let create_response = client.create_key(create_request).await?;
//     let key_id = create_response.into_inner().key_id;

//     // Test data
//     let original_data = "Hello, World! This is a test message for encryption.";
//     let plaintext_b64 = encode_b64(original_data);

//     // Encrypt the data
//     let encrypt_request = tonic::Request::new(EncryptRequest {
//         key_id: key_id.clone(),
//         plaintext_b64: plaintext_b64.clone(),
//     });

//     let encrypt_response = client.encrypt(encrypt_request).await?;
//     let ciphertext_b64 = encrypt_response.into_inner().ciphertext_b64;

//     // Verify ciphertext is different from plaintext
//     assert_ne!(ciphertext_b64, plaintext_b64);
//     assert!(!ciphertext_b64.is_empty());

//     // Decrypt the data
//     let decrypt_request = tonic::Request::new(DecryptRequest {
//         key_id: key_id.clone(),
//         ciphertext_b64: ciphertext_b64.clone(),
//     });

//     let decrypt_response = client.decrypt(decrypt_request).await?;
//     let decrypted_b64 = decrypt_response.into_inner().plaintext_b64;

//     // Verify roundtrip
//     assert_eq!(decrypted_b64, plaintext_b64);
    
//     // Decode and verify original data
//     let decrypted_data = decode_b64(&decrypted_b64)?;
//     assert_eq!(decrypted_data, original_data);

//     println!("✅ Encrypt/Decrypt roundtrip test passed");
//     Ok(())
// }

// #[tokio::test]
// async fn test_sign_verify_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = create_client().await?;
    
//     // First, create a key for signing (use symmetric algorithm for key creation)
//     let create_request = tonic::Request::new(CreateKeyRequest {
//         name: "sign-test-key".to_string(), // Changed to lowercase with hyphens
//         description: "Key for signing/verification testing".to_string(),
//         slug: "sign-test-key".to_string(),
//         encryption_algorithm: "aes-256-gcm".to_string(), // Use symmetric algorithm for key creation
//     });

//     let create_response = client.create_key(create_request).await?;
//     let key_id = create_response.into_inner().key_id;

//     // Test data
//     let original_data = "Important document that needs to be signed";
//     let data_b64 = encode_b64(original_data);

//     // Sign the data
//     let sign_request = tonic::Request::new(SignRequest {
//         key_id: key_id.clone(),
//         data_b64: data_b64.clone(),
//         algorithm: Some("RSASSA_PKCS1_V1_5_SHA_512".to_string()), // Use exact algorithm name
//     });

//     let sign_response = client.sign(sign_request).await?;
//     let signature_b64 = sign_response.into_inner().signature_b64;

//     // Verify signature is not empty
//     assert!(!signature_b64.is_empty());

//     // Verify the signature
//     let verify_request = tonic::Request::new(VerifyRequest {
//         key_id: key_id.clone(),
//         data_b64: data_b64.clone(),
//         signature_b64: signature_b64.clone(),
//         algorithm: Some("RSASSA_PKCS1_V1_5_SHA_512".to_string()), // Use exact algorithm name
//     });

//     let verify_response = client.verify(verify_request).await?;
//     let is_valid = verify_response.into_inner().valid;

//     assert!(is_valid, "Signature verification failed");

//     println!("✅ Sign/Verify roundtrip test passed");
//     Ok(())
// }

// #[tokio::test]
// async fn test_verify_invalid_signature() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = create_client().await?;
    
//     // Create a key
//     let create_request = tonic::Request::new(CreateKeyRequest {
//         name: "invalid-sign-test-key".to_string(), // Changed to lowercase with hyphens
//         description: "Key for invalid signature testing".to_string(),
//         slug: "invalid-sign-test-key".to_string(),
//         encryption_algorithm: "aes-256-gcm".to_string(), // Use symmetric algorithm for this test
//     });

//     let create_response = client.create_key(create_request).await?;
//     let key_id = create_response.into_inner().key_id;

//     // Test data
//     let original_data = "Data to be signed";
//     let data_b64 = encode_b64(original_data);

//     // Create an invalid signature
//     let invalid_signature = encode_b64("invalid_signature_data");

//     // Try to verify with invalid signature
//     let verify_request = tonic::Request::new(VerifyRequest {
//         key_id: key_id.clone(),
//         data_b64: data_b64.clone(),
//         signature_b64: invalid_signature,
//         algorithm: Some("RSASSA_PKCS1_V1_5_SHA_512".to_string()), // Use exact algorithm name
//     });

//     let verify_response = client.verify(verify_request).await?;
//     let is_valid = verify_response.into_inner().valid;

//     // Should return false for invalid signature
//     assert!(!is_valid, "Invalid signature should not be valid");

//     println!("✅ Invalid signature verification test passed");
//     Ok(())
// }

// #[tokio::test]
// async fn test_encrypt_with_nonexistent_key() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = create_client().await?;
    
//     // Try to encrypt with a non-existent key ID
//     let encrypt_request = tonic::Request::new(EncryptRequest {
//         key_id: "non-existent-key-id".to_string(),
//         plaintext_b64: encode_b64("test data"),
//     });

//     let result = client.encrypt(encrypt_request).await;
    
//     // Should return an error
//     assert!(result.is_err());
    
//     if let Err(status) = result {
//         // Check if it's a NotFound error (code 5)
//         assert_eq!(status.code(), tonic::Code::NotFound);
//     }

//     println!("✅ Non-existent key error handling test passed");
//     Ok(())
// }

// #[tokio::test]
// async fn test_multiple_encryptions_same_key() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = create_client().await?;
    
//     // Create a key
//     let create_request = tonic::Request::new(CreateKeyRequest {
//         name: "multiple-encrypt-test-key".to_string(), // Changed to lowercase with hyphens
//         description: "Key for multiple encryption testing".to_string(),
//         slug: "multiple-encrypt-test-key".to_string(),
//         encryption_algorithm: "aes-256-gcm".to_string(),
//     });

//     let create_response = client.create_key(create_request).await?;
//     let key_id = create_response.into_inner().key_id;

//     // Encrypt the same data multiple times
//     let test_data = "Same data encrypted multiple times";
//     let plaintext_b64 = encode_b64(test_data);

//     let mut ciphertexts = Vec::new();

//     for i in 0..3 {
//         let encrypt_request = tonic::Request::new(EncryptRequest {
//             key_id: key_id.clone(),
//             plaintext_b64: plaintext_b64.clone(),
//         });

//         let encrypt_response = client.encrypt(encrypt_request).await?;
//         let ciphertext_b64 = encrypt_response.into_inner().ciphertext_b64;
//         ciphertexts.push(ciphertext_b64);

//         println!("  Encryption {}: {}", i + 1, &ciphertexts[i][..20.min(ciphertexts[i].len())]);
//     }

//     // Verify all ciphertexts are different (due to random IV/nonce)
//     assert_ne!(ciphertexts[0], ciphertexts[1]);
//     assert_ne!(ciphertexts[1], ciphertexts[2]);
//     assert_ne!(ciphertexts[0], ciphertexts[2]);

//     // Verify all can be decrypted back to the same plaintext
//     for ciphertext in ciphertexts {
//         let decrypt_request = tonic::Request::new(DecryptRequest {
//             key_id: key_id.clone(),
//             ciphertext_b64: ciphertext,
//         });

//         let decrypt_response = client.decrypt(decrypt_request).await?;
//         let decrypted_b64 = decrypt_response.into_inner().plaintext_b64;
        
//         assert_eq!(decrypted_b64, plaintext_b64);
//     }

//     println!("✅ Multiple encryptions test passed");
//     Ok(())
// }

// Integration test that tests the full workflow
#[tokio::test]
async fn test_full_workflow() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = create_client().await?;
    
    println!("🚀 Starting full workflow test...");

    // 1. Create a key
    let create_request = tonic::Request::new(CreateKeyRequest {
        name: "workflow-test-key".to_string(), // Changed to lowercase with hyphens
        description: "Key for full workflow testing".to_string(),
        slug: "workflow-test-key".to_string(),
        encryption_algorithm: "aes-256-gcm".to_string(),
    });

    let create_response = client.create_key(create_request).await?;
    let key_id = create_response.into_inner().key_id;
    println!("  ✅ Key created: {}", key_id);

    // 2. Encrypt sensitive data
    let sensitive_data = "This is confidential information that needs to be encrypted";
    let plaintext_b64 = encode_b64(sensitive_data);

    let encrypt_request = tonic::Request::new(EncryptRequest {
        key_id: key_id.clone(),
        plaintext_b64: plaintext_b64.clone(),
    });

    let encrypt_response = client.encrypt(encrypt_request).await?;
    let ciphertext_b64 = encrypt_response.into_inner().ciphertext_b64;
    println!("  ✅ Data encrypted");

    // 3. Decrypt the data
    let decrypt_request = tonic::Request::new(DecryptRequest {
        key_id: key_id.clone(),
        ciphertext_b64: ciphertext_b64.clone(),
    });

    let decrypt_response = client.decrypt(decrypt_request).await?;
    let decrypted_b64 = decrypt_response.into_inner().plaintext_b64;
    let decrypted_data = decode_b64(&decrypted_b64)?;
    
    assert_eq!(decrypted_data, sensitive_data);
    println!("  ✅ Data decrypted successfully");

    // 4. Sign the decrypted data
    let sign_request = tonic::Request::new(SignRequest {
        key_id: key_id.clone(),
        data_b64: decrypted_b64.clone(),
        algorithm: Some("RSASSA_PKCS1_V1_5_SHA_512".to_string()), // Use exact algorithm name
    });

    let sign_response = client.sign(sign_request).await?;
    let signature_b64 = sign_response.into_inner().signature_b64;
    println!("  ✅ Data signed");

    // 5. Verify the signature
    let verify_request = tonic::Request::new(VerifyRequest {
        key_id: key_id.clone(),
        data_b64: decrypted_b64.clone(),
        signature_b64: signature_b64.clone(),
        algorithm: Some("RSASSA_PKCS1_V1_5_SHA_512".to_string()), // Use exact algorithm name
    });

    let verify_response = client.verify(verify_request).await?;
    let is_valid = verify_response.into_inner().valid;
    
    assert!(is_valid);
    println!("  ✅ Signature verified");

    println!("🎉 Full workflow test completed successfully!");
    Ok(())
}

// // Test for concurrent operations
// #[tokio::test]
// async fn test_concurrent_operations() -> Result<(), Box<dyn std::error::Error>> {
//     let mut client = create_client().await?;
    
//     // Create a key
//     let create_request = tonic::Request::new(CreateKeyRequest {
//         name: "concurrent-test-key".to_string(), // Changed to lowercase with hyphens
//         description: "Key for concurrent operation testing".to_string(),
//         slug: "concurrent-test-key".to_string(),
//         encryption_algorithm: "aes-256-gcm".to_string(),
//     });

//     let create_response = client.create_key(create_request).await?;
//     let key_id = create_response.into_inner().key_id;

//     // Test data
//     let test_data = "Concurrent test data";
//     let plaintext_b64 = encode_b64(test_data);

//     // Perform multiple concurrent encryptions
//     let mut handles = Vec::new();
    
//     for i in 0..5 {
//         let mut client_clone = client.clone();
//         let key_id_clone = key_id.clone();
//         let plaintext_b64_clone = plaintext_b64.clone();
        
//         let handle = tokio::spawn(async move {
//             let encrypt_request = tonic::Request::new(EncryptRequest {
//                 key_id: key_id_clone,
//                 plaintext_b64: plaintext_b64_clone,
//             });

//             let result = client_clone.encrypt(encrypt_request).await;
//             (i, result)
//         });
        
//         handles.push(handle);
//     }

//     // Wait for all operations to complete
//     let mut results = Vec::new();
//     for handle in handles {
//         let result = handle.await?;
//         results.push(result);
//     }

//     // Verify all operations succeeded
//     for (i, result) in results {
//         assert!(result.is_ok(), "Concurrent operation {} failed", i);
//     }

//     println!("✅ Concurrent operations test passed");
//     Ok(())
// }