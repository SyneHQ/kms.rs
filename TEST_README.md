# gRPC Client Tests

This directory contains comprehensive tests for the syne-kms gRPC client.

## Test Overview

The test suite includes:

- **Basic Operations**: Create key, encrypt, decrypt, sign, verify
- **Roundtrip Tests**: Encrypt/decrypt and sign/verify workflows
- **Error Handling**: Invalid keys, invalid signatures
- **Multiple Operations**: Concurrent operations, multiple encryptions
- **Integration Tests**: Full workflow testing

## Prerequisites

1. **Infisical Setup**: You need access to an Infisical instance
2. **Environment Variables**: Set the following environment variables either in your shell or in a `.env` file:

```bash
export INFISICAL_TOKEN="your-infisical-api-token"
export INFISICAL_API_URL="https://your-infisical-instance.com"
export INFISICAL_PROJECT_ID="your-project-id"
```

Or create a `.env` file in the project root:
```env
INFISICAL_TOKEN=your-infisical-api-token
INFISICAL_API_URL=https://your-infisical-instance.com
INFISICAL_PROJECT_ID=your-project-id
```

## Running Tests

### Option 1: Using the Test Runner Script (Recommended)

```bash
./run_tests.sh
```

This script will:
- Load environment variables from `.env` file (if present)
- Check environment variables
- Kill any existing processes on port 50051
- Build the project
- Start the gRPC server
- Run all tests
- Clean up the server

### Option 2: Test Server Startup Only

If you want to test if the server can start properly without running the full test suite:

```bash
./test_server_start.sh
```

This will:
- Check environment variables
- Kill any existing processes on port 50051
- Build the project
- Start the server and verify it's responding
- Clean up the server

### Option 3: Manual Testing

1. **Start the server** in one terminal:
```bash
cargo run
```

2. **Run tests** in another terminal:
```bash
cargo test --test grpc_client_test -- --nocapture
```

### Option 4: Run Individual Tests

```bash
# Run a specific test
cargo test --test grpc_client_test test_create_key -- --nocapture

# Run tests matching a pattern
cargo test --test grpc_client_test test_encrypt -- --nocapture
```

### Option 5: Run Example Client

```bash
# Start server in one terminal
cargo run

# Run example in another terminal
cargo run --example client_example
```

## Test Descriptions

### `test_create_key`
Tests basic key creation functionality.

### `test_encrypt_decrypt_roundtrip`
Tests the complete encrypt/decrypt workflow with data verification.

### `test_sign_verify_roundtrip`
Tests digital signature creation and verification.

### `test_verify_invalid_signature`
Tests error handling for invalid signatures.

### `test_encrypt_with_nonexistent_key`
Tests error handling for non-existent keys.

### `test_multiple_encryptions_same_key`
Tests that multiple encryptions of the same data produce different ciphertexts.

### `test_full_workflow`
Integration test covering the complete KMS workflow.

### `test_concurrent_operations`
Tests concurrent operations to ensure thread safety.

## Test Configuration

- **Server Address**: `[::1]:50051` (IPv6 localhost)
- **Test Timeout**: Default tokio test timeout
- **Base64 Encoding**: All data is base64 encoded for transmission using the modern base64 Engine API

## Troubleshooting

### Common Issues

1. **Connection Refused**: Make sure the server is running on port 50051
2. **Authentication Errors**: Verify your Infisical token is valid
3. **Project Not Found**: Ensure the project ID exists in your Infisical instance
4. **Permission Denied**: Check that your token has the necessary permissions
5. **Compilation Errors**: Make sure you've run `cargo clean && cargo build` after recent changes

### Port Conflicts

If you get an "Address already in use" error:

```bash
# Use the provided script to kill existing processes
./kill_server.sh

# Or manually check and kill processes
lsof -i:50051
kill -9 <PID>
```

### Debug Mode

To run tests with more verbose output:

```bash
RUST_LOG=debug cargo test --test grpc_client_test -- --nocapture
```

### Clean Build

If you encounter build issues:

```bash
cargo clean
cargo build
```

## Test Output

Successful test output will look like:

```
✅ CreateKey test passed - Key ID: abc123...
✅ Encrypt/Decrypt roundtrip test passed
✅ Sign/Verify roundtrip test passed
✅ Invalid signature verification test passed
✅ Non-existent key error handling test passed
✅ Multiple encryptions test passed
🚀 Starting full workflow test...
  ✅ Key created: def456...
  ✅ Data encrypted
  ✅ Data decrypted successfully
  ✅ Data signed
  ✅ Signature verified
🎉 Full workflow test completed successfully!
✅ Concurrent operations test passed
```

## Adding New Tests

To add new tests:

1. Add your test function to `tests/grpc_client_test.rs`
2. Use the `#[tokio::test]` attribute
3. Follow the existing pattern for client creation and assertions
4. Use descriptive test names that start with `test_`

Example:

```rust
#[tokio::test]
async fn test_your_new_feature() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = create_client().await?;
    
    // Your test logic here
    
    println!("✅ Your new test passed");
    Ok(())
}
```

## Recent Fixes

- ✅ Fixed gRPC client generation in `build.rs`
- ✅ Updated base64 usage to modern Engine API
- ✅ Added proper imports for client types
- ✅ Added `.env` file support in test runner
- ✅ Recreated example client with correct imports
- ✅ Added port conflict detection and resolution
- ✅ Added server health check before running tests