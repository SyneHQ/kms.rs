#!/bin/bash

# Test runner script for syne-kms gRPC client tests
# This script sets up the environment and runs the tests

set -e

source .env

echo "🚀 Starting syne-kms gRPC client tests..."

# Check if required environment variables are set
if [ -z "$INFISICAL_TOKEN" ]; then
    echo "❌ Error: INFISICAL_TOKEN environment variable is not set"
    echo "Please set it with: export INFISICAL_TOKEN='your-token-here'"
    exit 1
fi

if [ -z "$INFISICAL_API_URL" ]; then
    echo "❌ Error: INFISICAL_API_URL environment variable is not set"
    echo "Please set it with: export INFISICAL_API_URL='https://your-infisical-instance.com'"
    exit 1
fi

if [ -z "$INFISICAL_PROJECT_ID" ]; then
    echo "❌ Error: INFISICAL_PROJECT_ID environment variable is not set"
    echo "Please set it with: export INFISICAL_PROJECT_ID='your-project-id'"
    exit 1
fi

echo "✅ Environment variables are set"

# Set the gRPC server address for tests
export GRPC_SERVER_ADDRESS="[::1]:50051"

# Check if port 50051 is already in use and kill existing processes
echo "🔍 Checking for existing processes on port 50051..."
if lsof -ti:50051 > /dev/null 2>&1; then
    echo "⚠️  Found existing process on port 50051, killing it..."
    lsof -ti:50051 | xargs kill -9 2>/dev/null || true
    sleep 2
fi

# Build the project
echo "🔨 Building the project..."
cargo build

# Start the gRPC server in the background
echo "🚀 Starting gRPC server..."
cargo run &
SERVER_PID=$!

# Wait for the server to start
echo "⏳ Waiting for server to start..."
sleep 5

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Error: Server failed to start"
    echo "Check the logs above for more details"
    exit 1
fi

# Additional check: try to connect to the server
echo "🔍 Verifying server is responding..."
for i in {1..10}; do
    if timeout 2 bash -c "</dev/tcp/::1/50051" 2>/dev/null; then
        echo "✅ Server is responding on port 50051"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "❌ Error: Server is not responding on port 50051"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi
    echo "   Attempt $i/10: Server not ready yet, waiting..."
    sleep 1
done

echo "✅ Server is running (PID: $SERVER_PID)"

# Run the tests
echo "🧪 Running gRPC client tests..."
cargo test --test grpc_client_test -- --nocapture

# Capture the test exit code
TEST_EXIT_CODE=$?

# Stop the server
echo "🛑 Stopping server..."
kill $SERVER_PID 2>/dev/null || true

# Wait for server to stop
sleep 2

# Check if server is still running
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "⚠️  Warning: Server is still running, force killing..."
    kill -9 $SERVER_PID 2>/dev/null || true
fi

# Exit with the test exit code
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "🎉 All tests passed!"
else
    echo "❌ Some tests failed!"
fi

exit $TEST_EXIT_CODE