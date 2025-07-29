#!/bin/bash

# Script to test if the server can start properly

set -e

echo "🧪 Testing server startup..."

# Load environment variables
source .env

# Check if required environment variables are set
if [ -z "$INFISICAL_TOKEN" ]; then
    echo "❌ Error: INFISICAL_TOKEN environment variable is not set"
    exit 1
fi

if [ -z "$INFISICAL_API_URL" ]; then
    echo "❌ Error: INFISICAL_API_URL environment variable is not set"
    exit 1
fi

if [ -z "$INFISICAL_PROJECT_ID" ]; then
    echo "❌ Error: INFISICAL_PROJECT_ID environment variable is not set"
    exit 1
fi

echo "✅ Environment variables are set"

# Kill any existing processes
echo "🔍 Checking for existing processes on port 50051..."
if lsof -ti:50051 > /dev/null 2>&1; then
    echo "⚠️  Found existing process on port 50051, killing it..."
    lsof -ti:50051 | xargs kill -9 2>/dev/null || true
    sleep 2
fi

# Build the project
echo "🔨 Building the project..."
cargo build

# Start the server
echo "🚀 Starting server..."
timeout 10s cargo run &
SERVER_PID=$!

# Wait a moment for server to start
sleep 3

# Check if server is running
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "✅ Server started successfully (PID: $SERVER_PID)"
    
    # Test if server is responding
    if timeout 2 bash -c "</dev/tcp/::1/50051" 2>/dev/null; then
        echo "✅ Server is responding on port 50051"
    else
        echo "⚠️  Server is running but not responding on port 50051"
    fi
    
    # Kill the server
    echo "🛑 Stopping server..."
    kill $SERVER_PID 2>/dev/null || true
    sleep 2
    
    echo "🎉 Server startup test passed!"
else
    echo "❌ Server failed to start"
    exit 1
fi