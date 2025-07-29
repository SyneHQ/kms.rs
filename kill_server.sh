#!/bin/bash

# Script to kill any existing processes on port 50051

echo "🔍 Checking for processes on port 50051..."

if lsof -ti:50051 > /dev/null 2>&1; then
    echo "⚠️  Found processes on port 50051:"
    lsof -i:50051
    
    echo "🛑 Killing processes..."
    lsof -ti:50051 | xargs kill -9 2>/dev/null || true
    
    echo "✅ Processes killed"
else
    echo "✅ No processes found on port 50051"
fi