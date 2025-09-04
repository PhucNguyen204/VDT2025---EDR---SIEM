#!/bin/bash

# Build script for Rust sigma-engine library

set -e

echo "Building Rust sigma-engine library..."

# Navigate to sigma-engine directory
cd sigma-engine

# Clean previous builds
echo "Cleaning previous builds..."
cargo clean

# Build release version
echo "Building release version..."
cargo build --release

# Check if the library was built successfully
if [ -f "target/release/libsigma_engine.so" ]; then
    echo "✅ Linux shared library built successfully: target/release/libsigma_engine.so"
else
    echo "❌ Failed to build Linux shared library"
    exit 1
fi

if [ -f "target/release/libsigma_engine.a" ]; then
    echo "✅ Static library built successfully: target/release/libsigma_engine.a"
else
    echo "❌ Failed to build static library"
    exit 1
fi

# Copy libraries to Go project's lib directory
echo "Setting up libraries for Go integration..."
mkdir -p ../lib
cp target/release/libsigma_engine.so ../lib/
cp target/release/libsigma_engine.a ../lib/

# Create header file for CGO
echo "Creating header file for CGO..."
cat > ../lib/sigma_engine.h << 'EOF'
#ifndef SIGMA_ENGINE_H
#define SIGMA_ENGINE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t* matched_rules_ptr;
    size_t matched_rules_len;
    size_t nodes_evaluated;
    size_t primitive_evaluations;
    int error_code;
} CEngineResult;

typedef void CSigmaEngine;

// Function declarations
CSigmaEngine* sigma_engine_create(char** rules_ptr, size_t rules_len);
CEngineResult sigma_engine_evaluate(CSigmaEngine* engine_ptr, char* json_event);
void sigma_engine_free_result(size_t* matched_rules_ptr, size_t matched_rules_len);
void sigma_engine_destroy(CSigmaEngine* engine_ptr);
int sigma_engine_stats(CSigmaEngine* engine_ptr, size_t* rule_count, size_t* node_count, size_t* primitive_count);

#endif // SIGMA_ENGINE_H
EOF

echo "✅ Build completed successfully!"
echo "📁 Libraries available in ../lib/"
echo "📄 Header file created: ../lib/sigma_engine.h"

# Run tests to ensure everything works
echo "Running Rust tests..."
cargo test

echo "🎉 Rust sigma-engine is ready for Go integration!"
