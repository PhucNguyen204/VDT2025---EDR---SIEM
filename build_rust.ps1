# PowerShell build script for Rust sigma-engine library on Windows

Write-Host "Building Rust sigma-engine library..." -ForegroundColor Green

# Navigate to sigma-engine directory
Set-Location sigma-engine

# Clean previous builds
Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
cargo clean

# Build release version
Write-Host "Building release version..." -ForegroundColor Yellow
cargo build --release

# Check if the library was built successfully
$rustLibrary = "target\release\sigma_engine.dll"
$rustStaticLib = "target\release\sigma_engine.lib"

if (Test-Path $rustLibrary) {
    Write-Host "✅ Windows DLL built successfully: $rustLibrary" -ForegroundColor Green
} else {
    Write-Host "❌ Failed to build Windows DLL" -ForegroundColor Red
    exit 1
}

if (Test-Path $rustStaticLib) {
    Write-Host "✅ Static library built successfully: $rustStaticLib" -ForegroundColor Green
} else {
    Write-Host "❌ Failed to build static library" -ForegroundColor Red
    exit 1
}

# Copy libraries to Go project's lib directory
Write-Host "Setting up libraries for Go integration..." -ForegroundColor Yellow
$libDir = "..\lib"
if (!(Test-Path $libDir)) {
    New-Item -ItemType Directory -Path $libDir
}

Copy-Item $rustLibrary $libDir
Copy-Item $rustStaticLib $libDir

# Create header file for CGO
Write-Host "Creating header file for CGO..." -ForegroundColor Yellow
$headerContent = @"
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
"@

$headerContent | Out-File -FilePath "$libDir\sigma_engine.h" -Encoding ASCII

Write-Host "✅ Build completed successfully!" -ForegroundColor Green
Write-Host "📁 Libraries available in $libDir" -ForegroundColor Cyan
Write-Host "📄 Header file created: $libDir\sigma_engine.h" -ForegroundColor Cyan

# Run tests to ensure everything works
Write-Host "Running Rust tests..." -ForegroundColor Yellow
cargo test

Write-Host "Rust sigma-engine is ready for Go integration!" -ForegroundColor Green

# Return to original directory
Set-Location ..
