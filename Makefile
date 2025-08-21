# ====================================================================
# VDT2025 EDR - Makefile
# ====================================================================

.PHONY: build clean run test docker-build docker-up docker-down help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
BINARY_NAME=edr-server
BINARY_V2=edr-v2
BINARY_PATH=./bin/$(BINARY_NAME)
BINARY_V2_PATH=./bin/$(BINARY_V2)

# Build the original binary
build:
	@echo "🔨 Building $(BINARY_NAME)..."
	@mkdir -p bin
	$(GOBUILD) -o $(BINARY_PATH) ./cmd/edr-server/

# Build EDR v2
build-v2:
	@echo "🔨 Building $(BINARY_V2)..."
	@mkdir -p bin
	$(GOBUILD) -o $(BINARY_V2_PATH) ./cmd/edr-v2/

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	$(GOCLEAN)
	rm -rf bin/

# Run the original application
run: build
	@echo "🚀 Running $(BINARY_NAME)..."
	$(BINARY_PATH)

# Run EDR v2
run-v2: build-v2
	@echo "🚀 Running $(BINARY_V2)..."
	$(BINARY_V2_PATH)

# Run tests
test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v ./...

# Tidy dependencies
tidy:
	@echo "🔧 Tidying dependencies..."
	$(GOMOD) tidy

# Docker commands for EDR v1
docker-build:
	@echo "🐳 Building Docker image for EDR v1..."
	cd deployments && docker compose build

docker-up:
	@echo "🐳 Starting EDR v1 containers..."
	cd deployments && docker compose up -d

docker-down:
	@echo "🐳 Stopping EDR v1 containers..."
	cd deployments && docker compose down

docker-logs:
	@echo "📋 Showing EDR v1 container logs..."
	cd deployments && docker compose logs -f

# Docker commands for EDR v2
docker-build-v2:
	@echo "🐳 Building Docker image for EDR v2..."
	cd deployments && docker compose -f docker-compose.v2.yml build

docker-up-v2:
	@echo "🐳 Starting EDR v2 containers..."
	cd deployments && docker compose -f docker-compose.v2.yml up -d

docker-down-v2:
	@echo "🐳 Stopping EDR v2 containers..."
	cd deployments && docker compose -f docker-compose.v2.yml down

docker-logs-v2:
	@echo "📋 Showing EDR v2 container logs..."
	cd deployments && docker compose -f docker-compose.v2.yml logs -f

# Demo attack for original EDR
demo:
	@echo "⚔️ Running SSH brute-force attack demo..."
	powershell.exe -ExecutionPolicy Bypass -File ./examples/ssh_attack_simple.ps1

# Demo multi-attack for EDR v2
demo-v2:
	@echo "⚔️ Running multi-attack simulation demo..."
	powershell.exe -ExecutionPolicy Bypass -File ./examples/multi_attack_simulation.ps1

# Comprehensive attack simulation
demo-comprehensive:
	@echo "🔥 Running comprehensive attack simulation (SSH, XSS, SQLi, Scanning)..."
	powershell.exe -ExecutionPolicy Bypass -File ./examples/comprehensive_attack_simulation.ps1

# Help
help:
	@echo "VDT2025 EDR - Available commands:"
	@echo "  build        - Build the original EDR binary"
	@echo "  build-v2     - Build the EDR v2 binary (using go-sigma-rule-engine)"
	@echo "  clean        - Clean build artifacts"
	@echo "  run          - Build and run the original EDR"
	@echo "  run-v2       - Build and run EDR v2"
	@echo "  test         - Run tests"
	@echo "  tidy         - Tidy Go modules"
	@echo "  docker-build - Build EDR v1 Docker images"
	@echo "  docker-up    - Start EDR v1 Docker containers"
	@echo "  docker-down  - Stop EDR v1 Docker containers"
	@echo "  docker-logs  - Show EDR v1 container logs"
	@echo "  docker-build-v2 - Build EDR v2 Docker images"
	@echo "  docker-up-v2    - Start EDR v2 Docker containers"
	@echo "  docker-down-v2  - Stop EDR v2 Docker containers"
	@echo "  docker-logs-v2  - Show EDR v2 container logs"
	@echo "  demo         - Run SSH brute-force attack demo"
	@echo "  demo-v2      - Run multi-attack simulation demo"
	@echo "  demo-comprehensive - Run comprehensive attack simulation (SSH, XSS, SQLi, Scanning)"
	@echo "  help         - Show this help message"
