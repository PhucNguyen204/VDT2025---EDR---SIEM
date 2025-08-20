# ====================================================================
# EDR DETECTION ENGINE - MAKEFILE
# ====================================================================
# Tác giả: Senior Software Engineer - EDR Platform Team
# Mô tả: Makefile để build, test và deploy EDR detection engine
# ====================================================================

.PHONY: help build run test clean docker-build docker-run docker-stop logs deps

# Default target
help:
	@echo "🛡️  EDR Detection Engine - Available Commands:"
	@echo ""
	@echo "  📦 Build & Run:"
	@echo "    build          - Build Go application"
	@echo "    run            - Run application locally"
	@echo "    test           - Run tests"
	@echo "    deps           - Download dependencies"
	@echo ""
	@echo "  🐳 Docker:"
	@echo "    docker-build   - Build Docker image"
	@echo "    docker-run     - Run with Docker Compose"
	@echo "    docker-stop    - Stop Docker containers"
	@echo "    docker-logs    - View Docker logs"
	@echo ""
	@echo "  🧹 Maintenance:"
	@echo "    clean          - Clean build artifacts"
	@echo "    logs           - View application logs"
	@echo ""

# Build Go application
build:
	@echo "🔨 Building EDR Detection Engine..."
	go build -o bin/edr-detection-engine ./cmd/
	@echo "✅ Build completed!"

# Run application locally
run:
	@echo "🚀 Starting EDR Detection Engine..."
	@export EDR_RULES_DIR="../../sigma/rules/windows/process_creation" && \
	export EDR_PORT="8080" && \
	export EDR_LOG_LEVEL="info" && \
	go run ./cmd/

# Run tests
test:
	@echo "🧪 Running tests..."
	go test -v ./...
	@echo "✅ Tests completed!"

# Download dependencies
deps:
	@echo "📦 Downloading dependencies..."
	go mod download
	go mod tidy
	@echo "✅ Dependencies updated!"

# Build Docker image
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t edr-detection-engine:latest .
	@echo "✅ Docker image built!"

# Run with Docker Compose
docker-run:
	@echo "🚀 Starting EDR Detection Engine with Docker Compose..."
	docker-compose up -d
	@echo "✅ Services started!"
	@echo ""
	@echo "📊 Access points:"
	@echo "  Dashboard: http://localhost:9090"
	@echo "  Vector API: http://localhost:8686/health"
	@echo "  Log Viewer: http://localhost:8888"
	@echo "  Webhook Test: http://localhost:8090"

# Stop Docker containers
docker-stop:
	@echo "🛑 Stopping Docker containers..."
	docker-compose down
	@echo "✅ Containers stopped!"

# View Docker logs
docker-logs:
	@echo "📋 Viewing Docker logs..."
	docker-compose logs -f

# View application logs (if running locally)
logs:
	@echo "📋 Viewing application logs..."
	tail -f logs/*.log 2>/dev/null || echo "No log files found"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/
	rm -rf logs/*.log
	docker system prune -f
	@echo "✅ Cleanup completed!"

# Development setup
dev-setup:
	@echo "🛠️  Setting up development environment..."
	go mod init edr-detection-engine 2>/dev/null || true
	go mod tidy
	mkdir -p bin logs
	@echo "✅ Development environment ready!"

# Test with sample event
test-event:
	@echo "🧪 Sending test event..."
	curl -X POST http://localhost:9090/api/v1/events \
		-H "Content-Type: application/json" \
		-d '{"@timestamp":"2024-01-20T10:30:00.000Z","host":{"id":"test-host","name":"TEST-MACHINE"},"event":{"kind":"event","category":["process"],"type":["start"],"action":"process_created"},"process":{"pid":1234,"executable":"C:\\Windows\\System32\\powershell.exe","name":"powershell.exe","command_line":"powershell.exe -ExecutionPolicy Bypass -File malicious.ps1"},"ecs":{"version":"8.6.0"},"message":"Test suspicious PowerShell execution"}'
	@echo ""
	@echo "✅ Test event sent!"

# Check services health
health-check:
	@echo "🏥 Checking services health..."
	@echo "Vector Collector:"
	@curl -s http://localhost:8686/health | jq . || echo "❌ Vector not responding"
	@echo ""
	@echo "EDR Detection Engine:"
	@curl -s http://localhost:9090/health | jq . || echo "❌ EDR Engine not responding"
	@echo ""

# Show service URLs
urls:
	@echo "🌐 Service URLs:"
	@echo "  📊 EDR Dashboard:    http://localhost:9090"
	@echo "  🔌 EDR API:          http://localhost:9090/api/v1/"
	@echo "  📡 Vector API:       http://localhost:8686"
	@echo "  📋 Log Viewer:       http://localhost:8888"
	@echo "  🎯 Webhook Tester:   http://localhost:8090"
	@echo "  🧪 Test Event:       make test-event"
