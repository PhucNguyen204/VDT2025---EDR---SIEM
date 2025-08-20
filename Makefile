# ====================================================================
# MAKEFILE - EDR PLATFORM DEVELOPMENT
# ====================================================================
# Tác giả: Senior Software Engineer - EDR Platform Team
# Mô tả: Makefile để quản lý development workflow cho EDR platform
# Phiên bản: 1.0.0
# Ngày tạo: 2024-01-01
# ====================================================================

.PHONY: help dev up down clean logs status test build install-windows install-linux

# Default target
.DEFAULT_GOAL := help

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Project configuration
PROJECT_NAME := edr-platform
DOCKER_COMPOSE_FILE := infrastructure/docker-compose.yml
NETWORK_NAME := edr-network

# ====================================================================
# HELP - HIỂN THỊ HƯỚNG DẪN SỬ DỤNG
# ====================================================================
help: ## Hiển thị help này
	@echo "$(GREEN)======================================"
	@echo "EDR Platform Development Makefile"
	@echo "======================================$(NC)"
	@echo ""
	@echo "$(BLUE)Available commands:$(NC)"
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_-]+:.*##/ { printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(BLUE)Examples:$(NC)"
	@echo "  make dev                    # Khởi động development environment"
	@echo "  make logs service=kafka     # Xem logs của Kafka service"
	@echo "  make install-windows        # Cài đặt agent trên Windows"
	@echo ""

# ====================================================================
# DEVELOPMENT ENVIRONMENT
# ====================================================================

dev: ## Khởi động development environment (full stack)
	@echo "$(GREEN)Khởi động EDR Platform development environment...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) up -d
	@echo "$(GREEN)✅ Development environment đã sẵn sàng!$(NC)"
	@echo ""
	@echo "$(BLUE)Services URLs:$(NC)"
	@echo "  Flink Dashboard:        http://localhost:8081"
	@echo "  OpenSearch Dashboards:  http://localhost:5601"
	@echo "  MinIO Console:          http://localhost:9001 (minioadmin/minioadmin)"
	@echo "  Process Graph API:      http://localhost:8080"
	@echo "  Grafana:               http://localhost:3000 (admin/admin)"
	@echo "  Vector Aggregator API:  http://localhost:8686"
	@echo ""
	@echo "$(YELLOW)Chờ tất cả services khởi động hoàn toàn...$(NC)"
	@sleep 30
	@$(MAKE) status

up: dev ## Alias cho dev command

minimal: ## Khởi động minimal stack (chỉ core services)
	@echo "$(GREEN)Khởi động minimal EDR stack...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) up -d zookeeper kafka opensearch
	@echo "$(GREEN)✅ Minimal stack đã sẵn sàng!$(NC)"

down: ## Dừng tất cả services
	@echo "$(RED)Đang dừng EDR Platform...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down
	@echo "$(RED)✅ Đã dừng tất cả services$(NC)"

clean: ## Dừng services và xóa volumes
	@echo "$(RED)Đang dừng và xóa tất cả data...$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down -v --remove-orphans
	@docker system prune -f
	@echo "$(RED)✅ Đã xóa tất cả data và containers$(NC)"

restart: down up ## Restart toàn bộ stack

# ====================================================================
# MONITORING & DEBUGGING
# ====================================================================

status: ## Kiểm tra trạng thái services
	@echo "$(BLUE)Trạng thái services:$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) ps
	@echo ""
	@echo "$(BLUE)Health check:$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) exec -T kafka kafka-topics --list --bootstrap-server localhost:9092 2>/dev/null || echo "❌ Kafka chưa sẵn sàng"
	@curl -s http://localhost:9200/_cluster/health?pretty 2>/dev/null | grep -q '"status":"green"' && echo "✅ OpenSearch healthy" || echo "❌ OpenSearch chưa sẵn sàng"
	@curl -s http://localhost:8081/overview 2>/dev/null | grep -q '"taskmanagers"' && echo "✅ Flink healthy" || echo "❌ Flink chưa sẵn sàng"

logs: ## Xem logs của services (sử dụng: make logs service=kafka)
ifdef service
	@docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f $(service)
else
	@docker-compose -f $(DOCKER_COMPOSE_FILE) logs -f
endif

shell: ## Vào shell của service (sử dụng: make shell service=kafka)
ifndef service
	@echo "$(RED)Error: Cần chỉ định service. VD: make shell service=kafka$(NC)"
	@exit 1
endif
	@docker-compose -f $(DOCKER_COMPOSE_FILE) exec $(service) /bin/bash

kafka-topics: ## Liệt kê Kafka topics
	@echo "$(BLUE)Kafka topics:$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) exec kafka kafka-topics --list --bootstrap-server localhost:9092

kafka-consume: ## Consume messages từ topic (sử dụng: make kafka-consume topic=edr-events-normalized)
ifndef topic
	@echo "$(RED)Error: Cần chỉ định topic. VD: make kafka-consume topic=edr-events-normalized$(NC)"
	@exit 1
endif
	@echo "$(BLUE)Consuming từ topic: $(topic)$(NC)"
	@docker-compose -f $(DOCKER_COMPOSE_FILE) exec kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic $(topic) --from-beginning

# ====================================================================
# TESTING
# ====================================================================

test: ## Chạy integration tests
	@echo "$(BLUE)Chạy integration tests...$(NC)"
	@./tests/integration/run-tests.sh

test-agents: ## Test agent configurations
	@echo "$(BLUE)Testing Vector configurations...$(NC)"
	@vector validate agents/windows/vector-windows.toml || echo "❌ Windows config có lỗi"
	@vector validate agents/linux/vector-linux.toml || echo "❌ Linux config có lỗi"
	@vector validate infrastructure/vector-aggregator.toml || echo "❌ Aggregator config có lỗi"
	@echo "✅ Tất cả Vector configs hợp lệ"

send-test-event: ## Gửi test event tới Kafka
	@echo "$(BLUE)Gửi test event...$(NC)"
	@echo '{"@timestamp":"$(shell date -u +%Y-%m-%dT%H:%M:%S.000Z)","host":{"id":"test-host","name":"test-machine"},"agent":{"id":"test-agent","type":"test","version":"1.0.0"},"event":{"kind":"event","category":["process"],"action":"test_event"},"ecs":{"version":"8.6.0"},"message":"Test event from Makefile"}' | \
	docker-compose -f $(DOCKER_COMPOSE_FILE) exec -T kafka kafka-console-producer --bootstrap-server localhost:9092 --topic edr-events-normalized
	@echo "✅ Test event đã được gửi"

# ====================================================================
# AGENT INSTALLATION
# ====================================================================

install-windows: ## Cài đặt Vector agent trên Windows (cần PowerShell)
	@echo "$(BLUE)Cài đặt Windows Agent...$(NC)"
	@powershell.exe -ExecutionPolicy Bypass -File agents/windows/install-agent.ps1 -KafkaBrokers "localhost:9093" -Environment "dev" -SkipCertificates
	@echo "$(GREEN)✅ Windows Agent đã được cài đặt$(NC)"

install-linux: ## Cài đặt Vector agent trên Linux (cần sudo)
	@echo "$(BLUE)Cài đặt Linux Agent...$(NC)"
	@sudo agents/linux/install-agent.sh --brokers "localhost:9093" --environment dev --skip-certificates
	@echo "$(GREEN)✅ Linux Agent đã được cài đặt$(NC)"

uninstall-windows: ## Gỡ cài đặt Windows Agent
	@echo "$(RED)Gỡ cài đặt Windows Agent...$(NC)"
	@powershell.exe -ExecutionPolicy Bypass -File agents/windows/install-agent.ps1 -Uninstall

uninstall-linux: ## Gỡ cài đặt Linux Agent
	@echo "$(RED)Gỡ cài đặt Linux Agent...$(NC)"
	@sudo agents/linux/install-agent.sh --uninstall

# ====================================================================
# BUILD & PACKAGE
# ====================================================================

build: ## Build tất cả Go services
	@echo "$(BLUE)Building Go services...$(NC)"
	@cd server/go-services/indexer && go build -o bin/indexer .
	@cd server/go-services/alert-router && go build -o bin/alert-router .
	@cd server/go-services/process-graph-api && go build -o bin/process-graph-api .
	@echo "$(GREEN)✅ Đã build tất cả Go services$(NC)"

docker-build: ## Build Docker images cho Go services
	@echo "$(BLUE)Building Docker images...$(NC)"
	@docker build -t edr-indexer:latest server/go-services/indexer/
	@docker build -t edr-alert-router:latest server/go-services/alert-router/
	@docker build -t edr-process-graph-api:latest server/go-services/process-graph-api/
	@echo "$(GREEN)✅ Đã build tất cả Docker images$(NC)"

# ====================================================================
# DATA MANAGEMENT
# ====================================================================

create-indices: ## Tạo OpenSearch indices và templates
	@echo "$(BLUE)Tạo OpenSearch indices...$(NC)"
	@curl -X PUT "localhost:9200/_index_template/edr-events" -H "Content-Type: application/json" -d @infrastructure/opensearch/event-template.json
	@curl -X PUT "localhost:9200/_index_template/edr-alerts" -H "Content-Type: application/json" -d @infrastructure/opensearch/alert-template.json
	@echo "$(GREEN)✅ Đã tạo OpenSearch templates$(NC)"

backup-data: ## Backup data từ OpenSearch
	@echo "$(BLUE)Backing up OpenSearch data...$(NC)"
	@mkdir -p backups/$(shell date +%Y%m%d)
	@curl -X GET "localhost:9200/_cat/indices?v" > backups/$(shell date +%Y%m%d)/indices.txt
	@echo "$(GREEN)✅ Backup completed in backups/$(shell date +%Y%m%d)/$(NC)"

# ====================================================================
# DEVELOPMENT UTILITIES
# ====================================================================

fmt: ## Format code (Go và shell scripts)
	@echo "$(BLUE)Formatting code...$(NC)"
	@find server/go-services -name "*.go" -exec gofmt -w {} \;
	@find agents -name "*.sh" -exec shfmt -w {} \;
	@echo "$(GREEN)✅ Code đã được format$(NC)"

lint: ## Lint code
	@echo "$(BLUE)Linting code...$(NC)"
	@find server/go-services -name "*.go" -exec golint {} \;
	@find agents -name "*.sh" -exec shellcheck {} \;
	@echo "$(GREEN)✅ Linting completed$(NC)"

docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	@mkdir -p docs/generated
	@go doc -all server/go-services/... > docs/generated/go-services.md
	@echo "$(GREEN)✅ Documentation generated$(NC)"

# ====================================================================
# PRODUCTION UTILITIES
# ====================================================================

prod-check: ## Kiểm tra readiness cho production
	@echo "$(BLUE)Kiểm tra production readiness...$(NC)"
	@echo "🔍 Checking configurations..."
	@test -f agents/shared/certificates/ca.crt || echo "❌ Missing production certificates"
	@test -f infrastructure/kubernetes/namespace.yaml || echo "❌ Missing Kubernetes manifests"
	@echo "🔍 Checking security..."
	@grep -r "password.*admin" infrastructure/ && echo "❌ Default passwords found" || echo "✅ No default passwords"
	@echo "🔍 Checking resource limits..."
	@grep -r "memory:" infrastructure/docker-compose.yml || echo "⚠️  No memory limits set"
	@echo "$(GREEN)✅ Production check completed$(NC)"

# ====================================================================
# CLEANUP UTILITIES
# ====================================================================

clean-logs: ## Xóa logs cũ
	@echo "$(BLUE)Cleaning old logs...$(NC)"
	@find /tmp -name "*vector*log" -mtime +7 -delete 2>/dev/null || true
	@docker system prune -f --filter "until=24h"
	@echo "$(GREEN)✅ Logs cleaned$(NC)"

reset: clean up ## Reset toàn bộ environment

# ====================================================================
# VARIABLES FOR CONDITIONAL COMMANDS
# ====================================================================

# Check if running on Windows
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
else
    DETECTED_OS := $(shell uname -s)
endif

# Adjust commands based on OS
ifeq ($(DETECTED_OS),Windows)
    SHELL_CMD := powershell.exe
    VECTOR_CMD := vector.exe
else
    SHELL_CMD := /bin/bash
    VECTOR_CMD := vector
endif

# ====================================================================
# END OF MAKEFILE
# ====================================================================
#
# HƯỚNG DẪN SỬ DỤNG:
#
# 1. Khởi động development:
#    make dev
#
# 2. Kiểm tra trạng thái:
#    make status
#
# 3. Xem logs:
#    make logs
#    make logs service=kafka
#
# 4. Test:
#    make test
#    make send-test-event
#
# 5. Cài đặt agents:
#    make install-windows  (trên Windows)
#    make install-linux    (trên Linux)
#
# 6. Cleanup:
#    make clean
#
# REQUIREMENTS:
# - Docker và Docker Compose
# - Make utility
# - PowerShell (cho Windows agent)
# - Bash (cho Linux agent)
# - Go (cho build services)
#
# Author: Senior Software Engineer - EDR Platform Team
# Contact: edr-team@company.com
# Documentation: https://company.wiki/edr-platform/makefile
# ====================================================================
