# Hướng dẫn Triển khai EDR Platform

## Mục lục
- [Yêu cầu Hệ thống](#yêu-cầu-hệ-thống)
- [Triển khai Development](#triển-khai-development)
- [Triển khai Production](#triển-khai-production)
- [Cài đặt Agents](#cài-đặt-agents)
- [Monitoring & Maintenance](#monitoring--maintenance)
- [Troubleshooting](#troubleshooting)

## Yêu cầu Hệ thống

### Development Environment
```
OS: Windows 10/11, Linux (Ubuntu 20.04+, CentOS 8+)
CPU: 8 cores minimum
RAM: 16GB minimum
Storage: 100GB SSD
Network: 1Gbps
Software: Docker, Docker Compose, Make
```

### Production Environment
```
OS: Linux (Ubuntu 20.04 LTS, RHEL 8+)
CPU: 64+ cores
RAM: 128GB+
Storage: 10TB+ NVMe SSD (tiered storage)
Network: 10Gbps bonded
Kubernetes: 1.25+
```

## Triển khai Development

### 1. Clone Repository
```bash
git clone https://github.com/company/edr-platform.git
cd edr-platform
```

### 2. Khởi động Stack
```bash
# Khởi động full development environment
make dev

# Hoặc khởi động minimal stack
make minimal

# Kiểm tra trạng thái
make status
```

### 3. Verify Services
```bash
# Kiểm tra Kafka topics
make kafka-topics

# Gửi test event
make send-test-event

# Xem logs
make logs service=kafka
```

### 4. Access UIs
- **Flink Dashboard**: http://localhost:8081
- **OpenSearch Dashboards**: http://localhost:5601
- **MinIO Console**: http://localhost:9001 (minioadmin/minioadmin)
- **Process Graph API**: http://localhost:8080
- **Grafana**: http://localhost:3000 (admin/admin)

## Triển khai Production

### 1. Infrastructure Preparation

#### Kubernetes Cluster Setup
```bash
# Tạo namespace
kubectl create namespace edr-platform

# Apply resource quotas
kubectl apply -f infrastructure/kubernetes/resource-quota.yaml

# Setup network policies
kubectl apply -f infrastructure/kubernetes/network-policies.yaml
```

#### Storage Setup
```bash
# Tạo StorageClass cho high-performance storage
kubectl apply -f infrastructure/kubernetes/storage-class.yaml

# Tạo PersistentVolumes
kubectl apply -f infrastructure/kubernetes/persistent-volumes.yaml
```

### 2. Deploy Core Services

#### Kafka Cluster
```bash
# Deploy Strimzi Kafka Operator
kubectl apply -f https://strimzi.io/install/latest?namespace=edr-platform

# Deploy Kafka cluster
kubectl apply -f infrastructure/kubernetes/kafka-cluster.yaml

# Verify Kafka deployment
kubectl get kafka -n edr-platform
```

#### OpenSearch Cluster
```bash
# Deploy OpenSearch Operator
kubectl apply -f infrastructure/kubernetes/opensearch-operator.yaml

# Deploy OpenSearch cluster
kubectl apply -f infrastructure/kubernetes/opensearch-cluster.yaml

# Verify OpenSearch deployment
kubectl get opensearchclusters -n edr-platform
```

#### Flink Cluster
```bash
# Deploy Flink Kubernetes Operator
kubectl apply -f infrastructure/kubernetes/flink-operator.yaml

# Deploy Flink cluster
kubectl apply -f infrastructure/kubernetes/flink-cluster.yaml

# Deploy Flink jobs
kubectl apply -f infrastructure/kubernetes/flink-jobs.yaml
```

### 3. Deploy Application Services

#### Go Microservices
```bash
# Build và push images
docker build -t registry.company.com/edr-indexer:v1.0.0 server/go-services/indexer/
docker push registry.company.com/edr-indexer:v1.0.0

docker build -t registry.company.com/edr-alert-router:v1.0.0 server/go-services/alert-router/
docker push registry.company.com/edr-alert-router:v1.0.0

docker build -t registry.company.com/edr-process-graph-api:v1.0.0 server/go-services/process-graph-api/
docker push registry.company.com/edr-process-graph-api:v1.0.0

# Deploy services
kubectl apply -f infrastructure/kubernetes/go-services.yaml
```

### 4. Configuration Management

#### Secrets Management
```bash
# Tạo TLS certificates
kubectl create secret tls kafka-tls-secret \
  --cert=certs/kafka.crt \
  --key=certs/kafka.key \
  -n edr-platform

# Database credentials
kubectl create secret generic opensearch-credentials \
  --from-literal=username=admin \
  --from-literal=password=$(openssl rand -base64 32) \
  -n edr-platform

# API keys
kubectl create secret generic api-keys \
  --from-literal=flink-api-key=$(openssl rand -hex 32) \
  --from-literal=webhook-secret=$(openssl rand -hex 32) \
  -n edr-platform
```

#### ConfigMaps
```bash
# Agent configurations
kubectl create configmap agent-configs \
  --from-file=agents/windows/vector-windows.toml \
  --from-file=agents/linux/vector-linux.toml \
  -n edr-platform

# Flink configurations
kubectl create configmap flink-configs \
  --from-file=server/flink-jobs/configs/ \
  -n edr-platform
```

### 5. Ingress và Load Balancing

#### NGINX Ingress
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: edr-platform-ingress
  namespace: edr-platform
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - edr.company.com
    secretName: edr-tls-secret
  rules:
  - host: edr.company.com
    http:
      paths:
      - path: /api/v1/process-graph
        pathType: Prefix
        backend:
          service:
            name: process-graph-api
            port:
              number: 8080
      - path: /dashboards
        pathType: Prefix
        backend:
          service:
            name: opensearch-dashboards
            port:
              number: 5601
```

### 6. Monitoring Setup

#### Prometheus & Grafana
```bash
# Deploy Prometheus Operator
kubectl apply -f infrastructure/kubernetes/prometheus-operator.yaml

# Deploy monitoring stack
kubectl apply -f infrastructure/kubernetes/monitoring.yaml

# Import Grafana dashboards
kubectl apply -f infrastructure/kubernetes/grafana-dashboards.yaml
```

#### AlertManager Rules
```yaml
groups:
- name: edr-platform
  rules:
  - alert: KafkaConsumerLag
    expr: kafka_consumer_lag_sum > 10000
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High Kafka consumer lag detected"
      
  - alert: FlinkJobDown
    expr: up{job="flink-jobmanager"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Flink job is down"
      
  - alert: OpenSearchClusterRed
    expr: opensearch_cluster_status != 2
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "OpenSearch cluster status is red"
```

## Cài đặt Agents

### Windows Agent Deployment

#### Automated Deployment (Recommended)
```powershell
# Sử dụng Group Policy hoặc SCCM
# Download installer
Invoke-WebRequest -Uri "https://releases.company.com/edr-agent/windows/install-agent.ps1" -OutFile "install-agent.ps1"

# Deploy với parameters
.\install-agent.ps1 -KafkaBrokers "kafka1.prod:9093,kafka2.prod:9093,kafka3.prod:9093" -Environment "production" -DataCenter "dc1"
```

#### Manual Deployment
```powershell
# Chạy với quyền Administrator
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Cài đặt
.\agents\windows\install-agent.ps1 -KafkaBrokers "kafka.company.com:9093" -Environment "production"

# Verify installation
Get-Service vector
Test-NetConnection kafka.company.com -Port 9093
```

### Linux Agent Deployment

#### Ansible Playbook (Recommended)
```yaml
# ansible/deploy-linux-agents.yml
---
- hosts: linux_endpoints
  become: yes
  vars:
    kafka_brokers: "kafka1.prod:9093,kafka2.prod:9093,kafka3.prod:9093"
    environment: "production"
    datacenter: "{{ datacenter_name }}"
  
  tasks:
  - name: Download installer
    get_url:
      url: "https://releases.company.com/edr-agent/linux/install-agent.sh"
      dest: /tmp/install-agent.sh
      mode: '0755'
      
  - name: Install EDR agent
    shell: |
      /tmp/install-agent.sh \
        --brokers "{{ kafka_brokers }}" \
        --environment "{{ environment }}" \
        --datacenter "{{ datacenter }}"
    register: install_result
    
  - name: Verify agent status
    systemd:
      name: vector
      state: started
      enabled: yes
```

#### Manual Deployment
```bash
# Download installer
wget https://releases.company.com/edr-agent/linux/install-agent.sh
chmod +x install-agent.sh

# Cài đặt
sudo ./install-agent.sh --brokers "kafka.company.com:9093" --environment production

# Verify installation
sudo systemctl status vector
sudo journalctl -u vector -f
```

### Agent Configuration Management

#### Centralized Configuration Server
```go
// server/go-services/config-server/main.go
func (s *ConfigServer) GetAgentConfig(hostID, version string) (*AgentConfig, error) {
    template := s.getConfigTemplate(version)
    config := s.customizeForHost(template, hostID)
    
    // Sign configuration for integrity
    signature := s.signConfig(config)
    
    return &AgentConfig{
        Content:   config,
        Signature: signature,
        Version:   version,
        UpdatedAt: time.Now(),
    }, nil
}
```

#### Dynamic Configuration Updates
```bash
# Update agent configuration
curl -X POST https://config.company.com/api/v1/agents/update \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{
    "host_ids": ["host-001", "host-002"],
    "config_version": "1.1.0",
    "rollout_strategy": "canary"
  }'
```

## Monitoring & Maintenance

### 1. Health Checks

#### Service Health Endpoints
```bash
# Kafka cluster health
curl -f http://kafka-manager:9000/api/health

# Flink job health
curl -f http://flink-jobmanager:8081/jobs

# OpenSearch cluster health
curl -f http://opensearch:9200/_cluster/health

# Go services health
curl -f http://indexer:8080/health
curl -f http://alert-router:8080/health
curl -f http://process-graph-api:8080/health
```

#### Automated Health Monitoring
```yaml
# kubernetes/health-checks.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: health-check-script
data:
  health-check.sh: |
    #!/bin/bash
    
    # Check all services
    services=("kafka" "flink" "opensearch" "indexer" "alert-router")
    
    for service in "${services[@]}"; do
      if ! kubectl get pods -l app=$service | grep Running; then
        echo "❌ $service is not healthy"
        exit 1
      fi
    done
    
    echo "✅ All services are healthy"
```

### 2. Performance Monitoring

#### Key Metrics to Monitor
```
Kafka:
- Messages per second
- Consumer lag
- Disk usage
- Network I/O

Flink:
- Checkpoint duration
- Backpressure
- Records processed per second
- State size

OpenSearch:
- Indexing rate
- Query latency
- Cluster health
- Disk usage

Go Services:
- HTTP request rate
- Response time
- Error rate
- Memory usage
```

#### Grafana Dashboards
```json
{
  "dashboard": {
    "title": "EDR Platform Overview",
    "panels": [
      {
        "title": "Events Per Second",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(kafka_server_brokertopicmetrics_messagesin_total[5m])"
          }
        ]
      },
      {
        "title": "Alert Generation Rate", 
        "type": "graph",
        "targets": [
          {
            "expr": "rate(flink_taskmanager_job_task_operator_numrecordsout[5m])"
          }
        ]
      }
    ]
  }
}
```

### 3. Log Management

#### Centralized Logging
```bash
# Tất cả service logs đều được gửi vào OpenSearch
# Sử dụng Filebeat hoặc Fluentd để collect logs

# Query logs
curl -X GET "opensearch:9200/logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"term": {"level": "ERROR"}}
      ]
    }
  }
}'
```

#### Log Retention Policy
```bash
# Tự động xóa logs cũ
curl -X PUT "opensearch:9200/_ilm/policy/logs-policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "10gb",
            "max_age": "1d"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "cold": {
        "min_age": "30d"
      },
      "delete": {
        "min_age": "90d"
      }
    }
  }
}'
```

### 4. Backup & Recovery

#### Automated Backups
```bash
#!/bin/bash
# scripts/backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/edr-platform/$DATE"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup OpenSearch
curl -X PUT "opensearch:9200/_snapshot/backup_repo/$DATE" -d '{
  "indices": "edr-*",
  "ignore_unavailable": true,
  "include_global_state": false
}'

# Backup Kafka topics (metadata only)
kubectl exec kafka-0 -- kafka-topics --bootstrap-server localhost:9092 --describe > "$BACKUP_DIR/kafka-topics.txt"

# Backup configurations
kubectl get configmaps -n edr-platform -o yaml > "$BACKUP_DIR/configmaps.yaml"
kubectl get secrets -n edr-platform -o yaml > "$BACKUP_DIR/secrets.yaml"

echo "Backup completed: $BACKUP_DIR"
```

#### Recovery Procedures
```bash
#!/bin/bash
# scripts/recovery.sh

BACKUP_DATE=$1
BACKUP_DIR="/backups/edr-platform/$BACKUP_DATE"

if [ ! -d "$BACKUP_DIR" ]; then
  echo "Backup directory not found: $BACKUP_DIR"
  exit 1
fi

# Restore OpenSearch
curl -X POST "opensearch:9200/_snapshot/backup_repo/$BACKUP_DATE/_restore" -d '{
  "indices": "edr-*",
  "ignore_unavailable": true,
  "include_global_state": false
}'

# Restore configurations
kubectl apply -f "$BACKUP_DIR/configmaps.yaml"
kubectl apply -f "$BACKUP_DIR/secrets.yaml"

echo "Recovery completed from: $BACKUP_DIR"
```

### 5. Scaling Operations

#### Auto-scaling Configuration
```yaml
# kubernetes/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: indexer-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: indexer
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

#### Manual Scaling
```bash
# Scale Flink TaskManagers
kubectl scale deployment flink-taskmanager --replicas=6

# Scale Go services
kubectl scale deployment indexer --replicas=4
kubectl scale deployment alert-router --replicas=2

# Add Kafka partitions (không thể giảm)
kubectl exec kafka-0 -- kafka-topics --bootstrap-server localhost:9092 \
  --alter --topic edr-events-normalized --partitions 12

# Scale OpenSearch data nodes
kubectl patch opensearchcluster main-cluster --type='merge' -p='{"spec":{"nodes":{"data":{"replicas":5}}}}'
```

## Troubleshooting

### Common Issues

#### 1. Kafka Consumer Lag
```bash
# Kiểm tra consumer lag
kubectl exec kafka-0 -- kafka-consumer-groups --bootstrap-server localhost:9092 \
  --group indexer-group --describe

# Solutions:
# - Scale up consumers (indexer replicas)
# - Increase batch size
# - Check OpenSearch indexing performance
```

#### 2. Flink Job Failures
```bash
# Check Flink job status
curl http://flink-jobmanager:8081/jobs

# Check checkpoints
curl http://flink-jobmanager:8081/jobs/{job-id}/checkpoints

# Solutions:
# - Restart from last checkpoint
# - Increase checkpoint timeout
# - Check state backend storage
```

#### 3. OpenSearch Performance Issues
```bash
# Check cluster health
curl opensearch:9200/_cluster/health?pretty

# Check slow queries
curl opensearch:9200/_nodes/stats/indices/search?pretty

# Solutions:
# - Optimize queries
# - Add more data nodes
# - Adjust refresh interval
# - Use index templates properly
```

#### 4. Agent Connection Issues
```bash
# Windows
Test-NetConnection kafka.company.com -Port 9093
Get-EventLog -LogName Application -Source Vector

# Linux  
telnet kafka.company.com 9093
journalctl -u vector -f

# Solutions:
# - Check firewall rules
# - Verify DNS resolution
# - Check TLS certificates
# - Validate agent configuration
```

### Emergency Procedures

#### 1. Complete System Outage
```bash
# 1. Check infrastructure
kubectl get nodes
kubectl get pods -n edr-platform

# 2. Check persistent volumes
kubectl get pv

# 3. Restore from backup if needed
./scripts/recovery.sh 20241201_120000

# 4. Verify data integrity
./scripts/verify-data-integrity.sh
```

#### 2. Data Loss Recovery
```bash
# 1. Stop all consumers
kubectl scale deployment indexer --replicas=0

# 2. Reset Kafka consumer groups if needed
kubectl exec kafka-0 -- kafka-consumer-groups --bootstrap-server localhost:9092 \
  --group indexer-group --reset-offsets --to-earliest --topic edr-events-normalized

# 3. Restore OpenSearch from snapshot
curl -X POST "opensearch:9200/_snapshot/backup_repo/latest/_restore"

# 4. Resume processing
kubectl scale deployment indexer --replicas=3
```

---

*Tài liệu này được cập nhật thường xuyên. Vui lòng kiểm tra phiên bản mới nhất trên company wiki.*
