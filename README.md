# Real-time EDR Platform - Vector Agent System
## Hệ thống Agent EDR thời gian thực với Vector.dev

### Mô tả dự án
Đây là một hệ thống EDR (Endpoint Detection and Response) được phát triển dựa trên kiến trúc hiện đại:
- **Agent Layer**: Vector.dev thu thập logs từ Windows và Linux endpoints
- **Message Queue**: Apache Kafka làm tầng transport và buffering
- **Stream Processing**: Apache Flink xử lý real-time và Complex Event Processing (CEP)
- **Storage & Search**: OpenSearch để lưu trữ và tìm kiếm

### Cấu trúc dự án
```
edr-platform/
├── agents/                          # Cấu hình và scripts cho các agent
│   ├── windows/                     # Windows Vector agent
│   │   ├── vector-windows.toml      # Cấu hình Vector cho Windows
│   │   ├── install-agent.ps1        # Script PowerShell cài đặt
│   │   └── templates/               # Template cấu hình động
│   ├── linux/                       # Linux Vector agent
│   │   ├── vector-linux.toml        # Cấu hình Vector cho Linux
│   │   ├── install-agent.sh         # Script Bash cài đặt
│   │   └── templates/               # Template cấu hình động
│   └── shared/                      # Cấu hình chung
│       ├── certificates/            # TLS certificates
│       └── schemas/                 # JSON Schema cho dữ liệu
├── server/                          # Backend services
│   ├── flink-jobs/                  # Flink stream processing jobs
│   ├── go-services/                 # Go microservices
│   └── configurations/              # Server configurations
├── infrastructure/                  # Infrastructure as Code
│   ├── docker-compose.yml          # Development environment
│   ├── kubernetes/                  # K8s manifests cho production
│   └── terraform/                   # Cloud infrastructure
├── docs/                           # Documentation
│   ├── architecture.md            # Kiến trúc hệ thống
│   ├── deployment.md               # Hướng dẫn triển khai
│   └── troubleshooting.md          # Xử lý sự cố
└── tests/                          # Test suites
    ├── integration/                # Integration tests
    └── load/                       # Load testing
```

### Công nghệ sử dụng
- **Vector.dev**: High-performance log collection và transformation
- **Apache Kafka**: Message streaming platform
- **Apache Flink**: Stream processing và CEP
- **OpenSearch**: Search và analytics engine
- **Go**: Backend services development
- **Docker & Kubernetes**: Container orchestration

### Nhanh tức bắt đầu
1. Clone repository: `git clone <repo-url>`
2. Khởi động development environment: `docker-compose up -d`
3. Cài đặt agent trên endpoints (xem hướng dẫn trong `/docs`)

### Tính năng chính
- ✅ Thu thập real-time từ Windows Event Logs và Sysmon
- ✅ Thu thập từ Linux system logs và journald  
- ✅ Transform và normalize data theo chuẩn ECS
- ✅ Tích hợp với Sigma rules cho threat detection
- ✅ Xây dựng process tree và network graphs
- ✅ Scalable architecture cho 100k+ endpoints

---
*Developed with ❤️ for Vietnamese Cybersecurity Community*
