# VDT2025 EDR System

Hệ thống **Endpoint Detection and Response (EDR)** hiện đại sử dụng Sigma rules để phát hiện các mối đe dọa bảo mật.

## 🏗️ Kiến Trúc Hệ Thống

```
VDT2025_PhucNguyen204/
├── cmd/                        # Executable commands
│   └── edr-server/            # Main EDR server
├── internal/                   # Private application code
│   ├── detector/              # Detection engine
│   ├── models/                # Data models
│   ├── rules/                 # Rule processing
│   └── sigma/                 # Sigma rule engine

├── configs/                   # Configuration files
│   ├── vector-basic.toml      # Vector collector config
│   └── vector-windows.toml    # Vector Windows agent config
├── deployments/               # Deployment configs
│   ├── docker-compose.yml     # Docker orchestration
│   └── Dockerfile             # Container build
├── examples/                  # Example scripts and demos
│   ├── ssh_attack_simple.ps1  # SSH attack simulation
│   └── ssh_bruteforce_demo.ps1 # Extended demo
├── docs/                      # Documentation
├── sigma/                     # Sigma rules repository
└── go.mod                     # Go module definition
```

## 🚀 Khởi Chạy Nhanh

### Yêu Cầu Hệ Thống
- Go 1.21+
- Docker & Docker Compose
- PowerShell (Windows)

### 1. Clone Repository
```bash
git clone https://github.com/PhucNguyen204/VDT2025---EDR---SIEM.git
cd VDT2025---EDR---SIEM
```

### 2. Khởi Động Hệ Thống
```bash
# Sử dụng Makefile
make docker-up

# Hoặc trực tiếp với Docker Compose
cd deployments
docker compose up -d
```

### 3. Chạy Demo Tấn Công
```bash
# Chạy demo SSH brute-force
make demo

# Hoặc trực tiếp
powershell.exe -ExecutionPolicy Bypass -File ./examples/ssh_attack_simple.ps1
```

## 📊 Kết Quả Demo

Khi chạy thành công, bạn sẽ thấy:

```
=== Phase 1: SSH Process Creation Events ===
[HYDRA 1] Command: hydra.exe -u admin -p ^PASS^ -t 4 ssh://192.168.1.100
           Alerts: 108
           HYDRA DETECTED!

=== Phase 2: Authentication Failure Events ===
[AUTH 1] Failed login: admin from 203.0.113.127
          Alerts: 8
          FAILED LOGON DETECTED!

=== Results ===
Events processed: 10
Alerts generated: 580
SUCCESS: SSH Attack Detected!
```

## 🔧 Commands Makefile

```bash
make build        # Build ứng dụng Go
make run          # Chạy ứng dụng
make test         # Chạy tests
make docker-up    # Khởi động containers
make docker-down  # Dừng containers
make docker-logs  # Xem logs
make demo         # Chạy demo tấn công
make help         # Hiển thị help
```

## 🌐 Giao Diện Web

- **Dashboard**: http://localhost:9090/dashboard
- **API**: http://localhost:9090/api/v1/
- **Vector API**: http://localhost:8686/

## 🎯 Tính Năng Chính

### ✅ Đã Hoàn Thành
- **Sigma Rules Integration**: Hỗ trợ 2900+ Sigma rules
- **Real-time Detection**: Phát hiện threats theo thời gian thực
- **Process Monitoring**: Giám sát process creation events
- **Authentication Monitoring**: Phát hiện failed logon attempts
- **SSH Brute-force Detection**: Phát hiện các cuộc tấn công SSH
- **RESTful API**: API đầy đủ cho integration
- **Docker Support**: Triển khai dễ dàng với containers

### 🔄 Luồng Xử Lý
1. **Vector Agent** thu thập logs từ endpoints
2. **EDR Engine** nhận events qua HTTP API
3. **Sigma Engine** đối chiếu với 2900+ rules
4. **Alerts** được tạo cho events đáng nghi
5. **Dashboard** hiển thị kết quả real-time

## 📝 Cấu Hình

### Vector Agent (Windows)
```toml
# configs/vector-windows.toml
[sources.windows_logs]
type = "windows_event_log"
query = '''
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[EventID=4624 or EventID=4625]]</Select>
  </Query>
</QueryList>
'''
```

### Sigma Rules
Rules được mount từ `sigma/rules/` directory vào container tại runtime.

## 🐞 Debug

```bash
# Xem logs chi tiết
make docker-logs

# Kiểm tra container status
docker compose -f deployments/docker-compose.yml ps

# Test API endpoint
curl http://localhost:9090/api/v1/stats
```

## 🤝 Contribution

1. Fork repository
2. Tạo feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Tạo Pull Request

## 📜 License

Dự án này được phát triển cho mục đích học tập VDT2025.

## 🏆 Demo Results

Hệ thống đã được test thành công với khả năng:
- Phát hiện **108 alerts** cho mỗi Hydra process event
- Phát hiện **8 alerts** cho mỗi failed authentication event
- Xử lý **580 total alerts** từ 10 simulated events
- Response time < 100ms cho mỗi event

---

**VDT2025 - Phuc Nguyen**  
*Modern EDR with Sigma Rules Detection*