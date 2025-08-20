#!/bin/bash

# ====================================================================
# VECTOR EDR AGENT - LINUX INSTALLER SCRIPT
# ====================================================================
# Tác giả: Senior Software Engineer - EDR Platform Team
# Mô tả: Script Bash để cài đặt và cấu hình Vector EDR Agent trên Linux
# Phiên bản: 1.0.0
# Ngày tạo: 2024-01-01
# ====================================================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# ====================================================================
# CONFIGURATION CONSTANTS - HẰNG SỐ CẤU HÌNH
# ====================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SERVICE_NAME="vector"
readonly SERVICE_DISPLAY_NAME="Vector EDR Agent"

# Paths - đường dẫn cài đặt
readonly INSTALL_PATH="/opt/vector"
readonly CONFIG_PATH="/etc/vector/vector.toml"
readonly DATA_PATH="/var/lib/vector"
readonly CERT_PATH="/etc/vector/certificates"
readonly LOG_PATH="/var/log/vector"
readonly SYSTEMD_SERVICE_PATH="/etc/systemd/system/vector.service"

# URLs và downloads
readonly VECTOR_DEB_URL_TEMPLATE="https://packages.vector.dev/latest/vector_latest_amd64.deb"
readonly VECTOR_RPM_URL_TEMPLATE="https://packages.vector.dev/latest/vector_latest.x86_64.rpm"
readonly VECTOR_TAR_URL_TEMPLATE="https://packages.vector.dev/latest/vector_latest_x86_64-unknown-linux-musl.tar.gz"

# Log file
readonly LOG_FILE="/tmp/vector-edr-install.log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# ====================================================================
# GLOBAL VARIABLES - BIẾN TOÀN CỤC
# ====================================================================

# Command line parameters with defaults
VECTOR_VERSION="latest"
KAFKA_BROKERS=""
ENVIRONMENT="production"
DATACENTER="default"
HOST_ID=""
HEALTHCHECK_ENDPOINT=""
SKIP_CERTIFICATES=false
UNINSTALL=false
DRY_RUN=false
FORCE=false

# System detection
DISTRO=""
DISTRO_VERSION=""
PACKAGE_MANAGER=""

# ====================================================================
# HELPER FUNCTIONS - CÁC HÀM PHỤ TRỢ
# ====================================================================

# Hàm ghi log với timestamp và màu sắc
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Ghi vào file log
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Hiển thị với màu sắc
    case "$level" in
        "ERROR")
            echo -e "${RED}[$timestamp] [ERROR] $message${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[$timestamp] [WARN] $message${NC}"
            ;;
        "INFO")
            echo -e "${GREEN}[$timestamp] [INFO] $message${NC}"
            ;;
        "DEBUG")
            echo -e "${BLUE}[$timestamp] [DEBUG] $message${NC}"
            ;;
        *)
            echo "[$timestamp] [$level] $message"
            ;;
    esac
}

# Hiển thị help
show_help() {
    cat << EOF
Vector EDR Agent Installer v$SCRIPT_VERSION

SYNOPSIS:
    $SCRIPT_NAME [OPTIONS]

DESCRIPTION:
    Cài đặt và cấu hình Vector EDR Agent trên Linux endpoint

OPTIONS:
    -b, --brokers BROKERS       Kafka brokers (bắt buộc, format: "broker1:9093,broker2:9093")
    -e, --environment ENV       Môi trường (dev/staging/prod, mặc định: production)  
    -d, --datacenter DC         Datacenter identifier (mặc định: default)
    -i, --host-id ID            Host ID tùy chỉnh (tự generate nếu không có)
    -v, --version VERSION       Vector version (mặc định: latest)
    --health-endpoint URL       Health check endpoint URL
    --skip-certificates         Bỏ qua cài đặt TLS certificates (chỉ dùng dev)
    --uninstall                 Gỡ cài đặt Vector Agent
    --dry-run                   Chế độ thử nghiệm (không thực sự cài đặt)
    --force                     Bỏ qua các kiểm tra an toàn
    -h, --help                  Hiển thị help này

EXAMPLES:
    # Cài đặt production
    $SCRIPT_NAME -b "kafka1.company.com:9093,kafka2.company.com:9093" -e production
    
    # Cài đặt development  
    $SCRIPT_NAME -b "localhost:9093" -e dev --skip-certificates
    
    # Gỡ cài đặt
    $SCRIPT_NAME --uninstall
    
    # Dry run
    $SCRIPT_NAME -b "kafka1:9093" --dry-run

REQUIREMENTS:
    - Linux distribution với systemd
    - Root privileges hoặc sudo access
    - Internet connection (để tải Vector package)
    - Đủ disk space (ít nhất 500MB)

NOTES:
    - Script tạo log tại: $LOG_FILE
    - Service name: $SERVICE_NAME
    - Config file: $CONFIG_PATH
    - Data directory: $DATA_PATH

EOF
}

# Kiểm tra quyền root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "Script cần chạy với quyền root. Sử dụng: sudo $SCRIPT_NAME"
        exit 1
    fi
}

# Phát hiện Linux distribution
detect_distro() {
    log "INFO" "Đang phát hiện Linux distribution..."
    
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/etc/os-release
        source /etc/os-release
        DISTRO="$ID"
        DISTRO_VERSION="$VERSION_ID"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
        DISTRO_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
        DISTRO_VERSION=$(cat /etc/debian_version)
    else
        log "ERROR" "Không thể phát hiện Linux distribution"
        exit 1
    fi
    
    # Xác định package manager
    case "$DISTRO" in
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            ;;
        rhel|centos|fedora|rocky|almalinux)
            PACKAGE_MANAGER="yum"
            if command -v dnf >/dev/null 2>&1; then
                PACKAGE_MANAGER="dnf"
            fi
            ;;
        *)
            PACKAGE_MANAGER="generic"
            log "WARN" "Distribution chưa được test đầy đủ: $DISTRO"
            ;;
    esac
    
    log "INFO" "Phát hiện: $DISTRO $DISTRO_VERSION (Package manager: $PACKAGE_MANAGER)"
}

# Kiểm tra system requirements
check_requirements() {
    log "INFO" "Đang kiểm tra system requirements..."
    
    # Kiểm tra systemd
    if ! command -v systemctl >/dev/null 2>&1; then
        log "ERROR" "systemd là bắt buộc để chạy Vector service"
        exit 1
    fi
    
    # Kiểm tra disk space (cần ít nhất 500MB)
    local available_space
    available_space=$(df /tmp | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 512000 ]]; then
        log "ERROR" "Không đủ disk space. Cần ít nhất 500MB trong /tmp"
        exit 1
    fi
    
    # Kiểm tra kết nối internet
    if ! curl -s --connect-timeout 5 https://www.google.com >/dev/null; then
        log "WARN" "Không có kết nối internet. Cài đặt có thể thất bại"
        if [[ "$FORCE" != "true" ]]; then
            log "ERROR" "Sử dụng --force để bỏ qua kiểm tra này"
            exit 1
        fi
    fi
    
    # Kiểm tra các dependencies cơ bản
    local deps=("curl" "tar" "gzip")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "ERROR" "Thiếu dependency: $dep"
            exit 1
        fi
    done
    
    log "INFO" "System requirements OK"
}

# Thu thập thông tin hệ thống
get_system_info() {
    local hostname
    local kernel_version
    local total_memory
    local cpu_count
    local architecture
    
    hostname=$(hostname)
    kernel_version=$(uname -r)
    total_memory=$(free -h | awk '/^Mem:/ {print $2}')
    cpu_count=$(nproc)
    architecture=$(uname -m)
    
    log "INFO" "Thông tin hệ thống:"
    log "INFO" "  Hostname: $hostname"
    log "INFO" "  OS: $DISTRO $DISTRO_VERSION"
    log "INFO" "  Kernel: $kernel_version"
    log "INFO" "  Architecture: $architecture"
    log "INFO" "  CPU cores: $cpu_count"
    log "INFO" "  Memory: $total_memory"
}

# Tạo Host ID unique
generate_host_id() {
    if [[ -n "$HOST_ID" ]]; then
        echo "$HOST_ID"
        return
    fi
    
    # Tạo UUID dựa trên system info để đảm bảo consistency
    local hostname
    local machine_id
    local base_string
    local uuid
    
    hostname=$(hostname)
    
    # Sử dụng machine-id nếu có (systemd)
    if [[ -f /etc/machine-id ]]; then
        machine_id=$(cat /etc/machine-id)
        base_string="${hostname}-${machine_id}-${DISTRO}"
    else
        # Fallback sử dụng MAC address
        local mac_addr
        mac_addr=$(ip link show | awk '/ether/ {print $2}' | head -1 | tr -d ':')
        base_string="${hostname}-${mac_addr}-${DISTRO}"
    fi
    
    # Tạo MD5 hash và format như UUID
    uuid=$(echo -n "$base_string" | md5sum | cut -d' ' -f1)
    uuid="${uuid:0:8}-${uuid:8:4}-${uuid:12:4}-${uuid:16:4}-${uuid:20:12}"
    
    log "INFO" "Generated Host ID: $uuid"
    echo "$uuid"
}

# Dừng Vector service
stop_vector_service() {
    log "INFO" "Đang dừng Vector service..."
    
    if systemctl is-active --quiet vector; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "[DRY RUN] Sẽ dừng Vector service"
        else
            systemctl stop vector
            log "INFO" "Vector service đã được dừng"
        fi
    else
        log "INFO" "Vector service không chạy hoặc không tồn tại"
    fi
}

# Xóa Vector service
remove_vector_service() {
    log "INFO" "Đang xóa Vector service..."
    
    # Dừng service trước
    stop_vector_service
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Sẽ xóa Vector service và files"
        return
    fi
    
    # Disable và xóa service
    if systemctl is-enabled --quiet vector 2>/dev/null; then
        systemctl disable vector
    fi
    
    # Xóa service file
    if [[ -f "$SYSTEMD_SERVICE_PATH" ]]; then
        rm -f "$SYSTEMD_SERVICE_PATH"
    fi
    
    # Reload systemd
    systemctl daemon-reload
    
    log "INFO" "Vector service đã được xóa"
}

# Gỡ cài đặt Vector hoàn toàn
uninstall_vector() {
    log "INFO" "Bắt đầu gỡ cài đặt Vector EDR Agent..."
    
    # Dừng và xóa service
    remove_vector_service
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Sẽ gỡ cài đặt Vector package và xóa data directories"
        return
    fi
    
    # Gỡ cài đặt package theo package manager
    case "$PACKAGE_MANAGER" in
        apt)
            if dpkg -l | grep -q vector; then
                log "INFO" "Đang gỡ cài đặt Vector package (apt)..."
                apt-get remove --purge -y vector || true
            fi
            ;;
        yum|dnf)
            if rpm -q vector >/dev/null 2>&1; then
                log "INFO" "Đang gỡ cài đặt Vector package ($PACKAGE_MANAGER)..."
                $PACKAGE_MANAGER remove -y vector || true
            fi
            ;;
        *)
            log "WARN" "Generic installation - xóa manually"
            if [[ -d "$INSTALL_PATH" ]]; then
                rm -rf "$INSTALL_PATH"
            fi
            ;;
    esac
    
    # Xóa data directories
    local paths_to_remove=(
        "$DATA_PATH"
        "$CERT_PATH"
        "$LOG_PATH"
        "$(dirname "$CONFIG_PATH")"
    )
    
    for path in "${paths_to_remove[@]}"; do
        if [[ -d "$path" ]]; then
            log "INFO" "Đang xóa thư mục: $path"
            rm -rf "$path"
        fi
    done
    
    # Xóa user vector (nếu tồn tại)
    if id "vector" >/dev/null 2>&1; then
        log "INFO" "Đang xóa user vector"
        userdel vector || true
    fi
    
    log "INFO" "Vector EDR Agent đã được gỡ cài đặt hoàn toàn"
}

# Tải file với progress bar
download_file() {
    local url="$1"
    local output="$2"
    
    log "INFO" "Đang tải file từ: $url"
    
    # Tạo thư mục nếu cần
    local output_dir
    output_dir=$(dirname "$output")
    mkdir -p "$output_dir"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Sẽ tải file: $url -> $output"
        return 0
    fi
    
    # Tải file với progress bar
    if curl -L --progress-bar --fail "$url" -o "$output"; then
        log "INFO" "Đã tải file thành công: $output"
        return 0
    else
        log "ERROR" "Lỗi khi tải file: $url"
        return 1
    fi
}

# Cài đặt Vector package
install_vector_package() {
    log "INFO" "Đang cài đặt Vector package..."
    
    local temp_dir="/tmp/vector-install"
    mkdir -p "$temp_dir"
    
    case "$PACKAGE_MANAGER" in
        apt)
            # Cài đặt dependencies
            log "INFO" "Cài đặt dependencies (apt)..."
            if [[ "$DRY_RUN" != "true" ]]; then
                apt-get update
                apt-get install -y curl gnupg lsb-release
            fi
            
            # Tải và cài đặt Vector DEB package
            local deb_file="$temp_dir/vector.deb"
            if download_file "$VECTOR_DEB_URL_TEMPLATE" "$deb_file"; then
                if [[ "$DRY_RUN" != "true" ]]; then
                    dpkg -i "$deb_file" || true
                    apt-get install -f -y  # Fix dependencies nếu có
                fi
            else
                return 1
            fi
            ;;
            
        yum|dnf)
            # Cài đặt dependencies
            log "INFO" "Cài đặt dependencies ($PACKAGE_MANAGER)..."
            if [[ "$DRY_RUN" != "true" ]]; then
                $PACKAGE_MANAGER install -y curl
            fi
            
            # Tải và cài đặt Vector RPM package
            local rpm_file="$temp_dir/vector.rpm"
            if download_file "$VECTOR_RPM_URL_TEMPLATE" "$rpm_file"; then
                if [[ "$DRY_RUN" != "true" ]]; then
                    $PACKAGE_MANAGER install -y "$rpm_file"
                fi
            else
                return 1
            fi
            ;;
            
        generic)
            # Generic installation từ tarball
            log "INFO" "Generic installation từ tarball..."
            local tar_file="$temp_dir/vector.tar.gz"
            
            if download_file "$VECTOR_TAR_URL_TEMPLATE" "$tar_file"; then
                if [[ "$DRY_RUN" != "true" ]]; then
                    # Extract
                    tar -xzf "$tar_file" -C "$temp_dir"
                    
                    # Find extracted directory
                    local extracted_dir
                    extracted_dir=$(find "$temp_dir" -maxdepth 1 -type d -name "vector-*" | head -1)
                    
                    if [[ -n "$extracted_dir" ]]; then
                        # Copy binary
                        mkdir -p "$INSTALL_PATH/bin"
                        cp "$extracted_dir/bin/vector" "$INSTALL_PATH/bin/"
                        chmod +x "$INSTALL_PATH/bin/vector"
                        
                        # Create symlink
                        ln -sf "$INSTALL_PATH/bin/vector" "/usr/local/bin/vector"
                        
                        log "INFO" "Vector binary installed to $INSTALL_PATH/bin/vector"
                    else
                        log "ERROR" "Không tìm thấy extracted directory"
                        return 1
                    fi
                fi
            else
                return 1
            fi
            ;;
    esac
    
    # Cleanup
    rm -rf "$temp_dir"
    
    log "INFO" "Vector package đã được cài đặt thành công"
    return 0
}

# Tạo user vector
create_vector_user() {
    log "INFO" "Đang tạo user vector..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Sẽ tạo user vector"
        return 0
    fi
    
    # Kiểm tra user đã tồn tại chưa
    if id "vector" >/dev/null 2>&1; then
        log "INFO" "User vector đã tồn tại"
        return 0
    fi
    
    # Tạo system user
    useradd --system --home-dir "$DATA_PATH" --shell /bin/false vector
    
    log "INFO" "User vector đã được tạo"
}

# Tạo directories cần thiết
create_directories() {
    log "INFO" "Đang tạo directories..."
    
    local dirs=(
        "$DATA_PATH"
        "$LOG_PATH"
        "$CERT_PATH"
        "$(dirname "$CONFIG_PATH")"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ "$DRY_RUN" == "true" ]]; then
            log "INFO" "[DRY RUN] Sẽ tạo directory: $dir"
        else
            mkdir -p "$dir"
            chown vector:vector "$dir"
            chmod 755 "$dir"
            log "INFO" "Đã tạo directory: $dir"
        fi
    done
}

# Cài đặt TLS certificates
install_certificates() {
    log "INFO" "Đang cài đặt TLS certificates..."
    
    local ca_cert_path="$CERT_PATH/ca.crt"
    
    if [[ -f "$ca_cert_path" ]]; then
        log "INFO" "Certificate đã tồn tại: $ca_cert_path"
        return 0
    fi
    
    if [[ "$SKIP_CERTIFICATES" == "true" ]]; then
        log "WARN" "Bỏ qua cài đặt certificates (--skip-certificates)"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Sẽ cài đặt TLS certificates"
        return 0
    fi
    
    # Trong production, certificates sẽ được deploy bởi management system
    # Ở đây tạo self-signed cert cho development
    if [[ "$ENVIRONMENT" == "dev" ]]; then
        log "WARN" "Tạo self-signed certificate cho development"
        
        # Generate self-signed certificate
        openssl req -x509 -newkey rsa:4096 -keyout "$CERT_PATH/ca.key" -out "$ca_cert_path" \
            -days 365 -nodes -subj "/C=VN/ST=HCM/L=HCM/O=Company/CN=localhost"
        
        chown vector:vector "$CERT_PATH"/*
        chmod 600 "$CERT_PATH/ca.key"
        chmod 644 "$ca_cert_path"
        
        log "INFO" "Đã tạo self-signed certificate: $ca_cert_path"
    else
        log "ERROR" "Production environment - certificates cần được cài đặt bởi PKI system"
        return 1
    fi
}

# Tạo cấu hình Vector
create_vector_configuration() {
    log "INFO" "Đang tạo cấu hình Vector..."
    
    local generated_host_id
    generated_host_id=$(generate_host_id)
    
    # Đọc template từ file hoặc sử dụng embedded config
    local template_path
    template_path="$(dirname "$0")/vector-linux.toml"
    
    local config_content
    if [[ -f "$template_path" ]]; then
        log "INFO" "Sử dụng template: $template_path"
        config_content=$(cat "$template_path")
    else
        log "WARN" "Template không tìm thấy, sử dụng cấu hình embedded"
        config_content=$(get_embedded_vector_config)
    fi
    
    # Thay thế variables trong template
    config_content="${config_content//\$\{EDR_HOST_ID\}/$generated_host_id}"
    config_content="${config_content//\$\{KAFKA_BROKERS\}/$KAFKA_BROKERS}"
    config_content="${config_content//\$\{TLS_CA_FILE\}/$CERT_PATH/ca.crt}"
    config_content="${config_content//\$\{EDR_ENVIRONMENT\}/$ENVIRONMENT}"
    config_content="${config_content//\$\{EDR_DATACENTER\}/$DATACENTER}"
    config_content="${config_content//\$\{HEALTHCHECK_ENDPOINT\}/$HEALTHCHECK_ENDPOINT}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Sẽ tạo config file: $CONFIG_PATH"
    else
        # Ghi config file
        echo "$config_content" > "$CONFIG_PATH"
        chown vector:vector "$CONFIG_PATH"
        chmod 644 "$CONFIG_PATH"
        log "INFO" "Đã tạo config file: $CONFIG_PATH"
    fi
    
    echo "$generated_host_id"
}

# Tạo systemd service
create_systemd_service() {
    log "INFO" "Đang tạo systemd service..."
    
    local service_content
    service_content=$(cat << EOF
[Unit]
Description=$SERVICE_DISPLAY_NAME
Documentation=https://vector.dev
After=network.target
Requires=network.target

[Service]
Type=notify
User=vector
Group=vector
ExecStart=/usr/bin/vector --config $CONFIG_PATH
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_PATH $LOG_PATH

# Environment variables
Environment=EDR_HOST_ID=$1
Environment=KAFKA_BROKERS=$KAFKA_BROKERS
Environment=TLS_CA_FILE=$CERT_PATH/ca.crt
Environment=EDR_ENVIRONMENT=$ENVIRONMENT
Environment=EDR_DATACENTER=$DATACENTER
Environment=VECTOR_LOG=info

[Install]
WantedBy=multi-user.target
EOF
)
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Sẽ tạo systemd service: $SYSTEMD_SERVICE_PATH"
    else
        echo "$service_content" > "$SYSTEMD_SERVICE_PATH"
        
        # Reload systemd và enable service
        systemctl daemon-reload
        systemctl enable vector
        
        log "INFO" "Đã tạo và enable systemd service"
    fi
}

# Khởi động Vector service
start_vector_service() {
    log "INFO" "Đang khởi động Vector service..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "[DRY RUN] Sẽ khởi động Vector service"
        return 0
    fi
    
    # Khởi động service
    systemctl start vector
    
    # Đợi service khởi động
    sleep 5
    
    # Kiểm tra status
    if systemctl is-active --quiet vector; then
        log "INFO" "Vector service đã khởi động thành công"
        return 0
    else
        log "ERROR" "Vector service không khởi động được"
        
        # Hiển thị logs để debug
        log "ERROR" "Service logs:"
        journalctl -u vector --no-pager -n 20 || true
        return 1
    fi
}

# Kiểm tra health của Vector
test_vector_health() {
    log "INFO" "Đang kiểm tra health của Vector agent..."
    
    # Kiểm tra service status
    if ! systemctl is-active --quiet vector; then
        log "ERROR" "Vector service không chạy"
        return 1
    fi
    
    # Kiểm tra log files cho errors
    if [[ -f "$LOG_PATH/vector.log" ]]; then
        local error_count
        error_count=$(grep -c "ERROR\|FATAL" "$LOG_PATH/vector.log" 2>/dev/null || echo "0")
        if [[ $error_count -gt 0 ]]; then
            log "WARN" "Phát hiện $error_count lỗi trong Vector logs"
            log "WARN" "Kiểm tra: $LOG_PATH/vector.log"
        fi
    fi
    
    # Test kết nối đến Kafka brokers
    if [[ -n "$KAFKA_BROKERS" ]]; then
        IFS=',' read -ra BROKERS <<< "$KAFKA_BROKERS"
        for broker in "${BROKERS[@]}"; do
            broker=$(echo "$broker" | xargs)  # trim whitespace
            local host
            local port
            host=$(echo "$broker" | cut -d':' -f1)
            port=$(echo "$broker" | cut -d':' -f2)
            
            if timeout 5 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
                log "INFO" "Kết nối đến Kafka broker thành công: $broker"
            else
                log "WARN" "Không thể kết nối đến Kafka broker: $broker"
            fi
        done
    fi
    
    log "INFO" "Health check hoàn tất"
    return 0
}

# Embedded Vector config (fallback)
get_embedded_vector_config() {
    cat << 'EOF'
# Vector EDR Agent Configuration - Linux
# Generated by install script

data_dir = "/var/lib/vector/data"

[sources.linux_auth]
type = "file"
include = ["/var/log/auth.log", "/var/log/secure"]

[sources.journald]
type = "journald"
since_now = "-30m"

[transforms.ecs_normalizer]
type = "remap"
inputs = ["linux_auth", "journald"]
source = '''
.host.id = "${EDR_HOST_ID}"
.host.name = get_hostname!()
.agent.type = "vector-edr-linux"
.ecs.version = "8.6.0"
.@timestamp = .timestamp ?? now()
'''

[sinks.kafka]
type = "kafka"
inputs = ["ecs_normalizer"]
bootstrap_servers = "${KAFKA_BROKERS}"
topic = "edr-events-normalized"
key_field = "host.id"

[sinks.kafka.tls]
enabled = true
ca_file = "${TLS_CA_FILE}"
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -b|--brokers)
                KAFKA_BROKERS="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -d|--datacenter)
                DATACENTER="$2"
                shift 2
                ;;
            -i|--host-id)
                HOST_ID="$2"
                shift 2
                ;;
            -v|--version)
                VECTOR_VERSION="$2"
                shift 2
                ;;
            --health-endpoint)
                HEALTHCHECK_ENDPOINT="$2"
                shift 2
                ;;
            --skip-certificates)
                SKIP_CERTIFICATES=true
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# ====================================================================
# MAIN FUNCTION - HÀM MAIN
# ====================================================================

main() {
    log "INFO" "======================================"
    log "INFO" "Vector EDR Agent Installer v$SCRIPT_VERSION"
    log "INFO" "======================================"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Kiểm tra quyền root
    check_root
    
    # Phát hiện system
    detect_distro
    get_system_info
    
    # Xử lý uninstall
    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall_vector
        log "INFO" "Gỡ cài đặt hoàn tất!"
        return 0
    fi
    
    # Validate parameters
    if [[ -z "$KAFKA_BROKERS" ]]; then
        log "ERROR" "Tham số --brokers là bắt buộc"
        log "ERROR" "Ví dụ: --brokers 'kafka1:9093,kafka2:9093'"
        exit 1
    fi
    
    # Kiểm tra requirements
    check_requirements
    
    # BƯỚC 1: Dừng Vector service cũ (nếu có)
    stop_vector_service
    
    # BƯỚC 2: Cài đặt Vector package
    if ! install_vector_package; then
        log "ERROR" "Cài đặt Vector package thất bại"
        exit 1
    fi
    
    # BƯỚC 3: Tạo user và directories
    create_vector_user
    create_directories
    
    # BƯỚC 4: Cài đặt certificates
    if ! install_certificates; then
        log "ERROR" "Cài đặt certificates thất bại"
        exit 1
    fi
    
    # BƯỚC 5: Tạo cấu hình Vector
    local generated_host_id
    generated_host_id=$(create_vector_configuration)
    
    # BƯỚC 6: Tạo systemd service
    create_systemd_service "$generated_host_id"
    
    # BƯỚC 7: Khởi động Vector service
    if ! start_vector_service; then
        log "ERROR" "Khởi động Vector service thất bại"
        exit 1
    fi
    
    # BƯỚC 8: Health check
    sleep 10  # Đợi service ổn định
    test_vector_health
    
    log "INFO" "======================================"
    log "INFO" "CÀI ĐẶT HOÀN TẤT THÀNH CÔNG!"
    log "INFO" "======================================"
    log "INFO" "Host ID: $generated_host_id"
    log "INFO" "Config: $CONFIG_PATH"
    log "INFO" "Data: $DATA_PATH"
    log "INFO" "Logs: $LOG_PATH"
    log "INFO" "Service: $SERVICE_NAME (Running)"
    log "INFO" "======================================"
    log "INFO" ""
    log "INFO" "Các lệnh hữu ích:"
    log "INFO" "  Xem status: sudo systemctl status vector"
    log "INFO" "  Xem logs: sudo journalctl -u vector -f"
    log "INFO" "  Restart: sudo systemctl restart vector"
    log "INFO" "  Config: sudo nano $CONFIG_PATH"
    log "INFO" ""
}

# ====================================================================
# SCRIPT EXECUTION - THỰC THI SCRIPT
# ====================================================================

# Tạo log file
touch "$LOG_FILE"

# Chạy main function với tất cả arguments
main "$@"

# ====================================================================
# END OF SCRIPT
# ====================================================================
#
# Ghi chú:
# 1. Script này cần chạy với quyền root (sudo)
# 2. Hỗ trợ các distribution: Ubuntu, Debian, RHEL, CentOS, Fedora
# 3. Trong production, certificates nên được quản lý bởi PKI system
# 4. Có thể integrate với configuration management tools (Ansible, Puppet)
# 5. Monitor logs tại: /tmp/vector-edr-install.log
#
# Ví dụ sử dụng:
#
# Development:
# sudo ./install-agent.sh --brokers "localhost:9093" --environment dev --skip-certificates
#
# Production:
# sudo ./install-agent.sh --brokers "kafka1.prod:9093,kafka2.prod:9093" --environment production --datacenter dc1
#
# Uninstall:
# sudo ./install-agent.sh --uninstall
#
# Dry run:
# sudo ./install-agent.sh --brokers "kafka1:9093" --dry-run
#
# Author: Senior Software Engineer - EDR Platform Team
# Contact: edr-team@company.com
# Support: https://company.wiki/edr-platform/linux-installer
# ====================================================================
