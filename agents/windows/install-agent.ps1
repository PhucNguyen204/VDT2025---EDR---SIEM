# ====================================================================
# VECTOR EDR AGENT - WINDOWS INSTALLER SCRIPT
# ====================================================================
# Tác giả: Senior Software Engineer - EDR Platform Team
# Mô tả: Script PowerShell để cài đặt và cấu hình Vector EDR Agent trên Windows
# Phiên bản: 1.0.0
# Ngày tạo: 2024-01-01
# ====================================================================

<#
.SYNOPSIS
    Cài đặt và cấu hình Vector EDR Agent trên Windows endpoint

.DESCRIPTION
    Script này thực hiện các tác vụ sau:
    1. Kiểm tra quyền Administrator
    2. Tải và cài đặt Vector phiên bản mới nhất
    3. Tạo cấu hình động cho endpoint
    4. Cài đặt TLS certificates
    5. Đăng ký và khởi động Vector service
    6. Thực hiện health check

.PARAMETER VectorVersion
    Phiên bản Vector cần cài đặt (mặc định: latest stable)

.PARAMETER KafkaBrokers
    Danh sách Kafka brokers (format: "broker1:9093,broker2:9093")

.PARAMETER Environment
    Môi trường triển khai (dev/staging/prod)

.PARAMETER DataCenter
    Datacenter identifier

.PARAMETER HostId
    Host ID tùy chỉnh (nếu không có sẽ tự generate UUID)

.PARAMETER InstallPath
    Đường dẫn cài đặt Vector (mặc định: C:\Program Files\Vector)

.PARAMETER ConfigPath
    Đường dẫn config file (mặc định: C:\ProgramData\Vector\vector.toml)

.PARAMETER SkipCertificates
    Bỏ qua việc cài đặt TLS certificates (chỉ dùng cho development)

.PARAMETER Uninstall
    Gỡ cài đặt Vector Agent

.EXAMPLE
    .\install-agent.ps1 -KafkaBrokers "kafka1.company.com:9093,kafka2.company.com:9093" -Environment "production"

.EXAMPLE
    .\install-agent.ps1 -Uninstall

.NOTES
    - Script cần chạy với quyền Administrator
    - Yêu cầu PowerShell 5.1 hoặc cao hơn
    - Hỗ trợ Windows 10/Server 2016 trở lên
#>

[CmdletBinding()]
param(
    [string]$VectorVersion = "0.36.0",
    [Parameter(Mandatory=$false)]
    [string]$KafkaBrokers = "",
    [string]$Environment = "production",
    [string]$DataCenter = "default",
    [string]$HostId = "",
    [string]$InstallPath = "C:\Program Files\Vector",
    [string]$ConfigPath = "C:\ProgramData\Vector\vector.toml",
    [string]$DataPath = "C:\ProgramData\Vector\data",
    [string]$CertPath = "C:\ProgramData\Vector\certificates",
    [string]$HealthCheckEndpoint = "",
    [switch]$SkipCertificates,
    [switch]$Uninstall,
    [switch]$DryRun
)

# ====================================================================
# CONFIGURATION CONSTANTS - HẰNG SỐ CẤU HÌNH
# ====================================================================

$SCRIPT_VERSION = "1.0.0"
$SERVICE_NAME = "vector"
$SERVICE_DISPLAY_NAME = "Vector EDR Agent"
$SERVICE_DESCRIPTION = "Vector EDR Agent for endpoint detection and response"

# URLs và paths
$VECTOR_DOWNLOAD_URL_TEMPLATE = "https://packages.vector.dev/windows/vector-{0}-x86_64.msi"
$VECTOR_CONFIG_TEMPLATE_URL = "https://raw.githubusercontent.com/company/edr-platform/main/agents/windows/vector-windows.toml"

# Log file
$LOG_FILE = "C:\Windows\Temp\vector-edr-install.log"

# ====================================================================
# HELPER FUNCTIONS - CÁC HÀM PHỤ TRỢ
# ====================================================================

function Write-Log {
    <#
    .SYNOPSIS
        Ghi log với timestamp
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Ghi ra console với màu sắc
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO"  { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry }
    }
    
    # Ghi vào file log
    Add-Content -Path $LOG_FILE -Value $logEntry -ErrorAction SilentlyContinue
}

function Test-Administrator {
    <#
    .SYNOPSIS
        Kiểm tra xem script có đang chạy với quyền Administrator không
    #>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-InternetConnection {
    <#
    .SYNOPSIS
        Kiểm tra kết nối internet
    #>
    try {
        $null = Invoke-WebRequest -Uri "https://www.google.com" -TimeoutSec 10 -UseBasicParsing
        return $true
    } catch {
        return $false
    }
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Thu thập thông tin hệ thống
    #>
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    
    return @{
        OSName = $osInfo.Caption
        OSVersion = $osInfo.Version
        Architecture = $osInfo.OSArchitecture
        ComputerName = $computerInfo.Name
        Domain = $computerInfo.Domain
        TotalMemory = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
        Manufacturer = $computerInfo.Manufacturer
        Model = $computerInfo.Model
    }
}

function Stop-VectorService {
    <#
    .SYNOPSIS
        Dừng Vector service một cách an toàn
    #>
    Write-Log "Đang dừng Vector service..." "INFO"
    
    try {
        $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Stop-Service -Name $SERVICE_NAME -Force -ErrorAction Stop
            Write-Log "Vector service đã được dừng" "INFO"
        } else {
            Write-Log "Vector service không chạy hoặc không tồn tại" "INFO"
        }
    } catch {
        Write-Log "Lỗi khi dừng Vector service: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Remove-VectorService {
    <#
    .SYNOPSIS
        Xóa Vector service
    #>
    Write-Log "Đang xóa Vector service..." "INFO"
    
    try {
        # Dừng service trước
        Stop-VectorService
        
        # Xóa service sử dụng sc.exe
        $result = & sc.exe delete $SERVICE_NAME
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Vector service đã được xóa thành công" "INFO"
        } else {
            Write-Log "Không thể xóa Vector service: $result" "WARN"
        }
    } catch {
        Write-Log "Lỗi khi xóa Vector service: $($_.Exception.Message)" "ERROR"
    }
}

function Uninstall-Vector {
    <#
    .SYNOPSIS
        Gỡ cài đặt Vector hoàn toàn
    #>
    Write-Log "Bắt đầu gỡ cài đặt Vector EDR Agent..." "INFO"
    
    try {
        # Dừng và xóa service
        Remove-VectorService
        
        # Xóa Vector MSI package
        Write-Log "Đang gỡ cài đặt Vector package..." "INFO"
        $uninstallString = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                          Where-Object { $_.DisplayName -like "*Vector*" } | 
                          Select-Object -First 1 -ExpandProperty UninstallString
        
        if ($uninstallString) {
            & cmd.exe /c $uninstallString /quiet
            Write-Log "Vector package đã được gỡ cài đặt" "INFO"
        }
        
        # Xóa data directories
        $pathsToRemove = @($DataPath, $CertPath, (Split-Path $ConfigPath -Parent))
        foreach ($path in $pathsToRemove) {
            if (Test-Path $path) {
                Write-Log "Đang xóa thư mục: $path" "INFO"
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Log "Vector EDR Agent đã được gỡ cài đặt hoàn toàn" "INFO"
        
    } catch {
        Write-Log "Lỗi trong quá trình gỡ cài đặt: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-HostId {
    <#
    .SYNOPSIS
        Tạo Host ID unique cho endpoint
    #>
    if (-not [string]::IsNullOrEmpty($HostId)) {
        return $HostId
    }
    
    # Tạo UUID dựa trên system info để đảm bảo consistency
    $systemInfo = Get-SystemInfo
    $baseString = "$($systemInfo.ComputerName)-$($systemInfo.OSVersion)-$($systemInfo.Architecture)"
    
    # Tạo MD5 hash từ base string
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($baseString))
    $hashString = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
    
    # Format như UUID
    $uuid = $hashString.Substring(0,8) + "-" + $hashString.Substring(8,4) + "-" + $hashString.Substring(12,4) + "-" + $hashString.Substring(16,4) + "-" + $hashString.Substring(20,12)
    
    Write-Log "Generated Host ID: $uuid" "INFO"
    return $uuid
}

function Download-File {
    <#
    .SYNOPSIS
        Tải file từ URL với progress bar
    #>
    param(
        [string]$Url,
        [string]$OutFile
    )
    
    Write-Log "Đang tải file từ: $Url" "INFO"
    
    try {
        # Tạo thư mục nếu cần
        $outDir = Split-Path $OutFile -Parent
        if (-not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        }
        
        # Tải file với progress
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $OutFile)
        
        Write-Log "Đã tải file thành công: $OutFile" "INFO"
        return $true
        
    } catch {
        Write-Log "Lỗi khi tải file: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-VectorMSI {
    <#
    .SYNOPSIS
        Cài đặt Vector từ MSI package
    #>
    param([string]$MsiPath)
    
    Write-Log "Đang cài đặt Vector từ: $MsiPath" "INFO"
    
    try {
        # Cài đặt MSI với silent mode
        $installArgs = @(
            "/i", "`"$MsiPath`"",
            "/quiet", "/norestart",
            "INSTALLDIR=`"$InstallPath`""
        )
        
        Write-Log "Chạy lệnh: msiexec $($installArgs -join ' ')" "INFO"
        
        if (-not $DryRun) {
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
            
            if ($process.ExitCode -eq 0) {
                Write-Log "Vector đã được cài đặt thành công" "INFO"
                return $true
            } else {
                Write-Log "Cài đặt Vector thất bại với exit code: $($process.ExitCode)" "ERROR"
                return $false
            }
        } else {
            Write-Log "[DRY RUN] Sẽ cài đặt Vector MSI" "INFO"
            return $true
        }
        
    } catch {
        Write-Log "Lỗi khi cài đặt Vector: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function New-VectorConfiguration {
    <#
    .SYNOPSIS
        Tạo file cấu hình Vector cho endpoint
    #>
    Write-Log "Đang tạo cấu hình Vector..." "INFO"
    
    try {
        # Tạo thư mục config nếu cần
        $configDir = Split-Path $ConfigPath -Parent
        if (-not (Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }
        
        # Đọc template từ file hoặc URL
        $templatePath = Join-Path (Split-Path $PSScriptRoot -Parent) "vector-windows.toml"
        
        if (Test-Path $templatePath) {
            $configTemplate = Get-Content $templatePath -Raw
            Write-Log "Sử dụng template local: $templatePath" "INFO"
        } else {
            Write-Log "Template local không tìm thấy, sử dụng cấu hình embedded" "WARN"
            $configTemplate = Get-EmbeddedVectorConfig
        }
        
        # Thay thế các biến trong template
        $generatedHostId = New-HostId
        $configContent = $configTemplate -replace '\\$\\{EDR_HOST_ID\\}', $generatedHostId
        $configContent = $configContent -replace '\\$\\{KAFKA_BROKERS\\}', $KafkaBrokers
        $configContent = $configContent -replace '\\$\\{TLS_CA_FILE\\}', "$CertPath\ca.crt"
        $configContent = $configContent -replace '\\$\\{EDR_ENVIRONMENT\\}', $Environment
        $configContent = $configContent -replace '\\$\\{EDR_DATACENTER\\}', $DataCenter
        $configContent = $configContent -replace '\\$\\{HEALTHCHECK_ENDPOINT\\}', $HealthCheckEndpoint
        
        # Ghi file cấu hình
        if (-not $DryRun) {
            Set-Content -Path $ConfigPath -Value $configContent -Encoding UTF8
            Write-Log "Đã tạo file cấu hình: $ConfigPath" "INFO"
        } else {
            Write-Log "[DRY RUN] Sẽ tạo file cấu hình: $ConfigPath" "INFO"
        }
        
        return $generatedHostId
        
    } catch {
        Write-Log "Lỗi khi tạo cấu hình: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Install-Certificates {
    <#
    .SYNOPSIS
        Cài đặt TLS certificates
    #>
    Write-Log "Đang cài đặt TLS certificates..." "INFO"
    
    try {
        # Tạo thư mục certificates
        if (-not (Test-Path $CertPath)) {
            New-Item -ItemType Directory -Path $CertPath -Force | Out-Null
        }
        
        # Kiểm tra xem certificates đã có sẵn chưa
        $caCertPath = Join-Path $CertPath "ca.crt"
        
        if (Test-Path $caCertPath) {
            Write-Log "Certificate đã tồn tại: $caCertPath" "INFO"
            return $true
        }
        
        # Trong production, certificates sẽ được deploy bởi management system
        # Ở đây tạo self-signed cert cho development
        if ($Environment -eq "dev" -or $SkipCertificates) {
            Write-Log "Tạo self-signed certificate cho development" "WARN"
            $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"
            $certPath = "cert:\LocalMachine\My\$($cert.Thumbprint)"
            Export-Certificate -Cert $certPath -FilePath $caCertPath -Force | Out-Null
            Write-Log "Đã tạo self-signed certificate: $caCertPath" "INFO"
        } else {
            Write-Log "Production environment - certificates cần được cài đặt bởi PKI system" "ERROR"
            throw "Missing TLS certificates for production environment"
        }
        
        return $true
        
    } catch {
        Write-Log "Lỗi khi cài đặt certificates: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-EnvironmentVariables {
    <#
    .SYNOPSIS
        Đặt biến môi trường cho Vector service
    #>
    param([string]$GeneratedHostId)
    
    Write-Log "Đang cấu hình biến môi trường cho Vector service..." "INFO"
    
    try {
        # Đường dẫn registry cho Vector service
        $serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$SERVICE_NAME"
        
        if (Test-Path $serviceRegistryPath) {
            # Tạo mảng environment variables
            $envVars = @(
                "EDR_HOST_ID=$GeneratedHostId",
                "KAFKA_BROKERS=$KafkaBrokers",
                "TLS_CA_FILE=$CertPath\ca.crt",
                "EDR_ENVIRONMENT=$Environment",
                "EDR_DATACENTER=$DataCenter",
                "VECTOR_CONFIG=$ConfigPath",
                "VECTOR_LOG=info"
            )
            
            if (-not [string]::IsNullOrEmpty($HealthCheckEndpoint)) {
                $envVars += "HEALTHCHECK_ENDPOINT=$HealthCheckEndpoint"
            }
            
            if (-not $DryRun) {
                # Đặt environment variables cho service
                Set-ItemProperty -Path $serviceRegistryPath -Name "Environment" -Value $envVars
                Write-Log "Đã cấu hình biến môi trường cho Vector service" "INFO"
            } else {
                Write-Log "[DRY RUN] Sẽ cấu hình environment variables: $($envVars -join '; ')" "INFO"
            }
        } else {
            Write-Log "Không tìm thấy Vector service trong registry" "ERROR"
            return $false
        }
        
        return $true
        
    } catch {
        Write-Log "Lỗi khi cấu hình environment variables: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-VectorService {
    <#
    .SYNOPSIS
        Khởi động Vector service
    #>
    Write-Log "Đang khởi động Vector service..." "INFO"
    
    try {
        if (-not $DryRun) {
            # Khởi động service
            Start-Service -Name $SERVICE_NAME -ErrorAction Stop
            
            # Đợi service khởi động hoàn toàn
            Start-Sleep -Seconds 5
            
            # Kiểm tra trạng thái
            $service = Get-Service -Name $SERVICE_NAME
            if ($service.Status -eq "Running") {
                Write-Log "Vector service đã khởi động thành công" "INFO"
                return $true
            } else {
                Write-Log "Vector service không khởi động được - Status: $($service.Status)" "ERROR"
                return $false
            }
        } else {
            Write-Log "[DRY RUN] Sẽ khởi động Vector service" "INFO"
            return $true
        }
        
    } catch {
        Write-Log "Lỗi khi khởi động Vector service: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-VectorHealth {
    <#
    .SYNOPSIS
        Kiểm tra health của Vector agent
    #>
    Write-Log "Đang kiểm tra health của Vector agent..." "INFO"
    
    try {
        # Kiểm tra service status
        $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
        if (-not $service -or $service.Status -ne "Running") {
            Write-Log "Vector service không chạy" "ERROR"
            return $false
        }
        
        # Kiểm tra log files
        $logPath = "$DataPath\vector.log"
        if (Test-Path $logPath) {
            $recentLogs = Get-Content $logPath -Tail 10 | Where-Object { $_ -match "ERROR|FATAL" }
            if ($recentLogs) {
                Write-Log "Phát hiện lỗi trong Vector logs:" "WARN"
                $recentLogs | ForEach-Object { Write-Log $_ "WARN" }
            }
        }
        
        # Kiểm tra network connectivity đến Kafka
        if (-not [string]::IsNullOrEmpty($KafkaBrokers)) {
            $brokers = $KafkaBrokers -split ","
            foreach ($broker in $brokers) {
                $brokerParts = $broker.Trim() -split ":"
                $host = $brokerParts[0]
                $port = $brokerParts[1]
                
                $connection = Test-NetConnection -ComputerName $host -Port $port -InformationLevel Quiet
                if ($connection) {
                    Write-Log "Kết nối đến Kafka broker thành công: $broker" "INFO"
                } else {
                    Write-Log "Không thể kết nối đến Kafka broker: $broker" "WARN"
                }
            }
        }
        
        Write-Log "Health check hoàn tất" "INFO"
        return $true
        
    } catch {
        Write-Log "Lỗi trong health check: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-EmbeddedVectorConfig {
    <#
    .SYNOPSIS
        Trả về cấu hình Vector embedded (fallback khi không có template file)
    #>
    return @"
# Vector EDR Agent Configuration - Windows
# Generated by install script

data_dir = "$($DataPath -replace '\\', '\\\\')"

[sources.windows_security]
type = "winlog"
channel = "Security"

[sources.sysmon]
type = "winlog"
channel = "Microsoft-Windows-Sysmon/Operational"

[transforms.ecs_normalizer]
type = "remap"
inputs = ["windows_security", "sysmon"]
source = '''
.host.id = "`${EDR_HOST_ID}"
.host.name = get_hostname!()
.agent.type = "vector-edr"
.ecs.version = "8.6.0"
.@timestamp = .timestamp ?? now()
'''

[sinks.kafka]
type = "kafka"
inputs = ["ecs_normalizer"]
bootstrap_servers = "`${KAFKA_BROKERS}"
topic = "edr-events-normalized"
key_field = "host.id"

[sinks.kafka.tls]
enabled = true
ca_file = "`${TLS_CA_FILE}"
"@
}

# ====================================================================
# MAIN INSTALLATION LOGIC - LOGIC CHÍNH CỦA QUỸONG TRÌNH CÀI ĐẶT
# ====================================================================

function Main {
    <#
    .SYNOPSIS
        Hàm main thực hiện toàn bộ quá trình cài đặt
    #>
    
    try {
        Write-Log "=====================================" "INFO"
        Write-Log "Vector EDR Agent Installer v$SCRIPT_VERSION" "INFO"
        Write-Log "=====================================" "INFO"
        
        # Kiểm tra quyền Administrator
        if (-not (Test-Administrator)) {
            Write-Log "Script cần chạy với quyền Administrator. Vui lòng chạy PowerShell as Administrator." "ERROR"
            exit 1
        }
        
        # Xử lý uninstall
        if ($Uninstall) {
            Uninstall-Vector
            Write-Log "Gỡ cài đặt hoàn tất!" "INFO"
            return
        }
        
        # Validate parameters
        if ([string]::IsNullOrEmpty($KafkaBrokers)) {
            Write-Log "Tham số -KafkaBrokers là bắt buộc (VD: 'kafka1:9093,kafka2:9093')" "ERROR"
            exit 1
        }
        
        # Thu thập thông tin hệ thống
        $systemInfo = Get-SystemInfo
        Write-Log "Thông tin hệ thống:" "INFO"
        Write-Log "  OS: $($systemInfo.OSName) $($systemInfo.OSVersion)" "INFO"
        Write-Log "  Architecture: $($systemInfo.Architecture)" "INFO"
        Write-Log "  Computer: $($systemInfo.ComputerName)" "INFO"
        Write-Log "  Memory: $($systemInfo.TotalMemory) GB" "INFO"
        
        # Kiểm tra kết nối internet
        if (-not (Test-InternetConnection)) {
            Write-Log "Không có kết nối internet. Cài đặt có thể thất bại." "WARN"
        }
        
        # BƯỚC 1: Dừng Vector service cũ (nếu có)
        Stop-VectorService
        
        # BƯỚC 2: Tải Vector MSI
        $vectorMsiUrl = $VECTOR_DOWNLOAD_URL_TEMPLATE -f $VectorVersion
        $vectorMsiPath = "$env:TEMP\vector-$VectorVersion.msi"
        
        if (-not (Test-Path $vectorMsiPath)) {
            Write-Log "Đang tải Vector $VectorVersion..." "INFO"
            if (-not (Download-File -Url $vectorMsiUrl -OutFile $vectorMsiPath)) {
                Write-Log "Không thể tải Vector MSI. Kiểm tra kết nối internet và phiên bản." "ERROR"
                exit 1
            }
        } else {
            Write-Log "Vector MSI đã tồn tại: $vectorMsiPath" "INFO"
        }
        
        # BƯỚC 3: Cài đặt Vector
        if (-not (Install-VectorMSI -MsiPath $vectorMsiPath)) {
            Write-Log "Cài đặt Vector thất bại" "ERROR"
            exit 1
        }
        
        # BƯỚC 4: Tạo thư mục dữ liệu
        $dirsToCreate = @($DataPath, $CertPath, (Split-Path $ConfigPath -Parent))
        foreach ($dir in $dirsToCreate) {
            if (-not (Test-Path $dir)) {
                Write-Log "Tạo thư mục: $dir" "INFO"
                if (-not $DryRun) {
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                }
            }
        }
        
        # BƯỚC 5: Cài đặt certificates
        if (-not (Install-Certificates)) {
            Write-Log "Cài đặt certificates thất bại" "ERROR"
            exit 1
        }
        
        # BƯỚC 6: Tạo cấu hình Vector
        $generatedHostId = New-VectorConfiguration
        
        # BƯỚC 7: Cấu hình environment variables cho service
        if (-not (Set-EnvironmentVariables -GeneratedHostId $generatedHostId)) {
            Write-Log "Cấu hình environment variables thất bại" "ERROR"
            exit 1
        }
        
        # BƯỚC 8: Khởi động Vector service
        if (-not (Start-VectorService)) {
            Write-Log "Khởi động Vector service thất bại" "ERROR"
            exit 1
        }
        
        # BƯỚC 9: Health check
        Start-Sleep -Seconds 10  # Đợi service ổn định
        Test-VectorHealth
        
        # BƯỚC 10: Cleanup
        if (Test-Path $vectorMsiPath) {
            Remove-Item $vectorMsiPath -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "=====================================" "INFO"
        Write-Log "CÀI ĐẶT HOÀN TẤT THÀNH CÔNG!" "INFO"
        Write-Log "=====================================" "INFO"
        Write-Log "Host ID: $generatedHostId" "INFO"
        Write-Log "Config: $ConfigPath" "INFO"
        Write-Log "Data: $DataPath" "INFO"
        Write-Log "Certificates: $CertPath" "INFO"
        Write-Log "Service: $SERVICE_NAME (Running)" "INFO"
        Write-Log "=====================================" "INFO"
        
    } catch {
        Write-Log "Cài đặt thất bại: $($_.Exception.Message)" "ERROR"
        Write-Log "Chi tiết lỗi: $($_.Exception.StackTrace)" "ERROR"
        exit 1
    }
}

# ====================================================================
# SCRIPT EXECUTION - THỰC THI SCRIPT
# ====================================================================

# Chạy main function
Main

# ====================================================================
# END OF SCRIPT
# ====================================================================
# 
# Ghi chú:
# 1. Script này cần chạy với quyền Administrator
# 2. Trong production, certificates nên được quản lý bởi PKI system
# 3. Có thể customize để integrate với configuration management tools
# 4. Monitor logs tại: C:\Windows\Temp\vector-edr-install.log
# 
# Ví dụ sử dụng:
# 
# Development:
# .\install-agent.ps1 -KafkaBrokers "localhost:9093" -Environment "dev" -SkipCertificates
# 
# Production:
# .\install-agent.ps1 -KafkaBrokers "kafka1.prod:9093,kafka2.prod:9093" -Environment "production" -DataCenter "dc1"
# 
# Uninstall:
# .\install-agent.ps1 -Uninstall
#
# Author: Senior Software Engineer - EDR Platform Team
# Contact: edr-team@company.com
# Support: https://company.wiki/edr-platform/windows-installer
# ====================================================================
