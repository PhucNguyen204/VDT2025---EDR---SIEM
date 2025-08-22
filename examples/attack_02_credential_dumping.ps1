# Credential Dumping Attack Simulation
# Mô phỏng các cuộc tấn công nhằm đánh cắp thông tin xác thực từ endpoint

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

Write-Host "=== CREDENTIAL DUMPING ATTACK SIMULATION ===" -ForegroundColor Yellow
Write-Host "Target: Windows Endpoint - Stealing credentials from memory and registry" -ForegroundColor White

$totalAlerts = 0

# ATTACK 1: Mimikatz Execution
# Mô tả: Sử dụng Mimikatz để dump password từ memory
# Kỹ thuật: T1003.001 - OS Credential Dumping: LSASS Memory
Write-Host "`n[ATTACK 1] Mimikatz Credential Dumping" -ForegroundColor Cyan
Write-Host "- Mô tả: Sử dụng Mimikatz để dump credentials từ LSASS memory" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Rất cao - Có thể lấy plaintext passwords của tất cả users" -ForegroundColor Gray
Write-Host "- Phát hiện: Dựa trên tên file 'mimikatz.exe' và command line arguments" -ForegroundColor Gray

$event1 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "mimikatz-dump-1"
    "logsource" = @{
        "category" = "process_creation"  # Log process creation
        "product" = "windows"
    }
    "EventID" = 1                       # Sysmon Event ID 1
    "Image" = "C:\Temp\mimikatz.exe"    # Đường dẫn tool Mimikatz
    # Command line chứa các lệnh Mimikatz đặc trưng
    "CommandLine" = "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"
    "ProcessId" = 4567
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\admin"   # Cần quyền admin để dump LSASS
    "LogonId" = "0x12348"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "High"           # Cần High integrity
    "Hashes" = "SHA1=B1C2D3E4F5A6"     # Hash của Mimikatz
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Temp\"
    "OriginalFileName" = "mimikatz.exe"
    "FileVersion" = "2.2.0.20210810"   # Version của Mimikatz
}
$totalAlerts += Send-Event -Event $event1
Start-Sleep $DelaySeconds

# ATTACK 2: LSASS Memory Access
# Mô tả: Truy cập trực tiếp vào LSASS process để đọc memory
# Kỹ thuật: T1003.001 - OS Credential Dumping: LSASS Memory
Write-Host "`n[ATTACK 2] Direct LSASS Memory Access" -ForegroundColor Cyan
Write-Host "- Mô tả: Truy cập trực tiếp vào LSASS process memory" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Rất cao - Có thể bypass một số detection tools" -ForegroundColor Gray
Write-Host "- Phát hiện: Sysmon Event ID 10 - ProcessAccess với GrantedAccess đặc biệt" -ForegroundColor Gray

$event2 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "lsass-access-1"
    "logsource" = @{
        "category" = "process_access"   # Log process access (Sysmon Event ID 10)
        "product" = "windows"
    }
    "EventID" = 10                     # Sysmon Event ID 10: ProcessAccess
    "SourceImage" = "C:\Temp\procdump.exe"  # Tool thực hiện dump
    "TargetImage" = "C:\Windows\System32\lsass.exe"  # Target: LSASS process
    # GrantedAccess 0x1410 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    "GrantedAccess" = "0x1410"         # Quyền truy cập memory
    "CallTrace" = "C:\Windows\SYSTEM32\ntdll.dll+a0344"  # Call stack
    "SourceProcessId" = 5678
    "SourceThreadId" = 9012
    "TargetProcessId" = 678            # PID của LSASS
    "User" = "DESKTOP-ENDPOINT\admin"
    "LogonId" = "0x12349"
}
$totalAlerts += Send-Event -Event $event2
Start-Sleep $DelaySeconds

# ATTACK 3: SAM Registry Access
# Mô tả: Truy cập SAM registry để lấy password hashes
# Kỹ thuật: T1003.002 - OS Credential Dumping: Security Account Manager
Write-Host "`n[ATTACK 3] SAM Registry Credential Dumping" -ForegroundColor Cyan
Write-Host "- Mô tả: Truy cập SAM registry để lấy password hashes" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1003.002 - OS Credential Dumping: Security Account Manager" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - Có thể crack offline để lấy plaintext passwords" -ForegroundColor Gray
Write-Host "- Phát hiện: Sysmon Event ID 12/13 - Registry access vào SAM hive" -ForegroundColor Gray

$event3 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "sam-registry-access-1"
    "logsource" = @{
        "category" = "registry_access"  # Log registry access
        "product" = "windows"
    }
    "EventID" = 12                     # Sysmon Event ID 12: RegistryEvent (Object create/delete)
    "Image" = "C:\Temp\reg.exe"        # Registry tool
    # SAM registry path chứa user account info
    "TargetObject" = "HKLM\SAM\SAM\Domains\Account\Users"
    "EventType" = "QueryValue"         # Loại truy cập registry
    "ProcessId" = 6789
    "User" = "DESKTOP-ENDPOINT\admin"  # Cần admin để access SAM
    "LogonId" = "0x12350"
}
$totalAlerts += Send-Event -Event $event3
Start-Sleep $DelaySeconds

# ATTACK 4: DCSync Attack (Advanced)
# Mô tả: Sử dụng DCSync để lấy credentials từ Domain Controller
# Kỹ thuật: T1003.006 - OS Credential Dumping: DCSync
Write-Host "`n[ATTACK 4] DCSync Attack" -ForegroundColor Cyan
Write-Host "- Mô tả: Sử dụng DCSync technique để lấy credentials từ AD" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1003.006 - OS Credential Dumping: DCSync" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cực cao - Có thể lấy credentials của bất kỳ user nào trong domain" -ForegroundColor Gray
Write-Host "- Phát hiện: Mimikatz với lsadump::dcsync command" -ForegroundColor Gray

$event4 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "dcsync-attack-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Temp\mimikatz.exe"
    # DCSync command để replicate domain data
    "CommandLine" = "mimikatz.exe `"lsadump::dcsync /domain:company.local /user:Administrator`" exit"
    "ProcessId" = 7890
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "COMPANY\compromised_user"  # User có replication rights
    "LogonId" = "0x12351"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "High"
    "Hashes" = "SHA1=B1C2D3E4F5A6"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Temp\"
    "OriginalFileName" = "mimikatz.exe"
    "FileVersion" = "2.2.0.20210810"
}
$totalAlerts += Send-Event -Event $event4
Start-Sleep $DelaySeconds

# Summary
Write-Host "`n=== CREDENTIAL DUMPING ATTACK SUMMARY ===" -ForegroundColor Yellow
Write-Host "Events sent: 4" -ForegroundColor White
Write-Host "Alerts generated: $totalAlerts" -ForegroundColor $(if ($totalAlerts -gt 0) { "Green" } else { "Red" })
Write-Host "Detection rate: $(($totalAlerts / 4 * 100).ToString('F1'))%" -ForegroundColor $(if ($totalAlerts -gt 2) { "Green" } else { "Red" })

Write-Host "`n[GIẢI THÍCH KỸ THUẬT CHI TIẾT]" -ForegroundColor Magenta
Write-Host "1. MIMIKATZ DETECTION:" -ForegroundColor White
Write-Host "   - Sigma rules detect 'mimikatz.exe' filename" -ForegroundColor Gray
Write-Host "   - Command line patterns: 'sekurlsa::logonpasswords', 'privilege::debug'" -ForegroundColor Gray
Write-Host "   - Requires High/System integrity level" -ForegroundColor Gray

Write-Host "2. LSASS ACCESS DETECTION:" -ForegroundColor White
Write-Host "   - Sysmon Event ID 10 (ProcessAccess)" -ForegroundColor Gray
Write-Host "   - GrantedAccess 0x1410 = suspicious memory read permissions" -ForegroundColor Gray
Write-Host "   - TargetImage = lsass.exe (Local Security Authority Subsystem)" -ForegroundColor Gray

Write-Host "3. SAM REGISTRY DETECTION:" -ForegroundColor White
Write-Host "   - Sysmon Event ID 12/13 (Registry events)" -ForegroundColor Gray
Write-Host "   - TargetObject contains SAM registry paths" -ForegroundColor Gray
Write-Host "   - SAM = Security Account Manager (stores password hashes)" -ForegroundColor Gray

Write-Host "4. DCSYNC DETECTION:" -ForegroundColor White
Write-Host "   - Command line contains 'lsadump::dcsync'" -ForegroundColor Gray
Write-Host "   - Mimics Domain Controller replication to steal credentials" -ForegroundColor Gray
Write-Host "   - Requires specific AD permissions (Replicating Directory Changes)" -ForegroundColor Gray
