# Lateral Movement Attack Simulation
# Mô phỏng các cuộc tấn công di chuyển ngang trong mạng từ endpoint đã bị compromise

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

Write-Host "=== LATERAL MOVEMENT ATTACK SIMULATION ===" -ForegroundColor Yellow
Write-Host "Target: Network propagation from compromised endpoint to other systems" -ForegroundColor White

$totalAlerts = 0

# ATTACK 1: PsExec Lateral Movement
# Mô tả: Sử dụng PsExec để thực thi code trên remote machine
# Kỹ thuật: T1570 - Lateral Tool Transfer + T1021.002 - Remote Services: SMB/Windows Admin Shares
Write-Host "`n[ATTACK 1] PsExec Lateral Movement" -ForegroundColor Cyan
Write-Host "- Mô tả: Sử dụng PsExec để thực thi commands trên remote endpoint" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1021.002 - Remote Services: SMB/Windows Admin Shares" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - Cho phép thực thi code với SYSTEM privileges trên remote machine" -ForegroundColor Gray
Write-Host "- Phát hiện: PSEXESVC.exe process creation với parent = services.exe" -ForegroundColor Gray

$event1 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "psexec-lateral-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    # PSEXESVC.exe là service được PsExec tạo trên remote machine
    "Image" = "C:\Windows\PSEXESVC.exe"
    "CommandLine" = "C:\Windows\PSEXESVC.exe"
    "ProcessId" = 7890
    # Parent process là services.exe (Windows Service Control Manager)
    "ParentImage" = "C:\Windows\System32\services.exe"
    "User" = "NT AUTHORITY\SYSTEM"     # PsExec chạy với SYSTEM privileges
    "LogonId" = "0x3e7"                # SYSTEM logon session
    "TerminalSessionId" = 0            # Service session
    "IntegrityLevel" = "System"        # Highest privilege level
    "Hashes" = "SHA1=C1D2E3F4A5B6"
    "ParentProcessId" = 123            # services.exe PID
    "ParentCommandLine" = "C:\Windows\system32\services.exe"
    "CurrentDirectory" = "C:\Windows\system32\"
    "OriginalFileName" = "psexesvc.exe"  # PsExec service executable
    "FileVersion" = "2.2.0.0"
}
$totalAlerts += Send-Event -Event $event1
Start-Sleep $DelaySeconds

# ATTACK 2: WMI Lateral Movement
# Mô tả: Sử dụng WMI (Windows Management Instrumentation) để thực thi remote commands
# Kỹ thuật: T1047 - Windows Management Instrumentation
Write-Host "`n[ATTACK 2] WMI-based Lateral Movement" -ForegroundColor Cyan
Write-Host "- Mô tả: Sử dụng WMI để thực thi commands trên remote systems" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1047 - Windows Management Instrumentation" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - WMI là legitimate Windows feature, khó detect" -ForegroundColor Gray
Write-Host "- Phát hiện: WmiPrvSE.exe spawning unusual child processes" -ForegroundColor Gray

$event2 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "wmi-lateral-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    # WmiPrvSE.exe = WMI Provider Host
    "Image" = "C:\Windows\System32\wbem\WmiPrvSE.exe"
    "CommandLine" = "C:\Windows\system32\wbem\wmiprvse.exe -Embedding"
    "ProcessId" = 8901
    # Parent process là svchost.exe hosting WMI service
    "ParentImage" = "C:\Windows\System32\svchost.exe"
    "User" = "NT AUTHORITY\NETWORK SERVICE"  # WMI service account
    "LogonId" = "0x3e4"                # Network Service logon session
    "TerminalSessionId" = 0
    "IntegrityLevel" = "System"
    "Hashes" = "SHA1=D1E2F3A4B5C6"
    "ParentProcessId" = 234            # svchost.exe PID
    "ParentCommandLine" = "C:\Windows\system32\svchost.exe -k netsvcs"
    "CurrentDirectory" = "C:\Windows\system32\"
    "OriginalFileName" = "WmiPrvSE.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event2
Start-Sleep $DelaySeconds

# ATTACK 3: Remote Service Creation
# Mô tả: Tạo service trên remote machine để thực thi payload
# Kỹ thuật: T1543.003 - Create or Modify System Process: Windows Service
Write-Host "`n[ATTACK 3] Remote Service Creation" -ForegroundColor Cyan
Write-Host "- Mô tả: Tạo Windows service trên remote machine để execute payload" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1543.003 - Create or Modify System Process: Windows Service" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - Service có thể chạy với SYSTEM privileges và persist" -ForegroundColor Gray
Write-Host "- Phát hiện: sc.exe với remote UNC path và suspicious service name" -ForegroundColor Gray

$event3 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "remote-service-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\sc.exe"  # Service Control utility
    # sc.exe command để tạo service trên remote machine (\\192.168.1.100)
    "CommandLine" = "sc.exe \\192.168.1.100 create malicious_service binpath= `"C:\Temp\backdoor.exe`""
    "ProcessId" = 9012
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\admin"   # Cần admin rights để tạo remote service
    "LogonId" = "0x12351"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "High"           # Cần High integrity
    "Hashes" = "SHA1=E1F2A3B4C5D6"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\admin\"
    "OriginalFileName" = "sc.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event3
Start-Sleep $DelaySeconds

# ATTACK 4: Remote Registry Manipulation
# Mô tả: Truy cập remote registry để modify startup programs
# Kỹ thuật: T1112 - Modify Registry + T1021.002 - Remote Services: SMB/Windows Admin Shares
Write-Host "`n[ATTACK 4] Remote Registry Manipulation" -ForegroundColor Cyan
Write-Host "- Mô tả: Truy cập remote registry để modify autostart entries" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1112 - Modify Registry" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Trung bình - Có thể establish persistence trên remote machine" -ForegroundColor Gray
Write-Host "- Phát hiện: reg.exe với remote registry paths" -ForegroundColor Gray

$event4 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "remote-registry-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\reg.exe"
    # reg.exe command để add registry entry trên remote machine
    "CommandLine" = "reg.exe add `"\\192.168.1.100\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`" /v backdoor /d `"C:\Temp\payload.exe`" /f"
    "ProcessId" = 1357
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\admin"
    "LogonId" = "0x12352"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "High"
    "Hashes" = "SHA1=F1A2B3C4D5E6"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\admin\"
    "OriginalFileName" = "reg.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event4
Start-Sleep $DelaySeconds

# Summary
Write-Host "`n=== LATERAL MOVEMENT ATTACK SUMMARY ===" -ForegroundColor Yellow
Write-Host "Events sent: 4" -ForegroundColor White
Write-Host "Alerts generated: $totalAlerts" -ForegroundColor $(if ($totalAlerts -gt 0) { "Green" } else { "Red" })
Write-Host "Detection rate: $(($totalAlerts / 4 * 100).ToString('F1'))%" -ForegroundColor $(if ($totalAlerts -gt 2) { "Green" } else { "Red" })

Write-Host "`n[GIẢI THÍCH KỸ THUẬT CHI TIẾT]" -ForegroundColor Magenta
Write-Host "1. PSEXEC DETECTION:" -ForegroundColor White
Write-Host "   - Sigma rules detect 'PSEXESVC.exe' filename" -ForegroundColor Gray
Write-Host "   - Parent process = services.exe (unusual for normal programs)" -ForegroundColor Gray
Write-Host "   - User = NT AUTHORITY\SYSTEM (high privilege execution)" -ForegroundColor Gray
Write-Host "   - IntegrityLevel = System (highest Windows privilege level)" -ForegroundColor Gray

Write-Host "2. WMI DETECTION:" -ForegroundColor White
Write-Host "   - WmiPrvSE.exe spawning from svchost.exe" -ForegroundColor Gray
Write-Host "   - Command line contains '-Embedding' parameter" -ForegroundColor Gray
Write-Host "   - User = NETWORK SERVICE (WMI service context)" -ForegroundColor Gray
Write-Host "   - Suspicious when spawning unusual child processes" -ForegroundColor Gray

Write-Host "3. REMOTE SERVICE DETECTION:" -ForegroundColor White
Write-Host "   - sc.exe with UNC path (\\remote_machine)" -ForegroundColor Gray
Write-Host "   - Command contains 'create' + suspicious service name" -ForegroundColor Gray
Write-Host "   - binpath points to suspicious executable location" -ForegroundColor Gray

Write-Host "4. REMOTE REGISTRY DETECTION:" -ForegroundColor White
Write-Host "   - reg.exe with remote registry path (\\machine\HKLM)" -ForegroundColor Gray
Write-Host "   - Targeting Run keys for persistence" -ForegroundColor Gray
Write-Host "   - /f flag = force overwrite (suspicious behavior)" -ForegroundColor Gray

Write-Host "`n[NETWORK INDICATORS]" -ForegroundColor Magenta
Write-Host "- SMB traffic to ports 445/139 on remote machines" -ForegroundColor White
Write-Host "- RPC traffic for WMI communication" -ForegroundColor White
Write-Host "- Authentication events on remote systems" -ForegroundColor White
Write-Host "- Service installation events on target machines" -ForegroundColor White
