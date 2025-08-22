# Persistence Attack Simulation
# Mô phỏng các cuộc tấn công nhằm duy trì sự hiện diện lâu dài trên endpoint

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

Write-Host "=== PERSISTENCE ATTACK SIMULATION ===" -ForegroundColor Yellow
Write-Host "Target: Establishing long-term access to compromised endpoint" -ForegroundColor White

$totalAlerts = 0

# ATTACK 1: Registry Run Key Persistence
# Mô tả: Thêm malware vào Registry Run key để tự động khởi động
# Kỹ thuật: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
Write-Host "`n[ATTACK 1] Registry Run Key Persistence" -ForegroundColor Cyan
Write-Host "- Mô tả: Thêm malware vào Registry Run key để auto-start khi user login" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - Malware sẽ chạy mỗi khi user đăng nhập" -ForegroundColor Gray
Write-Host "- Phát hiện: Sysmon Event ID 13 - Registry value set vào Run keys" -ForegroundColor Gray

$event1 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "registry-persistence-1"
    "logsource" = @{
        "category" = "registry_set"     # Sysmon Event ID 13
        "product" = "windows"
    }
    "EventID" = 13                     # Registry value set
    "Image" = "C:\Windows\System32\reg.exe"  # Registry editor tool
    # HKLM Run key = chạy cho tất cả users, HKCU = chỉ current user
    "TargetObject" = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityUpdate"
    "Details" = "C:\Temp\backdoor.exe"  # Path to malware executable
    "EventType" = "SetValue"           # Registry operation type
    "ProcessId" = 1357
    "User" = "DESKTOP-ENDPOINT\admin"  # Cần admin để write vào HKLM
    "LogonId" = "0x12352"
}
$totalAlerts += Send-Event -Event $event1
Start-Sleep $DelaySeconds

# ATTACK 2: Scheduled Task Persistence
# Mô tả: Tạo scheduled task để chạy malware theo lịch trình
# Kỹ thuật: T1053.005 - Scheduled Task/Job: Scheduled Task
Write-Host "`n[ATTACK 2] Scheduled Task Persistence" -ForegroundColor Cyan
Write-Host "- Mô tả: Tạo Windows scheduled task để execute malware định kỳ" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1053.005 - Scheduled Task/Job: Scheduled Task" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - Task có thể chạy với SYSTEM privileges và theo schedule" -ForegroundColor Gray
Write-Host "- Phát hiện: schtasks.exe với /create parameter và suspicious task name" -ForegroundColor Gray

$event2 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "schtask-persistence-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\schtasks.exe"  # Task Scheduler utility
    # /create = tạo task mới, /tn = task name, /tr = task run (executable), /sc = schedule
    "CommandLine" = "schtasks.exe /create /tn `"Microsoft Windows Security Update`" /tr `"C:\Temp\backdoor.exe`" /sc onlogon /ru SYSTEM"
    "ProcessId" = 2468
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\admin"  # Cần admin để create system tasks
    "LogonId" = "0x12353"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "High"
    "Hashes" = "SHA1=F1A2B3C4D5E6"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\admin\"
    "OriginalFileName" = "schtasks.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event2
Start-Sleep $DelaySeconds

# ATTACK 3: Windows Service Persistence
# Mô tả: Tạo Windows service để chạy malware như system service
# Kỹ thuật: T1543.003 - Create or Modify System Process: Windows Service
Write-Host "`n[ATTACK 3] Windows Service Persistence" -ForegroundColor Cyan
Write-Host "- Mô tả: Tạo Windows service để run malware với SYSTEM privileges" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1543.003 - Create or Modify System Process: Windows Service" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Rất cao - Service chạy với SYSTEM privileges và auto-start" -ForegroundColor Gray
Write-Host "- Phát hiện: sc.exe với create command và suspicious service characteristics" -ForegroundColor Gray

$event3 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "service-persistence-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\sc.exe"  # Service Control utility
    # create = tạo service, binpath = executable path, start = auto (tự động khởi động)
    "CommandLine" = "sc.exe create `"Windows Security Service`" binpath= `"C:\Temp\service_backdoor.exe`" start= auto"
    "ProcessId" = 3579
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\admin"  # Cần admin để create services
    "LogonId" = "0x12354"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "High"
    "Hashes" = "SHA1=A2B3C4D5E6F1"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\admin\"
    "OriginalFileName" = "sc.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event3
Start-Sleep $DelaySeconds

# ATTACK 4: WMI Event Subscription Persistence
# Mô tả: Sử dụng WMI event subscription để trigger malware
# Kỹ thuật: T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription
Write-Host "`n[ATTACK 4] WMI Event Subscription Persistence" -ForegroundColor Cyan
Write-Host "- Mô tả: Tạo WMI event subscription để trigger malware execution" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1546.003 - Event Triggered Execution: WMI Event Subscription" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Rất cao - Khó phát hiện, có thể trigger based on system events" -ForegroundColor Gray
Write-Host "- Phát hiện: wmic.exe với event subscription commands" -ForegroundColor Gray

$event4 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "wmi-persistence-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\wbem\wmic.exe"  # WMI command-line utility
    # Tạo WMI event subscription để execute command khi có user logon
    "CommandLine" = "wmic.exe /NAMESPACE:`"\\root\subscription`" PATH __EventFilter CREATE Name=`"BotFilter82`", EventNameSpace=`"root\cimv2`", QueryLanguage=`"WQL`", Query=`"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325`""
    "ProcessId" = 4680
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\admin"  # Cần admin để create WMI subscriptions
    "LogonId" = "0x12355"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "High"
    "Hashes" = "SHA1=B2C3D4E5F6A1"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\admin\"
    "OriginalFileName" = "wmic.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event4
Start-Sleep $DelaySeconds

# ATTACK 5: Startup Folder Persistence
# Mô tả: Copy malware vào Startup folder
# Kỹ thuật: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
Write-Host "`n[ATTACK 5] Startup Folder Persistence" -ForegroundColor Cyan
Write-Host "- Mô tả: Copy malware vào Windows Startup folder" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1547.001 - Boot or Logon Autostart Execution: Startup Folder" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Trung bình - Dễ phát hiện nhưng effective" -ForegroundColor Gray
Write-Host "- Phát hiện: File creation trong Startup directories" -ForegroundColor Gray

$event5 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "startup-persistence-1"
    "logsource" = @{
        "category" = "file_create"     # File creation event
        "product" = "windows"
    }
    "EventID" = 11                    # Sysmon Event ID 11: FileCreate
    "Image" = "C:\Windows\System32\cmd.exe"
    # Copy command để copy malware vào startup folder
    "CommandLine" = "cmd.exe /c copy C:\Temp\backdoor.exe `"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\WindowsUpdate.exe`""
    # Target file trong startup folder
    "TargetFilename" = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\WindowsUpdate.exe"
    "ProcessId" = 5791
    "User" = "DESKTOP-ENDPOINT\admin"
    "LogonId" = "0x12356"
    "CreationUtcTime" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
}
$totalAlerts += Send-Event -Event $event5
Start-Sleep $DelaySeconds

# Summary
Write-Host "`n=== PERSISTENCE ATTACK SUMMARY ===" -ForegroundColor Yellow
Write-Host "Events sent: 5" -ForegroundColor White
Write-Host "Alerts generated: $totalAlerts" -ForegroundColor $(if ($totalAlerts -gt 0) { "Green" } else { "Red" })
Write-Host "Detection rate: $(($totalAlerts / 5 * 100).ToString('F1'))%" -ForegroundColor $(if ($totalAlerts -gt 2) { "Green" } else { "Red" })

Write-Host "`n[GIẢI THÍCH KỸ THUẬT CHI TIẾT]" -ForegroundColor Magenta
Write-Host "1. REGISTRY RUN KEY DETECTION:" -ForegroundColor White
Write-Host "   - Sysmon Event ID 13 (RegistryEvent - Value Set)" -ForegroundColor Gray
Write-Host "   - TargetObject chứa Run registry paths" -ForegroundColor Gray
Write-Host "   - HKLM\...\Run = system-wide autostart" -ForegroundColor Gray
Write-Host "   - HKCU\...\Run = user-specific autostart" -ForegroundColor Gray
Write-Host "   - Details field chứa path to executable" -ForegroundColor Gray

Write-Host "2. SCHEDULED TASK DETECTION:" -ForegroundColor White
Write-Host "   - schtasks.exe với /create parameter" -ForegroundColor Gray
Write-Host "   - Task name thường mimic legitimate Windows tasks" -ForegroundColor Gray
Write-Host "   - /sc onlogon = trigger khi user login" -ForegroundColor Gray
Write-Host "   - /ru SYSTEM = run với highest privileges" -ForegroundColor Gray

Write-Host "3. WINDOWS SERVICE DETECTION:" -ForegroundColor White
Write-Host "   - sc.exe với create command" -ForegroundColor Gray
Write-Host "   - binpath pointing to suspicious locations (C:\Temp\)" -ForegroundColor Gray
Write-Host "   - start=auto = service tự động khởi động với Windows" -ForegroundColor Gray
Write-Host "   - Service name thường mimic legitimate services" -ForegroundColor Gray

Write-Host "4. WMI SUBSCRIPTION DETECTION:" -ForegroundColor White
Write-Host "   - wmic.exe với /NAMESPACE:\\root\subscription" -ForegroundColor Gray
Write-Host "   - __EventFilter CREATE = tạo event filter mới" -ForegroundColor Gray
Write-Host "   - WQL query định nghĩa trigger conditions" -ForegroundColor Gray
Write-Host "   - Rất khó detect vì WMI là legitimate Windows feature" -ForegroundColor Gray

Write-Host "5. STARTUP FOLDER DETECTION:" -ForegroundColor White
Write-Host "   - Sysmon Event ID 11 (FileCreate)" -ForegroundColor Gray
Write-Host "   - TargetFilename trong Startup directories:" -ForegroundColor Gray
Write-Host "     * C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\" -ForegroundColor Gray
Write-Host "     * C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" -ForegroundColor Gray

Write-Host "`n[PERSISTENCE LOCATIONS PRIORITY]" -ForegroundColor Magenta
Write-Host "1. WMI Event Subscription (Hardest to detect)" -ForegroundColor Red
Write-Host "2. Windows Services (High privileges)" -ForegroundColor Red  
Write-Host "3. Scheduled Tasks (Flexible timing)" -ForegroundColor Yellow
Write-Host "4. Registry Run Keys (Common but detectable)" -ForegroundColor Yellow
Write-Host "5. Startup Folder (Easiest to detect)" -ForegroundColor Green
