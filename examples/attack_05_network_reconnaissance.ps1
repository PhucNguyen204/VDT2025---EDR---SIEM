# Network Reconnaissance Attack Simulation
# Mô phỏng các cuộc tấn công trinh sát mạng từ endpoint đã bị compromise

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

Write-Host "=== NETWORK RECONNAISSANCE ATTACK SIMULATION ===" -ForegroundColor Yellow
Write-Host "Target: Network discovery and enumeration from compromised endpoint" -ForegroundColor White

$totalAlerts = 0

# ATTACK 1: Port Scanning with Nmap
# Mô tả: Sử dụng Nmap để scan network và tìm các services
# Kỹ thuật: T1046 - Network Service Scanning
Write-Host "`n[ATTACK 1] Network Port Scanning" -ForegroundColor Cyan
Write-Host "- Mô tả: Sử dụng Nmap để scan ports trên network range" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1046 - Network Service Scanning" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Trung bình - Reveal network topology và running services" -ForegroundColor Gray
Write-Host "- Phát hiện: nmap.exe execution với network scanning parameters" -ForegroundColor Gray

$event1 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "nmap-scan-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Tools\nmap.exe"        # Nmap network scanner
    # -sS = SYN scan, -O = OS detection, /24 = scan entire subnet
    "CommandLine" = "nmap.exe -sS -O -p 1-1000 192.168.1.0/24"
    "ProcessId" = 4680
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\user"    # Thường không cần admin cho basic scanning
    "LogonId" = "0x12355"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "Medium"
    "Hashes" = "SHA1=B2C3D4E5F6A1"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Tools\"
    "OriginalFileName" = "nmap.exe"
    "FileVersion" = "7.80.0.0"
}
$totalAlerts += Send-Event -Event $event1
Start-Sleep $DelaySeconds

# ATTACK 2: Domain Enumeration with Net Commands
# Mô tả: Sử dụng built-in Windows commands để enumerate domain
# Kỹ thuật: T1018 - Remote System Discovery
Write-Host "`n[ATTACK 2] Domain and Network Enumeration" -ForegroundColor Cyan
Write-Host "- Mô tả: Sử dụng 'net' commands để enumerate domain resources" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1018 - Remote System Discovery" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Trung bình - Reveal domain structure và available shares" -ForegroundColor Gray
Write-Host "- Phát hiện: net.exe với domain enumeration parameters" -ForegroundColor Gray

$event2 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "net-enum-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\net.exe"  # Windows NET command
    # net view /domain = list all domains, net view = list computers in domain
    "CommandLine" = "net.exe view /domain"
    "ProcessId" = 5791
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\user"
    "LogonId" = "0x12356"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "Medium"
    "Hashes" = "SHA1=C2D3E4F5A6B1"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\user\"
    "OriginalFileName" = "net.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event2
Start-Sleep $DelaySeconds

# ATTACK 3: DNS Enumeration and Domain Controller Discovery
# Mô tả: Sử dụng nslookup để tìm Domain Controllers và services
# Kỹ thuật: T1087.002 - Account Discovery: Domain Account
Write-Host "`n[ATTACK 3] DNS Enumeration for Domain Controllers" -ForegroundColor Cyan
Write-Host "- Mô tả: Sử dụng DNS queries để discover Domain Controllers" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1087.002 - Account Discovery: Domain Account" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - Identify critical infrastructure (Domain Controllers)" -ForegroundColor Gray
Write-Host "- Phát hiện: nslookup.exe với DNS SRV record queries" -ForegroundColor Gray

$event3 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "dns-enum-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\nslookup.exe"  # DNS lookup utility
    # Query DNS SRV records để tìm LDAP services (Domain Controllers)
    "CommandLine" = "nslookup.exe -type=SRV _ldap._tcp.dc._msdcs.company.local"
    "ProcessId" = 6802
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\user"
    "LogonId" = "0x12357"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "Medium"
    "Hashes" = "SHA1=D2E3F4A5B6C1"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\user\"
    "OriginalFileName" = "nslookup.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event3
Start-Sleep $DelaySeconds

# ATTACK 4: SMB Share Enumeration
# Mô tả: Enumerate SMB shares trên network
# Kỹ thuật: T1135 - Network Share Discovery
Write-Host "`n[ATTACK 4] SMB Share Discovery" -ForegroundColor Cyan
Write-Host "- Mô tả: Enumerate SMB shares để tìm sensitive data" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1135 - Network Share Discovery" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Cao - Có thể access sensitive files và data" -ForegroundColor Gray
Write-Host "- Phát hiện: net.exe với share enumeration commands" -ForegroundColor Gray

$event4 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "smb-enum-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\net.exe"
    # net view \\computer = list shares on specific computer
    "CommandLine" = "net.exe view \\192.168.1.10"
    "ProcessId" = 7913
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\user"
    "LogonId" = "0x12358"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "Medium"
    "Hashes" = "SHA1=E2F3A4B5C6D1"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\user\"
    "OriginalFileName" = "net.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event4
Start-Sleep $DelaySeconds

# ATTACK 5: Active Directory Enumeration with PowerShell
# Mô tả: Sử dụng PowerShell AD modules để enumerate domain
# Kỹ thuật: T1087.002 - Account Discovery: Domain Account
Write-Host "`n[ATTACK 5] PowerShell Active Directory Enumeration" -ForegroundColor Cyan
Write-Host "- Mô tả: Sử dụng PowerShell để enumerate AD objects" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1087.002 - Account Discovery: Domain Account" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Rất cao - Có thể enumerate users, groups, computers, policies" -ForegroundColor Gray
Write-Host "- Phát hiện: PowerShell với AD enumeration cmdlets" -ForegroundColor Gray

$event5 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "ps-ad-enum-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    # PowerShell command để enumerate domain users và groups
    "CommandLine" = "powershell.exe -Command `"Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties *; Get-ADGroup -Filter *`""
    "ProcessId" = 8024
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\user"
    "LogonId" = "0x12359"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "Medium"
    "Hashes" = "SHA1=F2A3B4C5D6E1"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\user\"
    "OriginalFileName" = "PowerShell.EXE"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event5
Start-Sleep $DelaySeconds

# ATTACK 6: Network Ping Sweep
# Mô tả: Ping sweep để tìm live hosts
# Kỹ thuật: T1018 - Remote System Discovery
Write-Host "`n[ATTACK 6] Network Ping Sweep" -ForegroundColor Cyan
Write-Host "- Mô tả: Ping sweep để identify live hosts trong network" -ForegroundColor Gray
Write-Host "- MITRE ATT&CK: T1018 - Remote System Discovery" -ForegroundColor Gray
Write-Host "- Nguy hiểm: Thấp - Chỉ identify live hosts, nhưng là bước đầu của reconnaissance" -ForegroundColor Gray
Write-Host "- Phát hiện: Multiple ping.exe executions với sequential IP addresses" -ForegroundColor Gray

$event6 = @{
    "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    "id" = "ping-sweep-1"
    "logsource" = @{
        "category" = "process_creation"
        "product" = "windows"
    }
    "EventID" = 1
    "Image" = "C:\Windows\System32\ping.exe"  # Windows ping utility
    # -n 1 = send only 1 ping, -w 1000 = wait 1 second for response
    "CommandLine" = "ping.exe -n 1 -w 1000 192.168.1.50"
    "ProcessId" = 9135
    "ParentImage" = "C:\Windows\System32\cmd.exe"
    "User" = "DESKTOP-ENDPOINT\user"
    "LogonId" = "0x12360"
    "TerminalSessionId" = 1
    "IntegrityLevel" = "Medium"
    "Hashes" = "SHA1=A3B4C5D6E7F2"
    "ParentProcessId" = 567
    "ParentCommandLine" = "cmd.exe"
    "CurrentDirectory" = "C:\Users\user\"
    "OriginalFileName" = "ping.exe"
    "FileVersion" = "10.0.19041.1"
}
$totalAlerts += Send-Event -Event $event6
Start-Sleep $DelaySeconds

# Summary
Write-Host "`n=== NETWORK RECONNAISSANCE ATTACK SUMMARY ===" -ForegroundColor Yellow
Write-Host "Events sent: 6" -ForegroundColor White
Write-Host "Alerts generated: $totalAlerts" -ForegroundColor $(if ($totalAlerts -gt 0) { "Green" } else { "Red" })
Write-Host "Detection rate: $(($totalAlerts / 6 * 100).ToString('F1'))%" -ForegroundColor $(if ($totalAlerts -gt 3) { "Green" } else { "Red" })

Write-Host "`n[GIẢI THÍCH KỸ THUẬT CHI TIẾT]" -ForegroundColor Magenta
Write-Host "1. NMAP SCANNING DETECTION:" -ForegroundColor White
Write-Host "   - nmap.exe filename detection" -ForegroundColor Gray
Write-Host "   - Command line chứa scanning parameters (-sS, -O, -p)" -ForegroundColor Gray
Write-Host "   - Network range targets (192.168.1.0/24)" -ForegroundColor Gray
Write-Host "   - Unusual tool execution location (C:\Tools\)" -ForegroundColor Gray

Write-Host "2. NET COMMAND ENUMERATION:" -ForegroundColor White
Write-Host "   - net.exe với /domain parameter" -ForegroundColor Gray
Write-Host "   - Built-in Windows command = harder to detect" -ForegroundColor Gray
Write-Host "   - Command patterns: 'net view', 'net user', 'net group'" -ForegroundColor Gray
Write-Host "   - Multiple rapid executions = suspicious pattern" -ForegroundColor Gray

Write-Host "3. DNS ENUMERATION DETECTION:" -ForegroundColor White
Write-Host "   - nslookup.exe với -type=SRV parameter" -ForegroundColor Gray
Write-Host "   - DNS queries cho _ldap._tcp.dc._msdcs (Domain Controller discovery)" -ForegroundColor Gray
Write-Host "   - Unusual DNS record types (SRV, TXT, ANY)" -ForegroundColor Gray

Write-Host "4. SMB SHARE DISCOVERY:" -ForegroundColor White
Write-Host "   - net.exe view với UNC paths (\\IP_ADDRESS)" -ForegroundColor Gray
Write-Host "   - Sequential IP address enumeration" -ForegroundColor Gray
Write-Host "   - Network authentication attempts" -ForegroundColor Gray

Write-Host "5. POWERSHELL AD ENUMERATION:" -ForegroundColor White
Write-Host "   - PowerShell với ActiveDirectory module" -ForegroundColor Gray
Write-Host "   - AD cmdlets: Get-ADUser, Get-ADGroup, Get-ADComputer" -ForegroundColor Gray
Write-Host "   - -Filter * = enumerate all objects" -ForegroundColor Gray
Write-Host "   - -Properties * = get all attributes" -ForegroundColor Gray

Write-Host "6. PING SWEEP DETECTION:" -ForegroundColor White
Write-Host "   - Multiple ping.exe executions" -ForegroundColor Gray
Write-Host "   - Sequential IP addresses" -ForegroundColor Gray
Write-Host "   - Short timeouts (-w 1000)" -ForegroundColor Gray
Write-Host "   - Single ping attempts (-n 1)" -ForegroundColor Gray

Write-Host "`n[RECONNAISSANCE KILL CHAIN]" -ForegroundColor Magenta
Write-Host "1. Ping Sweep → Identify live hosts" -ForegroundColor White
Write-Host "2. Port Scanning → Identify running services" -ForegroundColor White  
Write-Host "3. DNS Enumeration → Identify infrastructure" -ForegroundColor White
Write-Host "4. SMB Enumeration → Identify file shares" -ForegroundColor White
Write-Host "5. Domain Enumeration → Identify domain structure" -ForegroundColor White
Write-Host "6. AD Enumeration → Identify users and privileges" -ForegroundColor White

Write-Host "`n[NETWORK DETECTION INDICATORS]" -ForegroundColor Magenta
Write-Host "- Unusual outbound connections to multiple IPs" -ForegroundColor Red
Write-Host "- DNS queries for SRV records" -ForegroundColor Red
Write-Host "- SMB connection attempts to multiple hosts" -ForegroundColor Red
Write-Host "- LDAP queries to Domain Controllers" -ForegroundColor Red
Write-Host "- High volume of ICMP traffic" -ForegroundColor Yellow
