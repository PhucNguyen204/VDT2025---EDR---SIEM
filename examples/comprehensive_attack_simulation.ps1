# Comprehensive Attack Simulation for EDR Testing
# Simulates: SSH Brute-Force, XSS, SQL Injection, Vulnerability Scanning
param(
    [int]$Count = 3,
    [string]$TargetUrl = "http://localhost:8080/api/v2/events"
)

Write-Host "Starting Comprehensive Attack Simulation..." -ForegroundColor Red
Write-Host "Target: $TargetUrl" -ForegroundColor Cyan
Write-Host "Count per attack: $Count" -ForegroundColor Cyan

# Load System.Web for URL encoding
Add-Type -AssemblyName System.Web

# Common functions
function Send-Event {
    param($Event, $AttackType, $Index)
    
    try {
        $jsonEvent = $Event | ConvertTo-Json -Depth 10 -Compress
        $response = Invoke-RestMethod -Uri $TargetUrl -Method POST -Body $jsonEvent -ContentType "application/json" -TimeoutSec 5
        
        $alertStatus = if ($response.alerts_generated -gt 0) { "[DETECTED]" } else { "[No Alert]" }
        $color = if ($response.alerts_generated -gt 0) { "Green" } else { "Yellow" }
        
        Write-Host "[$AttackType $Index] $alertStatus - Alerts: $($response.alerts_generated)" -ForegroundColor $color
        return $response.alerts_generated
    } catch {
        Write-Host "[$AttackType $Index] [ERROR] Error: $($_.Exception.Message)" -ForegroundColor Red
        return 0
    }
}

$totalAlerts = 0

# ===========================================
# 1. SSH BRUTE-FORCE ATTACKS
# ===========================================
Write-Host "`n=== SSH Brute-Force Attacks ===" -ForegroundColor Yellow
$usernames = @("admin", "root", "user", "administrator", "test")

for ($i = 1; $i -le $Count; $i++) {
    $username = $usernames | Get-Random
    
    # SSH Process Creation Event (Hydra-like)
    $sshEvent = @{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        "id" = "ssh-brute-$i"
        "host" = @{
            "name" = $env:COMPUTERNAME
            "os" = @{
                "platform" = "windows"
                "family" = "windows"
                "name" = "Windows 10"
            }
        }
        "agent" = @{
            "id" = "agent-001"
            "type" = "edr-agent"
            "version" = "2.0.0"
        }
        "event" = @{
            "category" = @("process_creation")
            "type" = @("start")
            "code" = "1"
            "module" = "sysmon"
        }
        "process" = @{
            "executable" = "C:\tools\hydra.exe"
            "command_line" = "hydra.exe -u $username -p ^PASS^ -t 4 ssh://192.168.1.100"
            "name" = "hydra.exe"
            "original_file_name" = "hydra.exe"
            "parent" = @{
                "executable" = "C:\Windows\System32\cmd.exe"
            }
        }
        "user" = @{
            "name" = "Attacker"
        }
    }
    
    # Add Sigma-compatible fields
    $sshEvent["EventID"] = "1"
    $sshEvent["CommandLine"] = $sshEvent.process.command_line
    $sshEvent["Image"] = $sshEvent.process.executable
    $sshEvent["OriginalFileName"] = "hydra.exe"
    $sshEvent["ComputerName"] = $sshEvent.host.name
    
    $alerts = Send-Event -Event $sshEvent -AttackType "SSH" -Index $i
    $totalAlerts += $alerts
    
    Start-Sleep -Seconds 1
}

# ===========================================
# 2. XSS ATTACKS
# ===========================================
Write-Host "`n=== XSS Attacks ===" -ForegroundColor Yellow
$xssPayloads = @(
    '<script>alert("XSS")</script>',
    '%3Cscript%3Ealert("XSS")%3C/script%3E',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<svg onload=alert(document.cookie)>',
    'javascript:alert("XSS")',
    '<img src=x onerror=alert("XSS")>',
    'document.cookie',
    'alert("XSS")'
)

for ($i = 1; $i -le $Count; $i++) {
    $payload = $xssPayloads | Get-Random
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    
    $xssEvent = @{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        "id" = "xss-attack-$i"
        "host" = @{
            "name" = "WEB-SERVER"
            "ip" = "192.168.1.200"
        }
        "agent" = @{
            "id" = "agent-002"
            "type" = "web-agent"
            "version" = "2.0.0"
        }
        "event" = @{
            "category" = @("web")
            "type" = @("access")
            "module" = "webserver"
        }
        "url" = @{
            "original" = "/search?q=$encodedPayload"
            "path" = "/search"
            "query" = "q=$encodedPayload"
        }
        "http" = @{
            "request" = @{
                "method" = "GET"
                "referrer" = "http://evil.com"
            }
            "response" = @{
                "status_code" = 200
            }
        }
        "source" = @{
            "ip" = "203.0.113.$(Get-Random -Minimum 10 -Maximum 250)"
        }
        "user_agent" = @{
            "original" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
    }
    
    # Add Sigma-compatible fields for web logs
    $xssEvent["cs-method"] = "GET"
    $xssEvent["cs-uri-query"] = "q=$encodedPayload"
    $xssEvent["sc-status"] = 200
    $xssEvent["c-ip"] = $xssEvent.source.ip
    $xssEvent["cs-uri-stem"] = "/search"
    
    $alerts = Send-Event -Event $xssEvent -AttackType "XSS" -Index $i
    $totalAlerts += $alerts
    
    Start-Sleep -Seconds 1
}

# ===========================================
# 3. SQL INJECTION ATTACKS
# ===========================================
Write-Host "`n=== SQL Injection Attacks ===" -ForegroundColor Yellow
$sqlPayloads = @(
    "' OR '1'='1",
    "' UNION SELECT * FROM users--",
    "'; DROP TABLE users;--",
    "' OR 1=1#",
    "admin'--",
    "' UNION ALL SELECT database()--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "%27%20UNION%20SELECT%20version()--",
    "1' OR '1'='1' /*",
    "'; SELECT * FROM mysql.user--"
)

for ($i = 1; $i -le $Count; $i++) {
    $payload = $sqlPayloads | Get-Random
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    
    $sqlEvent = @{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        "id" = "sql-injection-$i"
        "host" = @{
            "name" = "DB-SERVER"
            "ip" = "192.168.1.201"
        }
        "agent" = @{
            "id" = "agent-003"
            "type" = "web-agent"
            "version" = "2.0.0"
        }
        "event" = @{
            "category" = @("web")
            "type" = @("access")
            "module" = "webserver"
        }
        "url" = @{
            "original" = "/login?username=$encodedPayload&password=test"
            "path" = "/login"
            "query" = "username=$encodedPayload&password=test"
        }
        "http" = @{
            "request" = @{
                "method" = "GET"
                "referrer" = "http://evil.com"
            }
            "response" = @{
                "status_code" = 500
            }
        }
        "source" = @{
            "ip" = "203.0.113.$(Get-Random -Minimum 10 -Maximum 250)"
        }
        "user_agent" = @{
            "original" = "sqlmap/1.6.2#dev"
        }
    }
    
    # Add Sigma-compatible fields
    $sqlEvent["cs-method"] = "GET"
    $sqlEvent["cs-uri-query"] = "username=$encodedPayload&password=test"
    $sqlEvent["sc-status"] = 500
    $sqlEvent["c-ip"] = $sqlEvent.source.ip
    $sqlEvent["cs-uri-stem"] = "/login"
    
    $alerts = Send-Event -Event $sqlEvent -AttackType "SQLi" -Index $i
    $totalAlerts += $alerts
    
    Start-Sleep -Seconds 1
}

# ===========================================
# 4. VULNERABILITY SCANNING
# ===========================================
Write-Host "`n=== Vulnerability Scanning ===" -ForegroundColor Yellow

for ($i = 1; $i -le $Count; $i++) {
    $scanTypes = @("nmap", "masscan", "nikto", "dirb")
    $scanType = $scanTypes | Get-Random
    
    # Process creation for scanning tools
    $scanEvent = @{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        "id" = "scan-$i"
        "host" = @{
            "name" = $env:COMPUTERNAME
            "os" = @{
                "platform" = "windows"
                "family" = "windows"
                "name" = "Windows 10"
            }
        }
        "agent" = @{
            "id" = "agent-004"
            "type" = "edr-agent"
            "version" = "2.0.0"
        }
        "event" = @{
            "category" = @("process_creation")
            "type" = @("start")
            "code" = "1"
            "module" = "sysmon"
        }
        "process" = @{
            "executable" = "C:\tools\$scanType.exe"
            "name" = "$scanType.exe"
            "original_file_name" = "$scanType.exe"
            "parent" = @{
                "executable" = "C:\Windows\System32\cmd.exe"
            }
        }
        "user" = @{
            "name" = "Scanner"
        }
    }
    
    # Set command line based on scan type
    switch ($scanType) {
        "nmap" { 
            $scanEvent.process.command_line = "nmap.exe -sS -sV -O 192.168.1.0/24"
        }
        "masscan" { 
            $scanEvent.process.command_line = "masscan.exe -p1-65535 192.168.1.0/24 --rate=1000"
        }
        "nikto" { 
            $scanEvent.process.command_line = "nikto.pl -h 192.168.1.100 -p 80,443"
        }
        "dirb" { 
            $scanEvent.process.command_line = "dirb.exe http://192.168.1.100/ /usr/share/dirb/wordlists/common.txt"
        }
    }
    
    # Add Sigma-compatible fields
    $scanEvent["EventID"] = "1"
    $scanEvent["CommandLine"] = $scanEvent.process.command_line
    $scanEvent["Image"] = $scanEvent.process.executable
    $scanEvent["OriginalFileName"] = "$scanType.exe"
    $scanEvent["ComputerName"] = $scanEvent.host.name
    
    $alerts = Send-Event -Event $scanEvent -AttackType "SCAN" -Index $i
    $totalAlerts += $alerts
    
    Start-Sleep -Seconds 1
}

# ===========================================
# RESULTS SUMMARY
# ===========================================
Write-Host "`n=== Attack Simulation Results ===" -ForegroundColor Green

try {
    $stats = Invoke-RestMethod -Uri "http://localhost:8080/api/v2/stats" -TimeoutSec 5
    
    Write-Host "Events Processed: $($stats.events_processed)" -ForegroundColor Cyan
    Write-Host "Total Alerts Generated: $($stats.alerts_generated)" -ForegroundColor $(if ($stats.alerts_generated -gt 0) {"Green"} else {"Red"})
    Write-Host "This Session Alerts: $totalAlerts" -ForegroundColor $(if ($totalAlerts -gt 0) {"Green"} else {"Red"})
    Write-Host "Rules Loaded: $($stats.rules_loaded)" -ForegroundColor Cyan
    Write-Host "System Uptime: $($stats.uptime)" -ForegroundColor Cyan
    
    if ($stats.alerts_generated -gt 0) {
        Write-Host "`nSUCCESS: Multiple Attack Vectors Detected!" -ForegroundColor Green -BackgroundColor Black
        Write-Host "View detailed alerts: http://localhost:8080/api/v2/alerts" -ForegroundColor Cyan
    } else {
        Write-Host "`nWARNING: No attacks detected - Check detection rules" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[ERROR] Error getting stats: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nComprehensive Attack Simulation Completed!" -ForegroundColor Green
