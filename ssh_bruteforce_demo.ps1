# SSH Brute-Force Attack Demo cho EDR Detection
# Tạo cả process creation và authentication failure events

param(
    [int]$AttackDuration = 30,  # seconds
    [string]$TargetHost = "192.168.1.100",
    [int]$AttackCount = 10
)

Write-Host "🔥 Starting SSH Brute-Force Attack Demo..." -ForegroundColor Red
Write-Host "Target: $TargetHost" -ForegroundColor Yellow
Write-Host "Duration: $AttackDuration seconds" -ForegroundColor Yellow
Write-Host "Attack attempts: $AttackCount" -ForegroundColor Yellow

# Common SSH brute-force usernames/passwords
$usernames = @("root", "admin", "administrator", "user", "test", "guest", "oracle", "postgres", "mysql")
$passwords = @("password", "123456", "admin", "root", "password123", "admin123", "test", "guest", "12345")

$eventId = 1
$timestamp = Get-Date

Write-Host "`n=== Phase 1: SSH Process Creation Events (Hydra-like) ===" -ForegroundColor Cyan

for ($i = 1; $i -le $AttackCount; $i++) {
    $username = $usernames | Get-Random
    $password = $passwords | Get-Random
    
    # Create SSH brute-force process creation event (Hydra-like)
    $processEvent = @{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        "id" = "ssh-attack-$eventId"
        "host" = @{
            "id" = "attacker-machine-001"
            "name" = $env:COMPUTERNAME
            "os" = @{
                "platform" = "windows"
                "family" = "windows"
            }
        }
        "agent" = @{
            "id" = "edr-agent-001"
            "type" = "vector-edr"
            "version" = "1.0.0"
        }
        "ecs" = @{
            "version" = "8.6.0"
        }
        "event" = @{
            "kind" = "event"
            "category" = @("process")
            "type" = @("start")
            "action" = "process_created"
            "provider" = "Microsoft-Windows-Sysmon"
            "code" = "1"
            "module" = "sysmon"
        }
        "process" = @{
            "pid" = Get-Random -Minimum 1000 -Maximum 9999
            "executable" = "C:\tools\hydra.exe"
            "command_line" = "hydra.exe -u $username -p $password -t 4 ssh://$TargetHost"
            "name" = "hydra.exe"
            "parent" = @{
                "pid" = Get-Random -Minimum 100 -Maximum 999
                "executable" = "C:\Windows\System32\cmd.exe"
                "name" = "cmd.exe"
            }
        }
        "user" = @{
            "name" = "Attacker"
            "domain" = $env:COMPUTERNAME
        }
        "message" = "SSH Brute-force attempt: hydra -u $username -p $password ssh://$TargetHost"
    }
    
    # Add Sigma-compatible fields for process creation
    $processEvent["Image"] = $processEvent.process.executable
    $processEvent["CommandLine"] = $processEvent.process.command_line
    $processEvent["EventID"] = $processEvent.event.code
    $processEvent["ComputerName"] = $processEvent.host.name
    
    $jsonEvent = $processEvent | ConvertTo-Json -Depth 10 -Compress
    
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:9090/api/v1/events" -Method POST -Body $jsonEvent -ContentType "application/json" -TimeoutSec 5
        Write-Host "[PROCESS $i] SSH attack process: $($processEvent.process.command_line)" -ForegroundColor Red
        Write-Host "              Response: Alerts=$($response.alerts_generated)" -ForegroundColor $(if ($response.alerts_generated -gt 0) {"Green"} else {"Yellow"})
        
        if ($response.alerts_generated -gt 0) {
            Write-Host "              🚨 HYDRA DETECTION ALERT! 🚨" -ForegroundColor Green -BackgroundColor Red
        }
    } catch {
        Write-Host "[PROCESS $i] Failed to send: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    $eventId++
    Start-Sleep -Seconds 1
}

Write-Host "`n=== Phase 2: Authentication Failure Events (Event ID 4625) ===" -ForegroundColor Cyan

for ($i = 1; $i -le $AttackCount; $i++) {
    $username = $usernames | Get-Random
    $sourceIP = "203.0.113.$(Get-Random -Minimum 1 -Maximum 254)"  # Public IP range
    
    # Create authentication failure event (Event ID 4625)
    $authEvent = @{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        "id" = "ssh-auth-fail-$eventId"
        "host" = @{
            "id" = "target-server-001"
            "name" = "SSH-SERVER"
            "os" = @{
                "platform" = "windows"
                "family" = "windows"
            }
        }
        "agent" = @{
            "id" = "edr-agent-002"
            "type" = "vector-edr"
            "version" = "1.0.0"
        }
        "ecs" = @{
            "version" = "8.6.0"
        }
        "event" = @{
            "kind" = "event"
            "category" = @("authentication")
            "type" = @("start")
            "action" = "logon_failed"
            "provider" = "Microsoft-Windows-Security-Auditing"
            "code" = "4625"
            "module" = "security"
        }
        "user" = @{
            "name" = $username
            "domain" = "SSH-SERVER"
        }
        "source" = @{
            "ip" = $sourceIP
        }
        "winlog" = @{
            "event_id" = 4625
            "channel" = "Security"
            "computer_name" = "SSH-SERVER"
            "logon_type" = 10  # RemoteInteractive (SSH/RDP)
            "logon" = @{
                "failure" = @{
                    "reason" = "Unknown user name or bad password"
                    "status" = "0xC000006D"
                    "sub_status" = "0xC0000064"
                }
            }
        }
        "message" = "An account failed to log on. Subject: Account Name: $username, Source Network Address: $sourceIP, Logon Type: 10"
    }
    
    # Add Sigma-compatible fields for authentication
    $authEvent["EventID"] = $authEvent.event.code
    $authEvent["TargetUserName"] = $authEvent.user.name
    $authEvent["IpAddress"] = $authEvent.source.ip
    $authEvent["ComputerName"] = $authEvent.host.name
    $authEvent["LogonType"] = $authEvent.winlog.logon_type
    $authEvent["Status"] = $authEvent.winlog.logon.failure.status
    $authEvent["SubStatus"] = $authEvent.winlog.logon.failure.sub_status
    $authEvent["Channel"] = $authEvent.winlog.channel
    
    $jsonEvent = $authEvent | ConvertTo-Json -Depth 10 -Compress
    
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:9090/api/v1/events" -Method POST -Body $jsonEvent -ContentType "application/json" -TimeoutSec 5
        Write-Host "[AUTH $i] Failed SSH login: $username from $sourceIP" -ForegroundColor Yellow
        Write-Host "           Response: Alerts=$($response.alerts_generated)" -ForegroundColor $(if ($response.alerts_generated -gt 0) {"Green"} else {"Yellow"})
        
        if ($response.alerts_generated -gt 0) {
            Write-Host "           🚨 FAILED LOGON DETECTION ALERT! 🚨" -ForegroundColor Green -BackgroundColor Red
        }
    } catch {
        Write-Host "[AUTH $i] Failed to send: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    $eventId++
    Start-Sleep -Seconds 2
}

Write-Host "`n=== Attack Complete - Checking Results ===" -ForegroundColor Green

# Check final stats
try {
    $stats = Invoke-RestMethod -Uri "http://localhost:9090/api/v1/stats" -TimeoutSec 5
    Write-Host "📊 Final Stats:" -ForegroundColor Cyan
    Write-Host "   Events processed: $($stats.events_processed)" -ForegroundColor Green
    Write-Host "   Alerts generated: $($stats.alerts_generated)" -ForegroundColor $(if ($stats.alerts_generated -gt 0) {"Green"} else {"Red"})"
    
    if ($stats.alerts_generated -gt 0) {
        Write-Host "`n✅ SUCCESS: SSH Brute-Force Attack Detected!" -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Host "`n❌ No alerts generated - Detection needs debugging" -ForegroundColor Red
    }
} catch {
    Write-Host "Failed to get stats: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🔍 Check dashboard: http://localhost:9090/dashboard" -ForegroundColor Cyan
Write-Host "Check logs: docker logs edr-detection-engine --tail 50" -ForegroundColor Cyan
