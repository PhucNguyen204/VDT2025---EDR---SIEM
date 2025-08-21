# Simple SSH Brute-Force Demo
param([int]$Count = 5)

# EDR v2 Docker endpoint
$TargetUrl = "http://localhost:8080/api/v2/events"

Write-Host "Starting SSH Brute-Force Demo..." -ForegroundColor Red

$usernames = @("root", "admin", "administrator", "user", "test")
$passwords = @("password", "123456", "admin", "root", "password123")

Write-Host "`n=== Phase 1: SSH Process Creation Events ===" -ForegroundColor Cyan

for ($i = 1; $i -le $Count; $i++) {
    $username = $usernames | Get-Random
    $password = $passwords | Get-Random
    
    # Create Hydra-like process event
    $processEvent = @{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        "id" = "ssh-hydra-$i"
        "host" = @{
            "name" = $env:COMPUTERNAME
            "os" = @{
                "platform" = "windows"
                "family" = "windows"
                "name" = "Windows 10"
            }
        }
        "agent" = @{
            "id" = "test-agent-001"
            "type" = "edr-agent"
            "version" = "1.0.0"
        }
        "event" = @{
            "category" = @("process_creation") # <<< SỬA LẠI CATEGORY
            "type" = @("start")
            "code" = "1"
            "module" = "sysmon"
        }
        "process" = @{
            "executable" = "C:\tools\hydra.exe"
            "command_line" = "hydra.exe -u $username -p ^PASS^ -t 4 ssh://192.168.1.100" # Command line matches Sigma rule
            "name" = "hydra.exe"
            "original_file_name" = "hydra.exe" # <<< THÊM OriginalFileName
            "parent" = @{
                "executable" = "C:\Windows\System32\cmd.exe" # Thêm parent process
            }
        }
        "user" = @{
            "name" = "Attacker"
        }
    }
    
    # Add Sigma fields
    $processEvent["Image"] = $processEvent.process.executable
    $processEvent["CommandLine"] = $processEvent.process.command_line
    $processEvent["OriginalFileName"] = $processEvent.process.original_file_name # <<< THÊM VÀO TOP-LEVEL
    $processEvent["EventID"] = $processEvent.event.code
    $processEvent["ComputerName"] = $processEvent.host.name
    
    $jsonEvent = $processEvent | ConvertTo-Json -Depth 10 -Compress
    
    try {
        $response = Invoke-RestMethod -Uri $TargetUrl -Method POST -Body $jsonEvent -ContentType "application/json" -TimeoutSec 5
        Write-Host "[HYDRA $i] Command: $($processEvent.process.command_line)" -ForegroundColor Yellow
        Write-Host "           Alerts: $($response.alerts_generated)" -ForegroundColor $(if ($response.alerts_generated -gt 0) {"Green"} else {"Red"})
        
        if ($response.alerts_generated -gt 0) {
            Write-Host "           HYDRA DETECTED!" -ForegroundColor Green -BackgroundColor Black
        }
    } catch {
        Write-Host "[HYDRA $i] Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 1
}

Write-Host "`n=== Phase 2: Authentication Failure Events ===" -ForegroundColor Cyan

for ($i = 1; $i -le $Count; $i++) {
    $username = $usernames | Get-Random
    $sourceIP = "203.0.113.$(Get-Random -Minimum 1 -Maximum 254)"
    
    # Create failed logon event (4625)
    $authEvent = @{
        "@timestamp" = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        "id" = "ssh-fail-$i"
        "host" = @{
            "name" = "SSH-SERVER"
            "os" = @{
                "platform" = "windows"
                "family" = "windows"
                "name" = "Windows Server"
            }
        }
        "agent" = @{
            "id" = "test-agent-002"
            "type" = "edr-agent"
            "version" = "1.0.0"
        }
        "event" = @{
            "category" = @("authentication")
            "type" = @("start")
            "code" = "4625"
            "module" = "security"
        }
        "user" = @{
            "name" = $username
        }
        "source" = @{
            "ip" = $sourceIP
        }
        "winlog" = @{
            "event_id" = 4625
            "channel" = "Security"
            "logon_type" = 10
        }
    }
    
    # Add Sigma fields
    $authEvent["EventID"] = $authEvent.event.code
    $authEvent["TargetUserName"] = $authEvent.user.name
    $authEvent["IpAddress"] = $authEvent.source.ip
    $authEvent["ComputerName"] = $authEvent.host.name
    $authEvent["LogonType"] = $authEvent.winlog.logon_type
    $authEvent["Channel"] = $authEvent.winlog.channel
    
    $jsonEvent = $authEvent | ConvertTo-Json -Depth 10 -Compress
    
    try {
        $response = Invoke-RestMethod -Uri $TargetUrl -Method POST -Body $jsonEvent -ContentType "application/json" -TimeoutSec 5
        Write-Host "[AUTH $i] Failed login: $username from $sourceIP" -ForegroundColor Yellow
        Write-Host "          Alerts: $($response.alerts_generated)" -ForegroundColor $(if ($response.alerts_generated -gt 0) {"Green"} else {"Red"})
        
        if ($response.alerts_generated -gt 0) {
            Write-Host "          FAILED LOGON DETECTED!" -ForegroundColor Green -BackgroundColor Black
        }
    } catch {
        Write-Host "[AUTH $i] Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Start-Sleep -Seconds 1
}

Write-Host "`n=== Results ===" -ForegroundColor Green

try {
    $stats = Invoke-RestMethod -Uri "http://localhost:8080/api/v2/stats" -TimeoutSec 5
    Write-Host "Events processed: $($stats.events_processed)" -ForegroundColor Cyan
    Write-Host "Alerts generated: $($stats.alerts_generated)" -ForegroundColor $(if ($stats.alerts_generated -gt 0) {"Green"} else {"Red"})
    
    if ($stats.alerts_generated -gt 0) {
        Write-Host "`nSUCCESS: SSH Attack Detected!" -ForegroundColor Green -BackgroundColor Black
    } else {
        Write-Host "`nNo alerts - checking detection logic..." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error getting stats: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nAlerts: http://localhost:8080/api/v2/alerts" -ForegroundColor Cyan
