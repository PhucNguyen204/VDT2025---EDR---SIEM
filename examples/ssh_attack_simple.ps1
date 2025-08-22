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

