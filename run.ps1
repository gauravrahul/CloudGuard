# Set strict error handling and encoding
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Start-CloudGuard {
    $process = $null
    $handler = $null
    
    try {
        # Display header
        Clear-Host
        Write-Host "=================================" -ForegroundColor Cyan
        Write-Host "    CloudGuard DDoS Monitor      " -ForegroundColor Cyan
        Write-Host "=================================" -ForegroundColor Cyan

        # Build application
        Write-Host "`nBuilding application..." -ForegroundColor Yellow
        Remove-Item -Force intrualert.exe -ErrorAction SilentlyContinue
        go build -o intrualert.exe .\cmd
        if (-not $?) { throw "Build failed" }
        Write-Host "✓ Build successful" -ForegroundColor Green

        # Check port availability
        Write-Host "`nChecking port 8080..." -ForegroundColor Yellow
        $portCheck = netstat -ano | findstr :8080
        if ($portCheck) {
            $portProcessId = ($portCheck -split '\s+')[5]
            Write-Host "Port 8080 is in use. Stopping process $portProcessId..." -ForegroundColor Yellow
            Stop-Process -Id $portProcessId -Force
            Start-Sleep -Seconds 2
        }

        # Start application
        Write-Host "`nStarting CloudGuard..." -ForegroundColor Green
        $process = Start-Process -FilePath ".\intrualert.exe" -PassThru -NoNewWindow `
                  -RedirectStandardOutput "stdout.log" -RedirectStandardError "stderr.log"

        if (-not $process -or $process.HasExited) {
            throw "Failed to start CloudGuard"
        }

        # Display status
        Write-Host "`nCloudGuard is running!" -ForegroundColor Green
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
        Write-Host "  URL: http://localhost:8080" -ForegroundColor Cyan
        Write-Host "  PID: $($process.Id)" -ForegroundColor Cyan
        Write-Host "  Press Ctrl+C to stop" -ForegroundColor Cyan
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Gray

        # Set up log monitoring
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $PWD
        $watcher.Filter = "*.log"
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::LastWrite
        $watcher.EnableRaisingEvents = $true

        $handler = Register-ObjectEvent -InputObject $watcher -EventName Changed -Action {
            $path = $Event.SourceEventArgs.FullPath
            $tail = Get-Content $path -Tail 1
            if ($path -match 'stderr') {
                Write-Host $tail -ForegroundColor Red
            } else {
                Write-Host $tail -ForegroundColor Gray
            }
        }

        # Monitor process and handle shutdown
        while (-not $process.HasExited) {
            if ($Host.UI.RawUI.KeyAvailable) {
                $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                if ($key.VirtualKeyCode -eq 3) {
                    Write-Host "`nStopping CloudGuard..." -ForegroundColor Yellow
                    break
                }
            }
            Start-Sleep -Milliseconds 100
        }

        # Check if process exited unexpectedly
        if ($process.HasExited) {
            Write-Host "`nServer stopped unexpectedly!" -ForegroundColor Red
            Write-Host "Exit Code: $($process.ExitCode)" -ForegroundColor Red
            if (Test-Path "stderr.log") {
                Write-Host "Error log:" -ForegroundColor Red
                Get-Content "stderr.log" | Write-Host -ForegroundColor Red
            }
            throw "Server crashed with exit code $($process.ExitCode)"
        }

        return $true
    }
    catch {
        Write-Error "CloudGuard error: $_"
        return $false
    }
    finally {
        if ($handler) {
            Unregister-Event -SourceIdentifier $handler.Name -ErrorAction SilentlyContinue
        }
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            Write-Host "✓ Server stopped" -ForegroundColor Yellow
        }
        Remove-Item -Path "*.log" -ErrorAction SilentlyContinue
    }
}

# Main execution
try {
    if (-not (Start-CloudGuard)) {
        exit 1
    }
}
catch {
    Write-Error "Fatal error: $_"
    exit 1
}