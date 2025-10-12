# Reporting Module
# Handles enhanced reporting and monitoring for scheduling operations and Windows 11 readiness progress

#region Reporting Functions

function Get-SchedulingOperationsReport {
    [CmdletBinding()]
    param(
        [int]$Days = 7,
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating scheduling operations report for last $Days days..." -Level Info
        
        # Get scheduling engine status
        $engineStatus = Get-SchedulingEngineStatus
        
        # Get failed hosts data
        $failedHosts = Get-FailedHosts
        
        # Get scheduling configuration
        $schedulingConfig = Get-SchedulingConfiguration
        
        # Calculate statistics
        $totalFailedHosts = $failedHosts.Count
        $criticalHosts = ($failedHosts | Where-Object { $_.Priority -eq "critical" }).Count
        $normalHosts = ($failedHosts | Where-Object { $_.Priority -eq "normal" }).Count
        $lowHosts = ($failedHosts | Where-Object { $_.Priority -eq "low" }).Count
        
        # Calculate success rates
        $totalScans = $engineStatus.Stats.TotalScansExecuted
        $successfulScans = $engineStatus.Stats.SuccessfulScans
        $failedScans = $engineStatus.Stats.FailedScans
        $successRate = if ($totalScans -gt 0) { [math]::Round(($successfulScans / $totalScans) * 100, 2) } else { 0 }
        
        # Get hosts due for scan
        $dueHosts = Get-HostsDueForScheduledScan
        $dueHostsCount = $dueHosts.Count
        
        # Create report data
        $report = @{
            ReportGenerated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            ReportPeriod = "$Days days"
            SchedulingEngine = @{
                Status = if ($engineStatus.IsRunning) { "Running" } else { "Stopped" }
                StartTime = $engineStatus.StartTime
                TotalScansExecuted = $totalScans
                SuccessfulScans = $successfulScans
                FailedScans = $failedScans
                SuccessRate = "$successRate%"
                LastScanTime = $engineStatus.LastScanTime
                LastError = $engineStatus.LastError
            }
            FailedHosts = @{
                Total = $totalFailedHosts
                Critical = $criticalHosts
                Normal = $normalHosts
                Low = $lowHosts
                DueForScan = $dueHostsCount
            }
            SchedulingConfiguration = @{
                Enabled = $schedulingConfig.Enabled
                DefaultIntervalHours = $schedulingConfig.DefaultIntervalHours
                CriticalIntervalHours = $schedulingConfig.CriticalIntervalHours
                LowPriorityIntervalHours = $schedulingConfig.LowPriorityIntervalHours
                MaxConcurrentScheduledScans = $schedulingConfig.MaxConcurrentScheduledScans
            }
            Recommendations = @()
        }
        
        # Add recommendations based on data
        if ($successRate -lt 80) {
            $report.Recommendations += "Success rate is below 80%. Consider investigating network connectivity issues."
        }
        
        if ($dueHostsCount -gt 50) {
            $report.Recommendations += "High number of hosts due for scan. Consider increasing concurrent scan limit."
        }
        
        if ($criticalHosts -gt 0) {
            $report.Recommendations += "Critical hosts detected. Prioritize manual intervention for these systems."
        }
        
        if (-not $schedulingConfig.Enabled) {
            $report.Recommendations += "Scheduling is disabled. Enable scheduling to automate re-scanning of failed hosts."
        }
        
        # Output report
        if ($OutputPath) {
            $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Log "Scheduling operations report saved to: $OutputPath" -Level Success
        }
        
        return $report
    }
    catch {
        Write-Log "Failed to generate scheduling operations report: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-Windows11ReadinessProgressReport {
    [CmdletBinding()]
    param(
        [int]$Days = 30,
        [string]$OutputPath
    )
    
    try {
        Write-Log "Generating Windows 11 readiness progress report for last $Days days..." -Level Info
        
        # Get system data from CSV
        $csvPath = Join-Path (Get-ScriptDirectory) "system_data.csv"
        if (-not (Test-Path $csvPath)) {
            Write-Log "System data CSV not found: $csvPath" -Level Warning
            return $null
        }
        
        # Read CSV data
        $systemData = Import-Csv -Path $csvPath
        
        # Calculate readiness statistics
        $totalSystems = $systemData.Count
        $successfulScans = ($systemData | Where-Object { $_.Success -eq "True" }).Count
        $failedScans = ($systemData | Where-Object { $_.Success -eq "False" }).Count
        
        # Windows 11 readiness analysis
        $windows11Ready = 0
        $windows11NotReady = 0
        $unknownReadiness = 0
        
        foreach ($system in $systemData) {
            if ($system.Success -eq "True") {
                # Analyze Windows 11 readiness based on OS version and hardware requirements
                # Windows 11 minimum requirements: 4GB RAM, TPM 2.0, UEFI, 64GB storage
                $osName = $system.OS_Name
                $osVersion = $system.OS_Version
                $totalMemory = if ($system.TotalMemoryGB) { [double]$system.TotalMemoryGB } else { 0 }
                
                # Check if already running Windows 11
                if ($osName -match "Windows 11") {
                    $windows11Ready++
                }
                # Check if running Windows 10 with sufficient hardware
                elseif ($osName -match "Windows 10" -and $totalMemory -ge 4) {
                    # Windows 10 with 4GB+ RAM is potentially upgradeable to Windows 11
                    # (Note: Real readiness would require TPM 2.0, UEFI, CPU generation checks)
                    $windows11Ready++
                }
                # Windows 10 with insufficient RAM
                elseif ($osName -match "Windows 10" -and $totalMemory -lt 4) {
                    $windows11NotReady++
                }
                # Older Windows versions or unknown OS
                else {
                    $windows11NotReady++
                }
            } else {
                # Failed scans - unknown readiness
                $unknownReadiness++
            }
        }
        
        # Calculate percentages
        $readinessRate = if ($totalSystems -gt 0) { [math]::Round(($windows11Ready / $totalSystems) * 100, 2) } else { 0 }
        $scanSuccessRate = if ($totalSystems -gt 0) { [math]::Round(($successfulScans / $totalSystems) * 100, 2) } else { 0 }
        
        # Get failed hosts for context
        $failedHosts = Get-FailedHosts
        $failedHostsCount = $failedHosts.Count
        
        # Create progress report
        $report = @{
            ReportGenerated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            ReportPeriod = "$Days days"
            Summary = @{
                TotalSystems = $totalSystems
                SuccessfulScans = $successfulScans
                FailedScans = $failedScans
                ScanSuccessRate = "$scanSuccessRate%"
                Windows11Ready = $windows11Ready
                Windows11NotReady = $windows11NotReady
                UnknownReadiness = $unknownReadiness
                ReadinessRate = "$readinessRate%"
                FailedHostsPending = $failedHostsCount
            }
            ReadinessBreakdown = @{
                Ready = @{
                    Count = $windows11Ready
                    Percentage = if ($totalSystems -gt 0) { [math]::Round(($windows11Ready / $totalSystems) * 100, 2) } else { 0 }
                }
                NotReady = @{
                    Count = $windows11NotReady
                    Percentage = if ($totalSystems -gt 0) { [math]::Round(($windows11NotReady / $totalSystems) * 100, 2) } else { 0 }
                }
                Unknown = @{
                    Count = $unknownReadiness
                    Percentage = if ($totalSystems -gt 0) { [math]::Round(($unknownReadiness / $totalSystems) * 100, 2) } else { 0 }
                }
            }
            Recommendations = @()
        }
        
        # Add recommendations
        if ($readinessRate -lt 50) {
            $report.Recommendations += "Windows 11 readiness rate is below 50%. Consider hardware upgrades for non-ready systems."
        }
        
        if ($scanSuccessRate -lt 90) {
            $report.Recommendations += "Scan success rate is below 90%. Investigate network connectivity and system availability issues."
        }
        
        if ($failedHostsCount -gt 0) {
            $report.Recommendations += "There are $failedHostsCount failed hosts pending. Use automated scheduling to re-scan these systems."
        }
        
        # Output report
        if ($OutputPath) {
            $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Log "Windows 11 readiness progress report saved to: $OutputPath" -Level Success
        }
        
        return $report
    }
    catch {
        Write-Log "Failed to generate Windows 11 readiness progress report: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-FailedHostAlerts {
    [CmdletBinding()]
    param(
        [int]$FailureThreshold = 5,
        [int]$Days = 7
    )
    
    try {
        Write-Log "Generating failed host alerts for hosts with $FailureThreshold+ failures in last $Days days..." -Level Info
        
        $failedHosts = Get-FailedHosts
        $alerts = @()
        
        foreach ($failedHost in $failedHosts) {
            $failureCount = $failedHost.AttemptCount
            $lastAttempt = if ($failedHost.LastAttempt) { [DateTime]::Parse($failedHost.LastAttempt) } else { [DateTime]::MinValue }
            $daysSinceLastAttempt = (Get-Date) - $lastAttempt
            
            # Check if host meets alert criteria
            if ($failureCount -ge $FailureThreshold -and $daysSinceLastAttempt.Days -le $Days) {
                $alert = @{
                    Hostname = $failedHost.Hostname
                    Priority = $failedHost.Priority
                    FailureCount = $failureCount
                    LastAttempt = $failedHost.LastAttempt
                    LastError = $failedHost.LastError
                    DaysSinceLastAttempt = $daysSinceLastAttempt.Days
                    Recommendation = ""
                }
                
                # Add specific recommendations based on failure pattern
                if ($failureCount -ge 10) {
                    $alert.Recommendation = "CRITICAL: System has failed $failureCount times. Consider manual intervention or hardware replacement."
                } elseif ($failureCount -ge 5) {
                    $alert.Recommendation = "HIGH: System has failed $failureCount times. Investigate network connectivity and system status."
                } else {
                    $alert.Recommendation = "MEDIUM: System has failed $failureCount times. Monitor closely and consider manual check."
                }
                
                $alerts += $alert
            }
        }
        
        # Sort alerts by priority and failure count
        $alerts = $alerts | Sort-Object @{Expression = {$_.Priority -eq "critical"}; Descending = $true}, @{Expression = {$_.FailureCount}; Descending = $true}
        
        Write-Log "Generated $($alerts.Count) failed host alerts" -Level Info
        return $alerts
    }
    catch {
        Write-Log "Failed to generate failed host alerts: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Show-SchedulingStatus {
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "`n=== Scheduling Engine Status ===" -ForegroundColor Cyan
        
        # Get scheduling engine status
        $engineStatus = Get-SchedulingEngineStatus
        
        # Display engine status
        $statusColor = if ($engineStatus.IsRunning) { "Green" } else { "Red" }
        $statusText = if ($engineStatus.IsRunning) { "RUNNING" } else { "STOPPED" }
        
        Write-Host "Engine Status: " -NoNewline
        Write-Host $statusText -ForegroundColor $statusColor
        
        if ($engineStatus.IsRunning) {
            Write-Host "Start Time: $($engineStatus.StartTime)" -ForegroundColor Gray
            Write-Host "Uptime: $($engineStatus.Uptime)" -ForegroundColor Gray
        }
        
        # Display statistics
        Write-Host "`nStatistics:" -ForegroundColor Yellow
        Write-Host "  Total Scans Executed: $($engineStatus.Stats.TotalScansExecuted)" -ForegroundColor White
        Write-Host "  Successful Scans: $($engineStatus.Stats.SuccessfulScans)" -ForegroundColor Green
        Write-Host "  Failed Scans: $($engineStatus.Stats.FailedScans)" -ForegroundColor Red
        
        if ($engineStatus.Stats.TotalScansExecuted -gt 0) {
            $successRate = [math]::Round(($engineStatus.Stats.SuccessfulScans / $engineStatus.Stats.TotalScansExecuted) * 100, 2)
            Write-Host "  Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 80) { "Green" } elseif ($successRate -ge 60) { "Yellow" } else { "Red" })
        }
        
        if ($engineStatus.LastScanTime) {
            Write-Host "  Last Scan Time: $($engineStatus.LastScanTime)" -ForegroundColor Gray
        }
        
        if ($engineStatus.LastError) {
            Write-Host "  Last Error: $($engineStatus.LastError)" -ForegroundColor Red
        }
        
        # Display failed hosts summary
        $failedHosts = Get-FailedHosts
        $dueHosts = Get-HostsDueForScheduledScan
        
        Write-Host "`nFailed Hosts Summary:" -ForegroundColor Yellow
        Write-Host "  Total Failed Hosts: $($failedHosts.Count)" -ForegroundColor White
        Write-Host "  Critical Priority: $(($failedHosts | Where-Object { $_.Priority -eq 'critical' }).Count)" -ForegroundColor Red
        Write-Host "  Normal Priority: $(($failedHosts | Where-Object { $_.Priority -eq 'normal' }).Count)" -ForegroundColor Yellow
        Write-Host "  Low Priority: $(($failedHosts | Where-Object { $_.Priority -eq 'low' }).Count)" -ForegroundColor Green
        Write-Host "  Due for Scan: $($dueHosts.Count)" -ForegroundColor Cyan
        
        # Display configuration
        $schedulingConfig = Get-SchedulingConfiguration
        Write-Host "`nConfiguration:" -ForegroundColor Yellow
        Write-Host "  Scheduling Enabled: $($schedulingConfig.Enabled)" -ForegroundColor $(if ($schedulingConfig.Enabled) { "Green" } else { "Red" })
        Write-Host "  Default Interval: $($schedulingConfig.DefaultIntervalHours) hours" -ForegroundColor Gray
        Write-Host "  Critical Interval: $($schedulingConfig.CriticalIntervalHours) hours" -ForegroundColor Gray
        Write-Host "  Max Concurrent Scans: $($schedulingConfig.MaxConcurrentScheduledScans)" -ForegroundColor Gray
        
        Write-Host "`n" -NoNewline
    }
    catch {
        Write-Log "Failed to show scheduling status: $($_.Exception.Message)" -Level Error
    }
}

function Export-EnhancedReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("SchedulingOperations", "Windows11Readiness", "FailedHostAlerts", "All")]
        [string]$ReportType,
        
        [string]$OutputDirectory,
        [string]$Format = "JSON"
    )
    
    try {
        if (-not $OutputDirectory) {
            $OutputDirectory = Join-Path (Get-ScriptDirectory) "Reports"
        }
        
        # Create output directory if it doesn't exist
        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reports = @()
        
        switch ($ReportType) {
            "SchedulingOperations" {
                $report = Get-SchedulingOperationsReport
                if ($report) {
                    $outputPath = Join-Path $OutputDirectory "scheduling_operations_$timestamp.json"
                    $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputPath -Encoding UTF8
                    $reports += $outputPath
                }
            }
            "Windows11Readiness" {
                $report = Get-Windows11ReadinessProgressReport
                if ($report) {
                    $outputPath = Join-Path $OutputDirectory "windows11_readiness_$timestamp.json"
                    $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputPath -Encoding UTF8
                    $reports += $outputPath
                }
            }
            "FailedHostAlerts" {
                $alerts = Get-FailedHostAlerts
                if ($alerts.Count -gt 0) {
                    $outputPath = Join-Path $OutputDirectory "failed_host_alerts_$timestamp.json"
                    $alerts | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputPath -Encoding UTF8
                    $reports += $outputPath
                }
            }
            "All" {
                # Generate all reports
                $report = Get-SchedulingOperationsReport
                if ($report) {
                    $outputPath = Join-Path $OutputDirectory "scheduling_operations_$timestamp.json"
                    $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputPath -Encoding UTF8
                    $reports += $outputPath
                }
                
                $report = Get-Windows11ReadinessProgressReport
                if ($report) {
                    $outputPath = Join-Path $OutputDirectory "windows11_readiness_$timestamp.json"
                    $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputPath -Encoding UTF8
                    $reports += $outputPath
                }
                
                $alerts = Get-FailedHostAlerts
                if ($alerts.Count -gt 0) {
                    $outputPath = Join-Path $OutputDirectory "failed_host_alerts_$timestamp.json"
                    $alerts | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputPath -Encoding UTF8
                    $reports += $outputPath
                }
            }
        }
        
        if ($reports.Count -gt 0) {
            Write-Log "Exported $($reports.Count) report(s) to $OutputDirectory" -Level Success
            foreach ($reportPath in $reports) {
                Write-Host "Report exported: $reportPath" -ForegroundColor Green
            }
        } else {
            Write-Log "No reports generated" -Level Warning
        }
        
        return $reports
    }
    catch {
        Write-Log "Failed to export enhanced report: $($_.Exception.Message)" -Level Error
        return @()
    }
}

#endregion
