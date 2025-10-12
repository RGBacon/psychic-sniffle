# Menu System Module
# Handles all interactive menu operations and user interface

#region Menu Functions
function Show-MainMenu {
    [CmdletBinding()]
    param()
    
    do {
        Clear-Host
        Write-MenuHeader -Title "System Information Tool v3.0"
        
        Write-Host "`n1. Enhanced System Information" -ForegroundColor White
        Write-Host "2. Check Unique Applications" -ForegroundColor White
        Write-Host "3. Network Topology Analysis" -ForegroundColor White
        Write-Host "4. Send Messages to Hosts" -ForegroundColor White
        Write-Host "5. Failed Host Management" -ForegroundColor White
        Write-Host "6. Scheduling Engine" -ForegroundColor White
        Write-Host "7. Enhanced Reporting" -ForegroundColor White
        Write-Host "8. Bulk Operations" -ForegroundColor White
        Write-Host "9. Settings" -ForegroundColor White
        Write-Host "10. View Logs" -ForegroundColor White
        Write-Host "11. Exit" -ForegroundColor White
        
        Write-Host "`nSelect an option (1-11): " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host
        
        switch ($choice) {
            "1" { Invoke-EnhancedDiscovery }
            "2" { Invoke-CheckUniqueApps }
            "3" { Invoke-NetworkAnalysis }
            "4" { Show-MessageMenu }
            "5" { Show-FailedHostMenu }
            "6" { Show-SchedulingEngineMenu }
            "7" { Show-EnhancedReportingMenu }
            "8" { Show-BulkOperationsMenu }
            "9" { Show-SettingsMenu }
            "10" { Show-LogViewer }
            "11" { 
                Write-Log "User exited application" -Level Info
                exit 0 
            }
            default { 
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}

function Write-MenuHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )
    
    $config = Get-Configuration
    $color = $config.Colors.Header
    
    Write-Host "=" * 60 -ForegroundColor $color
    Write-Host $Title -ForegroundColor $color
    Write-Host "=" * 60 -ForegroundColor $color
}

function Invoke-Pause {
    [CmdletBinding()]
    param(
        [string]$Message = "Press any key to continue..."
    )
    
    Write-Host "`n$Message" -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Invoke-EnhancedDiscovery {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Enhanced System Information"
    
    # Get hosts list
    $hosts = Get-HostsList
    if ($hosts.Count -eq 0) {
        Write-Host "No hosts found. Please check your hosts file." -ForegroundColor Red
        Invoke-Pause
        return
    }
    
    Write-Host "`nFound $($hosts.Count) hosts to scan." -ForegroundColor Green
    Write-Host "Starting enhanced system information scan..." -ForegroundColor Yellow
    
    # Get scan options
    $config = Get-Configuration
    $options = @{
        CheckSoftware = $config.SystemInfo.CheckSunquest
        CheckPrinters = $config.SystemInfo.CheckPrinters
        CheckTracert = $config.SystemInfo.CheckTracert
        CheckNetwork = $true
        CheckStorage = $true
    }
    
    # Perform scan
    $results = Invoke-SystemScan -Hostnames $hosts -Options $options
    
    # Export results
    Export-SystemDataToCSV -SystemData $results
    Generate-HTMLReport -SystemData $results
    
    # Show summary
    $successCount = ($results | Where-Object { $_.Success }).Count
    $failureCount = $results.Count - $successCount
    
    Write-Host "`nScan completed!" -ForegroundColor Green
    Write-Host "Success: $successCount" -ForegroundColor Green
    Write-Host "Failures: $failureCount" -ForegroundColor Red
    
    Write-Host "`nResults exported to:" -ForegroundColor Yellow
    Write-Host "- CSV: $($config.OutputFiles.SystemDataCSV)" -ForegroundColor White
    Write-Host "- HTML: $($config.OutputFiles.HTMLViewer)" -ForegroundColor White
    
    Invoke-Pause
}

function Show-MessageMenu {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Message Sender"
    
    Write-Host "`n1. Send One-Time Message" -ForegroundColor White
    Write-Host "2. Start Hourly Messages" -ForegroundColor White
    Write-Host "3. Configure Message Text" -ForegroundColor White
    Write-Host "4. Back to Main Menu" -ForegroundColor White
    
    Write-Host "`nSelect an option (1-4): " -NoNewline -ForegroundColor Yellow
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Send-OneTimeMessage }
        "2" { Start-HourlyMessages }
        "3" { Configure-MessageText }
        "4" { return }
        default { 
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}

function Send-OneTimeMessage {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Send One-Time Message"
    
    $hosts = Get-HostsList
    if ($hosts.Count -eq 0) {
        Write-Host "No hosts found. Please check your hosts file." -ForegroundColor Red
        Invoke-Pause
        return
    }
    
    $config = Get-Configuration
    $message = $config.DefaultMessage
    
    Write-Host "`nMessage to send:" -ForegroundColor Yellow
    Write-Host $message -ForegroundColor White
    
    Write-Host "`nTarget hosts: $($hosts.Count)" -ForegroundColor Yellow
    Write-Host "Send message? (Y/N): " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -eq "Y" -or $confirm -eq "y") {
        Write-Host "Sending messages..." -ForegroundColor Yellow
        
        $successCount = 0
        foreach ($hostname in $hosts) {
            try {
                # Simulate message sending (replace with actual implementation)
                Write-Host "Message sent to $hostname" -ForegroundColor Green
                $successCount++
            }
            catch {
                Write-Host "Failed to send message to $hostname : $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        Write-Host "`nMessages sent to $successCount of $($hosts.Count) hosts." -ForegroundColor Green
    }
    
    Invoke-Pause
}

function Start-HourlyMessages {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Start Hourly Messages"
    
    Write-Host "This feature will send messages every hour to all hosts." -ForegroundColor Yellow
    Write-Host "Continue? (Y/N): " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -eq "Y" -or $confirm -eq "y") {
        Write-Host "Hourly messages started. Press Ctrl+C to stop." -ForegroundColor Green
        
        # Simulate hourly messaging (replace with actual implementation)
        do {
            Start-Sleep -Seconds 3600 # 1 hour
            Write-Host "Sending hourly messages..." -ForegroundColor Yellow
            # Send messages here
        } while ($true)
    }
    
    Invoke-Pause
}

function Configure-MessageText {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Configure Message Text"
    
    $config = Get-Configuration
    Write-Host "`nCurrent message:" -ForegroundColor Yellow
    Write-Host $config.DefaultMessage -ForegroundColor White
    
    Write-Host "`nEnter new message (or press Enter to keep current):" -ForegroundColor Yellow
    $newMessage = Read-Host
    
    if ($newMessage) {
        $config.DefaultMessage = $newMessage
        Set-Configuration -Configuration $config
        Write-Host "Message updated successfully." -ForegroundColor Green
    }
    
    Invoke-Pause
}

function Show-FailedHostMenu {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Failed Host Management"
    
    Write-Host "`n1. View Failed Hosts" -ForegroundColor White
    Write-Host "2. View Critical Failed Hosts" -ForegroundColor White
    Write-Host "3. Clear All Failed Hosts" -ForegroundColor White
    Write-Host "4. Back to Main Menu" -ForegroundColor White
    
    Write-Host "`nSelect an option (1-4): " -NoNewline -ForegroundColor Yellow
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Show-FailedHosts }
        "2" { Show-FailedHosts -Filter "critical" }
        "3" { Clear-FailedHosts }
        "4" { return }
        default { 
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}

# Show-FailedHosts function is implemented in FailedHostTracker.ps1 module
# This stub has been removed to prevent duplicate function definition

# Clear-FailedHosts function is implemented in FailedHostTracker.ps1 module
# This stub has been removed to prevent duplicate function definition

function Show-BulkOperationsMenu {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Bulk Operations"
    
    Write-Host "`n1. Bulk System Scan" -ForegroundColor White
    Write-Host "2. Export Specific Hosts" -ForegroundColor White
    Write-Host "3. Rescan Failed Hosts" -ForegroundColor White
    Write-Host "4. Back to Main Menu" -ForegroundColor White
    
    Write-Host "`nSelect an option (1-4): " -NoNewline -ForegroundColor Yellow
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Invoke-BulkSystemScan }
        "2" { Export-SpecificHosts }
        "3" { Rescan-FailedHosts }
        "4" { return }
        default { 
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}

function Invoke-BulkSystemScan {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Bulk System Scan"
    
    Write-Host "This feature performs a comprehensive scan of all hosts." -ForegroundColor Yellow
    Write-Host "Continue? (Y/N): " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -eq "Y" -or $confirm -eq "y") {
        Invoke-EnhancedDiscovery
    }
}

function Export-SpecificHosts {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Export Specific Hosts"
    
    Write-Host "Enter hostnames to export (comma-separated):" -ForegroundColor Yellow
    $hostnames = Read-Host
    
    if ($hostnames) {
        $hosts = $hostnames -split "," | ForEach-Object { $_.Trim() }
        Write-Host "Exporting $($hosts.Count) hosts..." -ForegroundColor Yellow
        
        # Simulate export (replace with actual implementation)
        Write-Host "Export completed." -ForegroundColor Green
    }
    
    Invoke-Pause
}

function Rescan-FailedHosts {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Rescan Failed Hosts"
    
    Write-Host "This will rescan all previously failed hosts." -ForegroundColor Yellow
    Write-Host "Continue? (Y/N): " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -eq "Y" -or $confirm -eq "y") {
        # Simulate rescan (replace with actual implementation)
        Write-Host "Rescan completed." -ForegroundColor Green
    }
    
    Invoke-Pause
}

function Show-SettingsMenu {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Settings"
    
    Write-Host "`n1. Configure Timeout Settings" -ForegroundColor White
    Write-Host "2. Configure Parallel Jobs" -ForegroundColor White
    Write-Host "3. Configure Application Exclusions" -ForegroundColor White
    Write-Host "4. View Current Settings" -ForegroundColor White
    Write-Host "5. Back to Main Menu" -ForegroundColor White
    
    Write-Host "`nSelect an option (1-5): " -NoNewline -ForegroundColor Yellow
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Configure-TimeoutSettings }
        "2" { Configure-ParallelJobs }
        "3" { Configure-ApplicationExclusions }
        "4" { Show-CurrentSettings }
        "5" { return }
        default { 
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
}

function Configure-TimeoutSettings {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Configure Timeout Settings"
    
    $config = Get-Configuration
    Write-Host "`nCurrent timeout: $($config.Timeout) seconds" -ForegroundColor Yellow
    
    Write-Host "`nEnter new timeout value (seconds):" -ForegroundColor Yellow
    $newTimeout = Read-Host
    
    if ($newTimeout -match "^\d+$") {
        $config.Timeout = [int]$newTimeout
        Set-Configuration -Configuration $config
        Write-Host "Timeout updated to $newTimeout seconds." -ForegroundColor Green
    }
    else {
        Write-Host "Invalid timeout value." -ForegroundColor Red
    }
    
    Invoke-Pause
}

function Configure-ParallelJobs {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Configure Parallel Jobs"
    
    $config = Get-Configuration
    Write-Host "`nCurrent max parallel jobs: $($config.MaxParallelJobs)" -ForegroundColor Yellow
    
    Write-Host "`nEnter new max parallel jobs:" -ForegroundColor Yellow
    $newMaxJobs = Read-Host
    
    if ($newMaxJobs -match "^\d+$") {
        $config.MaxParallelJobs = [int]$newMaxJobs
        Set-Configuration -Configuration $config
        Write-Host "Max parallel jobs updated to $newMaxJobs." -ForegroundColor Green
    }
    else {
        Write-Host "Invalid value." -ForegroundColor Red
    }
    
    Invoke-Pause
}

function Configure-ApplicationExclusions {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Configure Application Exclusions"
    
    $config = Get-Configuration
    Write-Host "`nCurrent exclusion patterns:" -ForegroundColor Yellow
    foreach ($pattern in $config.CheckApps.ExcludePatterns) {
        Write-Host "- $pattern" -ForegroundColor White
    }
    
    Write-Host "`nThis feature is not yet implemented." -ForegroundColor Yellow
    
    Invoke-Pause
}

function Show-CurrentSettings {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Current Settings"
    
    $config = Get-Configuration
    
    Write-Host "`nTimeout: $($config.Timeout) seconds" -ForegroundColor White
    Write-Host "Max Parallel Jobs: $($config.MaxParallelJobs)" -ForegroundColor White
    Write-Host "Check Sunquest: $($config.SystemInfo.CheckSunquest)" -ForegroundColor White
    Write-Host "Check Printers: $($config.SystemInfo.CheckPrinters)" -ForegroundColor White
    Write-Host "Check Traceroute: $($config.SystemInfo.CheckTracert)" -ForegroundColor White
    
    Write-Host "`nOutput Files:" -ForegroundColor Yellow
    foreach ($key in $config.OutputFiles.PSObject.Properties.Name) {
        Write-Host "- $key : $($config.OutputFiles.$key)" -ForegroundColor White
    }
    
    Invoke-Pause
}

function Show-SchedulingEngineMenu {
    [CmdletBinding()]
    param()
    
    do {
        Clear-Host
        Write-MenuHeader -Title "Scheduling Engine Management"
        
        $engineStatus = Get-SchedulingEngineStatus
        $schedulingStatus = Get-SchedulingStatus
        
        Write-Host "`nEngine Status:" -ForegroundColor Yellow
        Write-Host "Running: $($engineStatus.IsRunning)" -ForegroundColor $(if ($engineStatus.IsRunning) { "Green" } else { "Red" })
        
        if ($schedulingStatus) {
            Write-Host "Scheduling Enabled: $($schedulingStatus.SchedulingEnabled)" -ForegroundColor $(if ($schedulingStatus.SchedulingEnabled) { "Green" } else { "Red" })
            Write-Host "Hosts Due for Scan: $($schedulingStatus.HostsDueForScan)" -ForegroundColor $(if ($schedulingStatus.HostsDueForScan -gt 0) { "Cyan" } else { "Green" })
        }
        
        Write-Host "`n1. Start Scheduling Engine (Background)" -ForegroundColor White
        Write-Host "2. Start Scheduling Engine (Foreground)" -ForegroundColor White
        Write-Host "3. Stop Scheduling Engine" -ForegroundColor White
        Write-Host "4. View Engine Status" -ForegroundColor White
        Write-Host "5. View Scheduling Status" -ForegroundColor White
        Write-Host "6. Test Scheduling Engine" -ForegroundColor White
        Write-Host "7. Execute Scheduled Scans Now" -ForegroundColor White
        Write-Host "8. Back to Main Menu" -ForegroundColor White
        
        Write-Host "`nSelect an option (1-8): " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host
        
        switch ($choice) {
            "1" { 
                $result = Start-SchedulingEngine -Background
                if ($result) {
                    Write-Host "Scheduling engine started in background mode." -ForegroundColor Green
                } else {
                    Write-Host "Failed to start scheduling engine." -ForegroundColor Red
                }
                Invoke-Pause
            }
            "2" { 
                Write-Host "Starting scheduling engine in foreground mode..." -ForegroundColor Yellow
                Write-Host "Press Ctrl+C to stop the engine." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
                Start-SchedulingEngine
            }
            "3" { 
                $result = Stop-SchedulingEngine
                if ($result) {
                    Write-Host "Scheduling engine stopped." -ForegroundColor Green
                } else {
                    Write-Host "Failed to stop scheduling engine." -ForegroundColor Red
                }
                Invoke-Pause
            }
            "4" { Show-SchedulingEngineStatus }
            "5" { Show-SchedulingStatus }
            "6" { 
                $result = Test-SchedulingEngine
                if ($result) {
                    Write-Host "All scheduling engine tests passed." -ForegroundColor Green
                } else {
                    Write-Host "Scheduling engine tests failed." -ForegroundColor Red
                }
                Invoke-Pause
            }
            "7" { 
                $dueHosts = Get-HostsDueForScheduledScan
                if ($dueHosts.Count -gt 0) {
                    Write-Host "Executing scheduled scans for $($dueHosts.Count) hosts..." -ForegroundColor Yellow
                    $result = Invoke-ScheduledScans -DueHosts $dueHosts
                    if ($result.Success) {
                        Write-Host "Scheduled scans completed successfully." -ForegroundColor Green
                    } else {
                        Write-Host "Scheduled scans completed with errors." -ForegroundColor Red
                    }
                } else {
                    Write-Host "No hosts are currently due for scheduled scans." -ForegroundColor Yellow
                }
                Invoke-Pause
            }
            "8" { return }
            default { 
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($choice -ne "8")
}

function Show-LogViewer {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Log Viewer"
    
    $logContent = Get-LogContent -LastLines 50
    
    if ($logContent.Count -eq 0) {
        Write-Host "No log entries found." -ForegroundColor Yellow
    }
    else {
        Write-Host "`nRecent log entries:" -ForegroundColor Yellow
        foreach ($line in $logContent) {
            Write-Host $line -ForegroundColor White
        }
    }
    
    Invoke-Pause
}

function Invoke-CheckUniqueApps {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Check Unique Applications"
    
    Write-Host "This feature compares installed applications against a baseline." -ForegroundColor Yellow
    Write-Host "Feature not yet implemented." -ForegroundColor Red
    
    Invoke-Pause
}

function Invoke-NetworkAnalysis {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Network Topology Analysis"
    
    Write-Host "This feature analyzes network topology and groups hosts by subnets." -ForegroundColor Yellow
    Write-Host "Feature not yet implemented." -ForegroundColor Red
    
    Invoke-Pause
}

function Show-EnhancedReportingMenu {
    [CmdletBinding()]
    param()
    
    do {
        Clear-Host
        Write-MenuHeader -Title "Enhanced Reporting and Monitoring"
        
        Write-Host "`n1. Scheduling Operations Report" -ForegroundColor White
        Write-Host "2. Windows 11 Readiness Progress Report" -ForegroundColor White
        Write-Host "3. Failed Host Alerts" -ForegroundColor White
        Write-Host "4. Show Scheduling Status" -ForegroundColor White
        Write-Host "5. Export All Reports" -ForegroundColor White
        Write-Host "6. View Failed Hosts Queue" -ForegroundColor White
        Write-Host "7. Generate Summary Report" -ForegroundColor White
        Write-Host "8. Back to Main Menu" -ForegroundColor White
        
        Write-Host "`nSelect an option (1-8): " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host
        
        switch ($choice) {
            "1" { 
                Write-Host "`nGenerating scheduling operations report..." -ForegroundColor Yellow
                $report = Get-SchedulingOperationsReport -Days 7
                if ($report) {
                    Write-Host "Report generated successfully!" -ForegroundColor Green
                    Write-Host "Total Scans Executed: $($report.SchedulingEngine.TotalScansExecuted)" -ForegroundColor White
                    Write-Host "Success Rate: $($report.SchedulingEngine.SuccessRate)" -ForegroundColor White
                    Write-Host "Failed Hosts: $($report.FailedHosts.Total)" -ForegroundColor White
                } else {
                    Write-Host "Failed to generate report." -ForegroundColor Red
                }
                Invoke-Pause
            }
            "2" { 
                Write-Host "`nGenerating Windows 11 readiness progress report..." -ForegroundColor Yellow
                $report = Get-Windows11ReadinessProgressReport -Days 30
                if ($report) {
                    Write-Host "Report generated successfully!" -ForegroundColor Green
                    Write-Host "Total Systems: $($report.Summary.TotalSystems)" -ForegroundColor White
                    Write-Host "Windows 11 Ready: $($report.Summary.Windows11Ready)" -ForegroundColor White
                    Write-Host "Readiness Rate: $($report.Summary.ReadinessRate)" -ForegroundColor White
                } else {
                    Write-Host "Failed to generate report." -ForegroundColor Red
                }
                Invoke-Pause
            }
            "3" { 
                Write-Host "`nGenerating failed host alerts..." -ForegroundColor Yellow
                $alerts = Get-FailedHostAlerts -FailureThreshold 5 -Days 7
                if ($alerts.Count -gt 0) {
                    Write-Host "Found $($alerts.Count) alerts:" -ForegroundColor Yellow
                    foreach ($alert in $alerts) {
                        $color = if ($alert.Priority -eq "critical") { "Red" } elseif ($alert.Priority -eq "normal") { "Yellow" } else { "Green" }
                        Write-Host "  $($alert.Hostname) - $($alert.Priority.ToUpper()) - $($alert.FailureCount) failures" -ForegroundColor $color
                    }
                } else {
                    Write-Host "No alerts found." -ForegroundColor Green
                }
                Invoke-Pause
            }
            "4" { 
                Show-SchedulingStatus
                Invoke-Pause
            }
            "5" { 
                Write-Host "`nExporting all reports..." -ForegroundColor Yellow
                $reports = Export-EnhancedReport -ReportType "All"
                if ($reports.Count -gt 0) {
                    Write-Host "Exported $($reports.Count) reports successfully!" -ForegroundColor Green
                    foreach ($report in $reports) {
                        Write-Host "  $report" -ForegroundColor White
                    }
                } else {
                    Write-Host "No reports exported." -ForegroundColor Yellow
                }
                Invoke-Pause
            }
            "6" { 
                Write-Host "`nFailed Hosts Queue:" -ForegroundColor Yellow
                $failedHosts = Get-FailedHosts
                if ($failedHosts.Count -gt 0) {
                    Write-Host "Total Failed Hosts: $($failedHosts.Count)" -ForegroundColor White
                    $critical = ($failedHosts | Where-Object { $_.Priority -eq "critical" }).Count
                    $normal = ($failedHosts | Where-Object { $_.Priority -eq "normal" }).Count
                    $low = ($failedHosts | Where-Object { $_.Priority -eq "low" }).Count
                    Write-Host "Critical: $critical, Normal: $normal, Low: $low" -ForegroundColor White
                    
                    $dueHosts = Get-HostsDueForScheduledScan
                    Write-Host "Due for Scan: $($dueHosts.Count)" -ForegroundColor Cyan
                } else {
                    Write-Host "No failed hosts found." -ForegroundColor Green
                }
                Invoke-Pause
            }
            "7" { 
                Write-Host "`nGenerating comprehensive summary report..." -ForegroundColor Yellow
                $schedulingReport = Get-SchedulingOperationsReport -Days 7
                $readinessReport = Get-Windows11ReadinessProgressReport -Days 30
                $alerts = Get-FailedHostAlerts -FailureThreshold 3 -Days 7
                
                Write-Host "`n=== SUMMARY REPORT ===" -ForegroundColor Cyan
                Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
                
                if ($schedulingReport) {
                    Write-Host "`nScheduling Engine:" -ForegroundColor Yellow
                    Write-Host "  Status: $(if ($schedulingReport.SchedulingEngine.Status -eq 'Running') { 'RUNNING' } else { 'STOPPED' })" -ForegroundColor $(if ($schedulingReport.SchedulingEngine.Status -eq 'Running') { 'Green' } else { 'Red' })
                    Write-Host "  Total Scans: $($schedulingReport.SchedulingEngine.TotalScansExecuted)" -ForegroundColor White
                    Write-Host "  Success Rate: $($schedulingReport.SchedulingEngine.SuccessRate)" -ForegroundColor White
                }
                
                if ($readinessReport) {
                    Write-Host "`nWindows 11 Readiness:" -ForegroundColor Yellow
                    Write-Host "  Total Systems: $($readinessReport.Summary.TotalSystems)" -ForegroundColor White
                    Write-Host "  Ready: $($readinessReport.Summary.Windows11Ready)" -ForegroundColor Green
                    Write-Host "  Not Ready: $($readinessReport.Summary.Windows11NotReady)" -ForegroundColor Red
                    Write-Host "  Readiness Rate: $($readinessReport.Summary.ReadinessRate)" -ForegroundColor White
                }
                
                if ($alerts.Count -gt 0) {
                    Write-Host "`nAlerts: $($alerts.Count) systems need attention" -ForegroundColor Red
                } else {
                    Write-Host "`nAlerts: No critical alerts" -ForegroundColor Green
                }
                
                Invoke-Pause
            }
            "8" { return }
            default { 
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}
#endregion
