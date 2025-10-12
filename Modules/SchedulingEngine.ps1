# Scheduling Engine Module
# Handles automated re-scanning of failed hosts based on scheduling configuration

#region Scheduling Engine Variables
$script:SchedulingEngineRunning = $false
$script:SchedulingEngineJob = $null
$script:SchedulingEngineStartTime = $null
$script:LastSchedulingCheck = $null
$script:SchedulingEngineStats = @{
    TotalScansExecuted = 0
    SuccessfulScans = 0
    FailedScans = 0
    LastScanTime = $null
    LastError = $null
}
#endregion

#region Scheduling Engine Functions
function Start-SchedulingEngine {
    [CmdletBinding()]
    param(
        [switch]$Background,
        [int]$CheckIntervalMinutes = 5
    )
    
    try {
        $schedulingConfig = Get-SchedulingConfiguration
        
        # Check if scheduling is enabled
        if (-not $schedulingConfig.Enabled) {
            Write-Log "Scheduling is disabled. Cannot start scheduling engine." -Level Warning
            return $false
        }
        
        # Check if engine is already running
        if ($script:SchedulingEngineRunning) {
            Write-Log "Scheduling engine is already running." -Level Warning
            return $true
        }
        
        Write-Log "Starting scheduling engine..." -Level Info
        
        # Initialize scheduling engine state
        $script:SchedulingEngineRunning = $true
        $script:SchedulingEngineStartTime = Get-Date
        $script:LastSchedulingCheck = Get-Date
        $script:SchedulingEngineStats = @{
            TotalScansExecuted = 0
            SuccessfulScans = 0
            FailedScans = 0
            LastScanTime = $null
            LastError = $null
        }
        
        if ($Background) {
            # Start background job
            $script:SchedulingEngineJob = Start-Job -ScriptBlock {
                param($CheckIntervalMinutes)
                
                # Import required modules
                $scriptPath = $using:PSScriptRoot
                $modulesPath = Join-Path $scriptPath "Modules"
                
                # Load modules
                Get-ChildItem -Path $modulesPath -Filter "*.ps1" | ForEach-Object {
                    . $_.FullName
                }
                
                # Initialize configuration
                Initialize-Configuration
                
                while ($true) {
                    try {
                        # Check for hosts due for scan
                        $dueHosts = Get-HostsDueForScheduledScan
                        
                        if ($dueHosts.Count -gt 0) {
                            Write-Log "Found $($dueHosts.Count) hosts due for scheduled scan" -Level Info
                            
                            # Execute scheduled scans
                            $result = Invoke-ScheduledScans -DueHosts $dueHosts
                            
                            if ($result.Success) {
                                Write-Log "Scheduled scans completed successfully" -Level Success
                            } else {
                                Write-Log "Scheduled scans completed with errors: $($result.Error)" -Level Warning
                            }
                        }
                        
                        # Wait for next check
                        Start-Sleep -Seconds ($CheckIntervalMinutes * 60)
                    }
                    catch {
                        Write-Log "Error in scheduling engine background job: $($_.Exception.Message)" -Level Error
                        Start-Sleep -Seconds 60  # Wait 1 minute before retrying
                    }
                }
            } -ArgumentList $CheckIntervalMinutes
            
            Write-Log "Scheduling engine started in background (Job ID: $($script:SchedulingEngineJob.Id))" -Level Success
        } else {
            # Start foreground monitoring
            Write-Log "Scheduling engine started in foreground mode" -Level Success
            Write-Host "Scheduling engine is running. Press Ctrl+C to stop." -ForegroundColor Green
            
            try {
                while ($script:SchedulingEngineRunning) {
                    # Check for hosts due for scan
                    $dueHosts = Get-HostsDueForScheduledScan
                    
                    if ($dueHosts.Count -gt 0) {
                        Write-Log "Found $($dueHosts.Count) hosts due for scheduled scan" -Level Info
                        
                        # Execute scheduled scans
                        $result = Invoke-ScheduledScans -DueHosts $dueHosts
                        
                        if ($result.Success) {
                            Write-Log "Scheduled scans completed successfully" -Level Success
                        } else {
                            Write-Log "Scheduled scans completed with errors: $($result.Error)" -Level Warning
                        }
                    }
                    
                    # Wait for next check
                    Start-Sleep -Seconds ($CheckIntervalMinutes * 60)
                }
            }
            catch [System.Management.Automation.PipelineStoppedException] {
                Write-Log "Scheduling engine stopped by user" -Level Info
            }
            catch {
                Write-Log "Error in scheduling engine: $($_.Exception.Message)" -Level Error
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to start scheduling engine: $($_.Exception.Message)" -Level Error
        $script:SchedulingEngineRunning = $false
        return $false
    }
}

function Stop-SchedulingEngine {
    [CmdletBinding()]
    param()
    
    try {
        if (-not $script:SchedulingEngineRunning) {
            Write-Log "Scheduling engine is not running." -Level Warning
            return $true
        }
        
        Write-Log "Stopping scheduling engine..." -Level Info
        
        # Stop background job if running
        if ($script:SchedulingEngineJob) {
            Stop-Job -Job $script:SchedulingEngineJob
            Remove-Job -Job $script:SchedulingEngineJob
            $script:SchedulingEngineJob = $null
        }
        
        # Update state
        $script:SchedulingEngineRunning = $false
        $script:SchedulingEngineStartTime = $null
        
        Write-Log "Scheduling engine stopped successfully" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to stop scheduling engine: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Get-SchedulingEngineStatus {
    [CmdletBinding()]
    param()
    
    $status = @{
        IsRunning = $script:SchedulingEngineRunning
        StartTime = $script:SchedulingEngineStartTime
        LastCheck = $script:LastSchedulingCheck
        BackgroundJob = $script:SchedulingEngineJob
        Stats = $script:SchedulingEngineStats
    }
    
    if ($script:SchedulingEngineJob) {
        $status.JobState = $script:SchedulingEngineJob.State
        $status.JobId = $script:SchedulingEngineJob.Id
    }
    
    return $status
}

function Invoke-ScheduledScans {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$DueHosts
    )
    
    try {
        $schedulingConfig = Get-SchedulingConfiguration
        $maxConcurrent = $schedulingConfig.MaxConcurrentScheduledScans
        $conflictResolution = $schedulingConfig.ConflictResolution
        
        Write-Log "Starting scheduled scans for $($DueHosts.Count) hosts" -Level Info
        
        # Check for manual scan conflicts
        if ($conflictResolution.SkipIfManualScanInProgress) {
            # This would need integration with the main script to check if manual scans are running
            # For now, we'll proceed with scheduled scans
            Write-Log "Manual scan conflict check not implemented yet" -Level Info
        }
        
        # Group hosts by priority for processing
        $hostsByPriority = $DueHosts | Group-Object Priority | Sort-Object { 
            switch ($_.Name) {
                "critical" { 1 }
                "normal" { 2 }
                "low" { 3 }
                default { 4 }
            }
        }
        
        $totalScanned = 0
        $successfulScans = 0
        $failedScans = 0
        $errors = @()
        
        foreach ($priorityGroup in $hostsByPriority) {
            $priority = $priorityGroup.Name
            $hosts = $priorityGroup.Group
            
            Write-Log "Processing $($hosts.Count) hosts with priority: $priority" -Level Info
            
            # Process hosts in batches based on max concurrent scans
            $batches = @()
            for ($i = 0; $i -lt $hosts.Count; $i += $maxConcurrent) {
                $batch = $hosts[$i..([Math]::Min($i + $maxConcurrent - 1, $hosts.Count - 1))]
                $batches += ,$batch
            }
            
            foreach ($batch in $batches) {
                Write-Log "Processing batch of $($batch.Count) hosts" -Level Info
                
                # Execute scans for this batch
                $batchResults = Invoke-BatchScheduledScans -Hosts $batch
                
                $totalScanned += $batchResults.TotalScanned
                $successfulScans += $batchResults.SuccessfulScans
                $failedScans += $batchResults.FailedScans
                
                if ($batchResults.Errors.Count -gt 0) {
                    $errors += $batchResults.Errors
                }
                
                # Update scheduling metadata for processed hosts
                foreach ($hostItem in $batch) {
                    Update-HostSchedulingMetadata -Hostname $hostItem.Hostname
                }
                
                # Brief pause between batches
                Start-Sleep -Seconds 2
            }
        }
        
        # Update engine statistics
        $script:SchedulingEngineStats.TotalScansExecuted += $totalScanned
        $script:SchedulingEngineStats.SuccessfulScans += $successfulScans
        $script:SchedulingEngineStats.FailedScans += $failedScans
        $script:SchedulingEngineStats.LastScanTime = Get-Date
        
        if ($errors.Count -gt 0) {
            $script:SchedulingEngineStats.LastError = $errors[0]
        }
        
        $result = @{
            Success = ($errors.Count -eq 0)
            TotalScanned = $totalScanned
            SuccessfulScans = $successfulScans
            FailedScans = $failedScans
            Errors = $errors
        }
        
        Write-Log "Scheduled scans completed: $successfulScans successful, $failedScans failed" -Level Info
        
        return $result
    }
    catch {
        $errorMsg = "Failed to execute scheduled scans: $($_.Exception.Message)"
        Write-Log $errorMsg -Level Error
        
        $script:SchedulingEngineStats.LastError = $errorMsg
        
        return @{
            Success = $false
            TotalScanned = 0
            SuccessfulScans = 0
            FailedScans = 0
            Errors = @($errorMsg)
        }
    }
}

function Invoke-BatchScheduledScans {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Hosts
    )
    
    try {
        $totalScanned = 0
        $successfulScans = 0
        $failedScans = 0
        $errors = @()
        
        foreach ($hostItem in $Hosts) {
            try {
                Write-Log "Executing scheduled scan for host: $($hostItem.Hostname)" -Level Info
                
                # Attempt to connect and gather system information
                $scanResult = Invoke-ScheduledHostScan -Hostname $hostItem.Hostname
                
                $totalScanned++
                
                if ($scanResult.Success) {
                    $successfulScans++
                    Write-Log "Scheduled scan successful for host: $($hostItem.Hostname)" -Level Success
                    
                    # Remove host from failed hosts list since scan was successful
                    Remove-FailedHost -Hostname $hostItem.Hostname
                } else {
                    $failedScans++
                    $errorMsg = "Scheduled scan failed for host $($hostItem.Hostname): $($scanResult.Error)"
                    Write-Log $errorMsg -Level Warning
                    $errors += $errorMsg
                    
                    # Update failed host entry
                    Add-FailedHost -Hostname $hostItem.Hostname -Error $scanResult.Error -Priority $hostItem.Priority
                }
            }
            catch {
                $failedScans++
                $errorMsg = "Error during scheduled scan for host $($hostItem.Hostname): $($_.Exception.Message)"
                Write-Log $errorMsg -Level Error
                $errors += $errorMsg
            }
        }
        
        return @{
            TotalScanned = $totalScanned
            SuccessfulScans = $successfulScans
            FailedScans = $failedScans
            Errors = $errors
        }
    }
    catch {
        $errorMsg = "Failed to execute batch scheduled scans: $($_.Exception.Message)"
        Write-Log $errorMsg -Level Error
        
        return @{
            TotalScanned = 0
            SuccessfulScans = 0
            FailedScans = 0
            Errors = @($errorMsg)
        }
    }
}

function Invoke-ScheduledHostScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )
    
    try {
        # Import the SystemInfo module functions
        # This is a simplified version - in practice, you'd want to call the actual system info functions
        
        # Test basic connectivity first (PowerShell 5.1 compatible)
        $pingResult = Test-Connection -ComputerName $Hostname -Count 1 -Quiet -ErrorAction SilentlyContinue
        
        if (-not $pingResult) {
            return @{
                Success = $false
                Error = "Host $Hostname is not reachable"
            }
        }
        
        # Attempt WMI connection
        try {
            $wmiResult = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Hostname -ErrorAction Stop
            if ($wmiResult) {
                return @{
                    Success = $true
                    Error = $null
                }
            }
        }
        catch {
            return @{
                Success = $false
                Error = "WMI connection failed: $($_.Exception.Message)"
            }
        }
        
        return @{
            Success = $false
            Error = "Unknown error during scheduled scan"
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Show-SchedulingEngineStatus {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Scheduling Engine Status"
    
    $status = Get-SchedulingEngineStatus
    
    Write-Host "`nEngine Status:" -ForegroundColor Yellow
    Write-Host "Running: $($status.IsRunning)" -ForegroundColor $(if ($status.IsRunning) { "Green" } else { "Red" })
    
    if ($status.StartTime) {
        $uptime = (Get-Date) - $status.StartTime
        Write-Host "Start Time: $($status.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
        Write-Host "Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes" -ForegroundColor White
    }
    
    if ($status.LastCheck) {
        Write-Host "Last Check: $($status.LastCheck.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
    }
    
    if ($status.BackgroundJob) {
        Write-Host "`nBackground Job:" -ForegroundColor Yellow
        Write-Host "Job ID: $($status.JobId)" -ForegroundColor White
        Write-Host "Job State: $($status.JobState)" -ForegroundColor White
    }
    
    Write-Host "`nStatistics:" -ForegroundColor Yellow
    Write-Host "Total Scans Executed: $($status.Stats.TotalScansExecuted)" -ForegroundColor White
    Write-Host "Successful Scans: $($status.Stats.SuccessfulScans)" -ForegroundColor Green
    Write-Host "Failed Scans: $($status.Stats.FailedScans)" -ForegroundColor Red
    
    if ($status.Stats.LastScanTime) {
        Write-Host "Last Scan Time: $($status.Stats.LastScanTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
    }
    
    if ($status.Stats.LastError) {
        Write-Host "`nLast Error:" -ForegroundColor Yellow
        Write-Host $status.Stats.LastError -ForegroundColor Red
    }
    
    # Show current scheduling status
    $schedulingStatus = Get-SchedulingStatus
    if ($schedulingStatus) {
        Write-Host "`nScheduling Configuration:" -ForegroundColor Yellow
        Write-Host "Scheduling Enabled: $($schedulingStatus.SchedulingEnabled)" -ForegroundColor $(if ($schedulingStatus.SchedulingEnabled) { "Green" } else { "Red" })
        Write-Host "Hosts Due for Scan: $($schedulingStatus.HostsDueForScan)" -ForegroundColor $(if ($schedulingStatus.HostsDueForScan -gt 0) { "Cyan" } else { "Green" })
        Write-Host "Max Concurrent Scans: $($schedulingStatus.MaxConcurrentScans)" -ForegroundColor White
    }
    
    Invoke-Pause
}

function Test-SchedulingEngine {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Testing scheduling engine functionality..." -Level Info
        
        # Test 1: Check if scheduling configuration is valid
        $schedulingConfig = Get-SchedulingConfiguration
        if (-not $schedulingConfig) {
            Write-Log "Scheduling configuration test failed" -Level Error
            return $false
        }
        Write-Log "Scheduling configuration test passed" -Level Success
        
        # Test 2: Check if failed hosts can be retrieved
        $failedHosts = Get-FailedHosts
        Write-Log "Failed hosts retrieval test passed ($($failedHosts.Count) hosts found)" -Level Success
        
        # Test 3: Check if hosts due for scan can be identified
        $dueHosts = Get-HostsDueForScheduledScan
        Write-Log "Due hosts identification test passed ($($dueHosts.Count) hosts due)" -Level Success
        
        # Test 4: Test scheduling status retrieval
        $status = Get-SchedulingStatus
        if ($status) {
            Write-Log "Scheduling status test passed" -Level Success
        } else {
            Write-Log "Scheduling status test failed" -Level Error
            return $false
        }
        
        # Test 5: Test engine status retrieval
        $engineStatus = Get-SchedulingEngineStatus
        Write-Log "Engine status test passed" -Level Success
        
        Write-Log "All scheduling engine tests passed" -Level Success
        return $true
    }
    catch {
        Write-Log "Scheduling engine test failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}
#endregion
