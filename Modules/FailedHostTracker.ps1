# Failed Host Tracker Module
# Handles tracking and management of failed host connections

#region Failed Host Tracking Functions
function Get-FailedHostsFilePath {
    [CmdletBinding()]
    param()
    
    return Join-Path (Get-ScriptDirectory) "failed_hosts.json"
}

function Initialize-FailedHostsFile {
    [CmdletBinding()]
    param()
    
    $filePath = Get-FailedHostsFilePath
    
    if (-not (Test-Path $filePath)) {
        try {
            $emptyData = @{
                FailedHosts = @()
                LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            $emptyData | ConvertTo-Json -Depth 3 | Out-File -FilePath $filePath -Encoding UTF8
            Write-Log "Failed hosts file initialized: $filePath" -Level Success
            return $true
        }
        catch {
            Write-Log "Failed to initialize failed hosts file: $($_.Exception.Message)" -Level Error
            return $false
        }
    }
    
    return $true
}

function Get-FailedHosts {
    [CmdletBinding()]
    param(
        [string]$Filter
    )
    
    $filePath = Get-FailedHostsFilePath
    
    if (-not (Test-Path $filePath)) {
        Initialize-FailedHostsFile
    }
    
    try {
        $data = Get-Content -Path $filePath -Raw | ConvertFrom-Json
        $failedHosts = $data.FailedHosts
        
        if ($Filter) {
            switch ($Filter.ToLower()) {
                "critical" {
                    $failedHosts = $failedHosts | Where-Object { $_.Priority -eq "critical" }
                }
                "normal" {
                    $failedHosts = $failedHosts | Where-Object { $_.Priority -eq "normal" }
                }
                "low" {
                    $failedHosts = $failedHosts | Where-Object { $_.Priority -eq "low" }
                }
                "dueforscan" {
                    $failedHosts = Get-HostsDueForScheduledScan
                }
            }
        }
        
        return @($failedHosts)
    }
    catch {
        Write-Log "Failed to read failed hosts: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Add-FailedHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,
        
        [Parameter(Mandatory)]
        [string]$Error,
        
        [string]$Priority = "normal"
    )
    
    $filePath = Get-FailedHostsFilePath
    
    if (-not (Test-Path $filePath)) {
        Initialize-FailedHostsFile
    }
    
    try {
        $data = Get-Content -Path $filePath -Raw | ConvertFrom-Json
        $failedHosts = $data.FailedHosts
        
        # Check if host already exists
        $existingHost = $failedHosts | Where-Object { $_.Hostname -eq $Hostname }
        
        if ($existingHost) {
            # Update existing entry
            $now = Get-Date
            $existingHost.LastAttempt = $now.ToString("yyyy-MM-dd HH:mm:ss")
            $existingHost.AttemptCount++
            $existingHost.LastError = $Error
            
            # Check for automatic escalation
            $newPriority = Test-HostEscalation -HostInfo $existingHost
            
            # Update priority if escalated
            if ($newPriority -ne $existingHost.Priority) {
                $existingHost.Priority = $newPriority
                Write-Log "Host $Hostname escalated to $newPriority priority after $($existingHost.AttemptCount) failures" -Level Warning
            }
            
            # Check for automatic removal (14 days of continuous failure)
            if (Test-HostRemoval -HostInfo $existingHost) {
                Write-Log "Host $Hostname automatically removed after 14 days of continuous failure" -Level Warning
                Remove-FailedHost -Hostname $Hostname
                return $true
            }
            
            # Update scheduling metadata with new priority and randomized timing
            $randomInterval = Get-RandomScanTime -Priority $existingHost.Priority
            $scheduleProfile = Get-ScheduleProfile -Priority $existingHost.Priority
            $existingHost.NextScheduledScan = $now.AddHours($randomInterval).ToString("yyyy-MM-dd HH:mm:ss")
            $existingHost.ScheduleProfile = $scheduleProfile.Name
            $existingHost.IntervalHours = $randomInterval
            $existingHost.SchedulingEnabled = $scheduleProfile.Enabled
        }
        else {
            # Add new entry with scheduling metadata and randomized timing
            $now = Get-Date
            $randomInterval = Get-RandomScanTime -Priority $Priority
            $scheduleProfile = Get-ScheduleProfile -Priority $Priority
            $nextScheduledScan = $now.AddHours($randomInterval)
            
            $newHost = @{
                Hostname = $Hostname
                FirstFailure = $now.ToString("yyyy-MM-dd HH:mm:ss")
                LastAttempt = $now.ToString("yyyy-MM-dd HH:mm:ss")
                AttemptCount = 1
                LastError = $Error
                Priority = $Priority
                NextScheduledScan = $nextScheduledScan.ToString("yyyy-MM-dd HH:mm:ss")
                ScheduleProfile = $scheduleProfile.Name
                IntervalHours = $randomInterval
                SchedulingEnabled = $scheduleProfile.Enabled
            }
            
            $failedHosts += $newHost
        }
        
        # Update data
        $data.FailedHosts = $failedHosts
        $data.LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        
        # Save to file
        $data | ConvertTo-Json -Depth 3 | Out-File -FilePath $filePath -Encoding UTF8
        
        Write-Log "Failed host added/updated: $Hostname" -Level Info
        return $true
    }
    catch {
        Write-Log "Failed to add failed host: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Remove-FailedHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )
    
    $filePath = Get-FailedHostsFilePath
    
    if (-not (Test-Path $filePath)) {
        return $true
    }
    
    try {
        $data = Get-Content -Path $filePath -Raw | ConvertFrom-Json
        $failedHosts = $data.FailedHosts
        
        # Remove host from list
        $failedHosts = $failedHosts | Where-Object { $_.Hostname -ne $Hostname }
        
        # Update data
        $data.FailedHosts = $failedHosts
        $data.LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        
        # Save to file
        $data | ConvertTo-Json -Depth 3 | Out-File -FilePath $filePath -Encoding UTF8
        
        Write-Log "Failed host removed: $Hostname" -Level Info
        return $true
    }
    catch {
        Write-Log "Failed to remove failed host: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Update-FailedHostAttempt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,
        
        [Parameter(Mandatory)]
        [string]$Result,
        
        [string]$Error = $null
    )
    
    if ($Result -eq "Success") {
        # Remove from failed hosts list
        Remove-FailedHost -Hostname $Hostname
        Write-Log "Host $Hostname recovered successfully" -Level Success
    }
    else {
        # Add or update failed host
        Add-FailedHost -Hostname $Hostname -Error $Error
    }
}

function Clear-FailedHosts {
    [CmdletBinding()]
    param()
    
    $filePath = Get-FailedHostsFilePath
    
    if (-not (Test-Path $filePath)) {
        return $true
    }
    
    try {
        $data = Get-Content -Path $filePath -Raw | ConvertFrom-Json
        $data.FailedHosts = @()
        $data.LastUpdated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        
        $data | ConvertTo-Json -Depth 3 | Out-File -FilePath $filePath -Encoding UTF8
        
        Write-Log "All failed hosts cleared" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to clear failed hosts: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Get-FailedHostsSummary {
    [CmdletBinding()]
    param()
    
    $failedHosts = Get-FailedHosts
    
    $summary = @{
        Total = $failedHosts.Count
        Critical = ($failedHosts | Where-Object { $_.Priority -eq "critical" }).Count
        Normal = ($failedHosts | Where-Object { $_.Priority -eq "normal" }).Count
        Low = ($failedHosts | Where-Object { $_.Priority -eq "low" }).Count
        DueForScan = 0
    }
    
    # Calculate due for scan using scheduling logic
    $dueHosts = Get-HostsDueForScheduledScan
    $summary.DueForScan = $dueHosts.Count
    
    return $summary
}

function Show-FailedHosts {
    [CmdletBinding()]
    param(
        [string]$Filter,
        [switch]$Detailed
    )
    
    Clear-Host
    Write-MenuHeader -Title "Failed Hosts"
    
    $failedHosts = Get-FailedHosts -Filter $Filter
    $summary = Get-FailedHostsSummary
    
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "Total Failed: $($summary.Total)" -ForegroundColor White
    Write-Host "Critical: $($summary.Critical)" -ForegroundColor Red
    Write-Host "Normal: $($summary.Normal)" -ForegroundColor Yellow
    Write-Host "Low: $($summary.Low)" -ForegroundColor Green
    Write-Host "Due for Rescan: $($summary.DueForScan)" -ForegroundColor Cyan
    
    if ($failedHosts.Count -eq 0) {
        Write-Host "`nNo failed hosts found." -ForegroundColor Green
    }
    else {
        Write-Host "`nFailed Hosts:" -ForegroundColor Yellow
        
        foreach ($failedHost in $failedHosts) {
            $color = switch ($failedHost.Priority) {
                "critical" { "Red" }
                "normal" { "Yellow" }
                "low" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n$($failedHost.Hostname) ($($failedHost.Priority))" -ForegroundColor $color
            Write-Host "  Attempts: $($failedHost.AttemptCount)" -ForegroundColor White
            Write-Host "  Last Attempt: $($failedHost.LastAttempt)" -ForegroundColor White
            
            if ($failedHost.NextScheduledScan) {
                Write-Host "  Next Scheduled Scan: $($failedHost.NextScheduledScan)" -ForegroundColor Cyan
                Write-Host "  Schedule Profile: $($failedHost.ScheduleProfile)" -ForegroundColor Cyan
            }
            
            if ($Detailed) {
                Write-Host "  First Failure: $($failedHost.FirstFailure)" -ForegroundColor White
                Write-Host "  Last Error: $($failedHost.LastError)" -ForegroundColor White
                if ($failedHost.IntervalHours) {
                    Write-Host "  Retry Interval: $($failedHost.IntervalHours) hours" -ForegroundColor White
                }
                if ($failedHost.SchedulingEnabled -ne $null) {
                    Write-Host "  Scheduling Enabled: $($failedHost.SchedulingEnabled)" -ForegroundColor White
                }
            }
        }
    }
    
    Invoke-Pause
}

function Get-HostsDueForScheduledScan {
    [CmdletBinding()]
    param()
    
    try {
        $schedulingConfig = Get-SchedulingConfiguration
        
        # Check if scheduling is enabled
        if (-not $schedulingConfig.Enabled) {
            Write-Log "Scheduling is disabled. No hosts due for scan." -Level Info
            return @()
        }
        
        $filePath = Get-FailedHostsFilePath
        
        if (-not (Test-Path $filePath)) {
            return @()
        }
        
        $data = Get-Content -Path $filePath -Raw | ConvertFrom-Json
        $failedHosts = $data.FailedHosts
        $now = Get-Date
        
        $dueHosts = @()
        
        foreach ($failedHost in $failedHosts) {
            try {
                # Check if host has scheduling metadata
                if (-not $failedHost.NextScheduledScan) {
                    # Legacy host without scheduling metadata - use default interval
                    $scheduleProfile = Get-ScheduleProfile -Priority $failedHost.Priority
                    $nextScan = [DateTime]::Parse($failedHost.LastAttempt).AddHours($scheduleProfile.IntervalHours)
                    
                    if ($nextScan -le $now) {
                        $dueHosts += $failedHost
                    }
                } else {
                    # Host with scheduling metadata
                    $nextScan = [DateTime]::Parse($failedHost.NextScheduledScan)
                    
                    if ($nextScan -le $now -and $failedHost.SchedulingEnabled) {
                        $dueHosts += $failedHost
                    }
                }
            }
            catch {
                Write-Log "Error processing host $($failedHost.Hostname): $($_.Exception.Message)" -Level Warning
            }
        }
        
        Write-Log "Found $($dueHosts.Count) hosts due for scheduled scan" -Level Info
        return @($dueHosts)
    }
    catch {
        Write-Log "Failed to get hosts due for scheduled scan: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Update-HostSchedulingMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,
        
        [string]$Priority = $null
    )
    
    try {
        $filePath = Get-FailedHostsFilePath
        
        if (-not (Test-Path $filePath)) {
            return $false
        }
        
        $data = Get-Content -Path $filePath -Raw | ConvertFrom-Json
        $failedHosts = $data.FailedHosts
        
        $hostIndex = -1
        for ($i = 0; $i -lt $failedHosts.Count; $i++) {
            if ($failedHosts[$i].Hostname -eq $Hostname) {
                $hostIndex = $i
                break
            }
        }
        
        if ($hostIndex -eq -1) {
            Write-Log "Host $Hostname not found in failed hosts list" -Level Warning
            return $false
        }
        
        # Convert PSCustomObject to hashtable for modification
        $hostHashtable = @{}
        $failedHosts[$hostIndex].PSObject.Properties | ForEach-Object {
            $hostHashtable[$_.Name] = $_.Value
        }
        
        # Update priority if provided
        if ($Priority) {
            $hostHashtable.Priority = $Priority
        }
        
        # Update scheduling metadata
        $scheduleProfile = Get-ScheduleProfile -Priority $hostHashtable.Priority
        $now = Get-Date
        $hostHashtable.NextScheduledScan = $now.AddHours($scheduleProfile.IntervalHours).ToString("yyyy-MM-dd HH:mm:ss")
        $hostHashtable.ScheduleProfile = $scheduleProfile.Name
        $hostHashtable.IntervalHours = $scheduleProfile.IntervalHours
        $hostHashtable.SchedulingEnabled = $scheduleProfile.Enabled
        
        # Replace the original object with the updated hashtable
        $failedHosts[$hostIndex] = $hostHashtable
        
        # Save updated data
        $data.FailedHosts = $failedHosts
        $data.LastUpdated = $now.ToString("yyyy-MM-dd HH:mm:ss")
        
        $data | ConvertTo-Json -Depth 3 | Out-File -FilePath $filePath -Encoding UTF8
        
        Write-Log "Updated scheduling metadata for host $Hostname" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to update scheduling metadata for host $Hostname : $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Get-SchedulingStatus {
    [CmdletBinding()]
    param()
    
    try {
        $schedulingConfig = Get-SchedulingConfiguration
        $failedHosts = Get-FailedHosts
        $dueHosts = Get-HostsDueForScheduledScan
        
        $status = @{
            SchedulingEnabled = $schedulingConfig.Enabled
            TotalFailedHosts = $failedHosts.Count
            HostsDueForScan = $dueHosts.Count
            MaxConcurrentScans = $schedulingConfig.MaxConcurrentScheduledScans
            ScheduleProfiles = $schedulingConfig.ScheduleProfiles
            NextScheduledScans = @()
        }
        
        # Get next scheduled scans for each priority
        foreach ($scheduleProfile in $schedulingConfig.ScheduleProfiles) {
            if ($scheduleProfile.Enabled) {
                $profileHosts = $failedHosts | Where-Object { $_.Priority -eq $scheduleProfile.Priority }
                if ($profileHosts.Count -gt 0) {
                    $nextScan = ($profileHosts | Sort-Object { [DateTime]::Parse($_.NextScheduledScan) } | Select-Object -First 1).NextScheduledScan
                    $status.NextScheduledScans += @{
                        Priority = $scheduleProfile.Priority
                        ProfileName = $scheduleProfile.Name
                        NextScan = $nextScan
                        HostCount = $profileHosts.Count
                    }
                }
            }
        }
        
        return $status
    }
    catch {
        Write-Log "Failed to get scheduling status: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Show-SchedulingStatus {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-MenuHeader -Title "Scheduling Status"
    
    $status = Get-SchedulingStatus
    if (-not $status) {
        Write-Host "Failed to retrieve scheduling status." -ForegroundColor Red
        Invoke-Pause
        return
    }
    
    Write-Host "`nScheduling Configuration:" -ForegroundColor Yellow
    Write-Host "Scheduling Enabled: $($status.SchedulingEnabled)" -ForegroundColor $(if ($status.SchedulingEnabled) { "Green" } else { "Red" })
    Write-Host "Max Concurrent Scans: $($status.MaxConcurrentScans)" -ForegroundColor White
    
    Write-Host "`nFailed Hosts Summary:" -ForegroundColor Yellow
    Write-Host "Total Failed Hosts: $($status.TotalFailedHosts)" -ForegroundColor White
    Write-Host "Hosts Due for Scan: $($status.HostsDueForScan)" -ForegroundColor $(if ($status.HostsDueForScan -gt 0) { "Cyan" } else { "Green" })
    
    if ($status.NextScheduledScans.Count -gt 0) {
        Write-Host "`nNext Scheduled Scans:" -ForegroundColor Yellow
        foreach ($nextScan in $status.NextScheduledScans) {
            $color = switch ($nextScan.Priority) {
                "critical" { "Red" }
                "normal" { "Yellow" }
                "low" { "Green" }
                default { "White" }
            }
            
            Write-Host "`n$($nextScan.ProfileName) ($($nextScan.Priority))" -ForegroundColor $color
            Write-Host "  Hosts: $($nextScan.HostCount)" -ForegroundColor White
            Write-Host "  Next Scan: $($nextScan.NextScan)" -ForegroundColor White
        }
    }
    
    Invoke-Pause
}

function Test-HostEscalation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$HostInfo
    )
    
    try {
        $config = Get-Configuration
        $escalationThreshold = $config.FailedHostTracking.EscalationThreshold
        
        # Default escalation threshold if not configured
        if (-not $escalationThreshold) {
            $escalationThreshold = 5
        }
        
        # Check if host should be escalated to critical
        if ($HostInfo.AttemptCount -ge $escalationThreshold -and $HostInfo.Priority -eq "normal") {
            return "critical"
        }
        
        # Return current priority if no escalation needed
        return $HostInfo.Priority
    }
    catch {
        Write-Log "Error testing host escalation: $($_.Exception.Message)" -Level Error
        return $HostInfo.Priority
    }
}

function Test-HostRemoval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$HostInfo
    )
    
    try {
        $config = Get-Configuration
        $removalDays = $config.FailedHostTracking.RemovalDays
        
        # Default removal threshold if not configured
        if (-not $removalDays) {
            $removalDays = 14
        }
        
        # Calculate days since first failure
        $firstFailure = [DateTime]::Parse($HostInfo.FirstFailure)
        $daysSinceFirstFailure = (Get-Date) - $firstFailure
        
        # Check if host should be removed
        if ($daysSinceFirstFailure.Days -ge $removalDays) {
            return $true
        }
        
        return $false
    }
    catch {
        Write-Log "Error testing host escalation: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Get-RandomScanTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Priority
    )
    
    try {
        $config = Get-Configuration
        $schedulingConfig = $config.Scheduling
        
        # Get base interval for the priority
        $baseInterval = switch ($Priority) {
            "critical" { $schedulingConfig.CriticalIntervalHours }
            "normal" { $schedulingConfig.DefaultIntervalHours }
            "low" { $schedulingConfig.LowPriorityIntervalHours }
            default { $schedulingConfig.DefaultIntervalHours }
        }
        
        # Add randomization for 24/7 operations
        # Randomize between 80% and 120% of base interval
        $minInterval = [math]::Round($baseInterval * 0.8, 1)
        $maxInterval = [math]::Round($baseInterval * 1.2, 1)
        
        # Generate random interval within range
        $randomInterval = Get-Random -Minimum $minInterval -Maximum $maxInterval
        
        # Round to nearest 0.5 hours for cleaner scheduling
        $randomInterval = [math]::Round($randomInterval * 2) / 2
        
        return $randomInterval
    }
    catch {
        Write-Log "Error generating random scan time: $($_.Exception.Message)" -Level Error
        return 6.0  # Default fallback
    }
}
#endregion
