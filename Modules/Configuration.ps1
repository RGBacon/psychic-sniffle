# Configuration Management Module
# Handles all configuration loading, validation, and management

#region Configuration Functions
function Initialize-Configuration {
    [CmdletBinding()]
    param()
    
    $configPath = Get-ConfigurationPath
    
    if (Test-Path $configPath) {
        try {
            $script:Config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            Write-Host "Configuration loaded from $configPath" -ForegroundColor Green
            
            # Ensure backward compatibility - add missing scheduling section if needed
            if (-not $script:Config.Scheduling) {
                Write-Host "Scheduling configuration not found. Adding default scheduling settings." -ForegroundColor Yellow
                $script:Config.Scheduling = @{
                    Enabled = $false
                    DefaultIntervalHours = 24
                    CriticalIntervalHours = 6
                    LowPriorityIntervalHours = 48
                    MaxConcurrentScheduledScans = 5
                    ScheduleProfiles = @(
                        @{
                            Name = "Critical Systems"
                            Priority = "critical"
                            IntervalHours = 6
                            Enabled = $true
                        },
                        @{
                            Name = "Standard Systems"
                            Priority = "normal"
                            IntervalHours = 24
                            Enabled = $true
                        },
                        @{
                            Name = "Low Priority Systems"
                            Priority = "low"
                            IntervalHours = 48
                            Enabled = $false
                        }
                    )
                    AutomationSettings = @{
                        AutoStartOnScriptLaunch = $false
                        RunInBackground = $false
                        NotifyOnCompletion = $true
                        LogSchedulingOperations = $true
                    }
                    ConflictResolution = @{
                        SkipIfManualScanInProgress = $true
                        RescheduleOnConflict = $true
                        MaxConflictDelayMinutes = 30
                    }
                }
                
                # Save the updated configuration
                Save-Configuration
            }
            
            return $true
        }
        catch {
            Write-Host "Error loading configuration: $($_.Exception.Message)" -ForegroundColor Red
            Create-DefaultConfiguration
            return $false
        }
    }
    else {
        Write-Host "Configuration file not found. Creating default configuration." -ForegroundColor Yellow
        Create-DefaultConfiguration
        return $true
    }
}

function Get-ConfigurationPath {
    [CmdletBinding()]
    param()
    
    # Get the directory of the main script, not the module directory
    $scriptDir = Split-Path -Parent $PSScriptRoot
    return Join-Path $scriptDir "config.json"
}

function Create-DefaultConfiguration {
    [CmdletBinding()]
    param()
    
    $defaultConfig = @{
        DefaultMessage = "IMPORTANT: This device has been identified for replacement. Please contact IT Support via Teams or Outlook to schedule your device replacement."
        OutputFiles = @{
            EnhancedInfo = "enhanced_system_info.txt"
            NetworkTopology = "network_topology.txt"
            UniqueApps = "unique_apps.txt"
            SunquestResults = "sunquest_results.txt"
            SystemDataCSV = "system_data.csv"
            HTMLViewer = "system_data_viewer.html"
            LogFile = "script_log.txt"
        }
        HostsFile = "hosts.txt"
        Colors = @{
            Highlight = "White"
            Header = "Yellow"
            Error = "Red"
            Warning = "Yellow"
            Success = "Green"
            Info = "White"
            Menu = "Gray"
        }
        MaxParallelJobs = 10
        Timeout = 90
        SystemInfo = @{
            CheckSunquest = $true
            CheckPrinters = $true
            CheckTracert = $false
        }
        CheckApps = @{
            BaselineFile = "baseline.txt"
            ExcludePatterns = @(
                "^Microsoft ",
                "^McAfee ",
                "^Google Update Helper$",
                "^64 Bit HP CIO Components Installer$",
                "^Trellix Data Exchange Layer for MA$",
                "^Google Chrome$",
                "^Teams Machine-Wide Installer$"
            )
        }
        FailedHostTracking = @{
            Enabled = $true
            DefaultRetryIntervalHours = 24
            CriticalRetryIntervalHours = 6
            MaxRetryAttempts = 10
            PriorityLevels = @("critical", "normal", "low")
            EscalationThreshold = 5
            RemovalDays = 14
            MinRetryIntervalHours = 6
        }
        Scheduling = @{
            Enabled = $false
            DefaultIntervalHours = 24
            CriticalIntervalHours = 6
            LowPriorityIntervalHours = 48
            MaxConcurrentScheduledScans = 5
            ScheduleProfiles = @(
                @{
                    Name = "Critical Systems"
                    Priority = "critical"
                    IntervalHours = 6
                    Enabled = $true
                },
                @{
                    Name = "Standard Systems"
                    Priority = "normal"
                    IntervalHours = 24
                    Enabled = $true
                },
                @{
                    Name = "Low Priority Systems"
                    Priority = "low"
                    IntervalHours = 48
                    Enabled = $false
                }
            )
            AutomationSettings = @{
                AutoStartOnScriptLaunch = $false
                RunInBackground = $false
                NotifyOnCompletion = $true
                LogSchedulingOperations = $true
            }
            ConflictResolution = @{
                SkipIfManualScanInProgress = $true
                RescheduleOnConflict = $true
                MaxConflictDelayMinutes = 30
            }
        }
    }
    
    $configPath = Get-ConfigurationPath
    $defaultConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding UTF8
    $script:Config = $defaultConfig
    
    Write-Host "Default configuration created at $configPath" -ForegroundColor Green
}

function Get-Configuration {
    [CmdletBinding()]
    param()
    
    if (-not $script:Config) {
        Initialize-Configuration
    }
    
    return $script:Config
}

function Set-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Configuration
    )
    
    $script:Config = $Configuration
    Save-Configuration
}

function Save-Configuration {
    [CmdletBinding()]
    param()
    
    if (-not $script:Config) {
        # Fallback to Write-Host if logging not initialized
        if (Get-Command "Write-Log" -ErrorAction SilentlyContinue) {
            Write-Log "No configuration to save" -Level Warning
        } else {
            Write-Host "Warning: No configuration to save" -ForegroundColor Yellow
        }
        return $false
    }
    
    try {
        $configPath = Get-ConfigurationPath
        $script:Config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "Configuration saved to $configPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to save configuration: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-ScriptDirectory {
    [CmdletBinding()]
    param()
    
    # Get the directory of the main script, not the module directory
    $scriptDir = Split-Path -Parent $PSScriptRoot
    return $scriptDir
}

function Test-AdminPrivileges {
    [CmdletBinding()]
    param()
    
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SchedulingConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Config
    )
    
    $errors = @()
    $warnings = @()
    
    # Check if Scheduling section exists
    if (-not $Config.Scheduling) {
        $warnings += "Scheduling configuration section not found. Using defaults."
        return @{ IsValid = $true; Errors = @(); Warnings = $warnings }
    }
    
    $scheduling = $Config.Scheduling
    
    # Validate Enabled setting
    if ($scheduling.Enabled -isnot [bool]) {
        $errors += "Scheduling.Enabled must be a boolean value"
    }
    
    # Validate interval settings (accept both Int32 and Int64 from JSON)
    $intervalSettings = @('DefaultIntervalHours', 'CriticalIntervalHours', 'LowPriorityIntervalHours')
    foreach ($setting in $intervalSettings) {
        $value = $scheduling.$setting
        if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 1) {
            $errors += "Scheduling.$setting must be a positive integer"
        }
    }
    
    # Validate MaxConcurrentScheduledScans (accept both Int32 and Int64 from JSON)
    $value = $scheduling.MaxConcurrentScheduledScans
    if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 1) {
        $errors += "Scheduling.MaxConcurrentScheduledScans must be a positive integer"
    }
    
    # Validate ScheduleProfiles
    if ($scheduling.ScheduleProfiles) {
        if ($scheduling.ScheduleProfiles -isnot [array]) {
            $errors += "Scheduling.ScheduleProfiles must be an array"
        } else {
            foreach ($profile in $scheduling.ScheduleProfiles) {
                if (-not $profile.Name -or -not $profile.Priority -or -not $profile.IntervalHours) {
                    $errors += "Schedule profile missing required fields: Name, Priority, or IntervalHours"
                }
                if ($profile.Priority -notin @('critical', 'normal', 'low')) {
                    $errors += "Schedule profile priority must be 'critical', 'normal', or 'low'"
                }
                $intervalValue = $profile.IntervalHours
                if (($intervalValue -isnot [int] -and $intervalValue -isnot [long]) -or $intervalValue -lt 1) {
                    $errors += "Schedule profile IntervalHours must be a positive integer"
                }
            }
        }
    }
    
    # Validate AutomationSettings
    if ($scheduling.AutomationSettings) {
        $autoSettings = $scheduling.AutomationSettings
        $boolSettings = @('AutoStartOnScriptLaunch', 'RunInBackground', 'NotifyOnCompletion', 'LogSchedulingOperations')
        foreach ($setting in $boolSettings) {
            if ($autoSettings.$setting -isnot [bool]) {
                $errors += "Scheduling.AutomationSettings.$setting must be a boolean value"
            }
        }
    }
    
    # Validate ConflictResolution
    if ($scheduling.ConflictResolution) {
        $conflictSettings = $scheduling.ConflictResolution
        if ($conflictSettings.SkipIfManualScanInProgress -isnot [bool]) {
            $errors += "Scheduling.ConflictResolution.SkipIfManualScanInProgress must be a boolean value"
        }
        if ($conflictSettings.RescheduleOnConflict -isnot [bool]) {
            $errors += "Scheduling.ConflictResolution.RescheduleOnConflict must be a boolean value"
        }
        $delayValue = $conflictSettings.MaxConflictDelayMinutes
        if (($delayValue -isnot [int] -and $delayValue -isnot [long]) -or $delayValue -lt 0) {
            $errors += "Scheduling.ConflictResolution.MaxConflictDelayMinutes must be a non-negative integer"
        }
    }
    
    return @{
        IsValid = ($errors.Count -eq 0)
        Errors = $errors
        Warnings = $warnings
    }
}

function Get-SchedulingConfiguration {
    [CmdletBinding()]
    param()
    
    $config = Get-Configuration
    
    if (-not $config.Scheduling) {
        Write-Log "Scheduling configuration not found. Using defaults." -Level Warning
        # Return default scheduling configuration
        return @{
            Enabled = $false
            DefaultIntervalHours = 24
            CriticalIntervalHours = 6
            LowPriorityIntervalHours = 48
            MaxConcurrentScheduledScans = 5
            ScheduleProfiles = @(
                @{
                    Name = "Critical Systems"
                    Priority = "critical"
                    IntervalHours = 6
                    Enabled = $true
                },
                @{
                    Name = "Standard Systems"
                    Priority = "normal"
                    IntervalHours = 24
                    Enabled = $true
                },
                @{
                    Name = "Low Priority Systems"
                    Priority = "low"
                    IntervalHours = 48
                    Enabled = $false
                }
            )
            AutomationSettings = @{
                AutoStartOnScriptLaunch = $false
                RunInBackground = $false
                NotifyOnCompletion = $true
                LogSchedulingOperations = $true
            }
            ConflictResolution = @{
                SkipIfManualScanInProgress = $true
                RescheduleOnConflict = $true
                MaxConflictDelayMinutes = 30
            }
        }
    }
    
    # Validate configuration
    $validation = Test-SchedulingConfiguration -Config $config
    if (-not $validation.IsValid) {
        Write-Log "Scheduling configuration validation failed: $($validation.Errors -join ', ')" -Level Error
        throw "Invalid scheduling configuration: $($validation.Errors -join ', ')"
    }
    
    if ($validation.Warnings.Count -gt 0) {
        foreach ($warning in $validation.Warnings) {
            Write-Log "Scheduling configuration warning: $warning" -Level Warning
        }
    }
    
    return $config.Scheduling
}

function Set-SchedulingConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$SchedulingConfig
    )
    
    $config = Get-Configuration
    
    # Validate the new configuration
    # Deep clone the configuration object for testing
    $testConfig = $config | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    $testConfig.Scheduling = $SchedulingConfig
    
    $validation = Test-SchedulingConfiguration -Config $testConfig
    if (-not $validation.IsValid) {
        Write-Log "Scheduling configuration validation failed: $($validation.Errors -join ', ')" -Level Error
        throw "Invalid scheduling configuration: $($validation.Errors -join ', ')"
    }
    
    # Update the configuration
    $config.Scheduling = $SchedulingConfig
    $script:Config = $config
    
    # Save the configuration
    if (Save-Configuration) {
        Write-Log "Scheduling configuration updated successfully" -Level Success
        return $true
    } else {
        Write-Log "Failed to save scheduling configuration" -Level Error
        return $false
    }
}

function Get-ScheduleProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Priority
    )
    
    $schedulingConfig = Get-SchedulingConfiguration
    
    if (-not $schedulingConfig.ScheduleProfiles) {
        # Return default profile based on priority
        $defaultIntervals = @{
            'critical' = $schedulingConfig.CriticalIntervalHours
            'normal' = $schedulingConfig.DefaultIntervalHours
            'low' = $schedulingConfig.LowPriorityIntervalHours
        }
        
        $intervalHours = if ($defaultIntervals.ContainsKey($Priority)) { $defaultIntervals[$Priority] } else { $schedulingConfig.DefaultIntervalHours }
        
        return @{
            Name = "$Priority Systems"
            Priority = $Priority
            IntervalHours = $intervalHours
            Enabled = $true
        }
    }
    
    $profile = $schedulingConfig.ScheduleProfiles | Where-Object { $_.Priority -eq $Priority }
    if ($profile) {
        return $profile
    }
    
    # Fallback to default intervals
    $defaultIntervals = @{
        'critical' = $schedulingConfig.CriticalIntervalHours
        'normal' = $schedulingConfig.DefaultIntervalHours
        'low' = $schedulingConfig.LowPriorityIntervalHours
    }
    
    $intervalHours = if ($defaultIntervals.ContainsKey($Priority)) { $defaultIntervals[$Priority] } else { $schedulingConfig.DefaultIntervalHours }
    
    return @{
        Name = "$Priority Systems"
        Priority = $Priority
        IntervalHours = $intervalHours
        Enabled = $true
    }
}
#endregion
