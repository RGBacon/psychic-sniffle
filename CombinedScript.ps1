# Set error action preference globally
$ErrorActionPreference = 'Stop'

#region Global Variables
$script:Config = @{
    # File names
    HostsFile = "hosts.txt"
    OutputFiles = @{
        SunquestResults = "sunquest_results.txt"
        SystemInfo = "system_info_results.txt"
        LogFile = "script_log.txt"
        UniqueApps = "unique_apps.txt"
    }
    # Default settings
    Timeout = 30
    DefaultMessage = "IMPORTANT: This device has been identified for replacement. Please contact IT Support via Teams or Outlook to schedule your device replacement. This message will repeat hourly until action is taken."
    # System Info options
    SystemInfo = @{
        CheckSunquest = $false
        CheckPrinters = $false
    }
    # CheckApps options
    CheckApps = @{
        BaselineFile = "baseline.txt"
        ExcludePatterns = @(
            '^Microsoft '
            '^McAfee '
            '^Google Update Helper$'
            '^64 Bit HP CIO Components Installer$'
            '^Trellix Data Exchange Layer for MA$'
            '^Google Chrome$'
            '^Teams Machine-Wide Installer$'
        )
    }
    # Colors for consistent UI
    Colors = @{
        Success = "Green"
        Warning = "Yellow"
        Error = "Red"
        Info = "White"
        Header = "Yellow"
        Menu = "Gray"
        Highlight = "White"
    }
    # Line ending for better cross-platform compatibility
    NewLine = [System.Environment]::NewLine
}
#endregion

#region Helper Functions
# Check if running with admin privileges
function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Get script directory reliably
function Get-ScriptDirectory {
    $scriptDir = $PSScriptRoot
    if ([string]::IsNullOrEmpty($scriptDir)) {
        # Fallback if $PSScriptRoot is not available
        $scriptDir = (Get-Location).Path
    }
    return $scriptDir
}

# Write to log file and console with timestamp and color
function Write-ScriptLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info",
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    # Determine color based on message type
    $color = switch ($Type) {
        "Success" { $script:Config.Colors.Success }
        "Warning" { $script:Config.Colors.Warning }
        "Error" { $script:Config.Colors.Error }
        "Info" { $script:Config.Colors.Info }
        default { $script:Config.Colors.Info }
    }
    
    # Write to log file
    $logFile = Join-Path -Path (Get-ScriptDirectory) -ChildPath $script:Config.OutputFiles.LogFile
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    
    # Write to console if not suppressed
    if (-not $NoConsole) {
        Write-Host $Message -ForegroundColor $color
    }
}

# Create or verify hosts file exists
function Confirm-HostsFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$HostsFilePath
    )
    
    if (-not (Test-Path -Path $HostsFilePath)) {
        Write-ScriptLog "Hosts file not found: $HostsFilePath" -Type "Error"
        Write-ScriptLog "Please create this file with one hostname per line." -Type "Warning"
        Write-ScriptLog "Would you like to create a sample hosts file with 'localhost'? (Y/N)" -Type "Warning"
        $createSample = Read-Host
        
        if ($createSample -eq 'Y' -or $createSample -eq 'y') {
            # Create a sample hosts file with localhost
            "localhost" | Out-File -FilePath $HostsFilePath
            Write-ScriptLog "Created sample hosts file with 'localhost' entry." -Type "Success"
            return $true
        }
        else {
            return $false
        }
    }
    
    return $true
}

# Standard user prompt function
function Read-UserChoice {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Options,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 2147483647)]
        [int]$Default = 0
    )
    
    $optionString = ""
    for ($i = 0; $i -lt $Options.Length; $i++) {
        if ($i -eq $Default) {
            $optionString += "[$($i+1)] $($Options[$i]) (default) "
        } else {
            $optionString += "[$($i+1)] $($Options[$i]) "
        }
    }
    
    Write-Host $Prompt
    Write-Host $optionString
    
    $choice = Read-Host "Enter your choice"
    
    if ([string]::IsNullOrWhiteSpace($choice)) {
        return $Default
    }
    
    $choiceNum = 0
    if ([int]::TryParse($choice, [ref]$choiceNum) -and $choiceNum -ge 1 -and $choiceNum -le $Options.Length) {
        return $choiceNum - 1
    }
    
    # Invalid choice, return default
    Write-ScriptLog "Invalid choice. Using default option." -Type "Warning"
    return $Default
}

# Standard pause function
function Invoke-Pause {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Message = "Press Enter to continue..."
    )
    
    Read-Host $Message
}

# Return to main menu helper
function Invoke-ReturnToMainMenu {
    Invoke-Pause "Press Enter to return to main menu"
    Show-MainMenu
}

# Safely read file contents
function Get-HostsList {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$HostsFilePath
    )
    
    try {
        $hosts = Get-Content $HostsFilePath -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        Write-ScriptLog "Found $($hosts.Count) hosts to process in $HostsFilePath" -Type "Success"
        return $hosts
    }
    catch {
        Write-ScriptLog "Error reading hosts file: $_" -Type "Error"
        return @()
    }
}

# Check if file can be written to
function Test-FileWritable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )
    
    try {
        if (Test-Path $FilePath) {
            Clear-Content -Path $FilePath -ErrorAction Stop
        }
        else {
            $null = New-Item -Path $FilePath -ItemType File -Force -ErrorAction Stop
        }
        return $true
    }
    catch {
        Write-ScriptLog "Cannot write to file $FilePath : $_" -Type "Warning"
        return $false
    }
}

# Function to draw a header with title
function Write-MenuHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [int]$Width = 50
    )
    
    Write-Host ("=" * $Width) -ForegroundColor $script:Config.Colors.Header
    # Center the title
    $padding = [math]::Max(0, ($Width - $Title.Length) / 2)
    $leftPad = [math]::Floor($padding)
    $rightPad = [math]::Ceiling($padding)
    $formattedTitle = (" " * $leftPad) + $Title + (" " * $rightPad)
    Write-Host $formattedTitle -ForegroundColor $script:Config.Colors.Header
    Write-Host ("=" * $Width) -ForegroundColor $script:Config.Colors.Header
}

# Initialize an output file with a header
function Initialize-OutputFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Title
    )
    
    if (-not (Test-FileWritable -FilePath $FilePath)) {
        Write-ScriptLog "Cannot write to file $FilePath. Check permissions." -Type "Error"
        return $false
    }
    
    $header = @(
        "$Title",
        "Generated on $(Get-Date)",
        "==========================================",
        ""
    )
    
    $header | ForEach-Object { Add-Content -Path $FilePath -Value $_ -ErrorAction SilentlyContinue }
    return $true
}
#endregion

#region Main Menu
function Show-MainMenu {
    Clear-Host
    Write-MenuHeader -Title "Jeremy's All In One Utility" -Width 50
    Write-Host "System Tools:" -ForegroundColor $script:Config.Colors.Menu
    Write-Host "  1. Retrieve System Information" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host "  2. Check Sunquest Lab Applications" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host
    Write-Host "Communication Tools:" -ForegroundColor $script:Config.Colors.Menu
    Write-Host "  3. Send Messages to Hosts" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host
    Write-Host "Management:" -ForegroundColor $script:Config.Colors.Menu
    Write-Host "  4. Settings" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host "  5. Exit" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host ("=" * 50) -ForegroundColor $script:Config.Colors.Header
    
    $choice = Read-Host "Enter your choice (1-5)"
    
    switch ($choice) {
        "1" { Invoke-SystemInfoRetrieval }
        "2" { Invoke-SunquestCheck }
        "3" { Invoke-MessageSender }
        "4" { Show-SettingsMenu }
        "5" { exit }
        default { 
            Write-ScriptLog "Invalid choice. Press any key to try again..." -Type "Warning"
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-MainMenu 
        }
    }
}

function Show-SettingsMenu {
    Clear-Host
    Write-MenuHeader -Title "SETTINGS" -Width 40
    Write-Host "1. Edit Hosts File" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host "2. Set Default Timeout: $($script:Config.Timeout) seconds" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host "3. Edit Default Message" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host "4. Configure CheckApps" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host "5. Return to Main Menu" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host ("=" * 40) -ForegroundColor $script:Config.Colors.Header
    
    $choice = Read-Host "Enter your choice (1-5)"
    
    switch ($choice) {
        "1" { 
            $hostsFilePath = Join-Path -Path (Get-ScriptDirectory) -ChildPath $script:Config.HostsFile
            if (Test-Path $hostsFilePath) {
                Write-ScriptLog "Opening hosts file in notepad..." -Type "Info"
                Start-Process notepad.exe -ArgumentList $hostsFilePath
            } else {
                if (Confirm-HostsFile -HostsFilePath $hostsFilePath) {
                    Write-ScriptLog "Created hosts file. Opening in notepad..." -Type "Info"
                    Start-Process notepad.exe -ArgumentList $hostsFilePath
                }
            }
            Show-SettingsMenu
        }
        "2" { 
            $newTimeout = Read-Host "Enter new default timeout in seconds"
            if ($newTimeout -match '^\d+$') {
                $script:Config.Timeout = [int]$newTimeout
                Write-ScriptLog "Default timeout updated to $($script:Config.Timeout) seconds" -Type "Success"
            } else {
                Write-ScriptLog "Invalid timeout value. Must be a number." -Type "Warning"
            }
            Invoke-Pause
            Show-SettingsMenu
        }
        "3" { 
            Write-Host "Current default message:"
            Write-Host $script:Config.DefaultMessage -ForegroundColor $script:Config.Colors.Info
            Write-Host 
            $newMessage = Read-Host "Enter new default message (press Enter to keep current)"
            if (-not [string]::IsNullOrWhiteSpace($newMessage)) {
                $script:Config.DefaultMessage = $newMessage
                Write-ScriptLog "Message updated" -Type "Success"
            }
            Invoke-Pause
            Show-SettingsMenu
        }
        "4" {
            Show-CheckAppsSettings
        }
        "5" { Show-MainMenu }
        default { 
            Write-ScriptLog "Invalid choice. Press any key to try again..." -Type "Warning"
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-SettingsMenu 
        }
    }
}

function Show-CheckAppsSettings {
    Clear-Host
    Write-MenuHeader -Title "CHECK APPS SETTINGS" -Width 50
    
    $scriptDir = Get-ScriptDirectory
    $baselineFile = Join-Path -Path $scriptDir -ChildPath $script:Config.CheckApps.BaselineFile
    
    Write-Host "Current Settings:" -ForegroundColor $script:Config.Colors.Menu
    Write-Host "  1. Baseline File: $baselineFile" -ForegroundColor $script:Config.Colors.Info
    Write-Host "  2. Edit Exclude Patterns (currently $(($script:Config.CheckApps.ExcludePatterns).Count) patterns)" -ForegroundColor $script:Config.Colors.Info
    Write-Host "  3. Return to Settings Menu" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host ("=" * 50) -ForegroundColor $script:Config.Colors.Header
    
    $choice = Read-Host "Enter your choice (1-3)"
    
    switch ($choice) {
        "1" {
            $newBaselineFile = Read-Host "Enter new baseline file name (current: $($script:Config.CheckApps.BaselineFile))"
            if (-not [string]::IsNullOrWhiteSpace($newBaselineFile)) {
                $script:Config.CheckApps.BaselineFile = $newBaselineFile
                $baselineFile = Join-Path -Path $scriptDir -ChildPath $script:Config.CheckApps.BaselineFile
                Write-ScriptLog "Baseline file updated to: $baselineFile" -Type "Success"
                
                # Check if the new file exists, if not, offer to create it
                if (-not (Test-Path -Path $baselineFile)) {
                    Write-ScriptLog "New baseline file does not exist. Create it? (Y/N)" -Type "Warning"
                    $createFile = Read-Host
                    if ($createFile -eq 'Y' -or $createFile -eq 'y') {
                        "" | Out-File -FilePath $baselineFile
                        Write-ScriptLog "Created empty baseline file at $baselineFile" -Type "Success"
                        Write-ScriptLog "Would you like to edit it now? (Y/N)" -Type "Info"
                        $editFile = Read-Host
                        if ($editFile -eq 'Y' -or $editFile -eq 'y') {
                            Start-Process notepad.exe -ArgumentList $baselineFile
                        }
                    }
                }
            }
            Invoke-Pause
            Show-CheckAppsSettings
        }
        "2" {
            Clear-Host
            Write-MenuHeader -Title "EXCLUDE PATTERNS" -Width 60
            Write-Host "Current exclude patterns:" -ForegroundColor $script:Config.Colors.Menu
            
            for ($i = 0; $i -lt $script:Config.CheckApps.ExcludePatterns.Count; $i++) {
                Write-Host "  $($i+1). $($script:Config.CheckApps.ExcludePatterns[$i])" -ForegroundColor $script:Config.Colors.Info
            }
            
            Write-Host "`nOptions:" -ForegroundColor $script:Config.Colors.Menu
            Write-Host "  A. Add Pattern" -ForegroundColor $script:Config.Colors.Highlight
            Write-Host "  R. Remove Pattern" -ForegroundColor $script:Config.Colors.Highlight
            Write-Host "  B. Return to CheckApps Settings" -ForegroundColor $script:Config.Colors.Highlight
            
            $patternChoice = Read-Host "Enter your choice (A/R/B)"
            
            switch ($patternChoice.ToUpper()) {
                "A" {
                    $newPattern = Read-Host "Enter new exclude pattern (regex)"
                    if (-not [string]::IsNullOrWhiteSpace($newPattern)) {
                        $script:Config.CheckApps.ExcludePatterns += $newPattern
                        Write-ScriptLog "Pattern added" -Type "Success"
                    }
                }
                "R" {
                    $patternIndex = Read-Host "Enter the number of the pattern to remove (1-$($script:Config.CheckApps.ExcludePatterns.Count))"
                    if ($patternIndex -match '^\d+$' -and [int]$patternIndex -ge 1 -and [int]$patternIndex -le $script:Config.CheckApps.ExcludePatterns.Count) {
                        $removedPattern = $script:Config.CheckApps.ExcludePatterns[[int]$patternIndex-1]
                        $script:Config.CheckApps.ExcludePatterns = @($script:Config.CheckApps.ExcludePatterns | Where-Object { $_ -ne $removedPattern })
                        Write-ScriptLog "Pattern removed: $removedPattern" -Type "Success"
                    } else {
                        Write-ScriptLog "Invalid pattern number" -Type "Warning"
                    }
                }
                "B" {
                    # Do nothing, just return to previous menu
                }
                default {
                    Write-ScriptLog "Invalid choice" -Type "Warning"
                }
            }
            
            Invoke-Pause
            Show-CheckAppsSettings
        }
        "3" {
            Show-SettingsMenu
        }
        default {
            Write-ScriptLog "Invalid choice. Press any key to try again..." -Type "Warning"
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            Show-CheckAppsSettings
        }
    }
}
#endregion

#region Function 1: Check Sunquest Lab Applications
function Invoke-SunquestCheck {
    try {
        Clear-Host
        Write-MenuHeader -Title "SUNQUEST LAB APPLICATION CHECK" -Width 50
        Write-Host "Configuration:" -ForegroundColor $script:Config.Colors.Menu
        Write-Host "  Using hosts file: $($script:Config.HostsFile)" -ForegroundColor $script:Config.Colors.Info
        Write-Host "  Results will be saved to: $($script:Config.OutputFiles.SunquestResults)" -ForegroundColor $script:Config.Colors.Info
        Write-Host 
        Write-Host "1. Begin Scan" -ForegroundColor $script:Config.Colors.Highlight
        Write-Host "2. Return to Main Menu" -ForegroundColor $script:Config.Colors.Highlight
        Write-Host ("=" * 50) -ForegroundColor $script:Config.Colors.Header
        
        $choice = Read-Host "Enter your choice (1-2)"
        
        switch ($choice) {
            "1" { Start-SunquestCheck }
            "2" { Show-MainMenu; return }
            default {
                Write-ScriptLog "Invalid choice. Press any key to try again..." -Type "Warning"
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Invoke-SunquestCheck
                return
            }
        }
    }
    catch {
        Write-ScriptLog "Error in Sunquest check menu: ${_}" -Type "Error"
        Write-ScriptLog $_.ScriptStackTrace -Type "Error"
    }
    finally {
        Invoke-ReturnToMainMenu
    }
}

function Start-SunquestCheck {
    try {
        Write-Host ""
        $scriptDir = Get-ScriptDirectory
        $hostsFile = Join-Path -Path $scriptDir -ChildPath $script:Config.HostsFile
        
        # Check if hosts file exists
        if (-not (Confirm-HostsFile -HostsFilePath $hostsFile)) {
            return
        }

        # Get hosts to check
        $hostnames = Get-HostsList -HostsFilePath $hostsFile
        if ($hostnames.Count -eq 0) {
            Write-ScriptLog "No hosts found to process." -Type "Warning"
            return
        }

        # Initialize results file
        $resultsFile = Join-Path -Path $scriptDir -ChildPath $script:Config.OutputFiles.SunquestResults
        if (-not (Initialize-OutputFile -FilePath $resultsFile -Title "Results of Sunquest Lab application check:")) {
            return
        }

        # Process each hostname
        Write-ScriptLog "Starting scan of $($hostnames.Count) hosts..." -Type "Info"
        Write-ScriptLog "This may take some time depending on network conditions." -Type "Info"
        Write-Host ""

        $results = @()
        $count = 0
        $totalHosts = $hostnames.Count
        
        # Create progress parameters for splatting
        $progressParams = @{
            Activity = "Scanning for Sunquest Lab Applications"
            Status = "Processing hosts..."
            PercentComplete = 0
        }
        
        # Use a StringBuilder for building the output
        $outputBuilder = New-Object System.Text.StringBuilder

        foreach ($hostname in $hostnames) {
            $count++
            
            # Update progress
            $progressParams.Status = "Processing host $count of $totalHosts"
            $progressParams.PercentComplete = ($count / $totalHosts * 100)
            Write-Progress @progressParams
            
            Write-ScriptLog "Processing [$count/$totalHosts]: $hostname" -Type "Info"
            try {
                # Use timeout to prevent hanging on unresponsive hosts
                $apps = $null
                $job = Start-Job -ScriptBlock {
                    param($hostName)
                    Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName $hostName |
                    Where-Object { $_.Name -like 'Sunquest Lab*' } |
                    Select-Object -ExpandProperty Name
                } -ArgumentList $hostname
                
                # Wait for the job with timeout
                $null = Wait-Job -Job $job -Timeout $script:Config.Timeout
                
                if ($job.State -eq 'Completed') {
                    $apps = Receive-Job -Job $job
                }
                else {
                    throw "Operation timed out after $($script:Config.Timeout) seconds"
                }
                
                Remove-Job -Job $job -Force
                
                if ($apps) {
                    foreach ($app in $apps) {
                        $results += [PSCustomObject]@{ 
                            Hostname = $hostname
                            Application = $app
                            Status = "Found"
                        }
                        $null = $outputBuilder.AppendLine("Found Sunquest Lab application on $hostname`: $app")
                    }
                } else {
                    $results += [PSCustomObject]@{ 
                        Hostname = $hostname
                        Application = 'NoMatch'
                        Status = "NotFound"
                    }
                    $null = $outputBuilder.AppendLine("No Sunquest Lab application found on $hostname")
                }
            } 
            catch {
                $results += [PSCustomObject]@{ 
                    Hostname = $hostname
                    Application = 'Error'
                    Status = "Error"
                    ErrorMessage = $_
                }
                $null = $outputBuilder.AppendLine("Error connecting to $hostname`: $_")
                Write-ScriptLog "Error connecting to $hostname`: $_" -Type "Error"
            }
        }
        
        # Complete the progress bar
        Write-Progress -Activity "Scanning for Sunquest Lab Applications" -Completed
        
        # Write all results at once
        Add-Content -Path $resultsFile -Value $outputBuilder.ToString() -ErrorAction SilentlyContinue

        # Display summary
        Write-ScriptLog "Summary of results:" -Type "Success"
        $successCount = ($results | Where-Object { $_.Status -eq "Found" }).Count
        $noMatchCount = ($results | Where-Object { $_.Status -eq "NotFound" }).Count
        $errorCount = ($results | Where-Object { $_.Status -eq "Error" }).Count
        Write-ScriptLog "- Hosts with Sunquest Lab applications: $successCount" -Type "Success"
        Write-ScriptLog "- Hosts without Sunquest Lab applications: $noMatchCount" -Type "Warning"
        Write-ScriptLog "- Hosts with connection errors: $errorCount" -Type "Error"
        Write-ScriptLog "Detailed results saved to $resultsFile" -Type "Info"

        Write-Host ""
        Write-ScriptLog "Process completed successfully." -Type "Success"
    }
    catch {
        Write-ScriptLog "Error in Sunquest check: $_" -Type "Error"
        Write-ScriptLog $_.ScriptStackTrace -Type "Error"
    }
}
#endregion

#region Function 2: Send Hourly Messages
function Invoke-MessageSender {
    try {
        Clear-Host
        Write-MenuHeader -Title "MESSAGE SENDER" -Width 40
        Write-Host "Configuration:" -ForegroundColor $script:Config.Colors.Menu
        Write-Host "  Using hosts file: $($script:Config.HostsFile)" -ForegroundColor $script:Config.Colors.Info
        Write-Host 
        Write-Host "1. Send One-time Message" -ForegroundColor $script:Config.Colors.Highlight
        Write-Host "2. Start Hourly Message Service" -ForegroundColor $script:Config.Colors.Highlight
        Write-Host "3. Configure Message" -ForegroundColor $script:Config.Colors.Highlight
        Write-Host "4. Return to Main Menu" -ForegroundColor $script:Config.Colors.Highlight
        Write-Host ("=" * 40) -ForegroundColor $script:Config.Colors.Header
        
        $choice = Read-Host "Enter your choice (1-4)"
        
        switch ($choice) {
            "1" { Start-OneTimeMessageService }
            "2" { Start-HourlyMessageService }
            "3" { Configure-Message }
            "4" { Show-MainMenu; return }
            default {
                Write-ScriptLog "Invalid choice. Press any key to try again..." -Type "Warning"
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                Invoke-MessageSender
                return
            }
        }
    }
    catch {
        Write-ScriptLog "Error in message sender menu: ${_}" -Type "Error"
        Write-ScriptLog $_.ScriptStackTrace -Type "Error"
    }
    finally {
        Invoke-ReturnToMainMenu
    }
}

function Configure-Message {
    try {
        Clear-Host
        Write-MenuHeader -Title "CONFIGURE MESSAGE" -Width 50
        Write-Host "Current message:" -ForegroundColor $script:Config.Colors.Menu
        Write-Host $script:Config.DefaultMessage -ForegroundColor $script:Config.Colors.Info
        
        $useCustomMessage = Read-UserChoice -Prompt "`nWould you like to change the message?" -Options @("Yes", "No") -Default 1
        
        if ($useCustomMessage -eq 0) { # User chose "Yes"
            $message = Read-Host "Enter your message"
            if (-not [string]::IsNullOrWhiteSpace($message)) {
                $script:Config.DefaultMessage = $message
                Write-ScriptLog "Message updated" -Type "Success"
            } else {
                Write-ScriptLog "Message not changed (empty input)" -Type "Warning"
            }
        }
        
        Invoke-Pause
        Invoke-MessageSender
    }
    catch {
        Write-ScriptLog "Error configuring message: ${_}" -Type "Error"
        Invoke-Pause
    }
}

<#
.SYNOPSIS
    Sends messages to hosts.
.DESCRIPTION
    Sends a message to all hosts listed in the hosts file.
.PARAMETER HostsFilePath
    The path to the hosts file.
.PARAMETER Message
    The message to send.
.OUTPUTS
    PSCustomObject containing success and error counts.
#>
function Send-MessagesToHosts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$HostsFilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    
    # Read hostnames from file
    $hostnames = Get-HostsList -HostsFilePath $HostsFilePath
    if ($hostnames.Count -eq 0) {
        Write-ScriptLog "No hosts found to message." -Type "Warning"
        return [PSCustomObject]@{
            Success = $false
            SuccessCount = 0
            ErrorCount = 0
            TotalHosts = 0
        }
    }

    $successCount = 0
    $errorCount = 0
    $totalHosts = $hostnames.Count
    
    # Create progress parameters for splatting
    $progressParams = @{
        Activity = "Sending Messages"
        Status = "Processing hosts..."
        PercentComplete = 0
    }
    
    $count = 0
    foreach ($hostname in $hostnames) {
        $count++
        
        # Update progress
        $progressParams.Status = "Sending message to host $count of $totalHosts"
        $progressParams.PercentComplete = ($count / $totalHosts * 100)
        Write-Progress @progressParams
        
        try {
            # Prepare message command parameters
            $msgParams = @{
                FilePath = "msg.exe"
                ArgumentList = "* /SERVER:$hostname `"$Message`" /TIME:600"
                NoNewWindow = $true
                Wait = $true
                ErrorAction = "Stop"
            }
            
            # Execute the command with timeout
            $job = Start-Job -ScriptBlock {
                param($params)
                Start-Process @params
            } -ArgumentList $msgParams
            
            $null = Wait-Job -Job $job -Timeout ($script:Config.Timeout / 2)
            
            if ($job.State -eq 'Completed') {
                Receive-Job -Job $job | Out-Null
                Write-ScriptLog "Message sent successfully to $hostname" -Type "Success"
                $successCount++
            }
            else {
                throw "Operation timed out after $($script:Config.Timeout / 2) seconds"
            }
            
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-ScriptLog "Failed to send message to $hostname`: $_" -Type "Error"
            $errorCount++
        }
    }
    
    # Complete the progress bar
    Write-Progress -Activity "Sending Messages" -Completed
    
    Write-ScriptLog "Message sending complete. Success: $successCount, Failed: $errorCount" -Type "Info"
    
    return [PSCustomObject]@{
        Success = $true
        SuccessCount = $successCount
        ErrorCount = $errorCount
        TotalHosts = $totalHosts
    }
}

function Start-OneTimeMessageService {
    try {
        $scriptDir = Get-ScriptDirectory
        $hostsFile = Join-Path -Path $scriptDir -ChildPath $script:Config.HostsFile
        
        # Check if hosts file exists
        if (-not (Confirm-HostsFile -HostsFilePath $hostsFile)) {
            return
        }
        
        $message = $script:Config.DefaultMessage
        
        # Send one-time messages
        Write-ScriptLog "Sending one-time messages..." -Type "Info"
        $result = Send-MessagesToHosts -HostsFilePath $hostsFile -Message $message
        
        if ($result.Success) {
            Write-ScriptLog "One-time messages sent to $($result.SuccessCount) of $($result.TotalHosts) hosts." -Type "Success"
            if ($result.ErrorCount -gt 0) {
                Write-ScriptLog "Failed to send messages to $($result.ErrorCount) hosts." -Type "Warning"
            }
        }

        Invoke-Pause
    }
    catch {
        Write-ScriptLog "Error sending one-time messages: $_" -Type "Error"
        Write-ScriptLog $_.ScriptStackTrace -Type "Error"
        Invoke-Pause
    }
}

function Start-HourlyMessageService {
    try {
        $scriptDir = Get-ScriptDirectory
        $hostsFile = Join-Path -Path $scriptDir -ChildPath $script:Config.HostsFile
        
        # Check if hosts file exists
        if (-not (Confirm-HostsFile -HostsFilePath $hostsFile)) {
            return
        }
        
        $message = $script:Config.DefaultMessage
        
        # Main loop for hourly messages
        Write-ScriptLog "Starting hourly message sending service..." -Type "Info"
        Write-ScriptLog "Press Ctrl+C to stop the service and return to main menu" -Type "Warning"

        try {
            while ($true) {
                # Send messages
                $result = Send-MessagesToHosts -HostsFilePath $hostsFile -Message $message
                
                if (-not $result.Success) {
                    Write-ScriptLog "No hosts to message. Service will continue but no messages will be sent." -Type "Warning"
                }
                
                # Calculate time until next hour
                $now = Get-Date
                $nextHour = $now.AddHours(1).Date.AddHours($now.Hour + 1)
                $waitTime = ($nextHour - $now).TotalSeconds
                
                Write-ScriptLog "Waiting until next hour ($nextHour)..." -Type "Info"
                
                # Split wait time into smaller chunks to allow for cancellation
                $chunkSize = 10 # seconds
                $chunks = [Math]::Ceiling($waitTime / $chunkSize)
                
                for ($i = 0; $i -lt $chunks; $i++) {
                    $remainingTime = $waitTime - ($i * $chunkSize)
                    $sleepTime = [Math]::Min($chunkSize, $remainingTime)
                    
                    if ($sleepTime -le 0) { break }
                    
                    Start-Sleep -Seconds $sleepTime
                }
            }
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            # This catches Ctrl+C
            Write-ScriptLog "Hourly message service stopped." -Type "Warning"
            Invoke-Pause
        }
    }
    catch {
        Write-ScriptLog "Error in hourly message service: $_" -Type "Error"
        Write-ScriptLog $_.ScriptStackTrace -Type "Error"
        Invoke-Pause
    }
}
#endregion

#region Function 3: System Info Retriever
function Invoke-SystemInfoRetrieval {
    try {
        # Variables for SystemInfoRetriever
        $inputFile = Join-Path -Path (Get-ScriptDirectory) -ChildPath $script:Config.HostsFile
        $timeout = $script:Config.Timeout
        $checkSunquest = $script:Config.SystemInfo.CheckSunquest
        $checkPrinters = $script:Config.SystemInfo.CheckPrinters
        
        # Start the sub-menu for SystemInfoRetriever
        $exit = $false
        while (-not $exit) {
            Clear-Host
            Write-MenuHeader -Title "SYSTEM INFORMATION RETRIEVER" -Width 50
            Write-Host "Configuration:" -ForegroundColor $script:Config.Colors.Menu
            Write-Host "  1. Input File: $inputFile" -ForegroundColor $script:Config.Colors.Info
            Write-Host "  2. Timeout: $timeout seconds" -ForegroundColor $script:Config.Colors.Info
            Write-Host "  3. Include Sunquest Apps in Report: $(if ($checkSunquest) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $script:Config.Colors.Info
            Write-Host "  4. Include Printers in Report: $(if ($checkPrinters) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $script:Config.Colors.Info
            Write-Host
            Write-Host "Actions:" -ForegroundColor $script:Config.Colors.Menu
            Write-Host "  5. Start Batch Scan" -ForegroundColor $script:Config.Colors.Highlight
            Write-Host "  6. Check Single Host" -ForegroundColor $script:Config.Colors.Highlight
            Write-Host "  7. Check Unique Applications" -ForegroundColor $script:Config.Colors.Highlight
            Write-Host "  8. Return to Main Menu" -ForegroundColor $script:Config.Colors.Highlight
            Write-Host ("=" * 50) -ForegroundColor $script:Config.Colors.Header
            
            $choice = Read-Host "Enter your choice (1-8)"
            
            switch ($choice) {
                "1" {
                    $newFile = Read-Host "Enter new input file path"
                    if ($newFile) {
                        if (-not [System.IO.Path]::IsPathRooted($newFile)) {
                            $inputFile = Join-Path -Path (Get-ScriptDirectory) -ChildPath $newFile
                        } else {
                            $inputFile = $newFile
                        }
                        Write-ScriptLog "Input file updated to: $inputFile" -Type "Info"
                    }
                }
                "2" {
                    $newTimeout = Read-Host "Enter new timeout (seconds)"
                    if ($newTimeout -match '^\d+$') { 
                        $timeout = [int]$newTimeout 
                        Write-ScriptLog "Timeout updated to: $timeout seconds" -Type "Info"
                    }
                }
                "3" {
                    $checkSunquest = -not $checkSunquest
                    Write-ScriptLog "Sunquest Apps inclusion in report has been $(if ($checkSunquest) { 'enabled' } else { 'disabled' })" -Type "Info"
                    Start-Sleep -Seconds 1
                }
                "4" {
                    $checkPrinters = -not $checkPrinters
                    Write-ScriptLog "Printer inclusion in report has been $(if ($checkPrinters) { 'enabled' } else { 'disabled' })" -Type "Info"
                    Start-Sleep -Seconds 1
                }
                "5" {
                    Start-BatchSystemScan -InputFile $inputFile -Timeout $timeout -CheckSunquest $checkSunquest -CheckPrinters $checkPrinters
                }
                "6" {
                    $hostname = Read-Host "Enter hostname to check"
                    if ($hostname) {
                        Get-SingleHostInfo -ComputerName $hostname -Timeout $timeout -CheckSunquest $checkSunquest -CheckPrinters $checkPrinters
                    }
                }
                "7" {
                    Invoke-CheckUniqueApps
                }
                "8" {
                    $exit = $true
                }
                default {
                    Write-ScriptLog "Invalid choice. Please try again." -Type "Warning"
                    Start-Sleep -Seconds 1
                }
            }
        }
        
        # Update the global configuration with the current settings
        $script:Config.Timeout = $timeout
        $script:Config.SystemInfo.CheckSunquest = $checkSunquest
        $script:Config.SystemInfo.CheckPrinters = $checkPrinters
    }
    catch {
        Write-ScriptLog "An error occurred in the system info retrieval function:" -Type "Error"
        Write-ScriptLog $_.Exception.Message -Type "Error"
        Write-ScriptLog $_.ScriptStackTrace -Type "Error"
        Invoke-Pause
    }
    finally {
        Show-MainMenu
    }
}

function Get-SingleHostInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $false)]
        [int]$Timeout = $script:Config.Timeout,
        
        [Parameter(Mandatory = $false)]
        [bool]$CheckSunquest = $script:Config.SystemInfo.CheckSunquest,
        
        [Parameter(Mandatory = $false)]
        [bool]$CheckPrinters = $script:Config.SystemInfo.CheckPrinters
    )
    
    try {
        Write-Host "`nChecking host: $ComputerName" -ForegroundColor $script:Config.Colors.Info
        
        # Create a scriptblock that gets all the required information
        $scriptBlock = {
            param($computerName, $checkSunquest, $checkPrinters)
            
            try {
                # Create result object
                $result = [PSCustomObject]@{
                    Hostname = $computerName
                    Success = $true
                    OSName = $null
                    SystemModel = $null
                    TotalMemory = $null
                    SunquestApps = @()
                    Printers = @()
                    Error = $null
                }
                
                # Get basic system information
                $osInfo = Get-WmiObject -ComputerName $computerName -Class Win32_OperatingSystem -ErrorAction Stop
                $result.OSName = $osInfo.Caption
                $result.TotalMemory = [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
                
                # Get system model information
                $computerSystem = Get-WmiObject -ComputerName $computerName -Class Win32_ComputerSystem -ErrorAction Stop
                $result.SystemModel = $computerSystem.Model
                
                # If CheckSunquest is enabled, get Sunquest application information
                if ($checkSunquest) {
                    $sunquestApps = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName $computerName -Filter "Name LIKE 'Sunquest Lab%'" -ErrorAction Stop
                    if ($sunquestApps) {
                        $result.SunquestApps = $sunquestApps | Select-Object -ExpandProperty Name
                    }
                }
                
                # If CheckPrinters is enabled, get printer information
                if ($checkPrinters) {
                    $printers = Get-WmiObject -Class Win32_Printer -ComputerName $computerName -ErrorAction Stop
                    if ($printers) {
                        $result.Printers = $printers | Select-Object Name, ServerName, ShareName
                    }
                }
                
                return $result
            }
            catch {
                return [PSCustomObject]@{
                    Hostname = $computerName
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Execute the scriptblock with timeout
        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $ComputerName, $CheckSunquest, $CheckPrinters
        
        if (Wait-Job -Job $job -Timeout $Timeout) {
            $result = Receive-Job -Job $job
        }
        else {
            $result = [PSCustomObject]@{
                Hostname = $ComputerName
                Success = $false
                Error = "Operation timed out after $Timeout seconds"
            }
        }
        
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        
        # Display results
        if ($result.Success) {
            Write-Host "`nResults for $ComputerName" -ForegroundColor $script:Config.Colors.Success
            Write-Host ("OS Name: " + $result.OSName)
            Write-Host ("System Model: " + $result.SystemModel)
            Write-Host ("Total Physical Memory: " + $result.TotalMemory + " GB")
            
            # Display Sunquest applications if requested and found
            if ($CheckSunquest) {
                Write-Host "`nSunquest applications:" -ForegroundColor $script:Config.Colors.Info
                if ($result.SunquestApps -and $result.SunquestApps.Count -gt 0) {
                    foreach ($app in $result.SunquestApps) {
                        Write-Host ("- " + $app)
                    }
                } else {
                    Write-Host "No Sunquest Lab applications found" -ForegroundColor $script:Config.Colors.Warning
                }
            }
            
            # Display printers if requested and found
            if ($CheckPrinters) {
                Write-Host "`nPrinters:" -ForegroundColor $script:Config.Colors.Info
                if ($result.Printers -and $result.Printers.Count -gt 0) {
                    foreach ($printer in $result.Printers) {
                        Write-Host ("- Name: " + $printer.Name)
                        if ($printer.ServerName) { Write-Host ("  Server: " + $printer.ServerName) }
                        if ($printer.ShareName) { Write-Host ("  Share: " + $printer.ShareName) }
                    }
                } else {
                    Write-Host "No printers found" -ForegroundColor $script:Config.Colors.Warning
                }
            }
        }
        else {
            Write-Host ("Error checking host " + $ComputerName + " : " + $result.Error) -ForegroundColor $script:Config.Colors.Error
        }
    }
    catch {
        Write-Host ("Error checking host " + $ComputerName + " : $_") -ForegroundColor $script:Config.Colors.Error
    }
    
    Write-Host "`nPress any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Start-BatchSystemScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile,
        
        [Parameter(Mandatory = $false)]
        [int]$Timeout = $script:Config.Timeout,
        
        [Parameter(Mandatory = $false)]
        [bool]$CheckSunquest = $script:Config.SystemInfo.CheckSunquest,
        
        [Parameter(Mandatory = $false)]
        [bool]$CheckPrinters = $script:Config.SystemInfo.CheckPrinters
    )
    
    $scriptDir = Get-ScriptDirectory
    $outputFile = Join-Path -Path $scriptDir -ChildPath $script:Config.OutputFiles.SystemInfo
    
    if (-not (Test-Path $InputFile)) {
        Write-ScriptLog "Error: Input file $InputFile not found." -Type "Error"
        if (-not (Confirm-HostsFile -HostsFilePath $InputFile)) {
            Invoke-Pause
            return
        }
    }
    
    # Initialize output file
    if (-not (Initialize-OutputFile -FilePath $outputFile -Title "System Information Report")) {
        Invoke-Pause
        return
    }

    Write-ScriptLog "Current directory: $(Get-Location)" -Type "Info"
    Write-ScriptLog "Script directory: $scriptDir" -Type "Info"
    Write-ScriptLog "Using hosts file: $InputFile" -Type "Info"
    
    # Get hosts to check
    $hosts = Get-HostsList -HostsFilePath $InputFile
    if ($hosts.Count -eq 0) {
        Write-ScriptLog "No hosts found to process." -Type "Warning"
        Invoke-Pause
        return
    }
    
    $scriptBlock = {
        param($computerName, $checkSunquest, $checkPrinters)
        
        try {
            # Create result object
            $result = [PSCustomObject]@{
                Hostname = $computerName
                Success = $true
                OSName = $null
                SystemModel = $null
                TotalMemory = $null
                SunquestApps = @()
                Printers = @()
                Error = $null
            }
            
            # Get basic system information
            $osInfo = Get-WmiObject -ComputerName $computerName -Class Win32_OperatingSystem -ErrorAction Stop
            $result.OSName = $osInfo.Caption
            $result.TotalMemory = [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
            
            # Get system model information
            $computerSystem = Get-WmiObject -ComputerName $computerName -Class Win32_ComputerSystem -ErrorAction Stop
            $result.SystemModel = $computerSystem.Model
            
            # If CheckSunquest is enabled, get Sunquest application information
            if ($checkSunquest) {
                $sunquestApps = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName $computerName -Filter "Name LIKE 'Sunquest Lab%'" -ErrorAction Stop
                if ($sunquestApps) {
                    $result.SunquestApps = $sunquestApps | Select-Object -ExpandProperty Name
                }
            }
            
            # If CheckPrinters is enabled, get printer information
            if ($checkPrinters) {
                $printers = Get-WmiObject -Class Win32_Printer -ComputerName $computerName -ErrorAction Stop
                if ($printers) {
                    $result.Printers = $printers | Select-Object Name, ServerName, ShareName
                }
            }
            
            return $result
        }
        catch {
            return [PSCustomObject]@{
                Hostname = $computerName
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }

    Write-ScriptLog "Starting system information retrieval..." -Type "Info"
    
    $totalHosts = $hosts.Count
    $currentHost = 0
    $jobs = @()
    $results = @()
    $maxParallelJobs = [Math]::Min(10, $hosts.Count) # Limit concurrent jobs

    # Create a StringBuilder for collecting output
    $outputBuilder = New-Object System.Text.StringBuilder
    
    # Initialize progress bar parameters
    $progressParams = @{
        Activity = "Retrieving System Information"
        Status = "Starting jobs..."
        PercentComplete = 0
    }
    
    Write-Progress @progressParams
    
    # Start initial batch of jobs
    foreach ($computerName in $hosts | Select-Object -First $maxParallelJobs) {
        $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $computerName, $CheckSunquest, $CheckPrinters
        $currentHost++
    }
    
    # Process remaining hosts
    $jobIndex = $maxParallelJobs
    $completedHosts = 0
    
    while ($completedHosts -lt $totalHosts) {
        # Wait for any job to complete
        $completedJob = $jobs | Wait-Job -Any -Timeout 1
        
        if ($completedJob) {
            # Process completed job
            $result = Receive-Job -Job $completedJob
            $results += $result
            $completedHosts++
            
            # Update progress
            $progressParams.PercentComplete = ($completedHosts / $totalHosts * 100)
            $progressParams.Status = "Processed $completedHosts of $totalHosts hosts"
            Write-Progress @progressParams
            
            # Format and append result to output
            if ($result.Success) {
                $null = $outputBuilder.AppendLine("Host: $($result.Hostname)")
                $null = $outputBuilder.AppendLine("OS Name: $($result.OSName)")
                $null = $outputBuilder.AppendLine("System Model: $($result.SystemModel)")
                $null = $outputBuilder.AppendLine("Total Physical Memory: $($result.TotalMemory) GB")
                
                if ($CheckSunquest) {
                    $null = $outputBuilder.AppendLine("Sunquest Applications:")
                    if ($result.SunquestApps -and $result.SunquestApps.Count -gt 0) {
                        foreach ($app in $result.SunquestApps) {
                            $null = $outputBuilder.AppendLine("- $app")
                        }
                    } else {
                        $null = $outputBuilder.AppendLine("No Sunquest Lab applications found")
                    }
                }
                
                if ($CheckPrinters) {
                    $null = $outputBuilder.AppendLine("Printers:")
                    if ($result.Printers -and $result.Printers.Count -gt 0) {
                        foreach ($printer in $result.Printers) {
                            $null = $outputBuilder.AppendLine("- Name: $($printer.Name)")
                            if ($printer.ServerName) { $null = $outputBuilder.AppendLine("  Server: $($printer.ServerName)") }
                            if ($printer.ShareName) { $null = $outputBuilder.AppendLine("  Share: $($printer.ShareName)") }
                        }
                    } else {
                        $null = $outputBuilder.AppendLine("No printers found")
                    }
                }
            }
            else {
                $null = $outputBuilder.AppendLine("Host: $($result.Hostname)")
                $null = $outputBuilder.AppendLine("ERROR: $($result.Error)")
            }
            
            $null = $outputBuilder.AppendLine("")
            
            # Remove the completed job
            Remove-Job -Job $completedJob -Force
            $jobs = $jobs | Where-Object { $_ -ne $completedJob }
            
            # Start a new job if there are more hosts to process
            if ($jobIndex -lt $totalHosts) {
                $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $hosts[$jobIndex], $CheckSunquest, $CheckPrinters
                $jobIndex++
            }
        }
    }
    
    # Complete the progress bar
    Write-Progress -Activity "Retrieving System Information" -Completed
    
    # Write all results to the output file
    Add-Content -Path $outputFile -Value $outputBuilder.ToString() -ErrorAction SilentlyContinue
    
    # Summarize results
    $successCount = ($results | Where-Object { $_.Success }).Count
    $errorCount = ($results | Where-Object { -not $_.Success }).Count
    
    Write-ScriptLog "System information retrieval completed." -Type "Success"
    Write-ScriptLog "Successfully retrieved information for $successCount of $totalHosts hosts." -Type "Info"
    Write-ScriptLog "Failed to retrieve information for $errorCount hosts." -Type $(if ($errorCount -gt 0) { "Warning" } else { "Info" })
    Write-ScriptLog "Results saved to $outputFile" -Type "Info"
    
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Invoke-CheckUniqueApps {
    Clear-Host
    Write-MenuHeader -Title "CHECK UNIQUE APPLICATIONS" -Width 50
    
    # Define file paths
    $scriptDir = Get-ScriptDirectory
    $baselineFile = Join-Path -Path $scriptDir -ChildPath $script:Config.CheckApps.BaselineFile
    $inputFile = Join-Path -Path $scriptDir -ChildPath $script:Config.HostsFile
    $outputFile = Join-Path -Path $scriptDir -ChildPath $script:Config.OutputFiles.UniqueApps
    
    # Check if baseline file exists, if not prompt to create it
    if (-not (Test-Path -Path $baselineFile)) {
        Write-ScriptLog "Error: baseline file not found: $baselineFile" -Type "Error"
        Write-ScriptLog "The baseline file should contain a list of standard applications to exclude from the unique apps check." -Type "Info"
        Write-ScriptLog "Would you like to create an empty baseline file? (Y/N)" -Type "Warning"
        $createBaseline = Read-Host
        
        if ($createBaseline -eq 'Y' -or $createBaseline -eq 'y') {
            # Create empty baseline file
            "" | Out-File -FilePath $baselineFile
            Write-ScriptLog "Created empty baseline file at $baselineFile" -Type "Success"
            Write-ScriptLog "Please edit this file to add standard applications (one per line)." -Type "Info"
            Start-Process notepad.exe -ArgumentList $baselineFile
            Invoke-Pause
            return
        }
        else {
            Write-ScriptLog "Baseline file is required for this operation." -Type "Warning"
            Invoke-Pause
            return
        }
    }
    
    # Check if hosts file exists
    if (-not (Confirm-HostsFile -HostsFilePath $inputFile)) {
        return
    }
    
    # Initialize output file
    if (-not (Initialize-OutputFile -FilePath $outputFile -Title "Unique Applications Report")) {
        Invoke-Pause
        return
    }
    
    # Load baseline applications
    try {
        Write-ScriptLog "Loading baseline applications from $baselineFile" -Type "Info"
        $baseline = Get-Content -Path $baselineFile -ErrorAction Stop
        Write-ScriptLog "Loaded $(($baseline | Measure-Object).Count) baseline applications" -Type "Success"
    }
    catch {
        Write-ScriptLog "Error loading baseline applications: $_" -Type "Error"
        Invoke-Pause
        return
    }
    
    # Define applications to exclude by pattern
    $excludePatterns = $script:Config.CheckApps.ExcludePatterns
    
    # Get hosts to process
    $hostnames = Get-HostsList -HostsFilePath $inputFile
    if ($hostnames.Count -eq 0) {
        Write-ScriptLog "No hosts found to process." -Type "Warning"
        Invoke-Pause
        return
    }
    
    # Process each hostname
    $totalHosts = $hostnames.Count
    $currentHost = 0
    $successCount = 0
    $errorCount = 0
    
    # Create a StringBuilder for collecting output
    $outputBuilder = New-Object System.Text.StringBuilder
    
    # Create scriptblock for checking applications
    $scriptBlock = {
        param($hostname, $baseline, $excludePatterns)
        
        try {
            # Use Get-WmiObject to get installed applications
            $installedApps = Get-WmiObject -Class Win32_Product -ComputerName $hostname -ErrorAction Stop |
                            Select-Object -ExpandProperty Name
            
            # Find unique apps not in baseline and not matching exclude patterns
            $uniqueApps = @()
            foreach ($app in $installedApps) {
                $inBaseline = $baseline -contains $app
                $excluded = $false
                
                if (-not $inBaseline) {
                    foreach ($pattern in $excludePatterns) {
                        if ($app -match $pattern) {
                            $excluded = $true
                            break
                        }
                    }
                    
                    if (-not $excluded) {
                        $uniqueApps += $app
                    }
                }
            }
            
            return [PSCustomObject]@{
                Hostname = $hostname
                Success = $true
                UniqueApps = $uniqueApps
                Error = $null
            }
        }
        catch {
            return [PSCustomObject]@{
                Hostname = $hostname
                Success = $false
                UniqueApps = @()
                Error = $_.Exception.Message
            }
        }
    }
    
    # Progress parameters
    $progressParams = @{
        Activity = "Checking Unique Applications"
        Status = "Processing hosts..."
        PercentComplete = 0
    }
    
    # Process hosts with constrained parallelism
    $maxConcurrentJobs = [Math]::Min(10, $totalHosts)
    $jobs = @()
    $initialBatch = $hostnames | Select-Object -First $maxConcurrentJobs
    
    # Start initial batch of jobs
    foreach ($hostname in $initialBatch) {
        $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $hostname, $baseline, $excludePatterns
        $currentHost++
    }
    
    # Process all hosts
    $completedHosts = 0
    $hostsIndex = $maxConcurrentJobs
    
    while ($completedHosts -lt $totalHosts) {
        # Wait for any job to complete with a small timeout
        $completedJob = $jobs | Wait-Job -Any -Timeout 1
        
        if ($completedJob) {
            # Process completed job
            $result = Receive-Job -Job $completedJob
            $completedHosts++
            
            # Update progress
            $progressParams.Status = "Processed $completedHosts of $totalHosts hosts"
            $progressParams.PercentComplete = ($completedHosts / $totalHosts * 100)
            Write-Progress @progressParams
            
            if ($result.Success) {
                if ($result.UniqueApps.Count -gt 0) {
                    $null = $outputBuilder.AppendLine("Host: $($result.Hostname)")
                    $null = $outputBuilder.AppendLine("----------------------------------------")
                    foreach ($app in $result.UniqueApps) {
                        $null = $outputBuilder.AppendLine("- $app")
                    }
                    $null = $outputBuilder.AppendLine("")
                    Write-ScriptLog "Found $($result.UniqueApps.Count) unique applications on $($result.Hostname)" -Type "Success"
                } else {
                    $null = $outputBuilder.AppendLine("Host: $($result.Hostname) - No unique applications found")
                    $null = $outputBuilder.AppendLine("")
                    Write-ScriptLog "No unique applications found on $($result.Hostname)" -Type "Info"
                }
                $successCount++
            }
            else {
                $null = $outputBuilder.AppendLine("Error connecting to $($result.Hostname): $($result.Error)")
                $null = $outputBuilder.AppendLine("")
                Write-ScriptLog "Error connecting to $($result.Hostname): $($result.Error)" -Type "Error"
                $errorCount++
            }
            
            # Remove the completed job
            Remove-Job -Job $completedJob -Force
            $jobs = $jobs | Where-Object { $_ -ne $completedJob }
            
            # Start a new job if there are more hosts to process
            if ($hostsIndex -lt $totalHosts) {
                $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $hostnames[$hostsIndex], $baseline, $excludePatterns
                $hostsIndex++
            }
        }
    }
    
    # Complete the progress bar
    Write-Progress -Activity "Checking Unique Applications" -Completed
    
    # Write all results to the output file
    Add-Content -Path $outputFile -Value $outputBuilder.ToString() -ErrorAction SilentlyContinue
    
    # Display summary
    Write-ScriptLog "Process completed." -Type "Success"
    Write-ScriptLog "Successfully checked $successCount of $totalHosts hosts." -Type "Info"
    Write-ScriptLog "Failed to check $errorCount hosts." -Type $(if ($errorCount -gt 0) { "Warning" } else { "Info" })
    Write-ScriptLog "Unique applications saved to $outputFile" -Type "Info"
    
    Invoke-Pause
}
#endregion

#region Script Entry Point
# Check admin privileges and relaunch if needed
if (-not (Test-AdminPrivileges)) {
    Write-Host "This script requires administrator privileges." -ForegroundColor $script:Config.Colors.Warning
    Write-Host "Attempting to relaunch with elevated permissions..." -ForegroundColor $script:Config.Colors.Warning
    
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Clear log file at script start
$logFile = Join-Path -Path (Get-ScriptDirectory) -ChildPath $script:Config.OutputFiles.LogFile
"" | Out-File -FilePath $logFile -Force -ErrorAction SilentlyContinue

Write-ScriptLog "Script is running with administrator privileges" -Type "Success"
Write-ScriptLog "Script started at $(Get-Date)" -Type "Info"

# Start the program
Show-MainMenu
#endregion 