# Logging Module
# Handles all logging operations with different levels and formatting

#region Logging Functions
function Initialize-Logging {
    [CmdletBinding()]
    param()
    
    $config = Get-Configuration
    $logFile = Join-Path (Get-ScriptDirectory) $config.OutputFiles.LogFile
    
    # Clear existing log file
    Clear-Content -Path $logFile -Force -ErrorAction SilentlyContinue
    
    Write-Host "Logging initialized" -ForegroundColor Green
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("Info", "Success", "Warning", "Error", "Debug")]
        [string]$Level = "Info",
        
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    $config = Get-Configuration
    $logFile = Join-Path (Get-ScriptDirectory) $config.OutputFiles.LogFile
    
    try {
        Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
        # Fallback to console if file logging fails
        Write-Host "Log file write failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Write to console with appropriate color
    if (-not $NoConsole) {
        $color = switch ($Level) {
            "Success" { "Green" }
            "Warning" { "Yellow" }
            "Error" { "Red" }
            "Debug" { "Cyan" }
            default { "White" }
        }
        
        Write-Host $logMessage -ForegroundColor $color
    }
}

function Write-ScriptLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info",
        
        [switch]$NoConsole
    )
    
    # Legacy function for backward compatibility
    Write-Log -Message $Message -Level $Type -NoConsole:$NoConsole
}

function Get-LogContent {
    [CmdletBinding()]
    param(
        [int]$LastLines = 100
    )
    
    $config = Get-Configuration
    $logFile = Join-Path (Get-ScriptDirectory) $config.OutputFiles.LogFile
    
    if (Test-Path $logFile) {
        return Get-Content -Path $logFile -Tail $LastLines
    }
    
    return @()
}

function Clear-Log {
    [CmdletBinding()]
    param()
    
    $config = Get-Configuration
    $logFile = Join-Path (Get-ScriptDirectory) $config.OutputFiles.LogFile
    
    try {
        Clear-Content -Path $logFile -Force
        Write-Log "Log file cleared" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to clear log file: $($_.Exception.Message)" -Level Error
        return $false
    }
}
#endregion
