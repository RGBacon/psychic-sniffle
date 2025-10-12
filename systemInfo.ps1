# SystemInfo Tool - Refactored Modular Version
# Main entry point for the modular system information gathering tool

param(
    [string[]]$Hostnames = @(),
    [switch]$NoMenu,
    [switch]$Verbose,
    [switch]$Help,
    [string]$ConfigFile = "config.json"
)

# Check if running as administrator and relaunch with UAC if needed
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-Elevated {
    param(
        [string[]]$Arguments = @(),
        [string]$ScriptPath
    )
    
    $argumentString = $Arguments -join ' '
    
    Write-Host "This script requires administrator privileges." -ForegroundColor Yellow
    Write-Host "Relaunching with UAC elevation..." -ForegroundColor Cyan
    
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit -File `"$ScriptPath`" $argumentString" -Verb RunAs
        exit 0
    }
    catch {
        Write-Host "Failed to relaunch with elevation: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please run PowerShell as Administrator and execute this script again." -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# Check for administrator privileges
if (-not (Test-Administrator)) {
    # Build argument string for relaunch
    $relaunchArgs = @()
    
    if ($Hostnames.Count -gt 0) {
        $relaunchArgs += "-Hostnames"
        $relaunchArgs += "`"$($Hostnames -join ',')`""
    }
    
    if ($NoMenu) { $relaunchArgs += "-NoMenu" }
    if ($Verbose) { $relaunchArgs += "-Verbose" }
    if ($Help) { $relaunchArgs += "-Help" }
    if ($ConfigFile -ne "config.json") {
        $relaunchArgs += "-ConfigFile"
        $relaunchArgs += "`"$ConfigFile`""
    }
    
    Start-Elevated -Arguments $relaunchArgs -ScriptPath $PSCommandPath
}

# Import required modules
$modulePath = Join-Path $PSScriptRoot "Modules"
$modules = @(
    "Configuration.ps1",
    "Logging.ps1", 
    "FileOperations.ps1",
    "NetworkOperations.ps1",
    "SystemInfo.ps1",
    "MenuSystem.ps1",
    "FailedHostTracker.ps1",
    "Reporting.ps1",
    "SchedulingEngine.ps1"
)

# Load all modules
foreach ($module in $modules) {
    $moduleFile = Join-Path $modulePath $module
    if (Test-Path $moduleFile) {
        try {
            . $moduleFile
            if ($Verbose) {
                Write-Host "Loaded module: $module" -ForegroundColor Green
            }
        }
        catch {
            Write-Error "Failed to load module $module : $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Write-Error "Module not found: $moduleFile"
        exit 1
    }
}

# Initialize configuration
try {
    Initialize-Configuration
    $config = Get-Configuration
    if ($Verbose) {
        Write-Host "Configuration loaded successfully" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to initialize configuration: $($_.Exception.Message)"
    exit 1
}

# Initialize logging
try {
    Initialize-Logging
    if ($Verbose) {
        Write-Host "Logging initialized successfully" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to initialize logging: $($_.Exception.Message)"
    exit 1
}

# Show help if requested
if ($Help) {
    Write-Host @"
SystemInfo Tool - Refactored Modular Version

USAGE:
    .\systemInfo.ps1 [OPTIONS]

OPTIONS:
    -Hostnames <string[]>    Comma-separated list of hostnames to scan
    -NoMenu                  Run in headless mode without interactive menu
    -Verbose                Enable verbose output
    -Help                   Show this help message
    -ConfigFile <string>    Path to configuration file (default: config.json)

EXAMPLES:
    .\systemInfo.ps1                                    # Interactive mode
    .\systemInfo.ps1 -NoMenu -Verbose                  # Headless mode
    .\systemInfo.ps1 -Hostnames "PC1,PC2,PC3"          # Specific hosts
    .\systemInfo.ps1 -ConfigFile "custom.json"         # Custom config

MODULES:
    Configuration.ps1      - Configuration management
    Logging.ps1            - Logging operations  
    FileOperations.ps1     - File I/O operations
    NetworkOperations.ps1  - Network connectivity
    SystemInfo.ps1         - System information gathering
    MenuSystem.ps1         - Interactive menus
    FailedHostTracker.ps1 - Failed host tracking
    Reporting.ps1          - Report generation
    SchedulingEngine.ps1   - Task scheduling

"@
    exit 0
}

# Main execution logic
try {
    if ($NoMenu) {
        # Headless mode - process hosts directly
        if ($Hostnames.Count -eq 0) {
            Write-Host "No hostnames specified. Use -Hostnames parameter or run without -NoMenu for interactive mode." -ForegroundColor Yellow
            exit 1
        }
        
        Write-Host "Running in headless mode..." -ForegroundColor Cyan
        Write-Host "Processing hosts: $($Hostnames -join ', ')" -ForegroundColor Cyan
        
        # Process each host
        $results = @()
        
        # Convert SystemInfo config to hashtable for function parameter
        $scanOptions = @{
            CheckSunquest = $config.SystemInfo.CheckSunquest
            CheckPrinters = $config.SystemInfo.CheckPrinters
            CheckTracert = $config.SystemInfo.CheckTracert
        }
        
        foreach ($hostname in $Hostnames) {
            Write-Host "Processing $hostname..." -ForegroundColor Yellow
            try {
                $result = Get-RemoteSystemInfo -ComputerName $hostname -Options $scanOptions
                $results += $result
                
                if ($result.Success) {
                    Write-Host "✓ $hostname completed successfully" -ForegroundColor Green
                }
                else {
                    Write-Host "✗ $hostname failed: $($result.Error)" -ForegroundColor Red
                }
            }
            catch {
                Write-Host "✗ $hostname error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        # Generate reports
        if ($results.Count -gt 0) {
            Write-Host "Generating reports..." -ForegroundColor Cyan
            try {
                Export-SystemDataToCSV -SystemData $results
                Generate-HTMLReport -SystemData $results
                Write-Host "Reports generated successfully" -ForegroundColor Green
            }
            catch {
                Write-Host "Report generation failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    else {
        # Interactive mode - show menu
        Write-Host "SystemInfo Tool - Refactored Modular Version" -ForegroundColor Cyan
        Write-Host "=============================================" -ForegroundColor Cyan
        
        Show-MainMenu
    }
}
catch {
    Write-Error "Execution failed: $($_.Exception.Message)"
    exit 1
}
finally {
    # Cleanup
    if (Get-Command "Close-Logging" -ErrorAction SilentlyContinue) {
        Close-Logging
    }
}