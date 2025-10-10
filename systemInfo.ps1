# Set error action preference globally
$ErrorActionPreference = 'Stop'

#region Global Configuration
function Get-ScriptDirectory {
    if ($PSScriptRoot) { return $PSScriptRoot }
    return (Get-Location).Path
}

# Load configuration from JSON file, or create it if it doesn't exist
$script:Config = $null
$configFilePath = Join-Path (Get-ScriptDirectory) "config.json"

function Initialize-Configuration {
    if (Test-Path $configFilePath) {
        try {
            $configContent = Get-Content -Path $configFilePath | ConvertFrom-Json
            $script:Config = $configContent
            Write-ScriptLog "Configuration loaded from $configFilePath" -Type "Success"
        }
        catch {
            Create-DefaultConfiguration
            Write-ScriptLog "Error loading configuration file. Using default settings. Error: $_" -Type "Error"
        }
    }
    else {
        Create-DefaultConfiguration
        Write-ScriptLog "Configuration file not found. A default one has been created." -Type "Warning"
    }
}

function Create-DefaultConfiguration {
    $defaultConfig = @{
        HostsFile = "hosts.txt"
        OutputFiles = @{
            SunquestResults = "sunquest_results.txt"
            LogFile = "script_log.txt"
            UniqueApps = "unique_apps.txt"
            EnhancedInfo = "enhanced_system_info.txt"
            NetworkTopology = "network_topology.txt"
            SystemDataCSV = "system_data.csv"
            HTMLViewer = "system_data_viewer.html"
        }
        Timeout = 90
        MaxParallelJobs = 10
        DefaultMessage = "IMPORTANT: This device has been identified for replacement. Please contact IT Support via Teams or Outlook to schedule your device replacement. This message will repeat hourly until action is taken."
        SystemInfo = @{
            CheckSunquest = $false
            CheckPrinters = $false
            CheckTracert = $false
        }
        CheckApps = @{
            BaselineFile = "baseline.txt"
            ExcludePatterns = @(
                '^Microsoft ', '^McAfee ', '^Google Update Helper$',
                '^64 Bit HP CIO Components Installer$',
                '^Trellix Data Exchange Layer for MA$',
                '^Google Chrome$', '^Teams Machine-Wide Installer$'
            )
        }
        Colors = @{
            Success = "Green"; Warning = "Yellow"; Error = "Red"
            Info = "White"; Header = "Yellow"; Menu = "Gray"; Highlight = "White"
        }
    }
    $defaultConfig | ConvertTo-Json -Depth 5 | Out-File -FilePath $configFilePath -Encoding utf8
    $script:Config = $defaultConfig
}
#endregion

#region Core Helper Functions
function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-ScriptLog {
    param (
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info",
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    # Write to log file
    $logFile = Join-Path (Get-ScriptDirectory) $script:Config.OutputFiles.LogFile
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    
    # Write to console
    if (-not $NoConsole) {
        $color = $script:Config.Colors.Info # Default color
        switch ($Type) {
            "Success" { $color = $script:Config.Colors.Success }
            "Warning" { $color = $script:Config.Colors.Warning }
            "Error" { $color = $script:Config.Colors.Error }
            "Header" { $color = $script:Config.Colors.Header }
            "Menu" { $color = $script:Config.Colors.Menu }
            "Highlight" { $color = $script:Config.Colors.Highlight }
        }
        Write-Host $Message -ForegroundColor $color
    }
}

function Get-FilePath {
    param([string]$FileName, [string]$Default)
    $scriptDir = Get-ScriptDirectory
    return Join-Path $scriptDir $(if ($FileName) { $FileName } else { $Default })
}

function Initialize-OutputFile {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$Title
    )
    
    try {
        # Ensure the directory exists
        $directory = Split-Path -Path $FilePath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        
        # Create or overwrite the file with header
        $header = @(
            $Title,
            "Generated on $(Get-Date)",
            ("=" * 50),
            ""
        ) -join "`n"
        
        # Use Set-Content which will create the file if it doesn't exist
        Set-Content -Path $FilePath -Value $header -Force -ErrorAction Stop
        return $true
    }
    catch {
        Write-ScriptLog "Cannot write to file $FilePath : $_" -Type "Error"
        return $false
    }
}

function Get-HostsList {
    param([Parameter(Mandatory)][string]$HostsFilePath)
    
    if (-not (Test-Path $HostsFilePath)) {
        Write-ScriptLog "Hosts file not found: $HostsFilePath" -Type "Error"
        
        if ((Read-Host "Create sample hosts file? (Y/N)") -eq 'Y') {
            "localhost" | Out-File -FilePath $HostsFilePath
            Write-ScriptLog "Created sample hosts file" -Type "Success"
        }
        return @()
    }
    
    $hosts = Get-Content $HostsFilePath | Where-Object { $_.Trim() -ne '' }
    Write-ScriptLog "Found $($hosts.Count) hosts to process" -Type "Success"
    return $hosts
}

function Write-MenuHeader {
    param([string]$Title, [int]$Width = 50)
    
    $border = "=" * $Width
    $padding = [math]::Max(0, ($Width - $Title.Length) / 2)
    $centeredTitle = (" " * [math]::Floor($padding)) + $Title
    
    Write-Host $border -ForegroundColor $script:Config.Colors.Header
    Write-Host $centeredTitle -ForegroundColor $script:Config.Colors.Header
    Write-Host $border -ForegroundColor $script:Config.Colors.Header
}

function Invoke-Pause {
    param([string]$Message = "Press Enter to continue...")
    Read-Host $Message
}

function Initialize-CSVFile {
    param([string]$FilePath)
    
    try {
        # Ensure the directory exists
        $directory = Split-Path -Path $FilePath -Parent
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        
        # Check if CSV file exists
        if (-not (Test-Path $FilePath)) {
            # Create CSV with headers
            $headers = @(
                "Timestamp", "Hostname", "OS_Name", "OS_Version", "OS_Build", "Manufacturer", 
                "Model", "TotalMemory_GB", "Processor", "Cores", "LogicalProcessors", "LastBoot",
                "Drive_C", "Drive_C_Free_GB", "Drive_C_Size_GB", "Drive_C_Percent_Free",
                "Drive_D", "Drive_D_Free_GB", "Drive_D_Size_GB", "Drive_D_Percent_Free",
                "Primary_IP", "Primary_Gateway", "Primary_DNS", "MAC_Address", "Subnet",
                "Sunquest_Apps", "Printer_Count", "Printer_Names", "TraceRoute", "Status", "Error_Message"
            )
            
            $headers -join "," | Out-File -FilePath $FilePath -Encoding UTF8
            Write-ScriptLog "Created new CSV file: $FilePath" -Type "Success"
        }
        return $true
    }
    catch {
        Write-ScriptLog "Error initializing CSV file: $_" -Type "Error"
        return $false
    }
}

function Export-SystemDataToCSV {
    param(
        [array]$Results,
        [string]$FilePath
    )
    
    try {
        if (-not (Initialize-CSVFile -FilePath $FilePath)) {
            return $false
        }
        
        $csvData = @()
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        foreach ($result in $Results) {
            $row = @{
                Timestamp = $timestamp
                Hostname = $result.Hostname
                OS_Name = if ($result.Success -and $result.Data.OS) { $result.Data.OS.Name } else { "" }
                OS_Version = if ($result.Success -and $result.Data.OS) { $result.Data.OS.Version } else { "" }
                OS_Build = if ($result.Success -and $result.Data.OS) { $result.Data.OS.BuildNumber } else { "" }
                Manufacturer = if ($result.Success -and $result.Data.Hardware) { $result.Data.Hardware.Manufacturer } else { "" }
                Model = if ($result.Success -and $result.Data.Hardware) { $result.Data.Hardware.Model } else { "" }
                TotalMemory_GB = if ($result.Success -and $result.Data.OS) { $result.Data.OS.TotalMemoryGB } else { "" }
                Processor = if ($result.Success -and $result.Data.Hardware) { $result.Data.Hardware.Processor } else { "" }
                Cores = if ($result.Success -and $result.Data.Hardware) { $result.Data.Hardware.Cores } else { "" }
                LogicalProcessors = if ($result.Success -and $result.Data.Hardware) { $result.Data.Hardware.LogicalProcessors } else { "" }
                LastBoot = if ($result.Success -and $result.Data.OS) { $result.Data.OS.LastBoot.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
                Drive_C = ""
                Drive_C_Free_GB = ""
                Drive_C_Size_GB = ""
                Drive_C_Percent_Free = ""
                Drive_D = ""
                Drive_D_Free_GB = ""
                Drive_D_Size_GB = ""
                Drive_D_Percent_Free = ""
                Primary_IP = ""
                Primary_Gateway = ""
                Primary_DNS = ""
                MAC_Address = ""
                Subnet = ""
                Sunquest_Apps = ""
                Printer_Count = ""
                Printer_Names = ""
                TraceRoute = ""
                Status = if ($result.Success) { "Success" } else { "Error" }
                Error_Message = if (-not $result.Success) { $result.Error } else { "" }
            }
            
            # Process storage information
            if ($result.Success -and $result.Data.Storage) {
                foreach ($disk in $result.Data.Storage) {
                    if ($disk.Drive -eq "C:") {
                        $row.Drive_C = $disk.Drive
                        $row.Drive_C_Free_GB = $disk.FreeGB
                        $row.Drive_C_Size_GB = $disk.SizeGB
                        $row.Drive_C_Percent_Free = [math]::Round(($disk.FreeGB / $disk.SizeGB) * 100, 1)
                    }
                    elseif ($disk.Drive -eq "D:") {
                        $row.Drive_D = $disk.Drive
                        $row.Drive_D_Free_GB = $disk.FreeGB
                        $row.Drive_D_Size_GB = $disk.SizeGB
                        $row.Drive_D_Percent_Free = [math]::Round(($disk.FreeGB / $disk.SizeGB) * 100, 1)
                    }
                }
            }
            
            # Process network information
            if ($result.Success -and $result.Data.Network) {
                $primaryAdapter = $result.Data.Network | Where-Object { $_.IPAddress -and $_.IPAddress -ne "" } | Select-Object -First 1
                if ($primaryAdapter) {
                    $row.Primary_IP = $primaryAdapter.IPAddress
                    $row.Primary_Gateway = $primaryAdapter.DefaultGateway
                    $row.Primary_DNS = $primaryAdapter.DNSServers
                    $row.MAC_Address = $primaryAdapter.MACAddress
                    
                    # Extract subnet (first 3 octets)
                    if ($primaryAdapter.IPAddress) {
                        $ipParts = $primaryAdapter.IPAddress.Split('.')
                        if ($ipParts.Count -ge 3) {
                            $row.Subnet = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).*"
                        }
                    }
                }
            }
            
            # Process Sunquest applications
            if ($result.Success -and $result.Data.Software) {
                $sunquestApps = $result.Data.Software | Where-Object { 
                    $_ -like "*Sunquest*" -or 
                    $_ -like "*SunQuest*" -or 
                    $_ -like "*SUNQUEST*" -or
                    $_ -like "*Lab*" -and ($_ -like "*Sunquest*" -or $_ -like "*SunQuest*" -or $_ -like "*SUNQUEST*")
                }
                if ($sunquestApps) {
                    $row.Sunquest_Apps = ($sunquestApps -join "; ")
                }
            }
            
            # Process printer information
            if ($result.Success -and $result.Data.Printers) {
                $row.Printer_Count = $result.Data.Printers.Count
                $row.Printer_Names = ($result.Data.Printers | Select-Object -ExpandProperty Name) -join "; "
            }
            
            # Process tracert information
            if ($result.Success -and $result.Data.TraceRoute) {
                $row.TraceRoute = $result.Data.TraceRoute
            }
            
            $csvData += $row
        }
        
        # Append to CSV file
        foreach ($row in $csvData) {
            # Create CSV line with proper field order matching headers
            $csvLine = @(
                $row.Timestamp,
                $row.Hostname,
                $row.OS_Name,
                $row.OS_Version,
                $row.OS_Build,
                $row.Manufacturer,
                $row.Model,
                $row.TotalMemory_GB,
                $row.Processor,
                $row.Cores,
                $row.LogicalProcessors,
                $row.LastBoot,
                $row.Drive_C,
                $row.Drive_C_Free_GB,
                $row.Drive_C_Size_GB,
                $row.Drive_C_Percent_Free,
                $row.Drive_D,
                $row.Drive_D_Free_GB,
                $row.Drive_D_Size_GB,
                $row.Drive_D_Percent_Free,
                $row.Primary_IP,
                $row.Primary_Gateway,
                $row.Primary_DNS,
                $row.MAC_Address,
                $row.Subnet,
                $row.Sunquest_Apps,
                $row.Printer_Count,
                $row.Printer_Names,
                $row.TraceRoute,
                $row.Status,
                $row.Error_Message
            ) | ForEach-Object { 
                if ($_ -eq $null -or $_ -eq "") { '""' } 
                else { '"' + ($_.ToString() -replace '"', '""') + '"' } 
            }
            
            $csvLine = ($csvLine -join ",") + "`n"
            Add-Content -Path $FilePath -Value $csvLine -Encoding UTF8
        }
        
        Write-ScriptLog "Exported $($csvData.Count) records to CSV: $FilePath" -Type "Success"
        return $true
    }
    catch {
        Write-ScriptLog "Error exporting to CSV: $_" -Type "Error"
        return $false
    }
}

function Open-HTMLViewer {
    param([string]$HTMLFilePath)
    
    try {
        if (Test-Path $HTMLFilePath) {
            Start-Process $HTMLFilePath
            Write-ScriptLog "Opened HTML viewer: $HTMLFilePath" -Type "Success"
            return $true
        }
        else {
            Write-ScriptLog "HTML viewer not found: $HTMLFilePath" -Type "Error"
            return $false
        }
    }
    catch {
        Write-ScriptLog "Error opening HTML viewer: $_" -Type "Error"
        return $false
    }
}
#endregion

#region WMI Query Functions (Consolidated)
function Get-RemoteSystemInfo {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [hashtable]$Options = @{},
        [int]$Timeout = 90
    )
    
    $result = @{
        Hostname = $ComputerName
        Success = $true
        Data = @{}
        Error = $null
    }
    
    try {
        # Get OS info
        $os = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorAction Stop
        $result.Data.OS = @{
            Name = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            TotalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
            LastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        }
        
        # Get hardware info
        $cs = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem -ErrorAction Stop
        $cpu = Get-WmiObject -ComputerName $ComputerName -Class Win32_Processor -ErrorAction Stop | Select-Object -First 1
        
        $result.Data.Hardware = @{
            Manufacturer = $cs.Manufacturer
            Model = $cs.Model
            Domain = $cs.Domain
            TotalPhysicalMemory = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            Processor = $cpu.Name
            Cores = $cpu.NumberOfCores
            LogicalProcessors = $cpu.NumberOfLogicalProcessors
        }
        
        # Get installed software (faster than Win32_Product)
        if ($Options.CheckSoftware) {
            $result.Data.Software = @()
            
            # Try registry approach first (much faster)
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                $keys = @(
                    "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                )
                
                $software = @()
                foreach ($key in $keys) {
                    $regKey = $reg.OpenSubKey($key)
                    if ($regKey) {
                        foreach ($subKeyName in $regKey.GetSubKeyNames()) {
                            $subKey = $regKey.OpenSubKey($subKeyName)
                            $displayName = $subKey.GetValue("DisplayName")
                            if ($displayName) {
                                $software += $displayName
                            }
                        }
                    }
                }
                $result.Data.Software = $software | Select-Object -Unique
            }
            catch {
                # Fallback to WMI if registry fails
                $products = Get-WmiObject -ComputerName $ComputerName -Class Win32_Product -ErrorAction Stop
                $result.Data.Software = $products | Select-Object -ExpandProperty Name
            }
        }
        
        # Get printers
        if ($Options.CheckPrinters) {
            try {
                $printers = Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer -ErrorAction Stop
                $result.Data.Printers = $printers | Select-Object Name, DriverName, PortName, Shared, ShareName
            }
            catch {
                Write-ScriptLog "Failed to get printer information for $ComputerName : $_" -Type "Warning"
                $result.Data.Printers = @()
            }
        }
        
        # Get network info
        if ($Options.CheckNetwork) {
            $adapters = Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction Stop
            $result.Data.Network = $adapters | ForEach-Object {
                @{
                    Description = $_.Description
                    IPAddress = $_.IPAddress -join ', '
                    SubnetMask = $_.IPSubnet -join ', '
                    DefaultGateway = $_.DefaultIPGateway -join ', '
                    DNSServers = $_.DNSServerSearchOrder -join ', '
                    MACAddress = $_.MACAddress
                }
            }
        }
        
        # Get storage info
        if ($Options.CheckStorage) {
            $disks = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction Stop
            $result.Data.Storage = $disks | ForEach-Object {
                @{
                    Drive = $_.DeviceID
                    SizeGB = [math]::Round($_.Size / 1GB, 2)
                    FreeGB = [math]::Round($_.FreeSpace / 1GB, 2)
                    FileSystem = $_.FileSystem
                    VolumeName = $_.VolumeName
                }
            }
        }
        
                   # Get tracert information (asynchronous with caching)
                   if ($Options.CheckTracert) {
                       $result.Data.TraceRoute = "Pending..."
                   }
               }
               catch {
                   $result.Success = $false
                   $result.Error = $_.Exception.Message
                   
                   # Log detailed error information
                   Write-DetailedErrorLog -Operation "Get-RemoteSystemInfo" -ComputerName $ComputerName -ErrorMessage $_.Exception.Message -StackTrace $_.ScriptStackTrace -AdditionalInfo @{
                       Options = $Options
                       Timeout = $Timeout
                   }
               }
               
               return $result
}
#endregion

#region Traceroute Cache Management
$script:TracerouteCache = @{}
$script:TracerouteCacheFile = "traceroute_cache.json"
$script:TracerouteCacheTTL = 24 # hours

function Initialize-TracerouteCache {
    if (Test-Path $script:TracerouteCacheFile) {
        try {
            $cacheData = Get-Content $script:TracerouteCacheFile | ConvertFrom-Json
            $script:TracerouteCache = @{}
            foreach ($item in $cacheData) {
                $script:TracerouteCache[$item.Hostname] = @{
                    TraceRoute = $item.TraceRoute
                    Timestamp = [DateTime]::Parse($item.Timestamp)
                }
            }
            Write-Host "Loaded traceroute cache with $($script:TracerouteCache.Count) entries" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to load traceroute cache: $($_.Exception.Message)"
            $script:TracerouteCache = @{}
        }
    }
}

function Save-TracerouteCache {
    try {
        $cacheData = @()
        foreach ($hostname in $script:TracerouteCache.Keys) {
            $entry = $script:TracerouteCache[$hostname]
            $cacheData += @{
                Hostname = $hostname
                TraceRoute = $entry.TraceRoute
                Timestamp = $entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
        $cacheData | ConvertTo-Json | Set-Content $script:TracerouteCacheFile
    }
    catch {
        Write-Warning "Failed to save traceroute cache: $($_.Exception.Message)"
    }
}

function Get-CachedTraceroute {
    param([string]$Hostname)
    
    if ($script:TracerouteCache.ContainsKey($Hostname)) {
        $entry = $script:TracerouteCache[$Hostname]
        $age = (Get-Date) - $entry.Timestamp
        
        if ($age.TotalHours -lt $script:TracerouteCacheTTL) {
            return $entry.TraceRoute
        }
        else {
            # Remove expired entry
            $script:TracerouteCache.Remove($Hostname)
        }
    }
    
    return $null
}

function Set-CachedTraceroute {
    param(
        [string]$Hostname,
        [string]$TraceRoute
    )
    
    $script:TracerouteCache[$Hostname] = @{
        TraceRoute = $TraceRoute
        Timestamp = Get-Date
    }
}

function Start-AsyncTraceroute {
    param(
        [string]$Hostname,
        [int]$MaxHops = 10,
        [int]$TimeoutSeconds = 30
    )
    
    # Check cache first
    $cached = Get-CachedTraceroute -Hostname $Hostname
    if ($cached) {
        return $cached
    }
    
    # Start async traceroute job
    $job = Start-Job -ScriptBlock {
        param($ComputerName, $Hops, $Timeout)
        
        try {
            $process = Start-Process -FilePath "tracert" -ArgumentList @("-h", $Hops, $ComputerName) -NoNewWindow -PassThru -RedirectStandardOutput -RedirectStandardError
            
            # Wait for completion with timeout
            if ($process.WaitForExit($Timeout * 1000)) {
                $output = Get-Content $process.StandardOutput.FullName -Raw
                $error = Get-Content $process.StandardError.FullName -Raw
                
                if ($process.ExitCode -eq 0) {
                    return $output
                }
                else {
                    return "Tracert failed: $error"
                }
            }
            else {
                $process.Kill()
                return "Tracert timeout after $Timeout seconds"
            }
        }
        catch {
            return "Tracert error: $($_.Exception.Message)"
        }
    } -ArgumentList $Hostname, $MaxHops, $TimeoutSeconds
    
    return $job
}

function Complete-AsyncTraceroute {
    param(
        [System.Management.Automation.Job]$Job,
        [string]$Hostname
    )
    
    try {
        $result = Receive-Job -Job $Job -Wait -Timeout 60
        Remove-Job -Job $Job
        
        if ($result) {
            # Cache the result
            Set-CachedTraceroute -Hostname $Hostname -TraceRoute $result
            return $result
        }
        else {
            return "Tracert completed with no output"
        }
    }
    catch {
        Remove-Job -Job $Job -ErrorAction SilentlyContinue
        return "Tracert job failed: $($_.Exception.Message)"
    }
}

# Initialize cache on script start
Initialize-TracerouteCache

# Initialize verbose mode
$script:VerboseMode = $false

# Register cleanup function
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Save-TracerouteCache
}

#region Enhanced Error Handling and Retry Logic
$script:RetryConfig = @{
    MaxRetries = 3
    BaseDelay = 1000  # milliseconds
    MaxDelay = 10000  # milliseconds
    BackoffMultiplier = 2
}

function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [string]$OperationName = "Operation",
        [int]$MaxRetries = $script:RetryConfig.MaxRetries,
        [int]$BaseDelay = $script:RetryConfig.BaseDelay,
        [string]$ErrorContext = ""
    )
    
    $attempt = 1
    $delay = $BaseDelay
    
    while ($attempt -le $MaxRetries) {
        try {
            $result = & $ScriptBlock
            if ($attempt -gt 1) {
                Write-ScriptLog "$OperationName succeeded on attempt $attempt" -Type "Success"
            }
            return $result
        }
        catch {
            $errorMessage = $_.Exception.Message
            $errorDetails = $_.Exception.ToString()
            
            Write-ScriptLog "$OperationName failed on attempt $attempt/$MaxRetries`nError: $errorMessage`nContext: $ErrorContext`nDetails: $errorDetails" -Type "Error"
            
            if ($attempt -eq $MaxRetries) {
                Write-Host "$OperationName failed after $MaxRetries attempts. Last error: $errorMessage" -ForegroundColor $script:Config.Colors.Error
                throw $_
            }
            
            Write-Host "$OperationName failed (attempt $attempt/$MaxRetries). Retrying in $($delay/1000) seconds..." -ForegroundColor $script:Config.Colors.Warning
            Start-Sleep -Milliseconds $delay
            
            $delay = [Math]::Min($delay * $script:RetryConfig.BackoffMultiplier, $script:RetryConfig.MaxDelay)
            $attempt++
        }
    }
}

function Test-NetworkConnectivity {
    param(
        [string]$ComputerName,
        [int]$TimeoutSeconds = 5
    )
    
    try {
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -TimeoutSeconds $TimeoutSeconds
        return $ping
    }
    catch {
        return $false
    }
}

function Get-RemoteSystemInfoWithRetry {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [hashtable]$Options = @{},
        [int]$Timeout = 90,
        [int]$MaxRetries = 2
    )
    
    # First check basic connectivity
    if (-not (Test-NetworkConnectivity -ComputerName $ComputerName)) {
        return @{
            Hostname = $ComputerName
            Success = $false
            Data = @{}
            Error = "Host unreachable (ping failed)"
            RetryAttempts = 0
        }
    }
    
    $attempt = 1
    $lastError = $null
    
    while ($attempt -le $MaxRetries) {
        try {
            $result = Invoke-WithRetry -ScriptBlock {
                # Use the shared initialization script to get system info
                $initScript = [scriptblock]::Create($script:SharedInitializationScript.ToString())
                & $initScript
                Get-RemoteSystemInfo -ComputerName $ComputerName -Options $Options -Timeout $Timeout
            } -OperationName "Get-RemoteSystemInfo for $ComputerName" -ErrorContext "Host: $ComputerName, Attempt: $attempt"
            
            if ($result.Success) {
                $result.RetryAttempts = $attempt - 1
                return $result
            }
            else {
                $lastError = $result.Error
                Write-ScriptLog "Get-RemoteSystemInfo failed for $ComputerName (attempt $attempt): $lastError" -Type "Warning"
            }
        }
        catch {
            $lastError = $_.Exception.Message
            Write-ScriptLog "Get-RemoteSystemInfo exception for $ComputerName (attempt $attempt): $lastError" -Type "Error"
        }
        
        $attempt++
        if ($attempt -le $MaxRetries) {
            $delay = $script:RetryConfig.BaseDelay * $attempt
            Write-Host "Retrying $ComputerName in $($delay/1000) seconds..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds $delay
        }
    }
    
    return @{
        Hostname = $ComputerName
        Success = $false
        Data = @{}
        Error = "Failed after $MaxRetries attempts. Last error: $lastError"
        RetryAttempts = $MaxRetries
    }
}

function Write-DetailedErrorLog {
    param(
        [string]$Operation,
        [string]$ComputerName,
        [string]$ErrorMessage,
        [string]$StackTrace = "",
        [hashtable]$AdditionalInfo = @{}
    )
    
    $errorEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Operation = $Operation
        ComputerName = $ComputerName
        ErrorMessage = $ErrorMessage
        StackTrace = $StackTrace
        AdditionalInfo = $AdditionalInfo
    }
    
    $logFile = Get-FilePath -Default $script:Config.OutputFiles.LogFile
    $errorEntry | ConvertTo-Json -Depth 3 | Add-Content -Path $logFile
    
    Write-ScriptLog "Detailed error logged for $Operation on $ComputerName" -Type "Error"
}

function Test-WMIAccess {
    param(
        [string]$ComputerName,
        [int]$TimeoutSeconds = 30
    )
    
    try {
        $testQuery = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem -ErrorAction Stop -TimeoutSec $TimeoutSeconds
        return $true
    }
    catch {
        Write-ScriptLog "WMI access test failed for $ComputerName`: $($_.Exception.Message)" -Type "Warning"
        return $false
    }
}

function Get-RegistryValueWithRetry {
    param(
        [string]$ComputerName,
        [string]$RegistryPath,
        [string]$ValueName,
        [int]$MaxRetries = 2
    )
    
    return Invoke-WithRetry -ScriptBlock {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $key = $reg.OpenSubKey($RegistryPath)
            if ($key) {
                $value = $key.GetValue($ValueName)
                $key.Close()
                $reg.Close()
                return $value
            }
            return $null
        }
        catch {
            throw "Registry access failed: $($_.Exception.Message)"
        }
    } -OperationName "Registry access for $ComputerName" -ErrorContext "Path: $RegistryPath, Value: $ValueName"
}

#endregion

#endregion

#region Shared Initialization Script
$script:SharedInitializationScript = {
    function Get-RemoteSystemInfo {
        param(
            [Parameter(Mandatory)][string]$ComputerName,
            [hashtable]$Options = @{},
            [int]$Timeout = 90
        )
        
        $result = @{
            Hostname = $ComputerName
            Success = $true
            Data = @{}
            Error = $null
        }
        
               try {
                   # Test WMI access first
                   if (-not (Test-WMIAccess -ComputerName $ComputerName -TimeoutSeconds $Timeout)) {
                       throw "WMI access denied or timeout"
                   }
                   
                   # Get OS info with timeout
                   $os = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorAction Stop -TimeoutSec $Timeout
            $result.Data.OS = @{
                Name = $os.Caption
                Version = $os.Version
                BuildNumber = $os.BuildNumber
                TotalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                LastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
            }
            
            # Get hardware info with timeout
            $cs = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem -ErrorAction Stop -TimeoutSec $Timeout
            $cpu = Get-WmiObject -ComputerName $ComputerName -Class Win32_Processor -ErrorAction Stop -TimeoutSec $Timeout | Select-Object -First 1
            
            $result.Data.Hardware = @{
                Manufacturer = $cs.Manufacturer
                Model = $cs.Model
                Domain = $cs.Domain
                TotalPhysicalMemory = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                Processor = $cpu.Name
                Cores = $cpu.NumberOfCores
                LogicalProcessors = $cpu.NumberOfLogicalProcessors
            }
            
            # Get installed software (faster than Win32_Product)
            if ($Options.CheckSoftware) {
                $result.Data.Software = @()
                
                # Try registry approach first (much faster)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                    $keys = @(
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                    )
                    
                    $software = @()
                    foreach ($key in $keys) {
                        $regKey = $reg.OpenSubKey($key)
                        if ($regKey) {
                            foreach ($subKeyName in $regKey.GetSubKeyNames()) {
                                $subKey = $regKey.OpenSubKey($subKeyName)
                                $displayName = $subKey.GetValue("DisplayName")
                                if ($displayName) {
                                    $software += $displayName
                                }
                            }
                        }
                    }
                    $result.Data.Software = $software | Select-Object -Unique
                }
                catch {
                    # Fallback to WMI if registry fails
                    $products = Get-WmiObject -ComputerName $ComputerName -Class Win32_Product -ErrorAction Stop
                    $result.Data.Software = $products | Select-Object -ExpandProperty Name
                }
            }
            
            # Get printers
            if ($Options.CheckPrinters) {
                try {
                    $printers = Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer -ErrorAction Stop -TimeoutSec $Timeout
                    $result.Data.Printers = $printers | Select-Object Name, DriverName, PortName, Shared, ShareName
                }
                catch {
                    $result.Data.Printers = @()
                }
            }
            
            # Get network info
            if ($Options.CheckNetwork) {
                $adapters = Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction Stop -TimeoutSec $Timeout
                $result.Data.Network = $adapters | ForEach-Object {
                    @{
                        Description = $_.Description
                        IPAddress = $_.IPAddress -join ', '
                        SubnetMask = $_.IPSubnet -join ', '
                        DefaultGateway = $_.DefaultIPGateway -join ', '
                        DNSServers = $_.DNSServerSearchOrder -join ', '
                        MACAddress = $_.MACAddress
                    }
                }
            }
            
            # Get storage info
            if ($Options.CheckStorage) {
                $disks = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction Stop -TimeoutSec $Timeout
                $result.Data.Storage = $disks | ForEach-Object {
                    @{
                        Drive = $_.DeviceID
                        SizeGB = [math]::Round($_.Size / 1GB, 2)
                        FreeGB = [math]::Round($_.FreeSpace / 1GB, 2)
                        FileSystem = $_.FileSystem
                        VolumeName = $_.VolumeName
                    }
                }
            }
            
                   # Get tracert information (asynchronous with caching)
                   if ($Options.CheckTracert) {
                       $result.Data.TraceRoute = "Pending..."
                   }
               }
               catch {
                   $result.Success = $false
                   $result.Error = $_.Exception.Message
                   
                   # Log detailed error information
                   Write-DetailedErrorLog -Operation "Get-RemoteSystemInfo" -ComputerName $ComputerName -ErrorMessage $_.Exception.Message -StackTrace $_.ScriptStackTrace -AdditionalInfo @{
                       Options = $Options
                       Timeout = $Timeout
                   }
               }
               
               return $result
    }
}
#endregion

#region Job Management Functions
function Start-ParallelJobs {
    param(
        [Parameter(Mandatory)][array]$InputObjects,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [string]$Activity = "Processing",
        [int]$MaxJobs = $script:Config.MaxParallelJobs,
        [switch]$Verbose,
        [int]$ProgressUpdateInterval = 5,
        [scriptblock]$InitializationScript = $script:SharedInitializationScript,
        [int]$JobTimeout = $script:Config.Timeout
    )
    
    $jobs = @()
    $results = @()
    $totalItems = $InputObjects.Count
    $completed = 0
    $jobIndex = 0
    $jobStartTimes = @{}
    $startTime = Get-Date
    $lastProgressUpdate = $startTime
    $failedJobs = @()
    
    # Start initial batch
    while ($jobs.Count -lt $MaxJobs -and $jobIndex -lt $totalItems) {
        $item = $InputObjects[$jobIndex]
        $args = @($item) + $ArgumentList
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $args -InitializationScript $InitializationScript
        $jobs += $job
        $jobStartTimes[$job.Id] = Get-Date
        $jobIndex++
    }
    
    Write-ScriptLog "Started $($jobs.Count) parallel jobs with $JobTimeout second timeout per job" -Type "Info"
    Write-Host "Processing $totalItems items with max $MaxJobs parallel jobs..." -ForegroundColor $script:Config.Colors.Info
    if ($Verbose) {
        Write-Host "Verbose mode enabled. Progress updates every $ProgressUpdateInterval seconds." -ForegroundColor $script:Config.Colors.Info
    }
    
    while ($completed -lt $totalItems) {
        $completedJob = $jobs | Wait-Job -Any -Timeout 1
        
        if ($completedJob) {
            # Job completed successfully
            $jobResult = Receive-Job -Job $completedJob
            $results += $jobResult
            $completed++
            
            # Calculate ETA and progress
            $currentTime = Get-Date
            $elapsedTime = $currentTime - $startTime
            $avgTimePerItem = $elapsedTime.TotalSeconds / $completed
            $remainingItems = $totalItems - $completed
            $estimatedTimeRemaining = [TimeSpan]::FromSeconds($avgTimePerItem * $remainingItems)
            $eta = $currentTime.AddSeconds($estimatedTimeRemaining.TotalSeconds)
            
            $percentComplete = ($completed / $totalItems) * 100
            $statusMessage = "Completed $completed of $totalItems (ETA: $($eta.ToString('HH:mm:ss')))"
            
            Write-Progress -Activity $Activity -Status $statusMessage -PercentComplete $percentComplete
            
            # Verbose output
            if ($Verbose -and ($currentTime - $lastProgressUpdate).TotalSeconds -ge $ProgressUpdateInterval) {
                $runningJobs = $jobs.Count
                $avgJobTime = if ($jobStartTimes.Count -gt 0) { 
                    ($jobStartTimes.Values | ForEach-Object { ($currentTime - $_).TotalSeconds }) | Measure-Object -Average | Select-Object -ExpandProperty Average
                } else { 0 }
                
                Write-Host "Progress: $completed/$totalItems ($([math]::Round($percentComplete, 1))%) | " -NoNewline -ForegroundColor White
                Write-Host "Running: $runningJobs jobs | " -NoNewline -ForegroundColor Yellow
                Write-Host "Avg: $([math]::Round($avgTimePerItem, 1))s/item | " -NoNewline -ForegroundColor Cyan
                Write-Host "ETA: $($eta.ToString('HH:mm:ss'))" -ForegroundColor Green
                
                $lastProgressUpdate = $currentTime
            }
            
            Remove-Job -Job $completedJob -Force
            $jobs = $jobs | Where-Object { $_ -ne $completedJob }
            $jobStartTimes.Remove($completedJob.Id)
            
            # Start new job if available
            if ($jobIndex -lt $totalItems) {
                $item = $InputObjects[$jobIndex]
                $args = @($item) + $ArgumentList
                $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $args -InitializationScript $InitializationScript
                $jobs += $job
                $jobStartTimes[$job.Id] = Get-Date
                $jobIndex++
            }
        }
        else {
            # Check for individual job timeouts
            $currentTime = Get-Date
            $timedOutJobs = @()
            
            foreach ($job in $jobs) {
                $elapsed = ($currentTime - $jobStartTimes[$job.Id]).TotalSeconds
                if ($elapsed -gt $JobTimeout) {
                    Write-ScriptLog "Job for host timed out after $JobTimeout seconds. Removing job." -Type "Warning"
                    $timedOutJobs += $job
                }
            }
            
            # Remove timed out jobs
            foreach ($timedOutJob in $timedOutJobs) {
                Remove-Job -Job $timedOutJob -Force
                $jobs = $jobs | Where-Object { $_ -ne $timedOutJob }
                $jobStartTimes.Remove($timedOutJob.Id)
                $completed++
                
                # Add timeout result
                $results += @{
                    Hostname = "Unknown"
                    Success = $false
                    Error = "Job timed out after $JobTimeout seconds"
                }
                
                $failedJobs += $timedOutJob
                $percentComplete = ($completed / $totalItems) * 100
                Write-Progress -Activity $Activity -Status "Completed $completed of $totalItems (1 timeout)" -PercentComplete $percentComplete
                
                # Verbose timeout information
                if ($Verbose) {
                    Write-Host "Job timeout detected after $JobTimeout seconds" -ForegroundColor $script:Config.Colors.Warning
                }
                
                # Start new job if available
                if ($jobIndex -lt $totalItems) {
                    $item = $InputObjects[$jobIndex]
                    $args = @($item) + $ArgumentList
                    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $args -InitializationScript $InitializationScript
                    $jobs += $job
                    $jobStartTimes[$job.Id] = Get-Date
                    $jobIndex++
                }
            }
        }
    }
    
    Write-Progress -Activity $Activity -Completed
    
    # Final summary
    $endTime = Get-Date
    $totalTime = $endTime - $startTime
    $successfulJobs = $results | Where-Object { $_.Success -eq $true }
    $failedJobCount = $results | Where-Object { $_.Success -eq $false }
    
    Write-Host "`n$Activity completed!" -ForegroundColor $script:Config.Colors.Success
    Write-Host "Total time: $($totalTime.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "Successful: $($successfulJobs.Count)/$totalItems" -ForegroundColor $script:Config.Colors.Success
    Write-Host "Failed: $($failedJobCount.Count)/$totalItems" -ForegroundColor $script:Config.Colors.Error
    Write-Host "Average time per item: $([math]::Round($totalTime.TotalSeconds / $totalItems, 2)) seconds" -ForegroundColor White
    
    if ($Verbose) {
        Write-Host "`nVerbose Summary:" -ForegroundColor $script:Config.Colors.Header
        Write-Host "Max parallel jobs: $MaxJobs" -ForegroundColor White
        Write-Host "Job timeout: $JobTimeout seconds" -ForegroundColor White
        Write-Host "Progress update interval: $ProgressUpdateInterval seconds" -ForegroundColor White
    }
    
    Write-ScriptLog "Parallel job processing completed. $completed of $totalItems jobs finished in $($totalTime.ToString('hh\:mm\:ss'))." -Type "Success"
    return $results
}
#endregion

#region Menu System
$script:MenuDefinitions = @{
    Main = @{
        Title = "Jeremy's Utility"
        Options = @(
            @{Text = "Enhanced System Information"; Action = { Show-Menu -MenuName "SystemInfo" }}
            @{Text = "Check Unique Applications"; Action = { Invoke-CheckUniqueApps }}
            @{Text = "Network Topology Analysis"; Action = { Invoke-NetworkAnalysis }}
            @{Text = "Send Messages to Hosts"; Action = { Show-Menu -MenuName "Messages" }},
            @{Text = "Bulk Operations"; Action = { Show-BulkOperationsMenu }},
            @{Text = "Verbose Mode"; Action = { Toggle-VerboseMode }}
            @{Text = "Settings"; Action = { Show-Menu -MenuName "Settings" }}
            @{Text = "Exit"; Action = { exit }}
        )
    }
    SystemInfo = @{
        Title = "Enhanced System Information"
        Options = @(
            @{Text = "Start Enhanced Information"; Action = { Invoke-EnhancedDiscovery }}
            @{Text = "Check Single Host"; Action = { Start-SingleHostCheck }}
            @{Text = "Open CSV Data Viewer"; Action = { Open-CSVViewer }}
            @{Text = "Configure Options"; Action = { Configure-SystemInfoOptions }}
            @{Text = "Return to Main Menu"; Action = { Show-Menu -MenuName "Main" }}
        )
    }
    Messages = @{
        Title = "Message Sender"
        Options = @(
            @{Text = "Send One-time Message"; Action = { Send-OneTimeMessage }}
            @{Text = "Start Hourly Message Service"; Action = { Start-HourlyMessages }}
            @{Text = "Configure Message"; Action = { Configure-MessageText }}
            @{Text = "Return to Main Menu"; Action = { Show-Menu -MenuName "Main" }}
        )
    }
    Settings = @{
        Title = "Settings"
        Options = @(
            @{Text = "Edit Hosts File"; Action = { Edit-HostsFile }}
            @{Text = "Set Default Timeout"; Action = { Set-DefaultTimeout }}
            @{Text = "Configure CheckApps"; Action = { Configure-CheckApps }}
            @{Text = "Save Current Settings"; Action = { Save-CurrentSettings }},
            @{Text = "Manage Traceroute Cache"; Action = { Manage-TracerouteCache }},
            @{Text = "Configure Retry Settings"; Action = { Configure-RetrySettings }}
            @{Text = "Return to Main Menu"; Action = { Show-Menu -MenuName "Main" }}
        )
    }
}

function Show-Menu {
    param([string]$MenuName = "Main")
    
    Clear-Host
    $menu = $script:MenuDefinitions[$MenuName]
    Write-MenuHeader -Title $menu.Title
    
    for ($i = 0; $i -lt $menu.Options.Count; $i++) {
        Write-Host "$($i+1). $($menu.Options[$i].Text)" -ForegroundColor $script:Config.Colors.Highlight
    }
    
    Write-Host ("=" * 50) -ForegroundColor $script:Config.Colors.Header
    
    $choice = Read-Host "Enter your choice (1-$($menu.Options.Count))"
    
    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $menu.Options.Count) {
        & $menu.Options[[int]$choice - 1].Action
    }
    else {
        Write-ScriptLog "Invalid choice. Press any key to try again..." -Type "Warning"
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Show-Menu -MenuName $MenuName
    }
}
#endregion

#region Sunquest Check Functions
function Invoke-SunquestCheck {
    Clear-Host
    Write-MenuHeader -Title "SUNQUEST LAB APPLICATION CHECK"
    
    $hostsFile = Get-FilePath -Default $script:Config.HostsFile
    $hosts = Get-HostsList -HostsFilePath $hostsFile
    
    if ($hosts.Count -eq 0) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    $outputFile = Get-FilePath -Default $script:Config.OutputFiles.SunquestResults
    if (-not (Initialize-OutputFile -FilePath $outputFile -Title "Sunquest Lab Application Check Results")) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    Write-ScriptLog "Scanning for Sunquest Lab applications..." -Type "Info"
    
    $scriptBlock = {
        param($hostname)
        try {
            # Use registry instead of Win32_Product for performance
            $software = @()
            $keys = @(
                "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $hostname)
            foreach ($key in $keys) {
                $regKey = $reg.OpenSubKey($key)
                if ($regKey) {
                    foreach ($subKeyName in $regKey.GetSubKeyNames()) {
                        $subKey = $regKey.OpenSubKey($subKeyName)
                        $displayName = $subKey.GetValue("DisplayName")
                        if ($displayName -like "*Sunquest*" -or $displayName -like "*SunQuest*" -or $displayName -like "*SUNQUEST*") {
                            $software += $displayName
                        }
                    }
                }
            }
            
            return @{
                Hostname = $hostname
                Success = $true
                Apps = $software | Select-Object -Unique
            }
        }
        catch {
            return @{
                Hostname = $hostname
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    $results = Start-ParallelJobs -InputObjects $hosts -ScriptBlock $scriptBlock -Activity "Scanning for Sunquest Apps"
    
    # Process results
    $output = New-Object System.Text.StringBuilder
    $foundCount = 0
    $notFoundCount = 0
    $errorCount = 0
    
    foreach ($result in $results) {
        if ($result.Success) {
            if ($result.Apps.Count -gt 0) {
                $null = $output.AppendLine("Found on $($result.Hostname):")
                foreach ($app in $result.Apps) {
                    $null = $output.AppendLine("  - $app")
                }
                $foundCount++
            }
            else {
                $null = $output.AppendLine("Not found on $($result.Hostname)")
                $notFoundCount++
            }
        }
        else {
            $null = $output.AppendLine("Error on $($result.Hostname): $($result.Error)")
            $errorCount++
        }
        $null = $output.AppendLine("")
    }
    
    Add-Content -Path $outputFile -Value $output.ToString()
    
    Write-ScriptLog "`nSummary:" -Type "Success"
    Write-ScriptLog "- Hosts with Sunquest apps: $foundCount" -Type "Success"
    Write-ScriptLog "- Hosts without Sunquest apps: $notFoundCount" -Type "Warning"
    Write-ScriptLog "- Connection errors: $errorCount" -Type "Error"
    Write-ScriptLog "Results saved to: $outputFile" -Type "Info"
    
    Invoke-Pause
    Show-Menu -MenuName "Main"
}
#endregion

#region Message Functions
function Send-MessageToHosts {
    param(
        [string[]]$Hostnames,
        [string]$Message
    )
    
    $scriptBlock = {
        param($hostname, $message)
        try {
            $result = Start-Process -FilePath "msg.exe" -ArgumentList "* /SERVER:$hostname `"$message`" /TIME:600" -Wait -PassThru -NoNewWindow
            return @{ Hostname = $hostname; Success = $result.ExitCode -eq 0 }
        }
        catch {
            return @{ Hostname = $hostname; Success = $false; Error = $_.Exception.Message }
        }
    }
    
    return Start-ParallelJobs -InputObjects $Hostnames -ScriptBlock $scriptBlock -ArgumentList $Message -Activity "Sending Messages"
}

function Send-OneTimeMessage {
    $hostsFile = Get-FilePath -Default $script:Config.HostsFile
    $hosts = Get-HostsList -HostsFilePath $hostsFile
    
    if ($hosts.Count -eq 0) {
        Invoke-Pause
        Show-Menu -MenuName "Messages"
        return
    }
    
    Write-ScriptLog "Sending messages to $($hosts.Count) hosts..." -Type "Info"
    $results = Send-MessageToHosts -Hostnames $hosts -Message $script:Config.DefaultMessage
    
    $success = ($results | Where-Object { $_.Success }).Count
    $failed = ($results | Where-Object { -not $_.Success }).Count
    
    Write-ScriptLog "`nMessages sent successfully to $success hosts" -Type "Success"
    if ($failed -gt 0) {
        Write-ScriptLog "Failed to send to $failed hosts" -Type "Warning"
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Messages"
}

function Start-HourlyMessages {
    $hostsFile = Get-FilePath -Default $script:Config.HostsFile
    $hosts = Get-HostsList -HostsFilePath $hostsFile
    
    if ($hosts.Count -eq 0) {
        Invoke-Pause
        Show-Menu -MenuName "Messages"
        return
    }
    
    Write-ScriptLog "Starting hourly message service. Press Ctrl+C to stop." -Type "Warning"
    
    try {
        while ($true) {
            $results = Send-MessageToHosts -Hostnames $hosts -Message $script:Config.DefaultMessage
            
            $success = ($results | Where-Object { $_.Success }).Count
            Write-ScriptLog "Sent messages to $success of $($hosts.Count) hosts" -Type "Info"
            
            $nextHour = (Get-Date).AddHours(1).Date.AddHours((Get-Date).Hour + 1)
            $waitTime = ($nextHour - (Get-Date)).TotalSeconds
            
            Write-ScriptLog "Waiting until $nextHour..." -Type "Info"
            Start-Sleep -Seconds $waitTime
        }
    }
    catch {
        Write-ScriptLog "Hourly message service stopped" -Type "Warning"
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Messages"
}

function Configure-MessageText {
    Clear-Host
    Write-MenuHeader -Title "CONFIGURE MESSAGE"
    
    Write-Host "Current message:" -ForegroundColor $script:Config.Colors.Info
    Write-Host $script:Config.DefaultMessage -ForegroundColor $script:Config.Colors.Warning
    Write-Host
    
    $newMessage = Read-Host "Enter new message (or press Enter to keep current)"
    if ($newMessage.Trim()) {
        $script:Config.DefaultMessage = $newMessage
        Write-ScriptLog "Message updated successfully" -Type "Success"
        Save-Configuration
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Messages"
}
#endregion

#region System Info Functions

function Start-SingleHostCheck {
    $hostname = Read-Host "Enter hostname to check"
    if (-not $hostname) {
        Show-Menu -MenuName "SystemInfo"
        return
    }
    
    Write-ScriptLog "`nChecking $hostname..." -Type "Info"
    
    $options = @{
        CheckSoftware = $script:Config.SystemInfo.CheckSunquest
        CheckPrinters = $script:Config.SystemInfo.CheckPrinters
        CheckTracert = $script:Config.SystemInfo.CheckTracert
        CheckNetwork = $true
        CheckStorage = $true
    }
    
    $result = Get-RemoteSystemInfo -ComputerName $hostname -Options $options
    
    if ($result.Success) {
        Write-Host "`nSystem Information:" -ForegroundColor $script:Config.Colors.Success
        Write-Host "OS: $($result.Data.OS.Name)" 
        Write-Host "Version: $($result.Data.OS.Version)"
        Write-Host "Model: $($result.Data.Hardware.Model)"
        Write-Host "Memory: $($result.Data.OS.TotalMemoryGB) GB"
        Write-Host "Processor: $($result.Data.Hardware.Processor) ($($result.Data.Hardware.Cores) cores)"
        
        if ($result.Data.Storage) {
            Write-Host "`nStorage:" -ForegroundColor $script:Config.Colors.Info
            foreach ($disk in $result.Data.Storage) {
                Write-Host "$($disk.Drive) - $($disk.FreeGB)GB free of $($disk.SizeGB)GB"
            }
        }
        
        if ($result.Data.Network) {
            Write-Host "`nNetwork:" -ForegroundColor $script:Config.Colors.Info
            foreach ($adapter in $result.Data.Network) {
                Write-Host "$($adapter.Description): $($adapter.IPAddress)"
            }
        }
        
        # Tracert Information (now included in parallel results)
        if ($options.CheckTracert -and $result.Data.TraceRoute) {
            Write-Host "`nTracert Route:" -ForegroundColor $script:Config.Colors.Info
            Write-Host $result.Data.TraceRoute
        }
        
        # Export single host data to CSV
        $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
        Write-ScriptLog "Exporting single host data to CSV: $csvFile" -Type "Info"
        if (Export-SystemDataToCSV -Results @($result) -FilePath $csvFile) {
            Write-ScriptLog "Host data exported to CSV: $csvFile" -Type "Success"
        }
        else {
            Write-ScriptLog "Failed to export single host data to CSV" -Type "Error"
        }
    }
    else {
        Write-ScriptLog "Error: $($result.Error)" -Type "Error"
    }
    
    Invoke-Pause
    Show-Menu -MenuName "SystemInfo"
}

function Configure-SystemInfoOptions {
    Clear-Host
    Write-MenuHeader -Title "SYSTEM INFO OPTIONS"
    
    Write-Host "Current Settings:" -ForegroundColor $script:Config.Colors.Info
    Write-Host "1. Check Sunquest Apps: $(if ($script:Config.SystemInfo.CheckSunquest) { 'Enabled' } else { 'Disabled' })"
    Write-Host "2. Check Printers: $(if ($script:Config.SystemInfo.CheckPrinters) { 'Enabled' } else { 'Disabled' })"
    Write-Host "3. Check Tracert: $(if ($script:Config.SystemInfo.CheckTracert) { 'Enabled' } else { 'Disabled' })"
    Write-Host
    
    $choice = Read-Host "Toggle option (1-3) or press Enter to return"
    
    switch ($choice) {
        "1" {
            $script:Config.SystemInfo.CheckSunquest = -not $script:Config.SystemInfo.CheckSunquest
            Write-ScriptLog "Sunquest check $(if ($script:Config.SystemInfo.CheckSunquest) { 'enabled' } else { 'disabled' })" -Type "Success"
            Save-Configuration
            Start-Sleep -Seconds 1
            Configure-SystemInfoOptions
        }
        "2" {
            $script:Config.SystemInfo.CheckPrinters = -not $script:Config.SystemInfo.CheckPrinters
            Write-ScriptLog "Printer check $(if ($script:Config.SystemInfo.CheckPrinters) { 'enabled' } else { 'disabled' })" -Type "Success"
            Save-Configuration
            Start-Sleep -Seconds 1
            Configure-SystemInfoOptions
        }
        "3" {
            $script:Config.SystemInfo.CheckTracert = -not $script:Config.SystemInfo.CheckTracert
            Write-ScriptLog "Tracert check $(if ($script:Config.SystemInfo.CheckTracert) { 'enabled' } else { 'disabled' })" -Type "Success"
            Save-Configuration
            Start-Sleep -Seconds 1
            Configure-SystemInfoOptions
        }
        default {
            Show-Menu -MenuName "SystemInfo"
        }
    }
}

function Open-CSVViewer {
    Clear-Host
    Write-MenuHeader -Title "OPEN CSV DATA VIEWER"
    
    $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
    $htmlFile = Get-FilePath -Default $script:Config.OutputFiles.HTMLViewer
    
    if (-not (Test-Path $csvFile)) {
        Write-ScriptLog "CSV file not found: $csvFile" -Type "Error"
        Write-ScriptLog "Please run 'Start Enhanced Information' first to create data." -Type "Warning"
        Invoke-Pause
        Show-Menu -MenuName "SystemInfo"
        return
    }
    
    # Open HTML viewer
    if (Open-HTMLViewer -HTMLFilePath $htmlFile) {
        Write-ScriptLog "Opened HTML viewer: $htmlFile" -Type "Success"
    }
    else {
        Write-ScriptLog "Failed to open HTML viewer" -Type "Error"
    }
    
    Invoke-Pause
    Show-Menu -MenuName "SystemInfo"
}

#endregion

#region Check Unique Apps
function Invoke-CheckUniqueApps {
    Clear-Host
    Write-MenuHeader -Title "CHECK UNIQUE APPLICATIONS"
    
    $baselineFile = Get-FilePath -Default $script:Config.CheckApps.BaselineFile
    $hostsFile = Get-FilePath -Default $script:Config.HostsFile
    $outputFile = Get-FilePath -Default $script:Config.OutputFiles.UniqueApps
    
    # Check baseline file
    if (-not (Test-Path $baselineFile)) {
        Write-ScriptLog "Baseline file not found: $baselineFile" -Type "Error"
        if ((Read-Host "Create empty baseline file? (Y/N)") -eq 'Y') {
            "" | Out-File -FilePath $baselineFile
            Write-ScriptLog "Created baseline file. Please add standard applications." -Type "Success"
            Start-Process notepad.exe -ArgumentList $baselineFile
        }
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    $baseline = Get-Content $baselineFile | Where-Object { $_.Trim() }
    $hosts = Get-HostsList -HostsFilePath $hostsFile
    
    if ($hosts.Count -eq 0) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    if (-not (Initialize-OutputFile -FilePath $outputFile -Title "Unique Applications Report")) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    # Create a scriptblock that leverages the main Get-RemoteSystemInfoScriptBlock
    $scriptBlock = {
        param($hostname, $baseline, $excludePatterns)
        
        # Use the central system info function
        $getSystemInfoScript = {
            param($ComputerName, $Options)
            
            $result = @{
                Hostname = $ComputerName
                Success = $true
                Data = @{}
                Error = $null
            }
            
            try {
                # Get installed software (faster than Win32_Product)
                if ($Options.CheckSoftware) {
                    $result.Data.Software = @()
                    
                    # Try registry approach first (much faster)
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                        $keys = @(
                            "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                        )
                        
                        $software = @()
                        foreach ($key in $keys) {
                            $regKey = $reg.OpenSubKey($key)
                            if ($regKey) {
                                foreach ($subKeyName in $regKey.GetSubKeyNames()) {
                                    $subKey = $regKey.OpenSubKey($subKeyName)
                                    $displayName = $subKey.GetValue("DisplayName")
                                    if ($displayName) {
                                        $software += $displayName
                                    }
                                }
                            }
                        }
                        $result.Data.Software = $software | Select-Object -Unique
                    }
                    catch {
                        # Fallback to WMI if registry fails
                        $products = Get-WmiObject -ComputerName $ComputerName -Class Win32_Product -ErrorAction Stop -TimeoutSec $script:Config.Timeout
                        $result.Data.Software = $products | Select-Object -ExpandProperty Name
                    }
                }
               }
               catch {
                   $result.Success = $false
                   $result.Error = $_.Exception.Message
                   
                   # Log detailed error information
                   Write-DetailedErrorLog -Operation "Get-RemoteSystemInfo" -ComputerName $ComputerName -ErrorMessage $_.Exception.Message -StackTrace $_.ScriptStackTrace -AdditionalInfo @{
                       Options = $Options
                       Timeout = $Timeout
                   }
               }
               
               return $result
        }
        
        $result = & $getSystemInfoScript -ComputerName $hostname -Options @{CheckSoftware = $true}
        
        if ($result.Success -and $result.Data.Software) {
            $uniqueApps = $result.Data.Software | Where-Object {
                $app = $_
                $inBaseline = $baseline -contains $app
                $excluded = $false
                
                if (-not $inBaseline) {
                    foreach ($pattern in $excludePatterns) {
                        if ($app -match $pattern) {
                            $excluded = $true
                            break
                        }
                    }
                }
                
                -not $inBaseline -and -not $excluded
            }
            
            return @{
                Hostname = $hostname
                Success = $true
                UniqueApps = $uniqueApps
            }
        }
        else {
            return @{
                Hostname = $hostname
                Success = $false
                Error = if ($result.Error) { $result.Error } else { "No software data" }
            }
        }
    }
    
    Write-ScriptLog "Checking for unique applications..." -Type "Info"
    $results = Start-ParallelJobs -InputObjects $hosts -ScriptBlock $scriptBlock -ArgumentList @($baseline, $script:Config.CheckApps.ExcludePatterns) -Activity "Checking Unique Apps"
    
    # Process results
    $output = New-Object System.Text.StringBuilder
    $hostsWithUnique = 0
    
    foreach ($result in $results) {
        if ($result.Success -and $result.UniqueApps.Count -gt 0) {
            $hostsWithUnique++
            $null = $output.AppendLine("Host: $($result.Hostname)")
            foreach ($app in $result.UniqueApps) {
                $null = $output.AppendLine("  - $app")
            }
            $null = $output.AppendLine("")
        }
    }
    
    Add-Content -Path $outputFile -Value $output.ToString()
    
    Write-ScriptLog "`nFound unique applications on $hostsWithUnique hosts" -Type "Success"
    Write-ScriptLog "Results saved to: $outputFile" -Type "Info"
    
    Invoke-Pause
    Show-Menu -MenuName "Main"
}
#endregion

#region Enhanced Discovery
function Invoke-EnhancedDiscovery {
    param(
        [Parameter(Mandatory)][array]$Hostnames,
        [hashtable]$Options = @{},
        [switch]$Verbose
    )
    
    Clear-Host
    Write-MenuHeader -Title "ENHANCED SYSTEM INFORMATION"
    
    # Use provided hostnames or get from file
    if ($Hostnames) {
        $hosts = $Hostnames
    } else {
        $hostsFile = Get-FilePath -Default $script:Config.HostsFile
        $hosts = Get-HostsList -HostsFilePath $hostsFile
    }
    
    if ($hosts.Count -eq 0) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    $outputFile = Get-FilePath -Default $script:Config.OutputFiles.EnhancedInfo
    if (-not (Initialize-OutputFile -FilePath $outputFile -Title "Enhanced System Information Report")) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    $options = @{
        CheckSoftware = $script:Config.SystemInfo.CheckSunquest
        CheckPrinters = $script:Config.SystemInfo.CheckPrinters
        CheckTracert = $script:Config.SystemInfo.CheckTracert
        CheckNetwork = $true
        CheckStorage = $true
    }
    
    Write-ScriptLog "Starting enhanced system information scan on $($hosts.Count) hosts..." -Type "Info"
    $scriptBlock = {
        param($hostname, $options)
        Get-RemoteSystemInfo -ComputerName $hostname -Options $options
    }
    $initScript = {
        function Get-RemoteSystemInfo {
            param(
                [Parameter(Mandatory)][string]$ComputerName,
                [hashtable]$Options = @{},
                [int]$Timeout = 90
            )
            
            $result = @{
                Hostname = $ComputerName
                Success = $true
                Data = @{}
                Error = $null
            }
            
            try {
                # Get OS info
                $os = Get-WmiObject -ComputerName $ComputerName -Class Win32_OperatingSystem -ErrorAction Stop
                $result.Data.OS = @{
                    Name = $os.Caption
                    Version = $os.Version
                    BuildNumber = $os.BuildNumber
                    TotalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                    LastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
                }
                
                # Get hardware info
                $cs = Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem -ErrorAction Stop
                $cpu = Get-WmiObject -ComputerName $ComputerName -Class Win32_Processor -ErrorAction Stop | Select-Object -First 1
                
                $result.Data.Hardware = @{
                    Manufacturer = $cs.Manufacturer
                    Model = $cs.Model
                    Domain = $cs.Domain
                    TotalPhysicalMemory = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
                    Processor = $cpu.Name
                    Cores = $cpu.NumberOfCores
                    LogicalProcessors = $cpu.NumberOfLogicalProcessors
                }
                
                # Get installed software (faster than Win32_Product)
                if ($Options.CheckSoftware) {
                    $result.Data.Software = @()
                    
                    # Try registry approach first (much faster)
                    try {
                        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                        $keys = @(
                            "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                        )
                        
                        $software = @()
                        foreach ($key in $keys) {
                            $regKey = $reg.OpenSubKey($key)
                            if ($regKey) {
                                foreach ($subKeyName in $regKey.GetSubKeyNames()) {
                                    $subKey = $regKey.OpenSubKey($subKeyName)
                                    $displayName = $subKey.GetValue("DisplayName")
                                    if ($displayName) {
                                        $software += $displayName
                                    }
                                }
                            }
                        }
                        $result.Data.Software = $software | Select-Object -Unique
                    }
                    catch {
                        # Fallback to WMI if registry fails
                        $products = Get-WmiObject -ComputerName $ComputerName -Class Win32_Product -ErrorAction Stop -TimeoutSec $Timeout
                        $result.Data.Software = $products | Select-Object -ExpandProperty Name
                    }
                }
                
                # Get printers
                if ($Options.CheckPrinters) {
                    try {
                        $printers = Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer -ErrorAction Stop
                        $result.Data.Printers = $printers | Select-Object Name, DriverName, PortName, Shared, ShareName
                    }
                    catch {
                        $result.Data.Printers = @()
                    }
                }
                
                # Get network info
                if ($Options.CheckNetwork) {
                    $adapters = Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction Stop
                    $result.Data.Network = $adapters | ForEach-Object {
                        @{
                            Description = $_.Description
                            IPAddress = $_.IPAddress -join ', '
                            SubnetMask = $_.IPSubnet -join ', '
                            DefaultGateway = $_.DefaultIPGateway -join ', '
                            DNSServers = $_.DNSServerSearchOrder -join ', '
                            MACAddress = $_.MACAddress
                        }
                    }
                }
                
                # Get storage info
                if ($Options.CheckStorage) {
                    $disks = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction Stop
                    $result.Data.Storage = $disks | ForEach-Object {
                        @{
                            Drive = $_.DeviceID
                            SizeGB = [math]::Round($_.Size / 1GB, 2)
                            FreeGB = [math]::Round($_.FreeSpace / 1GB, 2)
                            FileSystem = $_.FileSystem
                            VolumeName = $_.VolumeName
                        }
                    }
                }
                
                   # Get tracert information (asynchronous with caching)
                   if ($Options.CheckTracert) {
                       $result.Data.TraceRoute = "Pending..."
                   }
               }
               catch {
                   $result.Success = $false
                   $result.Error = $_.Exception.Message
                   
                   # Log detailed error information
                   Write-DetailedErrorLog -Operation "Get-RemoteSystemInfo" -ComputerName $ComputerName -ErrorMessage $_.Exception.Message -StackTrace $_.ScriptStackTrace -AdditionalInfo @{
                       Options = $Options
                       Timeout = $Timeout
                   }
               }
               
               return $result
        }
    }
    $results = Start-ParallelJobs -InputObjects $hosts -ScriptBlock $scriptBlock -ArgumentList $options -Activity "Enhanced System Information" -Verbose:$Verbose
    
    # Format results
    $output = New-Object System.Text.StringBuilder
    
    foreach ($result in $results) {
        if ($result.Success) {
            $null = $output.AppendLine("Host: $($result.Hostname)")
            $null = $output.AppendLine("=" * 50)
            
            # OS and Hardware
            $null = $output.AppendLine("OS: $($result.Data.OS.Name) (Build $($result.Data.OS.BuildNumber))")
            $null = $output.AppendLine("Hardware: $($result.Data.Hardware.Manufacturer) $($result.Data.Hardware.Model)")
            $null = $output.AppendLine("Memory: $($result.Data.OS.TotalMemoryGB) GB")
            $null = $output.AppendLine("Processor: $($result.Data.Hardware.Processor)")
            $null = $output.AppendLine("Last Boot: $($result.Data.OS.LastBoot)")
            
            # Storage
            if ($result.Data.Storage) {
                $null = $output.AppendLine("`nStorage:")
                foreach ($disk in $result.Data.Storage) {
                    $percentFree = [math]::Round(($disk.FreeGB / $disk.SizeGB) * 100, 1)
                    $null = $output.AppendLine("  $($disk.Drive) - $($disk.FreeGB)GB free of $($disk.SizeGB)GB ($percentFree% free)")
                }
            }
            
            # Network
            if ($result.Data.Network) {
                $null = $output.AppendLine("`nNetwork Adapters:")
                foreach ($adapter in $result.Data.Network) {
                    $null = $output.AppendLine("  $($adapter.Description)")
                    $null = $output.AppendLine("    IP: $($adapter.IPAddress)")
                    $null = $output.AppendLine("    Gateway: $($adapter.DefaultGateway)")
                }
            }
            
            # Printers
            if ($options.CheckPrinters) {
                $null = $output.AppendLine("`nPrinters:")
                if ($result.Data.Printers -and $result.Data.Printers.Count -gt 0) {
                    foreach ($printer in $result.Data.Printers) {
                        $null = $output.AppendLine("  - $($printer.Name)")
                    }
                } else {
                    $null = $output.AppendLine("  No printers found")
                }
            }
            
            # Sunquest Applications
            if ($options.CheckSoftware) {
                $null = $output.AppendLine("`nSunquest Applications:")
                if ($result.Data.Software) {
                    $sunquestApps = $result.Data.Software | Where-Object { 
                        $_ -like "*Sunquest*" -or 
                        $_ -like "*SunQuest*" -or 
                        $_ -like "*SUNQUEST*" -or
                        $_ -like "*Lab*" -and ($_ -like "*Sunquest*" -or $_ -like "*SunQuest*" -or $_ -like "*SUNQUEST*")
                    }
                    if ($sunquestApps) {
                        foreach ($app in $sunquestApps) {
                            $null = $output.AppendLine("  - $app")
                        }
                    } else {
                        $null = $output.AppendLine("  No Sunquest applications found")
                    }
                } else {
                    $null = $output.AppendLine("  No software data available")
                }
            }
            
            # Tracert Information (now included in parallel results)
            if ($options.CheckTracert -and $result.Data.TraceRoute) {
                $null = $output.AppendLine("`nTracert Route:")
                $null = $output.AppendLine($result.Data.TraceRoute)
            }
        }
        else {
            $null = $output.AppendLine("Host: $($result.Hostname) - ERROR: $($result.Error)")
        }
        
        $null = $output.AppendLine("`n" + ("-" * 70) + "`n")
    }
    
    Add-Content -Path $outputFile -Value $output.ToString()
    
    Write-ScriptLog "Enhanced system information scan completed. Results saved to: $outputFile" -Type "Success"

    # Export to CSV
    $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
    Write-ScriptLog "Exporting data to CSV: $csvFile" -Type "Info"
    if (Export-SystemDataToCSV -Results $results -FilePath $csvFile) {
        Write-ScriptLog "Data exported to CSV: $csvFile" -Type "Success"
    }
    else {
        Write-ScriptLog "Failed to export data to CSV" -Type "Error"
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Main"
}

#endregion

#region Network Analysis
function Invoke-NetworkAnalysis {
    Clear-Host
    Write-MenuHeader -Title "NETWORK TOPOLOGY ANALYSIS"
    
    $hostsFile = Get-FilePath -Default $script:Config.HostsFile
    $hosts = Get-HostsList -HostsFilePath $hostsFile
    
    if ($hosts.Count -eq 0) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    $outputFile = Get-FilePath -Default $script:Config.OutputFiles.NetworkTopology
    if (-not (Initialize-OutputFile -FilePath $outputFile -Title "Network Topology Analysis")) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    # Get the base scriptblock with network and tracert options
    $scriptBlock = {
        param($hostname, $options)
        Get-RemoteSystemInfo -ComputerName $hostname -Options $options
    }
    $results = Start-ParallelJobs -InputObjects $hosts -ScriptBlock $scriptBlock -ArgumentList @{CheckNetwork = $true; CheckTracert = $true} -Activity "Network Analysis" -Verbose:$script:VerboseMode
    
    # Traceroute info is now included in parallel results
    
    # Format results
    $output = New-Object System.Text.StringBuilder
    $subnetMap = @{}
    
    foreach ($result in $results) {
        try {
            if ($result.Success -and $result.Data.Network) {
                # Build subnet map
                foreach ($adapter in $result.Data.Network) {
                    if ($adapter.IPAddress -and $adapter.IPAddress.Trim() -ne '') {
                        try {
                            $subnet = $adapter.IPAddress.Split('.')[0..2] -join '.'
                            if (-not $subnetMap.ContainsKey($subnet)) {
                                $subnetMap[$subnet] = @()
                            }
                            $subnetMap[$subnet] += $result.Hostname
                        }
                        catch {
                            Write-ScriptLog "Error processing IP address for $($result.Hostname): $($_.Exception.Message)" -Type "Warning"
                        }
                    }
                }
                
                # Output individual host info
                $null = $output.AppendLine("Host: $($result.Hostname)")
                foreach ($adapter in $result.Data.Network) {
                    $null = $output.AppendLine("  Adapter: $($adapter.Description)")
                    $null = $output.AppendLine("    IP: $($adapter.IPAddress)")
                    $null = $output.AppendLine("    Gateway: $($adapter.DefaultGateway)")
                }
                
                if ($result.Data.TraceRoute) {
                    $null = $output.AppendLine("  Route:")
                    $null = $output.AppendLine($result.Data.TraceRoute)
                }
                
                $null = $output.AppendLine("")
            }
            elseif (-not $result.Success) {
                $null = $output.AppendLine("Host: $($result.Hostname) - ERROR: $($result.Error)")
                $null = $output.AppendLine("")
            }
        }
        catch {
            Write-ScriptLog "Error processing result for $($result.Hostname): $($_.Exception.Message)" -Type "Warning"
            $null = $output.AppendLine("Host: $($result.Hostname) - PROCESSING ERROR: $($_.Exception.Message)")
            $null = $output.AppendLine("")
        }
    }
    
    # Add subnet summary
    try {
        $null = $output.AppendLine("`n" + ("=" * 50))
        $null = $output.AppendLine("SUBNET SUMMARY")
        $null = $output.AppendLine("=" * 50)
        
        if ($subnetMap.Count -gt 0) {
            foreach ($subnet in $subnetMap.Keys | Sort-Object) {
                $null = $output.AppendLine("`nSubnet $subnet.*: $($subnetMap[$subnet].Count) hosts")
                foreach ($hostname in $subnetMap[$subnet] | Sort-Object) {
                    $null = $output.AppendLine("  - $hostname")
                }
            }
        } else {
            $null = $output.AppendLine("`nNo subnet information available")
        }
    }
    catch {
        Write-ScriptLog "Error creating subnet summary: $($_.Exception.Message)" -Type "Warning"
        $null = $output.AppendLine("`nError generating subnet summary")
    }
    
    # Write results to file
    try {
        Add-Content -Path $outputFile -Value $output.ToString()
        Write-ScriptLog "Network analysis completed. Results saved to: $outputFile" -Type "Success"
    }
    catch {
        Write-ScriptLog "Error writing results to file: $($_.Exception.Message)" -Type "Error"
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Main"
}
#endregion

#region Settings Functions
function Edit-HostsFile {
    $hostsFile = Get-FilePath -Default $script:Config.HostsFile
    
    if (-not (Test-Path $hostsFile)) {
        if ((Read-Host "Hosts file not found. Create it? (Y/N)") -eq 'Y') {
            "localhost" | Out-File -FilePath $hostsFile
            Write-ScriptLog "Created hosts file" -Type "Success"
        }
        else {
            Show-Menu -MenuName "Settings"
            return
        }
    }
    
    Start-Process notepad.exe -ArgumentList $hostsFile
    Show-Menu -MenuName "Settings"
}

function Set-DefaultTimeout {
    Clear-Host
    Write-MenuHeader -Title "SET DEFAULT TIMEOUT"
    
    Write-Host "Current timeout: $($script:Config.Timeout) seconds" -ForegroundColor $script:Config.Colors.Info
    $newTimeout = Read-Host "`nEnter new timeout in seconds"
    
    if ($newTimeout -match '^\d+$' -and [int]$newTimeout -gt 0) {
        $script:Config.Timeout = [int]$newTimeout
        Write-ScriptLog "Timeout updated to $($script:Config.Timeout) seconds" -Type "Success"
        Save-Configuration
    }
    else {
        Write-ScriptLog "Invalid timeout value" -Type "Warning"
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Settings"
}

function Configure-CheckApps {
    Clear-Host
    Write-MenuHeader -Title "CONFIGURE CHECK APPS"
    
    Write-Host "1. Baseline File: $($script:Config.CheckApps.BaselineFile)"
    Write-Host "2. Exclude Patterns: $($script:Config.CheckApps.ExcludePatterns.Count) patterns"
    Write-Host "3. Return to Settings"
    
    $choice = Read-Host "`nEnter choice (1-3)"
    
    switch ($choice) {
        "1" {
            $newFile = Read-Host "Enter new baseline filename"
            if ($newFile.Trim()) {
                $script:Config.CheckApps.BaselineFile = $newFile
                Write-ScriptLog "Baseline file updated" -Type "Success"
                Save-Configuration
            }
            Invoke-Pause
            Configure-CheckApps
        }
        "2" {
            Clear-Host
            Write-MenuHeader -Title "EXCLUDE PATTERNS"
            
            for ($i = 0; $i -lt $script:Config.CheckApps.ExcludePatterns.Count; $i++) {
                Write-Host "$($i+1). $($script:Config.CheckApps.ExcludePatterns[$i])"
            }
            
            Write-Host "`nA. Add Pattern"
            Write-Host "R. Remove Pattern"
            Write-Host "B. Back"
            
            $action = Read-Host "`nChoice"
            
            switch ($action.ToUpper()) {
                "A" {
                    $pattern = Read-Host "Enter regex pattern"
                    if ($pattern.Trim()) {
                        $script:Config.CheckApps.ExcludePatterns += $pattern
                        Write-ScriptLog "Pattern added" -Type "Success"
                        Save-Configuration
                    }
                }
                "R" {
                    $index = Read-Host "Enter pattern number to remove"
                    if ($index -match '^\d+$' -and [int]$index -ge 1 -and [int]$index -le $script:Config.CheckApps.ExcludePatterns.Count) {
                        $removed = $script:Config.CheckApps.ExcludePatterns[[int]$index - 1]
                        $script:Config.CheckApps.ExcludePatterns = @($script:Config.CheckApps.ExcludePatterns | Where-Object { $_ -ne $removed })
                        Write-ScriptLog "Pattern removed" -Type "Success"
                        Save-Configuration
                    }
                }
            }
            
            Invoke-Pause
            Configure-CheckApps
        }
        "3" {
            Show-Menu -MenuName "Settings"
        }
        default {
            Configure-CheckApps
        }
    }
}

function Save-Configuration {
    try {
        $configFilePath = Join-Path (Get-ScriptDirectory) "config.json"
        $script:Config | ConvertTo-Json -Depth 5 | Out-File -FilePath $configFilePath -Encoding utf8 -Force
        Write-ScriptLog "Configuration saved to $configFilePath" -Type "Success"
        return $true
    }
    catch {
        Write-ScriptLog "Failed to save configuration: $_" -Type "Error"
        return $false
    }
}

function Save-CurrentSettings {
    Clear-Host
    Write-MenuHeader -Title "SAVE CURRENT SETTINGS"
    
    Write-Host "Current configuration will be saved to config.json" -ForegroundColor $script:Config.Colors.Info
    Write-Host
    Write-Host "Timeout: $($script:Config.Timeout) seconds"
    Write-Host "Max Parallel Jobs: $($script:Config.MaxParallelJobs)"
    Write-Host "Check Sunquest: $(if ($script:Config.SystemInfo.CheckSunquest) { 'Enabled' } else { 'Disabled' })"
    Write-Host "Check Printers: $(if ($script:Config.SystemInfo.CheckPrinters) { 'Enabled' } else { 'Disabled' })"
    Write-Host "Check Tracert: $(if ($script:Config.SystemInfo.CheckTracert) { 'Enabled' } else { 'Disabled' })"
    Write-Host
    
    $confirm = Read-Host "Save these settings? (Y/N)"
    if ($confirm -eq 'Y' -or $confirm -eq 'y') {
        if (Save-Configuration) {
            Write-ScriptLog "Settings saved successfully" -Type "Success"
        } else {
            Write-ScriptLog "Failed to save settings" -Type "Error"
        }
    } else {
        Write-ScriptLog "Settings not saved" -Type "Info"
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Settings"
}

function Manage-TracerouteCache {
    Clear-Host
    Write-MenuHeader -Title "TRACEROUTE CACHE MANAGEMENT"
    
    Write-Host "Cache Statistics:" -ForegroundColor $script:Config.Colors.Info
    Write-Host "Total Entries: $($script:TracerouteCache.Count)" -ForegroundColor White
    Write-Host "Cache File: $script:TracerouteCacheFile" -ForegroundColor White
    Write-Host "TTL: $script:TracerouteCacheTTL hours" -ForegroundColor White
    
    if ($script:TracerouteCache.Count -gt 0) {
        Write-Host "`nRecent Entries:" -ForegroundColor $script:Config.Colors.Info
        $recentEntries = $script:TracerouteCache.GetEnumerator() | Sort-Object Value.Timestamp -Descending | Select-Object -First 5
        foreach ($entry in $recentEntries) {
            $age = (Get-Date) - $entry.Value.Timestamp
            Write-Host "  $($entry.Key): $($age.ToString('hh\:mm\:ss')) ago" -ForegroundColor White
        }
    }
    
    Write-Host "`nOptions:" -ForegroundColor $script:Config.Colors.Header
    Write-Host "1. Clear Cache" -ForegroundColor White
    Write-Host "2. Save Cache" -ForegroundColor White
    Write-Host "3. Load Cache" -ForegroundColor White
    Write-Host "4. Show All Entries" -ForegroundColor White
    Write-Host "5. Back to Settings" -ForegroundColor White
    
    $choice = Read-Host "`nSelect an option"
    
    switch ($choice) {
        "1" {
            $script:TracerouteCache = @{}
            if (Test-Path $script:TracerouteCacheFile) {
                Remove-Item $script:TracerouteCacheFile -Force
            }
            Write-Host "Cache cleared" -ForegroundColor $script:Config.Colors.Success
            Write-ScriptLog "Traceroute cache cleared" -Type "Success"
        }
        "2" {
            Save-TracerouteCache
            Write-Host "Cache saved" -ForegroundColor $script:Config.Colors.Success
            Write-ScriptLog "Traceroute cache saved" -Type "Success"
        }
        "3" {
            Initialize-TracerouteCache
            Write-Host "Cache reloaded" -ForegroundColor $script:Config.Colors.Success
            Write-ScriptLog "Traceroute cache reloaded" -Type "Success"
        }
        "4" {
            if ($script:TracerouteCache.Count -gt 0) {
                Write-Host "`nAll Cache Entries:" -ForegroundColor $script:Config.Colors.Info
                foreach ($entry in $script:TracerouteCache.GetEnumerator() | Sort-Object Key) {
                    $age = (Get-Date) - $entry.Value.Timestamp
                    Write-Host "  $($entry.Key): $($age.ToString('d\.hh\:mm\:ss')) ago" -ForegroundColor White
                }
            }
            else {
                Write-Host "Cache is empty" -ForegroundColor Yellow
            }
        }
        "5" {
            return
        }
        default {
            Write-Host "Invalid option" -ForegroundColor $script:Config.Colors.Error
        }
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Settings"
}

function Show-BulkOperationsMenu {
    Clear-Host
    Write-MenuHeader -Title "BULK OPERATIONS"
    
    Write-Host "Bulk operations allow you to perform actions on multiple hosts based on CSV data." -ForegroundColor $script:Config.Colors.Info
    Write-Host
    
    Write-Host "Options:" -ForegroundColor $script:Config.Colors.Header
    Write-Host "1. Send Messages to Filtered Hosts" -ForegroundColor White
    Write-Host "2. Re-scan Failed Hosts" -ForegroundColor White
    Write-Host "3. Export Specific Hosts" -ForegroundColor White
    Write-Host "4. Bulk System Information Scan" -ForegroundColor White
    Write-Host "5. Back to Main Menu" -ForegroundColor White
    
    $choice = Read-Host "`nSelect an option"
    
    switch ($choice) {
        "1" {
            Send-MessagesToFilteredHosts
        }
        "2" {
            Rescan-FailedHosts
        }
        "3" {
            Export-SpecificHosts
        }
        "4" {
            Invoke-BulkSystemScan
        }
        "5" {
            Show-Menu -MenuName "Main"
        }
        default {
            Write-Host "Invalid option" -ForegroundColor $script:Config.Colors.Error
            Invoke-Pause
            Show-BulkOperationsMenu
        }
    }
}

function Send-MessagesToFilteredHosts {
    Clear-Host
    Write-MenuHeader -Title "SEND MESSAGES TO FILTERED HOSTS"
    
    $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
    if (-not (Test-Path $csvFile)) {
        Write-Host "CSV file not found: $csvFile" -ForegroundColor $script:Config.Colors.Error
        Write-Host "Please run Enhanced System Information first to generate the CSV file." -ForegroundColor $script:Config.Colors.Warning
        Invoke-Pause
        Show-BulkOperationsMenu
        return
    }
    
    Write-Host "CSV File: $csvFile" -ForegroundColor $script:Config.Colors.Info
    Write-Host
    
    # Load CSV data
    try {
        $csvData = Import-Csv -Path $csvFile
        Write-Host "Loaded $($csvData.Count) entries from CSV" -ForegroundColor $script:Config.Colors.Success
    }
    catch {
        Write-Host "Failed to load CSV file: $($_.Exception.Message)" -ForegroundColor $script:Config.Colors.Error
        Invoke-Pause
        Show-BulkOperationsMenu
        return
    }
    
    # Filter options
    Write-Host "`nFilter Options:" -ForegroundColor $script:Config.Colors.Header
    Write-Host "1. All hosts" -ForegroundColor White
    Write-Host "2. By OS" -ForegroundColor White
    Write-Host "3. By Subnet" -ForegroundColor White
    Write-Host "4. By Memory (GB)" -ForegroundColor White
    Write-Host "5. By Free Space %" -ForegroundColor White
    Write-Host "6. Custom filter" -ForegroundColor White
    
    $filterChoice = Read-Host "`nSelect filter option"
    $filteredHosts = @()
    
    switch ($filterChoice) {
        "1" {
            $filteredHosts = $csvData | Select-Object -ExpandProperty Hostname
        }
        "2" {
            $osOptions = $csvData | Select-Object -ExpandProperty OS_Name | Sort-Object -Unique
            Write-Host "`nAvailable OS:" -ForegroundColor $script:Config.Colors.Info
            for ($i = 0; $i -lt $osOptions.Count; $i++) {
                Write-Host "$($i + 1). $($osOptions[$i])" -ForegroundColor White
            }
            $osChoice = Read-Host "Select OS number"
            if ($osChoice -match '^\d+$' -and [int]$osChoice -le $osOptions.Count) {
                $selectedOS = $osOptions[[int]$osChoice - 1]
                $filteredHosts = $csvData | Where-Object { $_.OS_Name -eq $selectedOS } | Select-Object -ExpandProperty Hostname
            }
        }
        "3" {
            $subnetOptions = $csvData | Select-Object -ExpandProperty Subnet | Sort-Object -Unique
            Write-Host "`nAvailable Subnets:" -ForegroundColor $script:Config.Colors.Info
            for ($i = 0; $i -lt $subnetOptions.Count; $i++) {
                Write-Host "$($i + 1). $($subnetOptions[$i])" -ForegroundColor White
            }
            $subnetChoice = Read-Host "Select subnet number"
            if ($subnetChoice -match '^\d+$' -and [int]$subnetChoice -le $subnetOptions.Count) {
                $selectedSubnet = $subnetOptions[[int]$subnetChoice - 1]
                $filteredHosts = $csvData | Where-Object { $_.Subnet -eq $selectedSubnet } | Select-Object -ExpandProperty Hostname
            }
        }
        "4" {
            $minMemory = Read-Host "Minimum memory (GB)"
            if ($minMemory -match '^\d+(\.\d+)?$') {
                $filteredHosts = $csvData | Where-Object { [double]$_.TotalMemory_GB -ge [double]$minMemory } | Select-Object -ExpandProperty Hostname
            }
        }
        "5" {
            $minFreeSpace = Read-Host "Minimum free space %"
            if ($minFreeSpace -match '^\d+(\.\d+)?$') {
                $filteredHosts = $csvData | Where-Object { [double]$_.Drive_C_Percent_Free -ge [double]$minFreeSpace } | Select-Object -ExpandProperty Hostname
            }
        }
        "6" {
            Write-Host "Enter custom filter (PowerShell Where-Object syntax)" -ForegroundColor $script:Config.Colors.Info
            Write-Host "Example: { `$_.OS_Name -like '*Windows 10*' }" -ForegroundColor Yellow
            $customFilter = Read-Host "Filter"
            try {
                $filteredHosts = $csvData | Where-Object ([scriptblock]::Create($customFilter)) | Select-Object -ExpandProperty Hostname
            }
            catch {
                Write-Host "Invalid filter syntax: $($_.Exception.Message)" -ForegroundColor $script:Config.Colors.Error
                Invoke-Pause
                Show-BulkOperationsMenu
                return
            }
        }
        default {
            Write-Host "Invalid option" -ForegroundColor $script:Config.Colors.Error
            Invoke-Pause
            Show-BulkOperationsMenu
            return
        }
    }
    
    if ($filteredHosts.Count -eq 0) {
        Write-Host "No hosts match the filter criteria" -ForegroundColor $script:Config.Colors.Warning
        Invoke-Pause
        Show-BulkOperationsMenu
        return
    }
    
    Write-Host "`nFiltered hosts ($($filteredHosts.Count)):" -ForegroundColor $script:Config.Colors.Info
    $filteredHosts | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    
    Write-Host "`nMessage to send:" -ForegroundColor $script:Config.Colors.Header
    Write-Host $script:Config.DefaultMessage -ForegroundColor Yellow
    
    $confirm = Read-Host "`nSend message to these hosts? (Y/N)"
    if ($confirm -eq 'Y' -or $confirm -eq 'y') {
        $results = Send-MessageToHosts -Hostnames $filteredHosts -Message $script:Config.DefaultMessage
        Write-Host "`nMessage sending completed" -ForegroundColor $script:Config.Colors.Success
        Write-ScriptLog "Bulk message sent to $($filteredHosts.Count) hosts" -Type "Success"
    }
    else {
        Write-Host "Operation cancelled" -ForegroundColor $script:Config.Colors.Warning
    }
    
    Invoke-Pause
    Show-BulkOperationsMenu
}

function Rescan-FailedHosts {
    Clear-Host
    Write-MenuHeader -Title "RE-SCAN FAILED HOSTS"
    
    $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
    if (-not (Test-Path $csvFile)) {
        Write-Host "CSV file not found: $csvFile" -ForegroundColor $script:Config.Colors.Error
        Write-Host "Please run Enhanced System Information first to generate the CSV file." -ForegroundColor $script:Config.Colors.Warning
        Invoke-Pause
        Show-BulkOperationsMenu
        return
    }
    
    try {
        $csvData = Import-Csv -Path $csvFile
        $failedHosts = $csvData | Where-Object { $_.Success -eq 'False' -or $_.Error } | Select-Object -ExpandProperty Hostname
        
        if ($failedHosts.Count -eq 0) {
            Write-Host "No failed hosts found in CSV" -ForegroundColor $script:Config.Colors.Success
            Invoke-Pause
            Show-BulkOperationsMenu
            return
        }
        
        Write-Host "Found $($failedHosts.Count) failed hosts:" -ForegroundColor $script:Config.Colors.Info
        $failedHosts | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
        
        $confirm = Read-Host "`nRe-scan these failed hosts? (Y/N)"
        if ($confirm -eq 'Y' -or $confirm -eq 'y') {
            Write-Host "`nRe-scanning failed hosts..." -ForegroundColor $script:Config.Colors.Info
            $results = Invoke-EnhancedDiscovery -Hostnames $failedHosts -Verbose:$script:VerboseMode
            Write-Host "Re-scan completed" -ForegroundColor $script:Config.Colors.Success
            Write-ScriptLog "Re-scanned $($failedHosts.Count) failed hosts" -Type "Success"
        }
        else {
            Write-Host "Operation cancelled" -ForegroundColor $script:Config.Colors.Warning
        }
    }
    catch {
        Write-Host "Failed to process CSV file: $($_.Exception.Message)" -ForegroundColor $script:Config.Colors.Error
    }
    
    Invoke-Pause
    Show-BulkOperationsMenu
}

function Export-SpecificHosts {
    Clear-Host
    Write-MenuHeader -Title "EXPORT SPECIFIC HOSTS"
    
    $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
    if (-not (Test-Path $csvFile)) {
        Write-Host "CSV file not found: $csvFile" -ForegroundColor $script:Config.Colors.Error
        Write-Host "Please run Enhanced System Information first to generate the CSV file." -ForegroundColor $script:Config.Colors.Warning
        Invoke-Pause
        Show-BulkOperationsMenu
        return
    }
    
    try {
        $csvData = Import-Csv -Path $csvFile
        
        Write-Host "Export Options:" -ForegroundColor $script:Config.Colors.Header
        Write-Host "1. Export by OS" -ForegroundColor White
        Write-Host "2. Export by Subnet" -ForegroundColor White
        Write-Host "3. Export by Memory Range" -ForegroundColor White
        Write-Host "4. Export by Free Space Range" -ForegroundColor White
        Write-Host "5. Export Custom Filter" -ForegroundColor White
        
        $exportChoice = Read-Host "`nSelect export option"
        $exportData = @()
        $exportName = ""
        
        switch ($exportChoice) {
            "1" {
                $osOptions = $csvData | Select-Object -ExpandProperty OS_Name | Sort-Object -Unique
                Write-Host "`nAvailable OS:" -ForegroundColor $script:Config.Colors.Info
                for ($i = 0; $i -lt $osOptions.Count; $i++) {
                    Write-Host "$($i + 1). $($osOptions[$i])" -ForegroundColor White
                }
                $osChoice = Read-Host "Select OS number"
                if ($osChoice -match '^\d+$' -and [int]$osChoice -le $osOptions.Count) {
                    $selectedOS = $osOptions[[int]$osChoice - 1]
                    $exportData = $csvData | Where-Object { $_.OS_Name -eq $selectedOS }
                    $exportName = "OS_$($selectedOS -replace '[^a-zA-Z0-9]', '_')"
                }
            }
            "2" {
                $subnetOptions = $csvData | Select-Object -ExpandProperty Subnet | Sort-Object -Unique
                Write-Host "`nAvailable Subnets:" -ForegroundColor $script:Config.Colors.Info
                for ($i = 0; $i -lt $subnetOptions.Count; $i++) {
                    Write-Host "$($i + 1). $($subnetOptions[$i])" -ForegroundColor White
                }
                $subnetChoice = Read-Host "Select subnet number"
                if ($subnetChoice -match '^\d+$' -and [int]$subnetChoice -le $subnetOptions.Count) {
                    $selectedSubnet = $subnetOptions[[int]$subnetChoice - 1]
                    $exportData = $csvData | Where-Object { $_.Subnet -eq $selectedSubnet }
                    $exportName = "Subnet_$($selectedSubnet -replace '[^a-zA-Z0-9]', '_')"
                }
            }
            "3" {
                $minMemory = Read-Host "Minimum memory (GB)"
                $maxMemory = Read-Host "Maximum memory (GB)"
                if ($minMemory -match '^\d+(\.\d+)?$' -and $maxMemory -match '^\d+(\.\d+)?$') {
                    $exportData = $csvData | Where-Object { [double]$_.TotalMemory_GB -ge [double]$minMemory -and [double]$_.TotalMemory_GB -le [double]$maxMemory }
                    $exportName = "Memory_${minMemory}GB_to_${maxMemory}GB"
                }
            }
            "4" {
                $minFreeSpace = Read-Host "Minimum free space %"
                $maxFreeSpace = Read-Host "Maximum free space %"
                if ($minFreeSpace -match '^\d+(\.\d+)?$' -and $maxFreeSpace -match '^\d+(\.\d+)?$') {
                    $exportData = $csvData | Where-Object { [double]$_.Drive_C_Percent_Free -ge [double]$minFreeSpace -and [double]$_.Drive_C_Percent_Free -le [double]$maxFreeSpace }
                    $exportName = "FreeSpace_${minFreeSpace}%_to_${maxFreeSpace}%"
                }
            }
            "5" {
                Write-Host "Enter custom filter (PowerShell Where-Object syntax)" -ForegroundColor $script:Config.Colors.Info
                Write-Host "Example: { `$_.OS_Name -like '*Windows 10*' }" -ForegroundColor Yellow
                $customFilter = Read-Host "Filter"
                try {
                    $exportData = $csvData | Where-Object ([scriptblock]::Create($customFilter))
                    $exportName = "Custom_Filter"
                }
                catch {
                    Write-Host "Invalid filter syntax: $($_.Exception.Message)" -ForegroundColor $script:Config.Colors.Error
                    Invoke-Pause
                    Show-BulkOperationsMenu
                    return
                }
            }
            default {
                Write-Host "Invalid option" -ForegroundColor $script:Config.Colors.Error
                Invoke-Pause
                Show-BulkOperationsMenu
                return
            }
        }
        
        if ($exportData.Count -eq 0) {
            Write-Host "No data matches the export criteria" -ForegroundColor $script:Config.Colors.Warning
            Invoke-Pause
            Show-BulkOperationsMenu
            return
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $exportFile = "${exportName}_${timestamp}.csv"
        
        $exportData | Export-Csv -Path $exportFile -NoTypeInformation
        Write-Host "`nExported $($exportData.Count) entries to: $exportFile" -ForegroundColor $script:Config.Colors.Success
        Write-ScriptLog "Exported $($exportData.Count) entries to $exportFile" -Type "Success"
    }
    catch {
        Write-Host "Failed to export data: $($_.Exception.Message)" -ForegroundColor $script:Config.Colors.Error
    }
    
    Invoke-Pause
    Show-BulkOperationsMenu
}

function Invoke-BulkSystemScan {
    Clear-Host
    Write-MenuHeader -Title "BULK SYSTEM SCAN"
    
    Write-Host "This will perform a comprehensive system scan on all hosts in the hosts file." -ForegroundColor $script:Config.Colors.Info
    Write-Host
    
    $hostsFile = Get-FilePath -Default $script:Config.HostsFile
    if (-not (Test-Path $hostsFile)) {
        Write-Host "Hosts file not found: $hostsFile" -ForegroundColor $script:Config.Colors.Error
        Invoke-Pause
        Show-BulkOperationsMenu
        return
    }
    
    $hosts = Get-Content $hostsFile | Where-Object { $_.Trim() -ne '' -and -not $_.StartsWith('#') }
    Write-Host "Found $($hosts.Count) hosts in $hostsFile" -ForegroundColor $script:Config.Colors.Info
    
    Write-Host "`nScan Options:" -ForegroundColor $script:Config.Colors.Header
    Write-Host "1. Full System Scan (All options enabled)" -ForegroundColor White
    Write-Host "2. Basic System Scan (OS, Hardware, Network)" -ForegroundColor White
    Write-Host "3. Custom Scan Options" -ForegroundColor White
    
    $scanChoice = Read-Host "`nSelect scan option"
    
    switch ($scanChoice) {
        "1" {
            $options = @{
                CheckSoftware = $true
                CheckPrinters = $true
                CheckNetwork = $true
                CheckStorage = $true
                CheckTracert = $true
            }
        }
        "2" {
            $options = @{
                CheckSoftware = $false
                CheckPrinters = $false
                CheckNetwork = $true
                CheckStorage = $false
                CheckTracert = $false
            }
        }
        "3" {
            $options = @{
                CheckSoftware = $script:Config.SystemInfo.CheckSunquest
                CheckPrinters = $script:Config.SystemInfo.CheckPrinters
                CheckNetwork = $true
                CheckStorage = $true
                CheckTracert = $script:Config.SystemInfo.CheckTracert
            }
        }
        default {
            Write-Host "Invalid option" -ForegroundColor $script:Config.Colors.Error
            Invoke-Pause
            Show-BulkOperationsMenu
            return
        }
    }
    
    $confirm = Read-Host "`nStart bulk scan with $($hosts.Count) hosts? (Y/N)"
    if ($confirm -eq 'Y' -or $confirm -eq 'y') {
        Write-Host "`nStarting bulk system scan..." -ForegroundColor $script:Config.Colors.Info
        $results = Invoke-EnhancedDiscovery -Hostnames $hosts -Options $options -Verbose:$script:VerboseMode
        Write-Host "Bulk scan completed" -ForegroundColor $script:Config.Colors.Success
        Write-ScriptLog "Bulk system scan completed for $($hosts.Count) hosts" -Type "Success"
    }
    else {
        Write-Host "Operation cancelled" -ForegroundColor $script:Config.Colors.Warning
    }
    
    Invoke-Pause
    Show-BulkOperationsMenu
}

function Configure-RetrySettings {
    Clear-Host
    Write-MenuHeader -Title "CONFIGURE RETRY SETTINGS"
    
    Write-Host "Current Retry Configuration:" -ForegroundColor $script:Config.Colors.Info
    Write-Host "Max Retries: $($script:RetryConfig.MaxRetries)" -ForegroundColor White
    Write-Host "Base Delay: $($script:RetryConfig.BaseDelay) ms" -ForegroundColor White
    Write-Host "Max Delay: $($script:RetryConfig.MaxDelay) ms" -ForegroundColor White
    Write-Host "Backoff Multiplier: $($script:RetryConfig.BackoffMultiplier)" -ForegroundColor White
    Write-Host
    
    Write-Host "Options:" -ForegroundColor $script:Config.Colors.Header
    Write-Host "1. Set Max Retries" -ForegroundColor White
    Write-Host "2. Set Base Delay" -ForegroundColor White
    Write-Host "3. Set Max Delay" -ForegroundColor White
    Write-Host "4. Set Backoff Multiplier" -ForegroundColor White
    Write-Host "5. Reset to Defaults" -ForegroundColor White
    Write-Host "6. Back to Settings" -ForegroundColor White
    
    $choice = Read-Host "`nSelect an option"
    
    switch ($choice) {
        "1" {
            $newValue = Read-Host "Enter new max retries (1-10)"
            if ($newValue -match '^\d+$' -and [int]$newValue -ge 1 -and [int]$newValue -le 10) {
                $script:RetryConfig.MaxRetries = [int]$newValue
                Write-Host "Max retries set to $newValue" -ForegroundColor $script:Config.Colors.Success
                Write-ScriptLog "Max retries changed to $newValue" -Type "Success"
            }
            else {
                Write-Host "Invalid value. Must be a number between 1 and 10." -ForegroundColor $script:Config.Colors.Error
            }
        }
        "2" {
            $newValue = Read-Host "Enter new base delay in milliseconds (500-5000)"
            if ($newValue -match '^\d+$' -and [int]$newValue -ge 500 -and [int]$newValue -le 5000) {
                $script:RetryConfig.BaseDelay = [int]$newValue
                Write-Host "Base delay set to $newValue ms" -ForegroundColor $script:Config.Colors.Success
                Write-ScriptLog "Base delay changed to $newValue ms" -Type "Success"
            }
            else {
                Write-Host "Invalid value. Must be a number between 500 and 5000." -ForegroundColor $script:Config.Colors.Error
            }
        }
        "3" {
            $newValue = Read-Host "Enter new max delay in milliseconds (5000-60000)"
            if ($newValue -match '^\d+$' -and [int]$newValue -ge 5000 -and [int]$newValue -le 60000) {
                $script:RetryConfig.MaxDelay = [int]$newValue
                Write-Host "Max delay set to $newValue ms" -ForegroundColor $script:Config.Colors.Success
                Write-ScriptLog "Max delay changed to $newValue ms" -Type "Success"
            }
            else {
                Write-Host "Invalid value. Must be a number between 5000 and 60000." -ForegroundColor $script:Config.Colors.Error
            }
        }
        "4" {
            $newValue = Read-Host "Enter new backoff multiplier (1.5-5.0)"
            if ($newValue -match '^\d+(\.\d+)?$' -and [double]$newValue -ge 1.5 -and [double]$newValue -le 5.0) {
                $script:RetryConfig.BackoffMultiplier = [double]$newValue
                Write-Host "Backoff multiplier set to $newValue" -ForegroundColor $script:Config.Colors.Success
                Write-ScriptLog "Backoff multiplier changed to $newValue" -Type "Success"
            }
            else {
                Write-Host "Invalid value. Must be a number between 1.5 and 5.0." -ForegroundColor $script:Config.Colors.Error
            }
        }
        "5" {
            $script:RetryConfig = @{
                MaxRetries = 3
                BaseDelay = 1000
                MaxDelay = 10000
                BackoffMultiplier = 2
            }
            Write-Host "Retry settings reset to defaults" -ForegroundColor $script:Config.Colors.Success
            Write-ScriptLog "Retry settings reset to defaults" -Type "Success"
        }
        "6" {
            return
        }
        default {
            Write-Host "Invalid option" -ForegroundColor $script:Config.Colors.Error
        }
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Settings"
}

function Toggle-VerboseMode {
    Clear-Host
    Write-MenuHeader -Title "VERBOSE MODE"
    
    Write-Host "Verbose mode provides detailed progress information during parallel job processing." -ForegroundColor $script:Config.Colors.Info
    Write-Host
    
    Write-Host "Current Status:" -ForegroundColor $script:Config.Colors.Header
    Write-Host "Verbose Mode: $(if ($script:VerboseMode) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
    Write-Host
    
    Write-Host "Options:" -ForegroundColor $script:Config.Colors.Header
    Write-Host "1. Enable Verbose Mode" -ForegroundColor White
    Write-Host "2. Disable Verbose Mode" -ForegroundColor White
    Write-Host "3. Back to Main Menu" -ForegroundColor White
    
    $choice = Read-Host "`nSelect an option"
    
    switch ($choice) {
        "1" {
            $script:VerboseMode = $true
            Write-Host "Verbose mode enabled" -ForegroundColor $script:Config.Colors.Success
            Write-ScriptLog "Verbose mode enabled" -Type "Success"
        }
        "2" {
            $script:VerboseMode = $false
            Write-Host "Verbose mode disabled" -ForegroundColor $script:Config.Colors.Success
            Write-ScriptLog "Verbose mode disabled" -Type "Success"
        }
        "3" {
            Show-Menu -MenuName "Main"
            return
        }
        default {
            Write-Host "Invalid option" -ForegroundColor $script:Config.Colors.Error
        }
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Main"
}
#endregion

#region Script Entry Point
# Initialize configuration
Initialize-Configuration

# Ensure admin privileges
if (-not (Test-AdminPrivileges)) {
    Write-Host "This script requires administrator privileges." -ForegroundColor $script:Config.Colors.Warning
    Write-Host "Relaunching with elevated permissions..." -ForegroundColor $script:Config.Colors.Warning
    
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Initialize log
$logFile = Get-FilePath -Default $script:Config.OutputFiles.LogFile
Clear-Content -Path $logFile -Force -ErrorAction SilentlyContinue

Write-ScriptLog "Script started with administrator privileges" -Type "Success"
Write-ScriptLog "Script version: 2.0 (Cleaned and Optimized)" -Type "Info"

# Start main menu
Show-Menu -MenuName "Main"
#endregion
