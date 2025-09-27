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
        Timeout = 30
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
                $sunquestApps = $result.Data.Software | Where-Object { $_ -like "Sunquest Lab*" }
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
            $csvLine = ($row.Values | ForEach-Object { 
                if ($_ -eq $null) { "" } 
                else { '"' + ($_.ToString() -replace '"', '""') + '"' } 
            }) -join ","
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
        [int]$Timeout = 30
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
            $printers = Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer -ErrorAction Stop
            $result.Data.Printers = $printers | Select-Object Name, DriverName, PortName, Shared, ShareName
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
    }
    catch {
        $result.Success = $false
        $result.Error = $_.Exception.Message
    }
    
    return $result
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
        [scriptblock]$InitializationScript = $null
    )
    
    $jobs = @()
    $results = @()
    $totalItems = $InputObjects.Count
    $completed = 0
    $jobIndex = 0
    
    # Start initial batch
    while ($jobs.Count -lt $MaxJobs -and $jobIndex -lt $totalItems) {
        $item = $InputObjects[$jobIndex]
        $args = @($item) + $ArgumentList
        $jobs += Start-Job -ScriptBlock $ScriptBlock -ArgumentList $args -InitializationScript $InitializationScript
        $jobIndex++
    }
    
    # Process jobs with timeout handling
    $maxWaitTime = $script:Config.Timeout * 2  # Allow 2x timeout for job completion
    $startTime = Get-Date
    
    while ($completed -lt $totalItems) {
        $completedJob = $jobs | Wait-Job -Any -Timeout 1
        
        if ($completedJob) {
            $results += Receive-Job -Job $completedJob
            $completed++
            
            Write-Progress -Activity $Activity -Status "Completed $completed of $totalItems" -PercentComplete (($completed / $totalItems) * 100)
            
            Remove-Job -Job $completedJob -Force
            $jobs = $jobs | Where-Object { $_ -ne $completedJob }
            
            # Start new job if available
            if ($jobIndex -lt $totalItems) {
                $item = $InputObjects[$jobIndex]
                $args = @($item) + $ArgumentList
                $jobs += Start-Job -ScriptBlock $ScriptBlock -ArgumentList $args -InitializationScript $InitializationScript
                $jobIndex++
            }
        }
        else {
            # Check for stuck jobs
            $elapsed = (Get-Date) - $startTime
            if ($elapsed.TotalSeconds -gt $maxWaitTime) {
                Write-ScriptLog "Timeout reached. Cleaning up remaining jobs..." -Type "Warning"
                $jobs | Remove-Job -Force
                break
            }
        }
    }
    
    Write-Progress -Activity $Activity -Completed
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
            @{Text = "Send Messages to Hosts"; Action = { Show-Menu -MenuName "Messages" }}
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
            @{Text = "Export CSV Data"; Action = { Export-CSVData }}
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
                        if ($displayName -like "Sunquest Lab*") {
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
        if ((Read-Host "`nExport this host data to CSV? (Y/N)") -eq 'Y') {
            $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
            if (Export-SystemDataToCSV -Results @($result) -FilePath $csvFile) {
                Write-ScriptLog "Host data exported to CSV: $csvFile" -Type "Success"
                
                # Open HTML viewer
                $htmlFile = Get-FilePath -Default $script:Config.OutputFiles.HTMLViewer
                if ((Read-Host "Open HTML viewer? (Y/N)") -eq 'Y') {
                    Open-HTMLViewer -HTMLFilePath $htmlFile
                }
            }
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
            Start-Sleep -Seconds 1
            Configure-SystemInfoOptions
        }
        "2" {
            $script:Config.SystemInfo.CheckPrinters = -not $script:Config.SystemInfo.CheckPrinters
            Write-ScriptLog "Printer check $(if ($script:Config.SystemInfo.CheckPrinters) { 'enabled' } else { 'disabled' })" -Type "Success"
            Start-Sleep -Seconds 1
            Configure-SystemInfoOptions
        }
        "3" {
            $script:Config.SystemInfo.CheckTracert = -not $script:Config.SystemInfo.CheckTracert
            Write-ScriptLog "Tracert check $(if ($script:Config.SystemInfo.CheckTracert) { 'enabled' } else { 'disabled' })" -Type "Success"
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

function Export-CSVData {
    Clear-Host
    Write-MenuHeader -Title "EXPORT CSV DATA"
    
    $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
    
    if (-not (Test-Path $csvFile)) {
        Write-ScriptLog "CSV file not found: $csvFile" -Type "Error"
        Write-ScriptLog "Please run 'Start Enhanced Information' first to create data." -Type "Warning"
        Invoke-Pause
        Show-Menu -MenuName "SystemInfo"
        return
    }
    
    Write-Host "Current CSV file: $csvFile" -ForegroundColor $script:Config.Colors.Info
    Write-Host "File size: $([math]::Round((Get-Item $csvFile).Length / 1KB, 2)) KB" -ForegroundColor $script:Config.Colors.Info
    
    # Count records
    try {
        $csvContent = Get-Content $csvFile
        $recordCount = $csvContent.Count - 1  # Subtract header
        Write-Host "Records in file: $recordCount" -ForegroundColor $script:Config.Colors.Info
    }
    catch {
        Write-ScriptLog "Error reading CSV file: $_" -Type "Error"
        Invoke-Pause
        Show-Menu -MenuName "SystemInfo"
        return
    }
    
    Write-Host "`nExport Options:" -ForegroundColor $script:Config.Colors.Highlight
    Write-Host "1. Copy CSV file to desktop"
    Write-Host "2. Open CSV file location"
    Write-Host "3. Open CSV in Excel"
    Write-Host "4. Return to System Info Menu"
    
    $choice = Read-Host "`nEnter your choice (1-4)"
    
    switch ($choice) {
        "1" {
            $desktopPath = [Environment]::GetFolderPath("Desktop")
            $destFile = Join-Path $desktopPath "system_data_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            Copy-Item $csvFile $destFile
            Write-ScriptLog "CSV file copied to desktop: $destFile" -Type "Success"
        }
        "2" {
            Start-Process "explorer.exe" -ArgumentList "/select,`"$csvFile`""
            Write-ScriptLog "Opened file location" -Type "Success"
        }
        "3" {
            if (Get-Command excel.exe -ErrorAction SilentlyContinue) {
                Start-Process excel.exe -ArgumentList $csvFile
                Write-ScriptLog "Opening CSV in Excel" -Type "Success"
            }
            else {
                Start-Process $csvFile
                Write-ScriptLog "Opening CSV with default application" -Type "Success"
            }
        }
        "4" {
            Show-Menu -MenuName "SystemInfo"
            return
        }
        default {
            Write-ScriptLog "Invalid choice" -Type "Warning"
        }
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
    Clear-Host
    Write-MenuHeader -Title "ENHANCED SYSTEM DISCOVERY"
    
    $hostsFile = Get-FilePath -Default $script:Config.HostsFile
    $hosts = Get-HostsList -HostsFilePath $hostsFile
    
    if ($hosts.Count -eq 0) {
        Invoke-Pause
        Show-Menu -MenuName "Main"
        return
    }
    
    $outputFile = Get-FilePath -Default $script:Config.OutputFiles.EnhancedInfo
    if (-not (Initialize-OutputFile -FilePath $outputFile -Title "Enhanced System Discovery Report")) {
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
    
    Write-ScriptLog "Starting enhanced discovery on $($hosts.Count) hosts..." -Type "Info"
    $scriptBlock = {
        param($hostname, $options)
        Get-RemoteSystemInfo -ComputerName $hostname -Options $options
    }
    $initScript = {
        function Get-RemoteSystemInfo {
            param(
                [Parameter(Mandatory)][string]$ComputerName,
                [hashtable]$Options = @{},
                [int]$Timeout = 30
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
                    $printers = Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer -ErrorAction Stop
                    $result.Data.Printers = $printers | Select-Object Name, DriverName, PortName, Shared, ShareName
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
            }
            catch {
                $result.Success = $false
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
    }
    $results = Start-ParallelJobs -InputObjects $hosts -ScriptBlock $scriptBlock -ArgumentList $options -InitializationScript $initScript -Activity "Enhanced Discovery"
    
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
            if ($options.CheckPrinters -and $result.Data.Printers) {
                $null = $output.AppendLine("`nPrinters:")
                foreach ($printer in $result.Data.Printers) {
                    $null = $output.AppendLine("  - $($printer.Name)")
                }
            }
            
            # Sunquest Applications
            if ($options.CheckSoftware -and $result.Data.Software) {
                $sunquestApps = $result.Data.Software | Where-Object { $_ -like "Sunquest Lab*" }
                if ($sunquestApps) {
                    $null = $output.AppendLine("`nSunquest Applications:")
                    foreach ($app in $sunquestApps) {
                        $null = $output.AppendLine("  - $app")
                    }
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
    
    Write-ScriptLog "Enhanced discovery completed. Results saved to: $outputFile" -Type "Success"

    # Export to CSV
    $csvFile = Get-FilePath -Default $script:Config.OutputFiles.SystemDataCSV
    if (Export-SystemDataToCSV -Results $results -FilePath $csvFile) {
        Write-ScriptLog "Data exported to CSV: $csvFile" -Type "Success"
        
        # Open HTML viewer
        $htmlFile = Get-FilePath -Default $script:Config.OutputFiles.HTMLViewer
        if ((Read-Host "`nOpen HTML viewer in browser? (Y/N)") -eq 'Y') {
            Open-HTMLViewer -HTMLFilePath $htmlFile
        }
    }

    # Export to HTML (legacy)
    if ((Read-Host "`nExport results to legacy HTML report? (Y/N)") -eq 'Y') {
        Export-ResultsToHtml -Results $results
    }
    
    Invoke-Pause
    Show-Menu -MenuName "Main"
}

function Export-ResultsToHtml {
    param([array]$Results)

    $filteredResults = $Results

    # Filtering menu
    $filterChoice = Read-Host "Apply filters before exporting? (Y/N)"
    if ($filterChoice -eq 'Y') {
        $filters = @{}
        $minDiskSpace = Read-Host "Filter by minimum free disk space (GB) - leave blank for no filter"
        if ($minDiskSpace -match '^\d+$') {
            $filters.MinDiskSpace = [int]$minDiskSpace
        }

        $minMemory = Read-Host "Filter by minimum total memory (GB) - leave blank for no filter"
        if ($minMemory -match '^\d+$') {
            $filters.MinMemory = [int]$minMemory
        }

        $osFilter = Read-Host "Filter by OS Name (e.g., *Windows 10*) - leave blank for no filter"
        if ($osFilter) {
            $filters.OS = $osFilter
        }

        $filteredResults = $Results | Where-Object {
            $result = $_;
            ($filters.MinDiskSpace -eq $null -or $result.Data.Storage.FreeGB -ge $filters.MinDiskSpace) -and
            ($filters.MinMemory -eq $null -or $result.Data.OS.TotalMemoryGB -ge $filters.MinMemory) -and
            ($filters.OS -eq $null -or $result.Data.OS.Name -like $filters.OS)
        }
    }

    $htmlReportPath = Get-FilePath -Default "Enhanced_Discovery_Report.html"
    $filteredResults | ConvertTo-Html -Property Hostname, @{Name='OS';Expression={$_.Data.OS.Name}}, @{Name='Memory (GB)';Expression={$_.Data.OS.TotalMemoryGB}}, @{Name='Disk Space (GB)';Expression={$_.Data.Storage.FreeGB}} -Title "Enhanced System Discovery Report" | Out-File $htmlReportPath

    Write-ScriptLog "HTML report generated at $htmlReportPath" -Type "Success"
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
    $initScript = {
        function Get-RemoteSystemInfo {
            param(
                [Parameter(Mandatory)][string]$ComputerName,
                [hashtable]$Options = @{},
                [int]$Timeout = 30
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
                    $printers = Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer -ErrorAction Stop
                    $result.Data.Printers = $printers | Select-Object Name, DriverName, PortName, Shared, ShareName
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
            }
            catch {
                $result.Success = $false
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
    }
    $results = Start-ParallelJobs -InputObjects $hosts -ScriptBlock $scriptBlock -ArgumentList @{CheckNetwork = $true; CheckTracert = $true} -InitializationScript $initScript -Activity "Network Analysis"
    
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
                    }
                }
                "R" {
                    $index = Read-Host "Enter pattern number to remove"
                    if ($index -match '^\d+$' -and [int]$index -ge 1 -and [int]$index -le $script:Config.CheckApps.ExcludePatterns.Count) {
                        $removed = $script:Config.CheckApps.ExcludePatterns[[int]$index - 1]
                        $script:Config.CheckApps.ExcludePatterns = @($script:Config.CheckApps.ExcludePatterns | Where-Object { $_ -ne $removed })
                        Write-ScriptLog "Pattern removed" -Type "Success"
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
