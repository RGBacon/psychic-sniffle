# System Information Module
# Handles system information gathering, software detection, and hardware analysis

#region System Information Functions
function Get-RemoteSystemInfo {
    <#
    .SYNOPSIS
        Collects comprehensive system information from a remote computer via WMI/CIM.
    
    .DESCRIPTION
        This is the CORE function that queries WMI/CIM to collect all system data including:
        - OS information (name, version, build, last boot, memory)
        - Hardware information (manufacturer, model, processor, cores)
        - Storage information (drives, free space, sizes)
        - Network information (IP, gateway, DNS, MAC, adapters)
        - Optional: Sunquest applications
        - Optional: Installed printers
        - Optional: Network traceroute
    
    .PARAMETER ComputerName
        The hostname or IP address of the remote computer to query.
    
    .PARAMETER Options
        Hashtable of options from config.json SystemInfo section:
        - CheckSunquest: Query for Sunquest applications
        - CheckPrinters: Query for installed printers
        - CheckTracert: Perform network traceroute
    
    .PARAMETER TimeoutSeconds
        Timeout for the operation in seconds. Default: 90
    
    .RETURNS
        PSCustomObject with Success, Error, Hostname, Timestamp, and detailed Data object
        Format matches CSV export requirements (31 columns)
    
    .EXAMPLE
        $result = Get-RemoteSystemInfo -ComputerName "PC-12345" -Options @{CheckSunquest=$true; CheckPrinters=$true}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [hashtable]$Options = @{},
        
        [int]$TimeoutSeconds = 90
    )
    
    Write-Log "Starting system info collection for $ComputerName" -Level Info
    
    # Initialize result object
    $result = [PSCustomObject]@{
        Success = $false
        Error = ""
        Hostname = $ComputerName
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Data = $null
    }
    
    try {
        # Test connectivity first
        if (-not (Test-NetworkConnectivity -ComputerName $ComputerName)) {
            $result.Error = "Host unreachable (ping failed)"
            Write-Log "System info collection failed for $ComputerName : Host unreachable" -Level Error
            return $result
        }
        
        # Test WMI access
        if (-not (Test-WMIAccess -ComputerName $ComputerName -TimeoutSeconds $TimeoutSeconds)) {
            $result.Error = "WMI access denied or unavailable"
            Write-Log "System info collection failed for $ComputerName : WMI access failed" -Level Error
            return $result
        }
        
        Write-Log "Querying WMI data from $ComputerName" -Level Info
        
        # Check PowerShell version and use appropriate cmdlet
        $useCim = $PSVersionTable.PSVersion.Major -ge 6
        
        if ($useCim) {
            # PowerShell 7+ - Use CIM cmdlets with CimSession
            $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
            
            # Query 1: Win32_ComputerSystem
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $cimSession -ErrorAction Stop
            
            # Query 2: Win32_OperatingSystem
            $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $cimSession -ErrorAction Stop
            
            # Query 3: Win32_Processor
            $processor = Get-CimInstance -ClassName Win32_Processor -CimSession $cimSession -ErrorAction Stop | Select-Object -First 1
            
            # Query 4: Win32_LogicalDisk (Drive info)
            $drives = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $cimSession -Filter "DriveType=3" -ErrorAction Stop
            
            # Query 5: Win32_NetworkAdapterConfiguration
            $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -CimSession $cimSession -Filter "IPEnabled=True" -ErrorAction Stop
            $primaryAdapter = $networkAdapters | Where-Object { $_.IPAddress -ne $null } | Select-Object -First 1
        }
        else {
            # PowerShell 5.1 - Use legacy WMI cmdlets
            # Query 1: Win32_ComputerSystem
            $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction Stop
            
            # Query 2: Win32_OperatingSystem
            $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
            
            # Query 3: Win32_Processor
            $processor = Get-WmiObject -Class Win32_Processor -ComputerName $ComputerName -ErrorAction Stop | Select-Object -First 1
            
            # Query 4: Win32_LogicalDisk (Drive info)
            $drives = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $ComputerName -Filter "DriveType=3" -ErrorAction Stop
            
            # Query 5: Win32_NetworkAdapterConfiguration
            $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -Filter "IPEnabled=True" -ErrorAction Stop
            $primaryAdapter = $networkAdapters | Where-Object { $_.IPAddress -ne $null } | Select-Object -First 1
        }
        
        # Calculate total memory in GB
        $totalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
        
        # Calculate last boot time (CIM returns DateTime directly, WMI needs conversion)
        if ($useCim) {
            $lastBoot = $operatingSystem.LastBootUpTime
        }
        else {
            $lastBoot = $operatingSystem.ConvertToDateTime($operatingSystem.LastBootUpTime)
        }
        
        # Process drives
        $driveC = $drives | Where-Object { $_.DeviceID -eq "C:" }
        $driveD = $drives | Where-Object { $_.DeviceID -eq "D:" }
        
        # Helper function to calculate drive info
        function Get-DriveInfo {
            param($drive)
            if ($drive) {
                $freeGB = [math]::Round($drive.FreeSpace / 1GB, 2)
                $sizeGB = [math]::Round($drive.Size / 1GB, 2)
                $percentFree = if ($sizeGB -gt 0) { [math]::Round(($freeGB / $sizeGB) * 100, 1) } else { 0 }
                return @{
                    DeviceID = $drive.DeviceID
                    FreeGB = $freeGB
                    SizeGB = $sizeGB
                    PercentFree = $percentFree
                }
            }
            return $null
        }
        
        $driveCInfo = Get-DriveInfo $driveC
        $driveDInfo = Get-DriveInfo $driveD
        
        # Get network information
        $primaryIP = if ($primaryAdapter.IPAddress) { $primaryAdapter.IPAddress[0] } else { "" }
        $primaryGateway = if ($primaryAdapter.DefaultIPGateway) { $primaryAdapter.DefaultIPGateway[0] } else { "" }
        $primaryDNS = if ($primaryAdapter.DNSServerSearchOrder) { $primaryAdapter.DNSServerSearchOrder -join ";" } else { "" }
        $macAddress = if ($primaryAdapter.MACAddress) { $primaryAdapter.MACAddress } else { "" }
        
        # Calculate subnet mask notation (e.g., "10.24.128.*")
        $subnet = ""
        if ($primaryIP) {
            $ipParts = $primaryIP.Split('.')
            if ($ipParts.Count -eq 4) {
                $subnet = "$($ipParts[0]).$($ipParts[1]).$($ipParts[2]).*"
            }
        }
        
        # Optional: Check for Sunquest applications
        $sunquestApps = ""
        if ($Options.CheckSunquest) {
            try {
                Write-Log "Checking for Sunquest applications on $ComputerName" -Level Info
                $sunquestList = Get-SunquestApplications -ComputerName $ComputerName -UseCim $useCim -CimSession $(if ($useCim) { $cimSession } else { $null })
                if ($sunquestList -and $sunquestList.Count -gt 0) {
                    $sunquestApps = $sunquestList -join "; "
                    Write-Log "Found Sunquest applications on $ComputerName : $sunquestApps" -Level Success
                }
            }
            catch {
                Write-Log "Failed to check Sunquest applications on $ComputerName : $($_.Exception.Message)" -Level Warning
            }
        }
        
        # Optional: Get printer information
        $printerCount = 0
        $printerNames = ""
        if ($Options.CheckPrinters) {
            try {
                Write-Log "Checking printers on $ComputerName" -Level Info
                $printerList = Get-PrinterInfo -ComputerName $ComputerName -UseCim $useCim -CimSession $(if ($useCim) { $cimSession } else { $null })
                if ($printerList -and $printerList.Count -gt 0) {
                    $printerCount = $printerList.Count
                    $printerNames = ($printerList | ForEach-Object { $_.Name }) -join "; "
                    Write-Log "Found $printerCount printers on $ComputerName" -Level Success
                }
            }
            catch {
                Write-Log "Failed to check printers on $ComputerName : $($_.Exception.Message)" -Level Warning
            }
        }
        
        # Optional: Perform traceroute
        $traceRoute = ""
        if ($Options.CheckTracert) {
            try {
                Write-Log "Performing traceroute to $ComputerName" -Level Info
                $traceHops = Get-Traceroute -ComputerName $ComputerName -MaxHops 10
                if ($traceHops -and $traceHops.Count -gt 0) {
                    $traceRoute = "Tracing route to $ComputerName; " + (($traceHops | ForEach-Object { "$($_.Hop) ($($_.Latency) ms)" }) -join "; ")
                }
            }
            catch {
                Write-Log "Traceroute failed for $ComputerName : $($_.Exception.Message)" -Level Warning
                $traceRoute = ""
            }
        }
        
        # Check Windows 11 Readiness (RAM >= 14GB)
        $isWin11Ready = $totalMemoryGB -ge 14
        $isWin11 = $operatingSystem.Caption -like "*Windows 11*"
        
        # Build comprehensive data object (matches CSV export format)
        $result.Data = [PSCustomObject]@{
            # Operating System
            OS = [PSCustomObject]@{
                Name = $operatingSystem.Caption.Trim()
                Version = $operatingSystem.Version
                BuildNumber = $operatingSystem.BuildNumber
                LastBoot = $lastBoot.ToString("MM/dd/yyyy HH:mm:ss")
                TotalMemoryGB = $totalMemoryGB
            }
            
            # Hardware
            Hardware = [PSCustomObject]@{
                Manufacturer = $computerSystem.Manufacturer.Trim()
                Model = $computerSystem.Model.Trim()
                Domain = $computerSystem.Domain
                Processor = $processor.Name.Trim()
                Cores = $processor.NumberOfCores
                LogicalProcessors = $processor.NumberOfLogicalProcessors
            }
            
            # Storage
            Storage = [PSCustomObject]@{
                DriveC = $driveCInfo
                DriveD = $driveDInfo
            }
            
            # Network
            Network = [PSCustomObject]@{
                PrimaryIP = $primaryIP
                Gateway = $primaryGateway
                DNS = $primaryDNS
                MACAddress = $macAddress
                Subnet = $subnet
                TraceRoute = $traceRoute
            }
            
            # Applications & Printers
            SunquestApps = $sunquestApps
            PrinterCount = $printerCount
            PrinterNames = $printerNames
            
            # Windows 11 Readiness
            Windows11Ready = $isWin11Ready
            IsWindows11 = $isWin11
        }
        
        $result.Success = $true
        Write-Log "System info collection completed successfully for $ComputerName" -Level Success
        
        # Log key metrics
        Write-Log "  OS: $($result.Data.OS.Name) | RAM: ${totalMemoryGB}GB | Win11 Ready: $isWin11Ready" -Level Info
        
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Log "System info collection failed for $ComputerName : $($_.Exception.Message)" -Level Error
    }
    finally {
        # Clean up CIM session if it was created
        if ($useCim -and $cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
    }
    
    return $result
}

function Get-StorageInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [bool]$UseCim = $false,
        
        $CimSession = $null
    )
    
    try {
        if ($UseCim -and $CimSession) {
            $drives = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $CimSession -ErrorAction Stop
        }
        else {
            $drives = Get-WmiObject -ComputerName $ComputerName -Class Win32_LogicalDisk -ErrorAction Stop
        }
        
        $storageInfo = @()
        foreach ($drive in $drives) {
            if ($drive.DriveType -eq 3) { # Fixed drives only
                $storageInfo += @{
                    Drive = $drive.DeviceID
                    Label = $drive.VolumeName
                    SizeGB = [math]::Round($drive.Size / 1GB, 2)
                    FreeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
                    FileSystem = $drive.FileSystem
                }
            }
        }
        
        return $storageInfo
    }
    catch {
        Write-Log "Failed to get storage info for $ComputerName : $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-InstalledSoftware {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [bool]$UseCim = $false,
        
        $CimSession = $null
    )
    
    try {
        # Try registry approach first (much faster)
        $software = @()
        
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            $keys = @(
                "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            
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
        }
        catch {
            # Fallback to WMI/CIM if registry fails (SLOW!)
            Write-Log "Registry access failed, falling back to WMI/CIM (this will be slow)" -Level Warning
            
            if ($UseCim -and $CimSession) {
                $products = Get-CimInstance -ClassName Win32_Product -CimSession $CimSession -ErrorAction Stop
            }
            else {
                $products = Get-WmiObject -ComputerName $ComputerName -Class Win32_Product -ErrorAction Stop
            }
            $software = $products | ForEach-Object { $_.Name }
        }
        
        return $software | Select-Object -Unique
    }
    catch {
        Write-Log "Failed to get installed software for $ComputerName : $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-SunquestApplications {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [bool]$UseCim = $false,
        
        $CimSession = $null
    )
    
    try {
        Write-Log "Querying Sunquest applications on $ComputerName (this may be slow)" -Level Info
        
        # Use WMI/CIM Win32_Product (SLOW but reliable for installed software)
        if ($UseCim -and $CimSession) {
            $sunquestProducts = Get-CimInstance -ClassName Win32_Product -CimSession $CimSession -Filter "Name LIKE '%Sunquest%'" -ErrorAction SilentlyContinue
        }
        else {
            $sunquestProducts = Get-WmiObject -ComputerName $ComputerName -Class Win32_Product -Filter "Name LIKE '%Sunquest%'" -ErrorAction SilentlyContinue
        }
        
        if ($sunquestProducts) {
            $sunquestApps = $sunquestProducts | Select-Object -ExpandProperty Name
            return $sunquestApps
        }
        
        return @()
    }
    catch {
        Write-Log "Failed to get Sunquest applications for $ComputerName : $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-PrinterInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [bool]$UseCim = $false,
        
        $CimSession = $null
    )
    
    try {
        if ($UseCim -and $CimSession) {
            $printers = Get-CimInstance -ClassName Win32_Printer -CimSession $CimSession -ErrorAction Stop
        }
        else {
            $printers = Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer -ErrorAction Stop
        }
        
        $printerInfo = @()
        foreach ($printer in $printers) {
            $printerInfo += @{
                Name = $printer.Name
                DriverName = $printer.DriverName
                PortName = $printer.PortName
                Shared = $printer.Shared
                Default = $printer.Default
            }
        }
        
        return $printerInfo
    }
    catch {
        Write-Log "Failed to get printer info for $ComputerName : $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Invoke-SystemScan {
    <#
    .SYNOPSIS
        Performs parallel system scans on multiple computers.
    
    .DESCRIPTION
        Scans multiple computers in parallel using background jobs.
        Respects MaxParallelJobs configuration setting.
    
    .PARAMETER Hostnames
        Array of computer names to scan
    
    .PARAMETER Options
        Hashtable of scan options (CheckSunquest, CheckPrinters, CheckTracert)
    
    .PARAMETER MaxParallelJobs
        Maximum number of concurrent scans. Default: from config.json
    
    .PARAMETER TimeoutSeconds
        Timeout per host in seconds. Default: from config.json
    
    .RETURNS
        Array of scan results (one per host)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Hostnames,
        
        [hashtable]$Options = @{},
        
        [int]$MaxParallelJobs = 0,
        
        [int]$TimeoutSeconds = 0
    )
    
    $config = Get-Configuration
    $maxJobs = if ($MaxParallelJobs -gt 0) { $MaxParallelJobs } else { $config.MaxParallelJobs }
    $timeout = if ($TimeoutSeconds -gt 0) { $TimeoutSeconds } else { $config.Timeout }
    
    Write-Log "Starting system scan on $($Hostnames.Count) hosts with $maxJobs parallel jobs" -Level Info
    
    $results = @()
    $jobs = @()
    
    foreach ($hostname in $Hostnames) {
        # Wait if we've reached max parallel jobs
        while ($jobs.Count -ge $maxJobs) {
            $completedJobs = $jobs | Where-Object { $_.State -eq "Completed" -or $_.State -eq "Failed" }
            
            foreach ($job in $completedJobs) {
                $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
                if ($result) {
                    $results += $result
                }
                Remove-Job -Job $job -Force
                $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }
            }
            
            if ($jobs.Count -ge $maxJobs) {
                Start-Sleep -Milliseconds 100
            }
        }
        
        # Start new job
        $modulePath = Split-Path -Parent $PSScriptRoot
        $modulePath = Join-Path $modulePath "Modules"
        
        $job = Start-Job -ScriptBlock {
            param($ComputerName, $Options, $TimeoutSeconds, $ModulePath)
            
            # Import required modules in job context
            . "$ModulePath\Configuration.ps1"
            . "$ModulePath\Logging.ps1"
            . "$ModulePath\NetworkOperations.ps1"
            . "$ModulePath\SystemInfo.ps1"
            
            Initialize-Logging
            
            return Get-RemoteSystemInfo -ComputerName $ComputerName -Options $Options -TimeoutSeconds $TimeoutSeconds
        } -ArgumentList $hostname, $Options, $timeout, $modulePath
        
        $jobs += $job
    }
    
    # Wait for remaining jobs
    Write-Log "Waiting for remaining $($jobs.Count) jobs to complete..." -Level Info
    $jobs | Wait-Job -Timeout 300 | Out-Null
    
    foreach ($job in $jobs) {
        $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
        if ($result) {
            $results += $result
        }
        Remove-Job -Job $job -Force
    }
    
    $successCount = ($results | Where-Object { $_.Success }).Count
    $failureCount = $results.Count - $successCount
    
    Write-Log "System scan completed. Success: $successCount, Failures: $failureCount" -Level Success
    
    return $results
}

function Start-ParallelJobs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$InputObjects,
        
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        
        [int]$MaxJobs = 10,
        
        [int]$TimeoutSeconds = 90
    )
    
    $results = @()
    $jobs = @()
    
    foreach ($item in $InputObjects) {
        # Wait if we've reached max parallel jobs
        while ($jobs.Count -ge $MaxJobs) {
            $completedJobs = $jobs | Where-Object { $_.State -eq "Completed" }
            
            foreach ($job in $completedJobs) {
                $result = Receive-Job -Job $job
                $results += $result
                Remove-Job -Job $job
            }
            
            Start-Sleep -Milliseconds 100
        }
        
        # Start new job
        $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $item
        $jobs += $job
    }
    
    # Wait for remaining jobs
    $jobs | Wait-Job | Out-Null
    
    foreach ($job in $jobs) {
        $result = Receive-Job -Job $job
        $results += $result
        Remove-Job -Job $job
    }
    
    return $results
}
#endregion
