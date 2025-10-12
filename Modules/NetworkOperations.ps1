# Network Operations Module
# Handles network connectivity, WMI access, and network-related operations

#region Network Functions
function Test-WMIAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [int]$TimeoutSeconds = 30
    )
    
    try {
        # Check PowerShell version
        $useCim = $PSVersionTable.PSVersion.Major -ge 6
        
        $job = Start-Job -ScriptBlock {
            param($ComputerName, $UseCim)
            
            if ($UseCim) {
                # PowerShell 7+ - Use CIM
                $session = New-CimSession -ComputerName $ComputerName -ErrorAction Stop
                Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $session -ErrorAction Stop | Out-Null
                Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue
            }
            else {
                # PowerShell 5.1 - Use WMI
                Get-WmiObject -ComputerName $ComputerName -Class Win32_ComputerSystem -ErrorAction Stop | Out-Null
            }
            return $true
        } -ArgumentList $ComputerName, $useCim
        
        $result = Wait-Job -Job $job -Timeout $TimeoutSeconds
        
        if ($result) {
            $output = Receive-Job -Job $job
            Remove-Job -Job $job
            return $output
        }
        else {
            Remove-Job -Job $job -Force
            return $false
        }
    }
    catch {
        return $false
    }
}

function Test-NetworkConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [int]$TimeoutSeconds = 5
    )
    
    try {
        # PowerShell 5.1 compatible - uses -Count instead of -TimeoutSeconds
        # Note: In PS 5.1, timeout is not directly configurable via Test-Connection
        # The timeout is handled at the network level (typically 4-5 seconds per ping)
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        return $ping
    }
    catch {
        return $false
    }
}

function Get-NetworkAdapters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [int]$TimeoutSeconds = 30
    )
    
    try {
        $adapters = Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapter -ErrorAction Stop | Where-Object {
            $_.NetConnectionStatus -eq 2 -and $_.MACAddress
        }
        
        $adapterInfo = @()
        foreach ($adapter in $adapters) {
            $adapterInfo += @{
                Name = $adapter.Name
                MACAddress = $adapter.MACAddress
                Speed = $adapter.Speed
                NetConnectionStatus = $adapter.NetConnectionStatus
            }
        }
        
        return $adapterInfo
    }
    catch {
        Write-Log "Failed to get network adapters for $ComputerName : $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-NetworkConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [int]$TimeoutSeconds = 30
    )
    
    try {
        $configs = Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object {
            $_.IPEnabled -eq $true
        }
        
        $networkInfo = @()
        foreach ($config in $configs) {
            $networkInfo += @{
                Description = $config.Description
                IPAddress = $config.IPAddress -join ", "
                SubnetMask = $config.IPSubnet -join ", "
                DefaultGateway = $config.DefaultIPGateway -join ", "
                DNSServers = $config.DNSServerSearchOrder -join ", "
                DHCPEnabled = $config.DHCPEnabled
            }
        }
        
        return $networkInfo
    }
    catch {
        Write-Log "Failed to get network configuration for $ComputerName : $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        
        [int]$MaxRetries = 3,
        
        [int]$DelaySeconds = 5,
        
        [string]$ErrorMessage = "Operation failed"
    )
    
    $attempt = 1
    $lastError = $null
    
    while ($attempt -le $MaxRetries) {
        try {
            $result = & $ScriptBlock
            return $result
        }
        catch {
            $lastError = $_.Exception
            Write-Log "Attempt $attempt failed: $($_.Exception.Message)" -Level Warning
            
            if ($attempt -lt $MaxRetries) {
                Write-Log "Retrying in $DelaySeconds seconds..." -Level Info
                Start-Sleep -Seconds $DelaySeconds
            }
            
            $attempt++
        }
    }
    
    Write-Log "$ErrorMessage after $MaxRetries attempts: $($lastError.Message)" -Level Error
    throw $lastError
}

function Get-Traceroute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [int]$MaxHops = 30,
        
        [int]$TimeoutSeconds = 30
    )
    
    try {
        $tracert = tracert -h $MaxHops -w $($TimeoutSeconds * 1000) $ComputerName 2>$null
        
        if ($tracert) {
            $hops = @()
            foreach ($line in $tracert) {
                if ($line -match "^\s*\d+\s+(.+?)\s+(\d+)\s+ms") {
                    $hops += @{
                        Hop = $matches[1]
                        Latency = $matches[2]
                    }
                }
            }
            return $hops
        }
        
        return @()
    }
    catch {
        Write-Log "Traceroute failed for $ComputerName : $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-RemoteSystemInfo {
    <#
    .SYNOPSIS
        Collects comprehensive system information from a remote computer via WMI.
    
    .DESCRIPTION
        This is the CORE function that queries WMI to collect all system data including:
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
    
    .RETURNS
        PSCustomObject with Success, Error, Hostname, Timestamp, and detailed Data object
    
    .EXAMPLE
        $result = Get-RemoteSystemInfo -ComputerName "PC-12345" -Options @{CheckSunquest=$true; CheckPrinters=$true}
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [hashtable]$Options = @{}
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
        if (-not (Test-WMIAccess -ComputerName $ComputerName)) {
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
                if ($useCim) {
                    $sunquestProducts = Get-CimInstance -ClassName Win32_Product -CimSession $cimSession -Filter "Name LIKE '%Sunquest%'" -ErrorAction SilentlyContinue
                }
                else {
                    $sunquestProducts = Get-WmiObject -Class Win32_Product -ComputerName $ComputerName -Filter "Name LIKE '%Sunquest%'" -ErrorAction SilentlyContinue
                }
                
                if ($sunquestProducts) {
                    $sunquestApps = ($sunquestProducts | Select-Object -ExpandProperty Name) -join "; "
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
                if ($useCim) {
                    $printers = Get-CimInstance -ClassName Win32_Printer -CimSession $cimSession -ErrorAction SilentlyContinue
                }
                else {
                    $printers = Get-WmiObject -Class Win32_Printer -ComputerName $ComputerName -ErrorAction SilentlyContinue
                }
                
                if ($printers) {
                    $printerCount = $printers.Count
                    $printerNames = ($printers | Select-Object -ExpandProperty Name) -join "; "
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
        
        # Build comprehensive data object
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

#endregion
