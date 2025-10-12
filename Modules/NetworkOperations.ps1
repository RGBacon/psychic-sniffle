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
#endregion
