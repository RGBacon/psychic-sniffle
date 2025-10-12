# File Operations Module
# Handles all file operations including hosts file management, output file creation, and data export

#region File Operations Functions
function Get-FilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Default,
        
        [string]$CustomPath
    )
    
    if ($CustomPath) {
        return $CustomPath
    }
    
    return Join-Path (Get-ScriptDirectory) $Default
}

function Initialize-OutputFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [Parameter(Mandatory)]
        [string]$Title,
        
        [string]$Header = ""
    )
    
    try {
        # Create directory if it doesn't exist
        $directory = Split-Path -Path $FilePath -Parent
        if (-not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        
        # Create file with header
        $content = @"
$Title
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
$Header
"@
        
        Set-Content -Path $FilePath -Value $content -Encoding UTF8
        Write-Log "Output file initialized: $FilePath" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to initialize output file $FilePath : $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Get-HostsList {
    [CmdletBinding()]
    param(
        [string]$HostsFilePath
    )
    
    if (-not $HostsFilePath) {
        $config = Get-Configuration
        $HostsFilePath = Join-Path (Get-ScriptDirectory) $config.HostsFile
    }
    
    if (-not (Test-Path $HostsFilePath)) {
        Write-Log "Hosts file not found: $HostsFilePath" -Level Warning
        return @()
    }
    
    try {
        $hosts = Get-Content -Path $HostsFilePath | Where-Object { 
            $_.Trim() -ne "" -and -not $_.StartsWith("#") 
        }
        
        Write-Log "Loaded $($hosts.Count) hosts from $HostsFilePath" -Level Info
        return $hosts
    }
    catch {
        Write-Log "Error reading hosts file: $($_.Exception.Message)" -Level Error
        return @()
    }
}

# Initialize-CSVFile function removed - no longer needed as Export-Csv handles headers automatically

function Export-SystemDataToCSV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$SystemData,
        
        [string]$FilePath,
        
        [switch]$Append
    )
    
    if (-not $FilePath) {
        $config = Get-Configuration
        $FilePath = Join-Path (Get-ScriptDirectory) $config.OutputFiles.SystemDataCSV
    }
    
    try {
        # Transform data into CSV-friendly format matching system_data_viewer.html expectations
        $csvData = foreach ($system in $SystemData) {
            # Determine status
            $status = if ($system.Success) { "Success" } else { "Failed" }
            
            # Extract drive information
            $driveC = if ($system.Data.Storage.DriveC) { $system.Data.Storage.DriveC.DeviceID } else { "" }
            $driveCFreeGB = if ($system.Data.Storage.DriveC) { $system.Data.Storage.DriveC.FreeGB } else { "" }
            $driveCSizeGB = if ($system.Data.Storage.DriveC) { $system.Data.Storage.DriveC.SizeGB } else { "" }
            $driveCPercentFree = if ($system.Data.Storage.DriveC) { $system.Data.Storage.DriveC.PercentFree } else { "" }
            
            $driveD = if ($system.Data.Storage.DriveD) { $system.Data.Storage.DriveD.DeviceID } else { "" }
            $driveDFreeGB = if ($system.Data.Storage.DriveD) { $system.Data.Storage.DriveD.FreeGB } else { "" }
            $driveDSizeGB = if ($system.Data.Storage.DriveD) { $system.Data.Storage.DriveD.SizeGB } else { "" }
            $driveDPercentFree = if ($system.Data.Storage.DriveD) { $system.Data.Storage.DriveD.PercentFree } else { "" }
            
            # Build CSV row matching the exact format expected by system_data_viewer.html
            [PSCustomObject]@{
                Timestamp = $system.Timestamp
                Hostname = $system.Hostname
                OS_Name = if ($system.Data) { $system.Data.OS.Name } else { "" }
                OS_Version = if ($system.Data) { $system.Data.OS.Version } else { "" }
                OS_Build = if ($system.Data) { $system.Data.OS.BuildNumber } else { "" }
                Manufacturer = if ($system.Data) { $system.Data.Hardware.Manufacturer } else { "" }
                Model = if ($system.Data) { $system.Data.Hardware.Model } else { "" }
                TotalMemory_GB = if ($system.Data) { $system.Data.OS.TotalMemoryGB } else { "" }
                Processor = if ($system.Data) { $system.Data.Hardware.Processor } else { "" }
                Cores = if ($system.Data) { $system.Data.Hardware.Cores } else { "" }
                LogicalProcessors = if ($system.Data) { $system.Data.Hardware.LogicalProcessors } else { "" }
                LastBoot = if ($system.Data) { $system.Data.OS.LastBoot } else { "" }
                Drive_C = $driveC
                Drive_C_Free_GB = $driveCFreeGB
                Drive_C_Size_GB = $driveCSizeGB
                Drive_C_Percent_Free = $driveCPercentFree
                Drive_D = $driveD
                Drive_D_Free_GB = $driveDFreeGB
                Drive_D_Size_GB = $driveDSizeGB
                Drive_D_Percent_Free = $driveDPercentFree
                Primary_IP = if ($system.Data) { $system.Data.Network.PrimaryIP } else { "" }
                Primary_Gateway = if ($system.Data) { $system.Data.Network.Gateway } else { "" }
                Primary_DNS = if ($system.Data) { $system.Data.Network.DNS } else { "" }
                MAC_Address = if ($system.Data) { $system.Data.Network.MACAddress } else { "" }
                Subnet = if ($system.Data) { $system.Data.Network.Subnet } else { "" }
                Sunquest_Apps = if ($system.Data) { $system.Data.SunquestApps } else { "" }
                Printer_Count = if ($system.Data) { $system.Data.PrinterCount } else { "" }
                Printer_Names = if ($system.Data) { $system.Data.PrinterNames } else { "" }
                TraceRoute = if ($system.Data) { $system.Data.Network.TraceRoute } else { "" }
                Status = $status
                Error_Message = $system.Error
            }
        }
        
        # Export using PowerShell's built-in CSV handling (properly escapes special characters)
        if ($Append -and (Test-Path $FilePath)) {
            # Append mode - add without headers
            $csvData | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Append
        }
        else {
            # New file or overwrite mode
            $csvData | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        
        Write-Log "System data exported to CSV: $FilePath ($($csvData.Count) records)" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to export system data to CSV: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Generate-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$SystemData,
        
        [string]$FilePath
    )
    
    if (-not $FilePath) {
        $config = Get-Configuration
        $FilePath = Join-Path (Get-ScriptDirectory) $config.OutputFiles.HTMLViewer
    }
    
    try {
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Information Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
    </style>
</head>
<body>
    <h1>System Information Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p>Total Systems: $($SystemData.Count)</p>
    
    <table>
        <tr>
            <th>Hostname</th>
            <th>Status</th>
            <th>OS</th>
            <th>Memory (GB)</th>
            <th>Manufacturer</th>
            <th>Model</th>
            <th>Processor</th>
            <th>Error</th>
        </tr>
"@
        
        foreach ($system in $SystemData) {
            $statusClass = if ($system.Success) { "success" } else { "error" }
            $statusText = if ($system.Success) { "Success" } else { "Failed" }
            
            $html += @"
        <tr>
            <td>$($system.Hostname)</td>
            <td class="$statusClass">$statusText</td>
            <td>$($system.Data.OS.Name)</td>
            <td>$($system.Data.OS.TotalMemoryGB)</td>
            <td>$($system.Data.Hardware.Manufacturer)</td>
            <td>$($system.Data.Hardware.Model)</td>
            <td>$($system.Data.Hardware.Processor)</td>
            <td>$($system.Error)</td>
        </tr>
"@
        }
        
        $html += @"
    </table>
</body>
</html>
"@
        
        $html | Out-File -FilePath $FilePath -Encoding UTF8
        Write-Log "HTML report generated: $FilePath" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to generate HTML report: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Open-HTMLViewer {
    [CmdletBinding()]
    param()
    
    $config = Get-Configuration
    $htmlFile = Join-Path (Get-ScriptDirectory) $config.OutputFiles.HTMLViewer
    
    if (Test-Path $htmlFile) {
        try {
            Start-Process $htmlFile
            Write-Log "HTML viewer opened" -Level Success
            return $true
        }
        catch {
            Write-Log "Failed to open HTML viewer: $($_.Exception.Message)" -Level Error
            return $false
        }
    }
    else {
        Write-Log "HTML report not found. Run a scan first." -Level Warning
        return $false
    }
}
#endregion
