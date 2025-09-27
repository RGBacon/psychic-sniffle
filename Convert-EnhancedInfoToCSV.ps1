# Convert Enhanced System Info Text to CSV
# This script converts the enhanced_system_info.txt file to system_data.csv format

param(
    [string]$InputFile = "enhanced_system_info.txt",
    [string]$OutputFile = "system_data.csv"
)

function Convert-EnhancedInfoToCSV {
    param(
        [string]$InputPath,
        [string]$OutputPath
    )
    
    try {
        Write-Host "Converting $InputPath to $OutputPath..." -ForegroundColor Green
        
        # Check if input file exists
        if (-not (Test-Path $InputPath)) {
            Write-Error "Input file not found: $InputPath"
            return $false
        }
        
        # Read the input file
        $content = Get-Content -Path $InputPath -Raw
        
        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Warning "Input file is empty: $InputPath"
            return $false
        }
        
        # Parse the enhanced system info format
        $records = @()
        $currentRecord = @{}
        $lines = $content -split "`n"
        $traceRouteLines = $null
        
        foreach ($line in $lines) {
            $line = $line.Trim()
            
            # Skip empty lines and headers
            if ([string]::IsNullOrWhiteSpace($line) -or 
                $line -match "Enhanced System|Generated on|===|------") {
                continue
            }
            
            # Check if this is a new host entry (successful)
            if ($line -match "^Host:\s*(PC-[A-Z0-9-]+)$") {
                # Save previous record if exists
                if ($currentRecord.Count -gt 0) {
                    $records += $currentRecord
                }
                
                # Start new record
                $currentRecord = @{
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Hostname = $matches[1]
                    OS_Name = ""
                    OS_Version = ""
                    OS_Build = ""
                    Manufacturer = ""
                    Model = ""
                    TotalMemory_GB = ""
                    Processor = ""
                    Cores = ""
                    LogicalProcessors = ""
                    LastBoot = ""
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
                    Status = "Success"
                    Error_Message = ""
                }
            }
            # Check for error entries and skip them
            elseif ($line -match "^Host:\s*(PC-[A-Z0-9-]+)\s*-\s*ERROR:") {
                # Skip error entries - don't create records for them
                continue
            }
            # Parse other fields
            elseif ($line -match "^OS:\s*(.+)\s*\(Build\s*(\d+)\)$") {
                $currentRecord.OS_Name = $matches[1]
                $currentRecord.OS_Build = $matches[2]
                # Extract version from OS name
                if ($matches[1] -match "Windows\s+(\d+)") {
                    $currentRecord.OS_Version = "10.0.$($matches[2])"
                }
            }
            elseif ($line -match "^Hardware:\s*(.+?)\s+(.+)$") {
                $currentRecord.Manufacturer = $matches[1]
                $currentRecord.Model = $matches[2]
            }
            elseif ($line -match "^Memory:\s*([0-9.]+)\s*GB$") {
                $currentRecord.TotalMemory_GB = $matches[1]
            }
            elseif ($line -match "^Processor:\s*(.+)$") {
                $currentRecord.Processor = $matches[1]
            }
            elseif ($line -match "^Cores:\s*(.+)$") {
                $currentRecord.Cores = $matches[1]
            }
            elseif ($line -match "^Logical Processors:\s*(.+)$") {
                $currentRecord.LogicalProcessors = $matches[1]
            }
            elseif ($line -match "^\s*IP:\s*([0-9.]+)") {
                $currentRecord.Primary_IP = $matches[1]
                # Extract subnet from IP
                if ($matches[1] -match "^(\d+\.\d+\.\d+)\.\d+$") {
                    $currentRecord.Subnet = "$($matches[1]).*"
                }
            }
            elseif ($line -match "^\s*Gateway:\s*(.+)$") {
                $currentRecord.Primary_Gateway = $matches[1]
            }
            elseif ($line -match "^\s*DNS:\s*(.+)$") {
                $currentRecord.Primary_DNS = $matches[1]
            }
            elseif ($line -match "^\s*MAC Address:\s*(.+)$") {
                $currentRecord.MAC_Address = $matches[1]
            }
            elseif ($line -match "^\s*C:\s*-\s*([0-9.]+)GB\s*free\s*of\s*([0-9.]+)GB\s*\(([0-9.]+)%\s*free\)") {
                $currentRecord.Drive_C = "C:"
                $currentRecord.Drive_C_Free_GB = $matches[1]
                $currentRecord.Drive_C_Size_GB = $matches[2]
                $currentRecord.Drive_C_Percent_Free = $matches[3]
            }
            elseif ($line -match "^Last Boot:\s*(.+)$") {
                $currentRecord.LastBoot = $matches[1]
            }
            elseif ($line -match "Tracing route to") {
                # Start collecting traceroute data
                $traceRouteLines = @($line)
            }
            elseif ($line -match "^\s*\d+\s+\d+\s*ms" -and $traceRouteLines) {
                # Collect traceroute hop lines
                $traceRouteLines += $line
            }
            elseif ($line -match "Trace complete" -and $traceRouteLines) {
                # End of traceroute - save it as single line with semicolons
                $currentRecord.TraceRoute = ($traceRouteLines -join "; ")
                $traceRouteLines = $null
            }
            elseif ($line -match "^Status:\s*(.+)$") {
                $currentRecord.Status = $matches[1]
            }
            elseif ($line -match "^Error:\s*(.+)$") {
                $currentRecord.Error_Message = $matches[1]
                $currentRecord.Status = "Error"
            }
        }
        
        # Add the last record
        if ($currentRecord.Count -gt 0) {
            $records += $currentRecord
        }
        
        if ($records.Count -eq 0) {
            Write-Warning "No valid records found in the input file"
            return $false
        }
        
        # Create CSV content
        $headers = @(
            "Timestamp", "Hostname", "OS_Name", "OS_Version", "OS_Build", "Manufacturer", 
            "Model", "TotalMemory_GB", "Processor", "Cores", "LogicalProcessors", "LastBoot",
            "Drive_C", "Drive_C_Free_GB", "Drive_C_Size_GB", "Drive_C_Percent_Free",
            "Drive_D", "Drive_D_Free_GB", "Drive_D_Size_GB", "Drive_D_Percent_Free",
            "Primary_IP", "Primary_Gateway", "Primary_DNS", "MAC_Address", "Subnet",
            "Sunquest_Apps", "Printer_Count", "Printer_Names", "TraceRoute", "Status", "Error_Message"
        )
        
        # Write CSV file
        $csvContent = @()
        $csvContent += ($headers -join ",")
        
        foreach ($record in $records) {
            $row = @()
            foreach ($header in $headers) {
                $value = if ($record.ContainsKey($header)) { $record[$header] } else { "" }
                # Escape CSV values - always quote to handle commas, quotes, and newlines
                $value = '"' + ($value.ToString() -replace '"', '""') + '"'
                $row += $value
            }
            $csvContent += ($row -join ",")
        }
        
        # Write to output file
        $csvContent | Out-File -FilePath $OutputPath -Encoding UTF8
        
        Write-Host "Successfully converted $($records.Count) records to $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Error converting file: $_"
        return $false
    }
}

# Main execution
Write-Host "Enhanced System Info to CSV Converter" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

if (Convert-EnhancedInfoToCSV -InputPath $InputFile -OutputPath $OutputFile) {
    Write-Host "`nConversion completed successfully!" -ForegroundColor Green
    Write-Host "Output file: $OutputFile" -ForegroundColor Yellow
} else {
    Write-Host "`nConversion failed!" -ForegroundColor Red
    exit 1
}
