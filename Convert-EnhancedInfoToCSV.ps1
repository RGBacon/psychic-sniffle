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
        
        foreach ($line in $lines) {
            $line = $line.Trim()
            
            # Skip empty lines and headers
            if ([string]::IsNullOrWhiteSpace($line) -or 
                $line -match "Enhanced System|Generated on|===|Hostname|OS Name|Manufacturer") {
                continue
            }
            
            # Check if this is a new host entry
            if ($line -match "^Hostname:\s*(.+)$") {
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
            # Parse other fields
            elseif ($line -match "^OS Name:\s*(.+)$") {
                $currentRecord.OS_Name = $matches[1]
            }
            elseif ($line -match "^OS Version:\s*(.+)$") {
                $currentRecord.OS_Version = $matches[1]
            }
            elseif ($line -match "^OS Build:\s*(.+)$") {
                $currentRecord.OS_Build = $matches[1]
            }
            elseif ($line -match "^Manufacturer:\s*(.+)$") {
                $currentRecord.Manufacturer = $matches[1]
            }
            elseif ($line -match "^Model:\s*(.+)$") {
                $currentRecord.Model = $matches[1]
            }
            elseif ($line -match "^Total Memory:\s*(.+)\s*GB$") {
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
            elseif ($line -match "^Last Boot:\s*(.+)$") {
                $currentRecord.LastBoot = $matches[1]
            }
            elseif ($line -match "^Primary IP:\s*(.+)$") {
                $currentRecord.Primary_IP = $matches[1]
            }
            elseif ($line -match "^Gateway:\s*(.+)$") {
                $currentRecord.Primary_Gateway = $matches[1]
            }
            elseif ($line -match "^DNS:\s*(.+)$") {
                $currentRecord.Primary_DNS = $matches[1]
            }
            elseif ($line -match "^MAC Address:\s*(.+)$") {
                $currentRecord.MAC_Address = $matches[1]
            }
            elseif ($line -match "^Subnet:\s*(.+)$") {
                $currentRecord.Subnet = $matches[1]
            }
            elseif ($line -match "^Sunquest Apps:\s*(.+)$") {
                $currentRecord.Sunquest_Apps = $matches[1]
            }
            elseif ($line -match "^Printer Count:\s*(.+)$") {
                $currentRecord.Printer_Count = $matches[1]
            }
            elseif ($line -match "^Printer Names:\s*(.+)$") {
                $currentRecord.Printer_Names = $matches[1]
            }
            elseif ($line -match "^Trace Route:\s*(.+)$") {
                $currentRecord.TraceRoute = $matches[1]
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
                # Escape CSV values
                if ($value -and $value.ToString().Contains(",") -or $value.ToString().Contains('"')) {
                    $value = '"' + ($value.ToString() -replace '"', '""') + '"'
                }
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
