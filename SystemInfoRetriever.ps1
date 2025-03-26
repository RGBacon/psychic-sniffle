param (
    [string]$InputFile = "hosts.txt",
    [int]$Timeout = 30,
    [string]$LogFile = "system_check_log.txt"
)

function Show-Menu {
    Clear-Host
    Write-Host "=== System Information Retriever ==="
    Write-Host "1. Input File: $InputFile"
    Write-Host "2. Timeout: $Timeout seconds"
    Write-Host "3. Check Sunquest: $($CheckSunquest ? 'Enabled' : 'Disabled')"
    Write-Host "4. Check Printers: $($CheckPrinters ? 'Enabled' : 'Disabled')"
    Write-Host "5. Start Batch Scan"
    Write-Host "6. Check Single Host"
    Write-Host "7. Exit"
    Write-Host "=================================="
}

function Write-SystemLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$timestamp] $Message"
    Write-Host $Message
}

function Get-SingleHostInfo {
    param([string]$computerName)
    
    try {
        Write-Host "`nChecking host: $computerName"
        
        # Get basic system information
        $sysInfo = Get-WmiObject -ComputerName $computerName -Class Win32_OperatingSystem -ErrorAction Stop | 
        Select-Object @{
            Name='Hostname'; Expression={$computerName}
        }, 
        @{
            Name='OSName'; Expression={$_.Caption}
        },
        @{
            Name='TotalMemory'; Expression={[math]::Round($_.TotalVisibleMemorySize / 1MB, 2)}
        }

        # Get system model information
        $computerSystem = Get-WmiObject -ComputerName $computerName -Class Win32_ComputerSystem -ErrorAction Stop
        $sysInfo | Add-Member -NotePropertyName 'SystemModel' -NotePropertyValue $computerSystem.Model

        Write-Host "`nResults for $computerName"
        Write-Host ("OS Name: " + $sysInfo.OSName)
        Write-Host ("System Model: " + $sysInfo.SystemModel)
        Write-Host ("Total Physical Memory: " + $sysInfo.TotalMemory + " GB")

        # If CheckSunquest is enabled, get Sunquest application information
        if ($CheckSunquest) {
            Write-Host "`nChecking for Sunquest applications..."
            $sunquestApps = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName $computerName -Filter "Name LIKE 'Sunquest Lab%'" -ErrorAction Stop
            
            if ($sunquestApps) {
                Write-Host "Found Sunquest applications:"
                foreach ($app in $sunquestApps) {
                    Write-Host ("- " + $app.Name)
                }
            } else {
                Write-Host "No Sunquest Lab applications found"
            }
        }
        
        # If CheckPrinters is enabled, get printer information
        if ($CheckPrinters) {
            Write-Host "`nChecking for printers..."
            $printers = Get-WmiObject -Class Win32_Printer -ComputerName $computerName -ErrorAction Stop | 
                         Select-Object Name, ServerName, ShareName
            
            if ($printers -and $printers.Count -gt 0) {
                Write-Host "Found printers:"
                foreach ($printer in $printers) {
                    Write-Host ("- Name: " + $printer.Name)
                    if ($printer.ServerName) { Write-Host ("  Server: " + $printer.ServerName) }
                    if ($printer.ShareName) { Write-Host ("  Share: " + $printer.ShareName) }
                }
            } else {
                Write-Host "No printers found"
            }
        }
    }
    catch {
        Write-Host ("Error checking host " + $computerName + " : " + $_) -ForegroundColor Red
    }
    
    Write-Host "`nPress any key to return to menu..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Start-SystemScan {
    if (-not (Test-Path $InputFile)) {
        Write-SystemLog "Error: Input file $InputFile not found."
        return
    }

    Clear-Content -Path "output.txt" -ErrorAction SilentlyContinue
    Clear-Content -Path $LogFile -ErrorAction SilentlyContinue

    $hosts = Get-Content $InputFile | Where-Object { $_ -ne "" }
    $totalHosts = $hosts.Count
    $currentHost = 0

    $scriptBlock = {
        param($computerName, $timeout, $checkSunquest, $checkPrinters)
        
        try {
            # Get basic system information
            $sysInfo = Get-WmiObject -ComputerName $computerName -Class Win32_OperatingSystem -ErrorAction Stop | 
            Select-Object @{
                Name='Hostname'; Expression={$computerName}
            }, 
            @{
                Name='OSName'; Expression={$_.Caption}
            },
            @{
                Name='TotalMemory'; Expression={[math]::Round($_.TotalVisibleMemorySize / 1MB, 2)}
            }
            
            # Get system model information
            $computerSystem = Get-WmiObject -ComputerName $computerName -Class Win32_ComputerSystem -ErrorAction Stop
            $sysInfo | Add-Member -NotePropertyName 'SystemModel' -NotePropertyValue $computerSystem.Model

            # If CheckSunquest is enabled, get Sunquest application information
            if ($checkSunquest) {
                $sunquestApps = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName $computerName -Filter "Name LIKE 'Sunquest Lab%'" -ErrorAction Stop
                $sysInfo | Add-Member -NotePropertyName 'SunquestApps' -NotePropertyValue $sunquestApps
            }
            
            # If CheckPrinters is enabled, get printer information
            if ($checkPrinters) {
                $printers = Get-WmiObject -Class Win32_Printer -ComputerName $computerName -ErrorAction Stop | 
                             Select-Object Name, ServerName, ShareName
                $sysInfo | Add-Member -NotePropertyName 'Printers' -NotePropertyValue $printers
            }

            return $sysInfo
        }
        catch {
            return $null
        }
    }

    Write-Host "Starting system information retrieval..."
    $jobs = @()

    # Initialize progress bar
    $progressParams = @{
        Activity = "Retrieving System Information"
        Status = "Processing hosts..."
        PercentComplete = 0
    }
    Write-Progress @progressParams

    foreach ($computerName in $hosts) {
        $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $computerName, $Timeout, $CheckSunquest, $CheckPrinters
        $currentHost++
        
        # Update progress bar
        $progressParams.PercentComplete = ($currentHost / $totalHosts * 100)
        $progressParams.Status = "Processing host $currentHost of $totalHosts"
        Write-Progress @progressParams
    }

    # Update progress bar for job completion phase
    $progressParams.Status = "Waiting for jobs to complete..."
    Write-Progress @progressParams

    $results = $jobs | Wait-Job -Timeout $Timeout | Receive-Job
    Remove-Job -Job $jobs -Force

    # Complete the progress bar
    Write-Progress -Activity "Retrieving System Information" -Completed

    $results | Where-Object { $_ -ne $null } | ForEach-Object {
        $output = @"
Host: $($_.Hostname)
OS Name: $($_.OSName)
System Model: $($_.SystemModel)
Total Physical Memory: $($_.TotalMemory) GB
"@

        if ($CheckSunquest) {
            $output += "`nSunquest Applications:`n"
            if ($_.SunquestApps) {
                foreach ($app in $_.SunquestApps) {
                    $output += "- $($app.Name)`n"
                }
            } else {
                $output += "No Sunquest Lab applications found`n"
            }
        }
        
        if ($CheckPrinters) {
            $output += "`nPrinters:`n"
            if ($_.Printers -and $_.Printers.Count -gt 0) {
                foreach ($printer in $_.Printers) {
                    $output += "- Name: $($printer.Name)`n"
                    if ($printer.ServerName) { $output += "  Server: $($printer.ServerName)`n" }
                    if ($printer.ShareName) { $output += "  Share: $($printer.ShareName)`n" }
                }
            } else {
                $output += "No printers found`n"
            }
        }

        Add-Content -Path "output.txt" -Value $output
        Add-Content -Path "output.txt" -Value ""
    }

    Write-Host "System information retrieval completed."
    Write-Host "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

# Initialize variables
$CheckSunquest = $false
$CheckPrinters = $false

# Main menu loop
do {
    Show-Menu
    $choice = Read-Host "Enter your choice (1-7)"
    
    switch ($choice) {
        "1" {
            $newFile = Read-Host "Enter new input file path"
            if ($newFile) { $InputFile = $newFile }
        }
        "2" {
            $newTimeout = Read-Host "Enter new timeout (seconds)"
            if ($newTimeout -match '^\d+$') { $Timeout = [int]$newTimeout }
        }
        "3" {
            $CheckSunquest = -not $CheckSunquest
            Write-Host "Sunquest checking has been $($CheckSunquest ? 'enabled' : 'disabled')"
            Start-Sleep -Seconds 1
        }
        "4" {
            $CheckPrinters = -not $CheckPrinters
            Write-Host "Printer checking has been $($CheckPrinters ? 'enabled' : 'disabled')"
            Start-Sleep -Seconds 1
        }
        "5" {
            Start-SystemScan
        }
        "6" {
            $hostname = Read-Host "Enter hostname to check"
            if ($hostname) {
                Get-SingleHostInfo -computerName $hostname
            }
        }
        "7" {
            Write-Host "Exiting..."
            return
        }
        default {
            Write-Host "Invalid choice. Please try again."
            Start-Sleep -Seconds 1
        }
    }
} while ($true)
