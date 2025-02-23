param (
    [string]$InputFile = "hosts.txt",
    [int]$Timeout = 30,
    [string]$LogFile = "system_check_log.txt"
)

function Write-SystemLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $using:LogFile -Value "[$timestamp] $Message"
    Write-Host $Message
}

if (-not (Test-Path $InputFile)) {
    Write-SystemLog "Error: Input file $InputFile not found."
    exit 1
}

Clear-Content -Path "output.txt" -ErrorAction SilentlyContinue
Clear-Content -Path $LogFile -ErrorAction SilentlyContinue

$hosts = Get-Content $InputFile | Where-Object { $_ -ne "" }
$totalHosts = $hosts.Count
$currentHost = 0

$scriptBlock = {
    param($computerName, $timeout)
    
    try {
        $result = Get-WmiObject -ComputerName $computerName -Class Win32_OperatingSystem -ErrorAction Stop | 
        Select-Object @{
            Name='Hostname'; Expression={$computerName}
        }, 
        @{
            Name='OSName'; Expression={$_.Caption}
        },
        @{
            Name='TotalMemory'; Expression={[math]::Round($_.TotalVisibleMemorySize / 1MB, 2)}
        }
        return $result
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
    $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $computerName, $Timeout
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
Total Physical Memory: $($_.TotalMemory) GB
"@
    Add-Content -Path "output.txt" -Value $output
    Add-Content -Path "output.txt" -Value ""
}

Write-Host "System information retrieval completed."
