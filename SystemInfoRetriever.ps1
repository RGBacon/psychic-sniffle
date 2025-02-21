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

$scriptBlock = {
    param($computerName, $timeout)

    try {
        $result = Get-WmiObject -Namespace root\cimv2 -ComputerName $computerName -Class Win32_OperatingSystem -Property Hostname, Caption, TotalVisibleMemorySize -ErrorAction Stop
        return [PSCustomObject]@{
            Hostname = $computerName
            OSName = $result.Caption
            TotalMemory = [math]::Round($result.TotalVisibleMemorySize / 1MB, 2)
        }
    } catch {
        return $null
    }
}

$jobs = @()
$completed = 0

foreach ($computerName in $hosts) {
    $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList $computerName, $Timeout
}

Write-Progress -Activity "Processing Hosts" -Status "Starting..." -PercentComplete 0

$results = foreach ($job in $jobs) {
    Wait-Job $job -Timeout $Timeout
    $completed++
    Write-Progress -Activity "Processing Hosts" -Status "Processing..." -PercentComplete ([int]($completed / $jobs.Count * 100))
    Receive-Job $job
}

Remove-Job -Job $jobs -Force

$results | Where-Object { $_ -ne $null } | ForEach-Object {
    $output = @"
Host: $($_.Hostname)
OS Name: $($_.OSName)
Total Physical Memory: $($_.TotalMemory) GB
"@
} | Out-File "output.txt" -Append

Write-Host "System information retrieval completed."
