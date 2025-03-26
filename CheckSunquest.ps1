# CheckSunquest.ps1
$ErrorActionPreference = 'Stop'

Write-Host "Sunquest Lab Application Check Tool"
Write-Host "=================================="
Write-Host ""

# Check if input.txt exists
if (-not (Test-Path -Path "input.txt")) {
    Write-Host "Error: input.txt file not found." -ForegroundColor Red
    Write-Host "Please create this file with one hostname per line."
    Read-Host "Press Enter to exit"
    exit 1
}

# Count number of hosts to check
$hostnames = Get-Content 'input.txt'
$total = $hostnames.Count
Write-Host "Found $total hosts to check in input.txt"

# Create or clear results file
"Results of Sunquest Lab application check:" | Out-File -FilePath results.txt
"Generated on $(Get-Date)" | Out-File -FilePath results.txt -Append
"==========================================" | Out-File -FilePath results.txt -Append
"" | Out-File -FilePath results.txt -Append

# Process each hostname
Write-Host ""
Write-Host "Starting scan of $total hosts..."
Write-Host "This may take some time depending on network conditions."
Write-Host ""

$results = @()
$count = 0

foreach ($hostname in $hostnames) {
    $count++
    Write-Host "Processing [$count/$total]: $hostname"
    try {
        $apps = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName $hostname -ErrorAction Stop |
               Where-Object { $_.Name -like 'Sunquest Lab*' } |
               Select-Object -ExpandProperty Name
        if ($apps) {
            foreach ($app in $apps) {
                $results += [PSCustomObject]@{ Hostname = $hostname; Application = $app }
                "Found Sunquest Lab application on $hostname`: $app" | Out-File -FilePath results.txt -Append
            }
        } else {
            $results += [PSCustomObject]@{ Hostname = $hostname; Application = 'NoMatch' }
            "No Sunquest Lab application found on $hostname" | Out-File -FilePath results.txt -Append
        }
    } catch {
        $results += [PSCustomObject]@{ Hostname = $hostname; Application = 'Error' }
        "Error connecting to $hostname`: $_" | Out-File -FilePath results.txt -Append
        Write-Host "ERROR: $_" -ForegroundColor Red
    }
}

# Display summary
Write-Host "Summary of results:" -ForegroundColor Green
$successCount = ($results | Where-Object { $_.Application -ne 'Error' -and $_.Application -ne 'NoMatch' }).Count
$noMatchCount = ($results | Where-Object { $_.Application -eq 'NoMatch' }).Count
$errorCount = ($results | Where-Object { $_.Application -eq 'Error' }).Count
Write-Host "- Hosts with Sunquest Lab applications: $successCount" -ForegroundColor Green
Write-Host "- Hosts without Sunquest Lab applications: $noMatchCount" -ForegroundColor Yellow
Write-Host "- Hosts with connection errors: $errorCount" -ForegroundColor Red
Write-Host "Detailed results saved to results.txt"

Write-Host ""
Write-Host "Process completed. Results saved in results.txt"
Read-Host "Press Enter to exit"
