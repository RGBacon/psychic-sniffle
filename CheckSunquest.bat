@echo off
setlocal enabledelayedexpansion

:: Check if input.txt exists
if not exist input.txt (
    echo Error: input.txt file not found. Please create a file with hostnames.
    pause
    exit /b 1
)

:: Create or clear results file
echo Results of Sunquest Lab application check: > results.txt

:: Execute PowerShell command - all on one line with proper escaping
powershell -Command "$hostnames = Get-Content 'input.txt'; $results = @(); foreach ($hostname in $hostnames) { try { Write-Output \"Checking installed applications on host: $hostname\"; $apps = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName $hostname -ErrorAction Stop | Where-Object { $_.Name -like 'Sunquest Lab*' } | Select-Object -ExpandProperty Name; if ($apps) { foreach ($app in $apps) { $results += [PSCustomObject]@{ Hostname = $hostname; Application = $app } } } else { $results += [PSCustomObject]@{ Hostname = $hostname; Application = 'NoMatch' } } } catch { $results += [PSCustomObject]@{ Hostname = $hostname; Application = 'Error' } } }; $results | ForEach-Object { if ($_.Application -eq 'Error') { \"Error connecting to $($_.Hostname)\" } elseif ($_.Application -eq 'NoMatch') { \"No Sunquest Lab application found on $($_.Hostname)\" } else { \"Found Sunquest Lab application on $($_.Hostname): $($_.Application)\" } }" >> results.txt

echo Process completed. Results saved in results.txt
pause
endlocal
