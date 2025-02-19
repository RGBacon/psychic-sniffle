@echo off
setlocal enabledelayedexpansion

:: Check for input.txt and exit if not found
if not exist input.txt (
    echo Error: input.txt file not found. Please create a file with hostnames.
    pause
    exit /b 1
)

:: Create or clear results.txt (more efficient way)
> results.txt (echo.)

:: Build PowerShell script outside the loop for efficiency
set "psCommand=^
\$ErrorActionPreference = 'Stop'; ^
try { ^
    \$computers = Get-Content -Path 'input.txt'; ^
    foreach (\$computer in \$computers) { ^
        \$apps = Get-CimInstance -ClassName Win32_Product -ComputerName \$computer -Filter ""Name LIKE 'Sunquest Lab%%'""; ^
        if (\$apps) { ^
            foreach (\$app in \$apps) { ^
                Write-Output ""Found Sunquest Lab application on \$computer: \$($app.Name)"" ^
            } ^
        } else { ^
            Write-Output ""No Sunquest Lab application found on \$computer"" ^
        } ^
    } ^
} catch { ^
    Write-Output ""Error connecting to \$computer"" ^
}"

:: Run the PowerShell script and capture the output directly
powershell -NoProfile -ExecutionPolicy Bypass -Command "%psCommand%" >> results.txt

:: Output to console from results.txt
type results.txt

echo Process completed. Results saved in results.txt
endlocal
pause
