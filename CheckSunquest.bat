@echo off
setlocal enabledelayedexpansion

:: Check if input.txt exists
if not exist input.txt (
    echo Error: input.txt file not found. Please create a file with hostnames.
    pause
    exit /b 1
)

:: Create or clear results file
if exist results.txt del results.txt

:: Loop through each hostname in input.txt
for /f "delims=" %%A in (input.txt) do (
    echo Checking installed applications on host: %%A

    :: Run remote WMI query to get installed applications
    powershell -Command "try { $apps = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName '%%A' -ErrorAction Stop | Where-Object { $_.Name -like 'Sunquest Lab*' } | Select-Object -ExpandProperty Name; if ($apps) { $apps | ForEach-Object { Write-Output $_ } } else { Write-Output 'NoMatch' } } catch { Write-Output 'Error' }" > temp_result.txt

    :: Process the results
    for /f "delims=" %%B in (temp_result.txt) do (
        if "%%B"=="Error" (
            echo Error connecting to %%A >> results.txt
            echo Error: Could not connect to host %%A.
        ) else if "%%B"=="NoMatch" (
            echo No Sunquest Lab application found on %%A >> results.txt
            echo No Sunquest Lab application found on %%A.
        ) else (
            echo Found Sunquest Lab application on %%A: %%B >> results.txt
            echo Hostname: %%A has Sunquest Lab application: %%B.
        )
    )

    :: Clean up temporary file
    del temp_result.txt
)

echo Process completed. Results saved in results.txt
endlocal
pause