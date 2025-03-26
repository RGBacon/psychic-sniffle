@echo off
setlocal enabledelayedexpansion

:: Check if baseline and target files exist
if not exist baseline.txt (
    echo Error: baseline.txt file not found. 
    pause
    exit /b 1
)

if not exist input.txt (
    echo Error: input.txt file not found. 
    pause
    exit /b 1
)

:: Create or clear results file
if exist unique_apps.txt del unique_apps.txt

:: Loop through each hostname in input.txt
for /f "delims=" %%A in (input.txt) do (
    echo Checking applications on host: %%A

    :: Run remote WMI query to get unique applications
    powershell -Command "try { $baseline = Get-Content baseline.txt; $installedApps = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_Product -ComputerName '%%A' -ErrorAction Stop | Select-Object -ExpandProperty Name; $uniqueApps = $installedApps | Where-Object { $baseline -notcontains $_ -and $_ -notmatch '^Microsoft ' -and $_ -notmatch '^McAfee ' -and $_ -ne 'Google Update Helper' -and $_ -ne '64 Bit HP CIO Components Installer' -and $_ -ne 'Trellix Data Exchange Layer for MA' -and $_ -ne 'Google Chrome' -and $_ -ne 'Teams Machine-Wide Installer' }; if ($uniqueApps) { $uniqueApps | ForEach-Object { Write-Output $_ } } else { Write-Output 'NoUnique' } } catch { Write-Output 'Error' }" > temp_unique.txt

    :: Process the results
    for /f "delims=" %%B in (temp_unique.txt) do (
        if "%%B"=="Error" (
            echo Error connecting to %%A
        ) else if "%%B"=="NoUnique" (
            echo No unique applications found on %%A
        ) else (
            echo Unique application on %%A: %%B >> unique_apps.txt
            echo Unique application on %%A: %%B
        )
    )

    :: Clean up temporary file
    del temp_unique.txt
)

echo Process completed. 
echo Unique applications saved in unique_apps.txt
endlocal
pause