@echo off
setlocal enabledelayedexpansion

:: Path to the text file containing the list of hostnames
set "input_file=hosts.txt"

:: Path to the output file
set "output_file=output.txt"

:: Clear the output file before appending results
> "%output_file%" echo.

:: Read each line in the input file
for /f "delims=" %%i in (%input_file%) do (
    set "HOST=%%i"
    echo Running systeminfo for !HOST!

    :: Run systeminfo and filter for OS Name and Total Physical Memory
    systeminfo /S "!HOST!" 2>nul | findstr /C:"OS Name" /C:"Total Physical Memory" >nul && (
        echo Host: !HOST! >> "%output_file%"
        systeminfo /S "!HOST!" 2>nul | findstr /C:"OS Name" /C:"Total Physical Memory" >> "%output_file%"
    ) || (
        echo Failed to retrieve information for !HOST! >> "%output_file%"
    )
	:: Append an empty line after each host's info
    echo. >> "%output_file%"   
)

endlocal
pause
