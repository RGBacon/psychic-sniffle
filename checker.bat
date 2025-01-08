@echo off
setlocal enabledelayedexpansion

:: Path to the text file containing the list of hostnames
set input_file=hosts.txt

:: Path to the output file
set output_file=output.txt

:: Clear the output file before appending results
echo. > %output_file%

:: Read each line in the input file
for /f "delims=" %%i in (%input_file%) do (
    set HOST=%%i
    echo Running systeminfo for !HOST!

    :: Run systeminfo hostname and filter for OS Name and Total Physical Memory
    systeminfo /S !HOST! | findstr /C:"OS Name" /C:"Total Physical Memory" > temp.txt

    :: Check if temp.txt contains results
    for /f "delims=" %%a in (temp.txt) do (
        echo Host: !HOST! >> %output_file%
        echo %%a >> %output_file%
    )

    :: Clean up temp file
    del temp.txt

    echo. >> %output_file%
)

endlocal
pause