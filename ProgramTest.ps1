# Function to check if the script is running as administrator
function Test-IsElevated {
    return ([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole] "Administrator")
}

# Relaunch the script as Administrator if it's not running as Administrator
if (-not (Test-IsElevated)) {
    $scriptPath = $MyInvocation.MyCommand.Definition
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    exit
}

# Add necessary .NET assembly for GUI
Add-Type -AssemblyName System.Windows.Forms

# Set up logging
$logPath = Join-Path $PSScriptRoot "installation_log.txt"
function Write-Log {
    param (
        [string]$message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $logPath -Append
    Write-Host $message
}

Write-Log "Script started"

# Function to get silent install arguments based on file extension
function Get-SilentArgs {
    param (
        [string]$filePath
    )
    
    $extension = [System.IO.Path]::GetExtension($filePath).ToLower()
    
    switch ($extension) {
        ".exe" { 
            # Check if it's an InnoSetup, NSIS, or other common installer
            $fileName = [System.IO.Path]::GetFileName($filePath).ToLower()
            if ($fileName -match "setup|install|installer") {
                return "/SILENT /NORESTART"  # InnoSetup common parameter
            } else {
                return "/S"  # NSIS common parameter
            }
        }
        ".msi" { return "/qn /norestart" }  # Standard MSI silent
        ".msp" { return "/qn /norestart" }  # Standard MSP silent
        ".bat" { return "" }  # Batch files don't typically need args
        ".cmd" { return "" }  # CMD files don't typically need args
        default { return "" }
    }
}

# Function to discover programs in the apps directory
function Get-AvailablePrograms {
    Write-Log "Scanning for available programs..."
    
    $appsDir = Join-Path $PSScriptRoot "apps"
    $programs = @()
    
    # Check if apps directory exists
    if (-not (Test-Path -Path $appsDir -PathType Container)) {
        Write-Log "WARNING: Apps directory not found at: $appsDir"
        return $programs
    }
    
    # Check for a silent arguments configuration file
    $configPath = Join-Path $PSScriptRoot "silent_args.json"
    $customArgs = @{}
    
    if (Test-Path $configPath) {
        try {
            Write-Log "Loading custom silent arguments from: $configPath"
            $customArgs = Get-Content -Path $configPath -Raw | ConvertFrom-Json -AsHashtable
            Write-Log "Loaded custom arguments for $($customArgs.Count) programs"
        } catch {
            Write-Log "ERROR: Failed to load silent_args.json: $_"
        }
    } else {
        Write-Log "No custom silent arguments configuration found (silent_args.json)"
        # Create example silent_args.json file
        $exampleConfig = @{
            "example.exe" = "/S /v/qn"
            "setup.msi" = "/qn REBOOT=ReallySuppress"
        } | ConvertTo-Json
        $examplePath = Join-Path $PSScriptRoot "silent_args.json.example"
        $exampleConfig | Out-File -FilePath $examplePath -Force
        Write-Log "Created example silent_args.json.example file"
    }
    
    # Get all subdirectories in the apps directory
    $subDirs = Get-ChildItem -Path $appsDir -Directory
    
    # Add root directory to the list of directories to process
    $allDirs = @($appsDir) + $subDirs.FullName
    
    foreach ($dir in $allDirs) {
        # Get directory name for grouping (empty for root)
        $dirName = if ($dir -eq $appsDir) { "" } else { (Split-Path $dir -Leaf) }
        
        # Get all exe, msi, bat, cmd files in this directory (non-recursive)
        $installerFiles = Get-ChildItem -Path $dir -File -Include "*.exe", "*.msi", "*.bat", "*.cmd"
        
        foreach ($file in $installerFiles) {
            $fileName = $file.Name
            $displayName = $file.BaseName -replace "([a-z])([A-Z])", '$1 $2' # Add spaces between camel case
            
            # Prefix group name if from subdirectory
            if ($dirName) {
                $displayName = "$dirName - $displayName"
            }
            
            # Check if there are custom args for this file
            if ($customArgs.ContainsKey($fileName)) {
                $silentArgs = $customArgs[$fileName]
                Write-Log "Using custom arguments for $fileName: $silentArgs"
            } else {
                $silentArgs = Get-SilentArgs -filePath $file.FullName
            }
            
            $program = @{
                Name = $displayName
                Path = $file.FullName
                Args = $silentArgs
                Group = $dirName
            }
            
            $programs += $program
            Write-Log "Found program: $($displayName) at $($file.FullName) with args: $silentArgs"
        }
    }
    
    # Sort programs by group then by name
    $programs = $programs | Sort-Object -Property @{Expression="Group"; Descending=$false}, @{Expression="Name"; Descending=$false}
    
    Write-Log "Found $($programs.Count) programs in apps directory"
    return $programs
}

# Get available programs
$programs = Get-AvailablePrograms

# If no programs found, provide a warning
if ($programs.Count -eq 0) {
    $warningMessage = "No installable programs found in the apps directory.`n`nPlease make sure to place your installer files in the apps folder."
    [System.Windows.Forms.MessageBox]::Show($warningMessage, "No Programs Found", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    Write-Log "WARNING: No programs found in apps directory"
}

# Function to validate all program paths
function Test-ProgramPaths {
    Write-Log "Validating program paths..."
    $invalidPrograms = @()
    
    foreach ($program in $programs) {
        if (-not (Test-Path -Path $program.Path)) {
            Write-Log "WARNING: Program path not found: $($program.Path) for $($program.Name)"
            $invalidPrograms += $program.Name
        }
    }
    
    if ($invalidPrograms.Count -gt 0) {
        $warningMessage = "The following programs have invalid paths and may not work:`n`n"
        $warningMessage += $invalidPrograms -join "`n"
        $warningMessage += "`n`nDo you want to continue anyway?"
        
        Write-Log "Showing warning about invalid program paths"
        $result = [System.Windows.Forms.MessageBox]::Show($warningMessage, "Invalid Program Paths", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        
        if ($result -eq [System.Windows.Forms.DialogResult]::No) {
            Write-Log "User chose to exit due to invalid program paths"
            exit
        }
    } else {
        Write-Log "All program paths are valid"
    }
}

# Validate program paths before showing the form
Test-ProgramPaths

# Function to run the program (either EXE or BAT)
function Run-Program {
    param (
        [string]$programName,
        [string]$programPath,
        [string]$arguments
    )

    Write-Log "Attempting to run $programName..."

    if (-not (Test-Path -Path $programPath)) {
        $errorMsg = "Cannot find $programName at path: $programPath"
        Write-Log "ERROR: $errorMsg"
        [System.Windows.Forms.MessageBox]::Show($errorMsg, "File Not Found", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    try {
        Write-Log "Executing: $programPath $arguments"
        $process = Start-Process -FilePath $programPath -ArgumentList $arguments -PassThru -Wait
        Write-Log "$programName completed with exit code: $($process.ExitCode)"

        # Show message on success
        # [System.Windows.Forms.MessageBox]::Show("$programName completed successfully.", "Completion", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        # Show error message if something goes wrong
        $errorMsg = "Error running $programName. Error details: $_"
        Write-Log "ERROR: $errorMsg"
        [System.Windows.Forms.MessageBox]::Show("Error running $programName. Please check the file path and try again.`n$_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Function to trigger system reboot with user confirmation
function Reboot-System {
    Write-Log "Asking user about system reboot"
    $rebootConfirmation = [System.Windows.Forms.MessageBox]::Show("Do you want to reboot the system?", "Reboot", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($rebootConfirmation -eq [System.Windows.Forms.DialogResult]::Yes) {
        Write-Log "User confirmed reboot - initiating system restart"
        Shutdown.exe /r /t 0
    } else {
        Write-Log "User declined reboot request"
    }
}

# Function to create and show the main form
function Show-Form {
    Write-Log "Initializing application GUI"
    
    # Create the main form (window) for the GUI
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Program Installer"
    $form.Size = New-Object System.Drawing.Size(450, 700)
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.BackColor = [System.Drawing.Color]::White
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.AutoScroll = $true

    # Add a title label to the form
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "Select Programs to Install"
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $titleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $titleLabel.AutoSize = $true
    $form.Controls.Add($titleLabel)

    # Add a separator line
    $separator = New-Object System.Windows.Forms.Panel
    $separator.Location = New-Object System.Drawing.Point(20, 60)
    $separator.Size = New-Object System.Drawing.Size(410, 2)
    $separator.BackColor = [System.Drawing.Color]::LightGray
    $form.Controls.Add($separator)

    # Add a "Select All" checkbox
    $selectAllCheckbox = New-Object System.Windows.Forms.CheckBox
    $selectAllCheckbox.Text = "Select All Programs"
    $selectAllCheckbox.Location = New-Object System.Drawing.Point(20, 70)
    $selectAllCheckbox.Size = New-Object System.Drawing.Size(410, 25)
    $selectAllCheckbox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($selectAllCheckbox)

    # Add checkboxes for each program to the form
    $checkboxes = @()
    $yPosition = 100 # Start the first checkbox below the select all checkbox
    $currentGroup = ""
    
    # Sort programs by group for display
    foreach ($program in $programs) {
        # If we're starting a new group, add a header
        if ($program.Group -ne $currentGroup) {
            $currentGroup = $program.Group
            
            if ($currentGroup) {
                # Add some spacing
                $yPosition += 10
                
                # Add a group header
                $groupLabel = New-Object System.Windows.Forms.Label
                $groupLabel.Text = $currentGroup
                $groupLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
                $groupLabel.Location = New-Object System.Drawing.Point(20, $yPosition)
                $groupLabel.AutoSize = $true
                $form.Controls.Add($groupLabel)
                
                $yPosition += 25
                
                # Add a group separator line
                $groupSeparator = New-Object System.Windows.Forms.Panel
                $groupSeparator.Location = New-Object System.Drawing.Point(20, $yPosition)
                $groupSeparator.Size = New-Object System.Drawing.Size(410, 1)
                $groupSeparator.BackColor = [System.Drawing.Color]::LightGray
                $form.Controls.Add($groupSeparator)
                
                $yPosition += 5
            }
        }
        
        # Create the checkbox for this program
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $displayName = if ($program.Group) { $program.Name.Substring($program.Group.Length + 3) } else { $program.Name }
        $checkbox.Text = $displayName
        $checkbox.Location = New-Object System.Drawing.Point(30, $yPosition)
        $checkbox.Size = New-Object System.Drawing.Size(400, 25)
        $checkbox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $checkbox.Tag = $program  # Store the full program info in the Tag property
        
        $checkboxes += $checkbox
        $form.Controls.Add($checkbox)
        
        $yPosition += 30 # Update the vertical position for the next checkbox
    }

    # Handle the Select All checkbox
    $selectAllCheckbox.Add_Click({
        foreach ($checkbox in $checkboxes) {
            $checkbox.Checked = $selectAllCheckbox.Checked
        }
    })

    # Create progress bar (initially hidden)
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(20, $yPosition + 10)
    $progressBar.Size = New-Object System.Drawing.Size(410, 20)
    $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Blocks
    $progressBar.Visible = $false
    $form.Controls.Add($progressBar)
    
    $yPosition += 40

    # Create status label (initially hidden)
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Location = New-Object System.Drawing.Point(20, $yPosition)
    $statusLabel.Size = New-Object System.Drawing.Size(410, 20)
    $statusLabel.Text = "Ready"
    $statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $statusLabel.Visible = $false
    $form.Controls.Add($statusLabel)
    
    $yPosition += 30

    # Create a button to run the selected programs and add it to the form
    $runButton = New-Object System.Windows.Forms.Button
    $runButton.Text = "Run Selected Programs"
    $runButton.Size = New-Object System.Drawing.Size(410, 50)
    $runButton.Location = New-Object System.Drawing.Point(20, $yPosition)
    $runButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)

    # Define the Run Selected Programs button's click event
    $runButton.Add_Click({
        $selectedCount = ($checkboxes | Where-Object { $_.Checked }).Count
        
        if ($selectedCount -eq 0) {
            Write-Log "User attempted to run with no programs selected"
            [System.Windows.Forms.MessageBox]::Show("Please select at least one program to install.", "No Selection", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        Write-Log "Starting installation of $selectedCount programs"
        
        # Show progress bar and status
        $progressBar.Visible = $true
        $statusLabel.Visible = $true
        $progressBar.Maximum = $selectedCount
        $progressBar.Value = 0
        
        $currentProgress = 0
        
        foreach ($checkbox in $checkboxes) {
            if ($checkbox.Checked) {
                $program = $checkbox.Tag
                $statusLabel.Text = "Installing $($program.Name)..."
                $form.Refresh()
                
                Run-Program -programName $program.Name -programPath $program.Path -arguments $program.Args
                
                $currentProgress++
                $progressBar.Value = $currentProgress
                $form.Refresh()
            }
        }
        
        $statusLabel.Text = "Installation complete!"
        Write-Log "All selected programs have been installed"

        Reboot-System
    })

    $form.Controls.Add($runButton)

    # Adjust form height based on content
    $form.ClientSize = New-Object System.Drawing.Size(450, [Math]::Min($yPosition + 70, 700))

    # Show the form
    Write-Log "Displaying main application form"
    [void]$form.ShowDialog()
}

# Main script execution
Show-Form
