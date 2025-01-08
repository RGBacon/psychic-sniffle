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

# Define the programs (installers and batch files) with their respective silent installation arguments or empty args for batch files
$programs = @(
    @{ Name = "Autologon Conversion"; Path = Join-Path $PSScriptRoot "apps\AutologonConversionv4.exe"; Args = "/S" },
    @{ Name = "Remove Autologon";     Path = Join-Path $PSScriptRoot "apps\NoAutoLogon.bat";       Args = "/s" },
    @{ Name = "Visual Studio Code";   Path = Join-Path $PSScriptRoot "apps\VSCode_installer.exe";  Args = "/silent" },
    @{ Name = "Custom Batch File";    Path = Join-Path $PSScriptRoot "apps\custom_script.bat";     Args = "" }
)

# Function to run the program (either EXE or BAT)
function Run-Program {
    param (
        [string]$programName,
        [string]$programPath,
        [string]$arguments
    )

    Write-Host "Running $programName..."

    try {
        Start-Process -FilePath $programPath -ArgumentList $arguments -PassThru -Wait

        # Show message on success
        [System.Windows.Forms.MessageBox]::Show("$programName completed successfully.", "Completion", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } catch {
        # Show error message if something goes wrong
        [System.Windows.Forms.MessageBox]::Show("Error running $programName. Please check the file path and try again.`n$_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Function to trigger system reboot with user confirmation
function Reboot-System {
    $rebootConfirmation = [System.Windows.Forms.MessageBox]::Show("Do you want to reboot the system?", "Reboot", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($rebootConfirmation -eq [System.Windows.Forms.DialogResult]::Yes) {
        Write-Host "Rebooting the system..."
        Shutdown.exe /r /t 0
    }
}

# Function to get installed applications and save to CSV
function Get-InstalledApplications {
    param (
        [string]$hostname,
        [string]$csvPath
    )

    # Check if the hostname is already in the CSV file
    try {
        $installedApps = Get-WmiObject -Namespace "root\cimv2" -Class Win32_Product -ComputerName $hostname | Select-Object @{Name="Hostname";Expression={$hostname}}, Name, Version

        if (-not $installedApps) {
            [System.Windows.Forms.MessageBox]::Show("No applications found on $hostname.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            return
        }

        # Save to CSV file
        if (Test-Path -Path $csvPath) {
            $installedApps | Export-Csv -Path $csvPath -NoTypeInformation -Append
        } else {
            $installedApps | Export-Csv -Path $csvPath -NoTypeInformation
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error retrieving applications from $hostname. Please check the hostname and try again.`n$_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Function to create and show the main form
function Show-Form {
    # Create the main form (window) for the GUI
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Program Installer"
    $form.Size = New-Object System.Drawing.Size(400, 650)
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.BackColor = [System.Drawing.Color]::White

    # Add a title label to the form
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "Select Programs to Install"
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $titleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $titleLabel.AutoSize = $true
    $form.Controls.Add($titleLabel)

    # Add a hostname label to the form
    $hostnameLabel = New-Object System.Windows.Forms.Label
    $hostnameLabel.Text = "Hostname:"
    $hostnameLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $hostnameLabel.Location = New-Object System.Drawing.Point(20, 70) # Positioned above the textbox
    $hostnameLabel.AutoSize = $true
    $form.Controls.Add($hostnameLabel)

    # Add a hostname text box to the form
    $hostnameTextBox = New-Object System.Windows.Forms.TextBox
    $hostnameTextBox.Size = New-Object System.Drawing.Size(250, 25)
    $hostnameTextBox.Location = New-Object System.Drawing.Point(20, 100) # Positioned below the label with some spacing
    $form.Controls.Add($hostnameTextBox)

    # Add an "Enter" button next to the text box
    $enterButton = New-Object System.Windows.Forms.Button
    $enterButton.Text = "Enter"
    $enterButton.Size = New-Object System.Drawing.Size(75, 25)
    $enterButton.Location = New-Object System.Drawing.Point(280, 100) # Positioned next to the textbox

    # Define the Enter button's click event
    $enterButton.Add_Click({
        $hostnameVariable = $hostnameTextBox.Text.Trim()
        if (-not [string]::IsNullOrWhiteSpace($hostnameVariable)) {
            $csvFilePath = Join-Path -Path $PSScriptRoot -ChildPath "installed_apps.csv"
            Get-InstalledApplications -hostname $hostnameVariable -csvPath $csvFilePath
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please enter a valid hostname.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        }
    })

    $form.Controls.Add($enterButton)

    # Add checkboxes for each program to the form
    $checkboxes = @()
    $yPosition = 150 # Start the first checkbox below the text box and button

    foreach ($program in $programs) {
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Text = "Run $($program.Name)"
        $checkbox.Location = New-Object System.Drawing.Point(20, $yPosition)
        $checkbox.Size = New-Object System.Drawing.Size(360, 25)
        $checkbox.Font = New-Object System.Drawing.Font("Segoe UI", 10)

        $checkboxes += $checkbox
        $form.Controls.Add($checkbox)

        $yPosition += 40 # Update the vertical position for the next checkbox
    }

    # Create a button to run the selected programs and add it to the form
    $runButton = New-Object System.Windows.Forms.Button
    $runButton.Text = "Run Selected Programs"
    $runButton.Size = New-Object System.Drawing.Size(360, 50)
    $runButton.Location = New-Object System.Drawing.Point(20, $yPosition)
    $runButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)

    # Define the Run Selected Programs button's click event
    $runButton.Add_Click({
        foreach ($index in 0..($checkboxes.Count - 1)) {
            if ($checkboxes[$index].Checked) {
                $program = $programs[$index]
                Run-Program -programName $program.Name -programPath $program.Path -arguments $program.Args
            }
        }

        Reboot-System
    })

    $form.Controls.Add($runButton)

    # Show the form
    [void]$form.ShowDialog()
}

# Main script execution
Show-Form
