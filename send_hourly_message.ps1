# Check if running with admin privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Relaunch the script with admin privileges
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

Write-Host "Script is running with administrator privileges"

# Message to send
$message = "IMPORTANT: This device has been identified for replacement. Please contact IT Support via Teams or Outlook to schedule your device replacement. This message will repeat hourly until action is taken."

# Function to send messages to hostnames
function Send-MessagesToHosts {
    # Read hostnames from file
    try {
        $hostnames = Get-Content -Path "hostnames.txt" -ErrorAction Stop
        Write-Host "Successfully loaded hostnames from hostnames.txt"
    } catch {
        Write-Host "Error loading hostnames.txt: $_"
        return
    }

    # Validate the file had content
    if ($null -eq $hostnames -or $hostnames.Count -eq 0) {
        Write-Host "No hostnames found in hostnames.txt"
        return
    }

    foreach ($hostname in $hostnames) {
        try {
            # Using direct msg command with specified server and timeout
            $msgCommand = "msg * /SERVER:$hostname `"$message`" /TIME:600"
            Invoke-Expression $msgCommand
            
            Write-Host "Message sent successfully to $hostname at $(Get-Date)"
        }
        catch {
            Write-Host "Failed to send message to $hostname at $(Get-Date): $_"
        }
    }
}

# Main loop
Write-Host "Starting hourly message sending service..."
Write-Host "Press Ctrl+C to stop the script"

while ($true) {
    # Send messages
    Send-MessagesToHosts
    
    # Calculate time until next hour
    $now = Get-Date
    $nextHour = $now.AddHours(1).Date.AddHours($now.Hour + 1)
    $waitTime = ($nextHour - $now).TotalSeconds
    
    Write-Host "Waiting until next hour ($nextHour)..."
    Start-Sleep -Seconds $waitTime
} 