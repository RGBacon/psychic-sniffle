Add-Type -AssemblyName System.Windows.Forms

# Create the main form
$form = New-Object system.Windows.Forms.Form
$form.Text = "Message Sender"
$form.Width = 400
$form.Height = 200
$form.StartPosition = 'CenterScreen'

# Add a label for hostname input
$labelHostname = New-Object system.Windows.Forms.Label
$labelHostname.Text = "Hostname:"
$labelHostname.AutoSize = $true
$labelHostname.Location = New-Object System.Drawing.Point(10, 15)
$form.Controls.Add($labelHostname)

# Add textbox for hostname input
$textboxHostname = New-Object system.Windows.Forms.TextBox
$textboxHostname.Width = 260
$textboxHostname.Location = New-Object System.Drawing.Point(80, 15)
$form.Controls.Add($textboxHostname)

# Add a label for message input
$labelMessage = New-Object system.Windows.Forms.Label
$labelMessage.Text = "Message:"
$labelMessage.AutoSize = $true
$labelMessage.Location = New-Object System.Drawing.Point(10, 45)
$form.Controls.Add($labelMessage)

# Add textbox for message input
$textboxMessage = New-Object system.Windows.Forms.TextBox
$textboxMessage.Width = 260
$textboxMessage.Height = 70
$textboxMessage.Multiline = $true
$textboxMessage.Location = New-Object System.Drawing.Point(80, 45)
$form.Controls.Add($textboxMessage)

# Add a send button
$buttonSend = New-Object system.Windows.Forms.Button
$buttonSend.Text = "Send"
$buttonSend.Width = 60
$buttonSend.Height = 30
$buttonSend.Location = New-Object System.Drawing.Point(150, 125)
$form.Controls.Add($buttonSend)

# Define the action when the send button is clicked
$buttonSend.Add_Click({
    $hostname = $textboxHostname.Text
    $message = $textboxMessage.Text

    if ([string]::IsNullOrWhiteSpace($hostname) -or [string]::IsNullOrWhiteSpace($message)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter both hostname and message.", "Input Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    } else {
        # Run the msg command
        try {
            & cmd.exe /c "msg * /server:$hostname /TIME:9999999999 `"$message`""
            [System.Windows.Forms.MessageBox]::Show("Message sent successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("An error occurred while sending the message: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

# Show the form
$form.ShowDialog()
