# Prompts for a single line of text (XAML dialog). Returns the entered text, or "" when cancelled.
function Show-InputBox {
    param([string]$Prompt, [string]$Title = "Input", [string]$DefaultText = "")

    try {
        $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Input" Width="440" SizeToContent="Height" ResizeMode="NoResize" ShowInTaskbar="False"
        WindowStartupLocation="CenterScreen" Background="@FORM@" Foreground="@TEXT@" FontFamily="Segoe UI">
  <Window.Resources><!--APP_RESOURCES--></Window.Resources>
  <StackPanel Margin="22,18,22,18">
    <TextBlock x:Name="PromptText" TextWrapping="Wrap" Margin="0,0,0,10"/>
    <TextBox x:Name="InputBox" Height="32" VerticalContentAlignment="Center"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,18,0,0">
      <Button x:Name="OkButton" Style="{StaticResource PrimaryButton}" IsDefault="True" Width="90" Content="OK"/>
      <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
    </StackPanel>
  </StackPanel>
</Window>
'@
        $ui = New-WpfWindowFromXaml -Xaml $xaml -ControlNames 'PromptText', 'InputBox', 'OkButton', 'CancelButton'
        $window = $ui.Window
        $window.Title = $Title
        $ui.Controls['PromptText'].Text = $Prompt
        $ui.Controls['InputBox'].Text = $DefaultText
        $ui.Controls['OkButton'].Add_Click({ $window.DialogResult = $true })
        $window.Add_ContentRendered({ $ui.Controls['InputBox'].Focus() | Out-Null; $ui.Controls['InputBox'].SelectAll() })

        $result = ""
        if ((Show-WpfDialog -Window $window) -eq $true) { $result = $ui.Controls['InputBox'].Text }
        return $result
    } catch {
        Write-Log "WPF input dialog failed, using WinForms fallback: $($_.Exception.Message)" -Level Info
        return Show-InputBoxFallback -Prompt $Prompt -Title $Title -DefaultText $DefaultText
    }
}

# WinForms fallback used only if the WPF dialog cannot be created.
function Show-InputBoxFallback {
    param([string]$Prompt, [string]$Title = "Input", [string]$DefaultText = "")
    $form = New-Object System.Windows.Forms.Form -Property @{ Text=$Title; Size=New-Object System.Drawing.Size(400,160); StartPosition="CenterParent"; FormBorderStyle="FixedDialog"; MaximizeBox=$false; MinimizeBox=$false; BackColor=$script:Theme.FormBackground }
    $lbl = New-Label -Text $Prompt -Property @{ Location=New-Object System.Drawing.Point(15,15); AutoSize=$true; ForeColor=$script:Theme.TextColor }
    $txt = New-TextBox -Property @{ Location=New-Object System.Drawing.Point(15,40); Width=350; Text=$DefaultText }
    $btnOk = New-Button -Text "OK" -Style 'Primary' -Property @{ Location=New-Object System.Drawing.Point(210,80); Width=75; DialogResult="OK" }
    $btnCancel = New-Button -Text "Cancel" -Property @{ Location=New-Object System.Drawing.Point(290,80); Width=75; DialogResult="Cancel" }
    $form.Controls.AddRange(@($lbl, $txt, $btnOk, $btnCancel))
    $form.AcceptButton = $btnOk
    $form.CancelButton = $btnCancel
    $result = ""
    if ($form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $result = $txt.Text }
    $form.Dispose()
    return $result
}

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('Info', 'Debug', 'Warning', 'Error')][string]$Level = 'Debug' # Default to Debug for existing calls
    )
    if ($logFilePath -and -not (Test-Path -LiteralPath (Split-Path -Parent $logFilePath))) { Initialize-DataFolders }
    if ($script:settings.EnableLogs) {
        # Log Rotation: Check if file exceeds 5MB and rotate if necessary
        if (Test-Path $logFilePath) {
            try {
                if ((Get-Item $logFilePath).Length -gt 5MB) {
                    $timestamp = (Get-Date).ToString('yyyyMMddHHmmss')
                    $logName = [System.IO.Path]::GetFileName($logFilePath)
                    Rename-Item -Path $logFilePath -NewName "$logName.$timestamp.bak" -ErrorAction SilentlyContinue

                    # Cleanup old logs (keep last 5)
                    $logDir = [System.IO.Path]::GetDirectoryName($logFilePath)
                    Get-ChildItem -Path $logDir -Filter "$logName.*.bak" | Sort-Object CreationTime -Descending | Select-Object -Skip 5 | Remove-Item -Force -ErrorAction SilentlyContinue
                }
            } catch { }
        }
        # Only log if the level is 'Info' or if the configured level is 'Debug'
        if ($Level -eq 'Info' -or $script:settings.LogLevel -eq 'Debug') {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            if (-not (Test-Path $logFilePath)) {
                Add-Content -Path $logFilePath -Value "Timestamp,Level,Message"
            }
            $safeMessage = '"' + $Message.Replace('"', '""') + '"'
            $logEntry = "$timestamp,$Level,$safeMessage"
            Add-Content -Path $logFilePath -Value $logEntry
        }
    }
}

# Factory function to create a System.Windows.Forms.Label control.
function Test-IsHtmlBody {
    param([string]$Body)
    if ([string]::IsNullOrWhiteSpace($Body)) { return $false }
    return ($Body -match '<\s*(html|body|div|span|p|br|table|tr|td|a|b|i|strong|em|ul|ol|li)\b')
}

# Factory function to create a standardized TableLayoutPanel for authentication details.
function Protect-String {
    param([string]$String)
    if ([string]::IsNullOrEmpty($String)) { return $String }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Convert]::ToBase64String($encrypted)
    } catch { return $String }
}

function Unprotect-String {
    param([string]$String)
    if ([string]::IsNullOrEmpty($String)) { return $String }
    try {
        $bytes = [Convert]::FromBase64String($String)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    } catch { return $String } # Return original if decryption fails (e.g. plain text)
}

# Sends an email using SMTP XOAUTH2 (required for Gmail/Outlook Modern Auth).

function Set-AppTheme {
    param([System.Windows.Forms.Control]$Form)
    if (-not $Form) { return }
    
    $themeName = if ($script:settings.AppTheme) { $script:settings.AppTheme } else { "Light" }
    $script:Theme = $script:Themes[$themeName]
    
    if (-not $script:Theme) { return }

    # Function to apply theme recursively
    function Set-ControlTheme {
        param([System.Windows.Forms.Control]$Control)
        if (-not $Control) { return }
        
        $type = $Control.GetType().Name
        if ($type -match "Button") {
            $buttonStyleName = Get-ButtonStyleName -Control $Control
            if ($buttonStyleName -eq "Primary") {
                $Control.BackColor = $script:Theme.PrimaryButton
                $Control.ForeColor = $script:Theme.PrimaryButtonText
            } elseif ($buttonStyleName -eq "Danger") {
                $Control.BackColor = $script:Theme.DangerButton
                $Control.ForeColor = $script:Theme.DangerButtonText
            } else {
                $Control.BackColor = $script:Theme.SecondaryButton
                $Control.ForeColor = $script:Theme.SecondaryButtonText
            }
        } elseif ($type -match "TextBox|RichTextBox|ComboBox|ListBox|TreeView") {
            $Control.BackColor = $script:Theme.TextBoxBackground
            $Control.ForeColor = $script:Theme.TextColor
        } elseif ($type -match "DataGridView") {
            $Control.BackgroundColor = $script:Theme.GridBackground
            $Control.DefaultCellStyle.BackColor = $script:Theme.TextBoxBackground
            $Control.DefaultCellStyle.ForeColor = $script:Theme.TextColor
            $Control.ColumnHeadersDefaultCellStyle.BackColor = $script:Theme.SecondaryButton
            $Control.ColumnHeadersDefaultCellStyle.ForeColor = $script:Theme.TextColor
        } else {
            # Forms, GroupBoxes, Panels, Labels
            if ($type -eq "Form") { 
                $Control.BackColor = $script:Theme.FormBackground 
            } elseif ($type -match "GroupBox") { 
                $Control.BackColor = $script:Theme.GroupBackground 
            }
            if ($type -notmatch "TabControl") {
                $Control.ForeColor = $script:Theme.TextColor
            }
        }

        # Tab pages need their own back color explicitly set in some OS versions
        if ($type -eq "TabPage") {
            $Control.BackColor = $script:Theme.FormBackground
        }

        foreach ($child in $Control.Controls) {
            Set-ControlTheme -Control $child
        }
    }

    Set-ControlTheme -Control $Form
    Set-ThemedToolStripRenderer
}

# ConvertFrom-Json -AsHashtable only exists in PowerShell 6+. These helpers give the same result on Windows PowerShell 5.1.
function ConvertTo-HashtableDeep {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $table = @{}
        foreach ($property in $InputObject.PSObject.Properties) { $table[$property.Name] = ConvertTo-HashtableDeep -InputObject $property.Value }
        return $table
    }
    if ($InputObject -is [System.Collections.IList] -and $InputObject -isnot [string]) {
        return , @($InputObject | ForEach-Object { ConvertTo-HashtableDeep -InputObject $_ })
    }
    return $InputObject
}

function ConvertFrom-JsonToHashtable {
    param([string]$Json)
    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    if ($PSVersionTable.PSVersion.Major -ge 6) { return ($Json | ConvertFrom-Json -AsHashtable) }
    return (ConvertTo-HashtableDeep -InputObject ($Json | ConvertFrom-Json))
}

# Windows PowerShell 5.1 on older .NET Framework builds may still default to TLS 1.0; make sure TLS 1.2 is allowed.
function Enable-ModernTls {
    try {
        $current = [System.Net.ServicePointManager]::SecurityProtocol
        if ([int]$current -ne 0 -and -not ($current -band [System.Net.SecurityProtocolType]::Tls12)) {
            [System.Net.ServicePointManager]::SecurityProtocol = $current -bor [System.Net.SecurityProtocolType]::Tls12
        }
    } catch { }
}
