# Proxy configuration dialog (XAML; WinForms fallback if WPF is unavailable).
function Show-ProxySettings {
    param($parentForm)

    try {
        $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Proxy Configuration" Width="500" SizeToContent="Height" ResizeMode="NoResize" ShowInTaskbar="False"
        WindowStartupLocation="CenterScreen" Background="@FORM@" Foreground="@TEXT@" FontFamily="Segoe UI">
  <Window.Resources><!--APP_RESOURCES--></Window.Resources>
  <StackPanel Margin="24,18,24,18">
    <TextBlock Text="Proxy Configuration" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Primary}"/>
    <TextBlock Margin="0,2,0,12" Foreground="{StaticResource Muted}" TextWrapping="Wrap" Text="Choose how requests reach the network. The password is stored encrypted."/>
    <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14">
      <StackPanel>
        <TextBlock Style="{StaticResource SectionLabel}" Text="MODE"/>
        <ComboBox x:Name="ModeBox" Margin="0,8,0,0" Width="220" HorizontalAlignment="Left"/>
      </StackPanel>
    </Border>
    <Border x:Name="CustomPanel" Margin="0,10,0,0" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="8" Padding="14">
      <StackPanel>
        <TextBlock Style="{StaticResource SectionLabel}" Text="CUSTOM PROXY"/>
        <Grid Margin="0,10,0,0">
          <Grid.ColumnDefinitions><ColumnDefinition Width="90"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="8"/><RowDefinition Height="Auto"/><RowDefinition Height="8"/><RowDefinition Height="Auto"/><RowDefinition Height="8"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <TextBlock VerticalAlignment="Center" Text="Address"/><TextBox x:Name="AddressBox" Grid.Column="1" Height="30" VerticalContentAlignment="Center"/>
          <TextBlock Grid.Row="2" VerticalAlignment="Center" Text="Port"/><TextBox x:Name="PortBox" Grid.Row="2" Grid.Column="1" Width="90" HorizontalAlignment="Left" Height="30" VerticalContentAlignment="Center"/>
          <TextBlock Grid.Row="4" VerticalAlignment="Center" Text="Username"/><TextBox x:Name="UserBox" Grid.Row="4" Grid.Column="1" Height="30" VerticalContentAlignment="Center"/>
          <TextBlock Grid.Row="6" VerticalAlignment="Center" Text="Password"/><PasswordBox x:Name="PasswordBox" Grid.Row="6" Grid.Column="1" Height="30" VerticalContentAlignment="Center"/>
        </Grid>
      </StackPanel>
    </Border>
    <DockPanel Margin="0,16,0,0">
      <TextBlock x:Name="StatusText" DockPanel.Dock="Bottom" Margin="0,10,0,0" TextWrapping="Wrap" Foreground="{StaticResource Muted}"/>
      <Button x:Name="TestButton" Content="Test connection" HorizontalAlignment="Left"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="SaveButton" Style="{StaticResource PrimaryButton}" IsDefault="True" Width="90" Content="Save"/>
        <Button x:Name="CancelButton" IsCancel="True" Width="90" Margin="10,0,0,0" Content="Cancel"/>
      </StackPanel>
    </DockPanel>
  </StackPanel>
</Window>
'@
        $ui = New-WpfWindowFromXaml -Xaml $xaml -ControlNames 'ModeBox', 'CustomPanel', 'AddressBox', 'PortBox', 'UserBox', 'PasswordBox', 'StatusText', 'TestButton', 'SaveButton', 'CancelButton'
        $window = $ui.Window
        $controls = $ui.Controls

        foreach ($mode in @("System", "Custom", "None")) { [void]$controls['ModeBox'].Items.Add($mode) }
        $controls['ModeBox'].SelectedItem = if ($script:settings.ProxyMode) { $script:settings.ProxyMode } else { "System" }
        $controls['AddressBox'].Text = $script:settings.ProxyAddress
        $controls['PortBox'].Text = [string]$script:settings.ProxyPort
        $controls['UserBox'].Text = $script:settings.ProxyUser
        $controls['PasswordBox'].Password = [string]$script:settings.ProxyPass

        $updateCustomState = { $controls['CustomPanel'].IsEnabled = ($controls['ModeBox'].SelectedItem -eq "Custom") }
        & $updateCustomState
        $controls['ModeBox'].Add_SelectionChanged($updateCustomState)

        $controls['SaveButton'].Add_Click({
            $portNumber = 0
            if ($controls['ModeBox'].SelectedItem -eq "Custom" -and -not [int]::TryParse($controls['PortBox'].Text, [ref]$portNumber)) {
                $controls['StatusText'].Text = "Port must be a number."
                return
            }
            [int]::TryParse($controls['PortBox'].Text, [ref]$portNumber) | Out-Null
            $script:settings.ProxyMode    = $controls['ModeBox'].SelectedItem
            $script:settings.ProxyAddress = $controls['AddressBox'].Text
            $script:settings.ProxyPort    = $portNumber
            $script:settings.ProxyUser    = $controls['UserBox'].Text
            $script:settings.ProxyPass    = $controls['PasswordBox'].Password
            Save-Settings
            $window.DialogResult = $true
        })

        $controls['TestButton'].Add_Click({
            if ($controls['ModeBox'].SelectedItem -ne "Custom") { $controls['StatusText'].Text = "Select 'Custom' mode to test custom proxy settings."; return }
            $portNumber = 0
            if (-not $controls['AddressBox'].Text -or -not [int]::TryParse($controls['PortBox'].Text, [ref]$portNumber)) { $controls['StatusText'].Text = "A valid address and port are required."; return }
            try {
                $window.Cursor = [System.Windows.Input.Cursors]::Wait
                $controls['StatusText'].Text = "Testing..."
                $proxy = New-Object System.Net.WebProxy($controls['AddressBox'].Text, $portNumber)
                if ($controls['UserBox'].Text) { $proxy.Credentials = New-Object System.Net.NetworkCredential($controls['UserBox'].Text, $controls['PasswordBox'].Password) }
                $webRequest = [System.Net.WebRequest]::Create("http://www.google.com")
                $webRequest.Proxy = $proxy
                $webRequest.Timeout = 5000
                $webResponse = $webRequest.GetResponse()
                $webResponse.Close()
                $controls['StatusText'].Text = "Connection successful."
            } catch {
                $controls['StatusText'].Text = "Connection failed: $($_.Exception.Message)"
            } finally {
                $window.Cursor = [System.Windows.Input.Cursors]::Arrow
            }
        })

        Show-WpfDialog -Window $window -OwnerForm $parentForm | Out-Null
    } catch {
        Write-Log "WPF proxy dialog failed, using WinForms fallback: $($_.Exception.Message)" -Level Info
        Show-ProxySettingsFallback -parentForm $(if ($parentForm -is [System.Windows.Forms.Form]) { $parentForm } else { $null })
    }
}

function Show-ProxySettingsFallback {
    param($parentForm)
    $form = New-Object System.Windows.Forms.Form -Property @{ Text="Proxy Configuration"; Size=New-Object System.Drawing.Size(500, 450); StartPosition="CenterParent"; BackColor=$script:Theme.FormBackground; FormBorderStyle='FixedDialog'; MaximizeBox=$false; MinimizeBox=$false }
    $layout = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; FlowDirection='TopDown'; Padding=[System.Windows.Forms.Padding]::new(15) }

    $lblMode = New-Label -Text "Proxy Mode:" -Property @{ AutoSize=$true }
    $comboMode = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle='DropDownList'; Width=200; Margin=[System.Windows.Forms.Padding]::new(0,0,0,10) }
    $comboMode.Items.AddRange(@("System", "Custom", "None"))
    $comboMode.SelectedItem = if ($script:settings.ProxyMode) { $script:settings.ProxyMode } else { "System" }

    $grpCustom = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Custom Proxy Settings"; Width=450; Height=220; Enabled=($comboMode.SelectedItem -eq "Custom") }
    $customLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=2; Padding=[System.Windows.Forms.Padding]::new(10) }
    $customLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $customLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $txtAddr = New-TextBox -Property @{ Text=$script:settings.ProxyAddress; Dock='Fill' }
    $txtPort = New-TextBox -Property @{ Text=$script:settings.ProxyPort; Width=60 }
    $txtUser = New-TextBox -Property @{ Text=$script:settings.ProxyUser; Dock='Fill' }
    $txtPass = New-TextBox -Property @{ Text=$script:settings.ProxyPass; Dock='Fill'; UseSystemPasswordChar=$true }

    $customLayout.Controls.Add((New-Label -Text "Address:" -Property @{AutoSize=$true; Anchor='Left'}), 0, 0); $customLayout.Controls.Add($txtAddr, 1, 0)
    $customLayout.Controls.Add((New-Label -Text "Port:" -Property @{AutoSize=$true; Anchor='Left'}), 0, 1); $customLayout.Controls.Add($txtPort, 1, 1)
    $customLayout.Controls.Add((New-Label -Text "Username:" -Property @{AutoSize=$true; Anchor='Left'}), 0, 2); $customLayout.Controls.Add($txtUser, 1, 2)
    $customLayout.Controls.Add((New-Label -Text "Password:" -Property @{AutoSize=$true; Anchor='Left'}), 0, 3); $customLayout.Controls.Add($txtPass, 1, 3)
    $grpCustom.Controls.Add($customLayout)

    $comboMode.Add_SelectedIndexChanged({ $grpCustom.Enabled = ($comboMode.SelectedItem -eq "Custom") })

    $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize=$true; FlowDirection='LeftToRight'; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }

    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Width=180; Height=35; Margin=[System.Windows.Forms.Padding]::new(0,0,10,0) } -OnClick {
        $script:settings.ProxyMode = $comboMode.SelectedItem
        $script:settings.ProxyAddress = $txtAddr.Text
        $script:settings.ProxyPort = [int]$txtPort.Text
        $script:settings.ProxyUser = $txtUser.Text
        $script:settings.ProxyPass = $txtPass.Text
        Save-Settings
        $form.Close()
    }

    $btnTest = New-Button -Text "Test Connection" -Style 'Secondary' -Property @{ Width=180; Height=35 } -OnClick {
        if ($comboMode.SelectedItem -ne "Custom") {
             [System.Windows.Forms.MessageBox]::Show("Please select 'Custom' mode to test custom proxy settings.", "Info", "OK", "Information")
             return
        }
        $addr = $txtAddr.Text
        $port = $txtPort.Text
        if (-not $addr -or -not $port) {
             [System.Windows.Forms.MessageBox]::Show("Address and Port are required.", "Missing Info", "OK", "Warning")
             return
        }
        
        try {
            $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            $proxy = New-Object System.Net.WebProxy($addr, [int]$port)
            if ($txtUser.Text) {
                $proxy.Credentials = New-Object System.Net.NetworkCredential($txtUser.Text, $txtPass.Text)
            }
            
            $req = [System.Net.WebRequest]::Create("http://www.google.com")
            $req.Proxy = $proxy
            $req.Timeout = 5000 # 5 seconds timeout
            $resp = $req.GetResponse()
            $resp.Close()
            
            [System.Windows.Forms.MessageBox]::Show("Connection successful!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Connection failed: $($_.Exception.Message)", "Error", "OK", "Error")
        } finally {
            $form.Cursor = [System.Windows.Forms.Cursors]::Default
        }
    }

    $btnPanel.Controls.AddRange(@($btnSave, $btnTest))
    $layout.Controls.AddRange(@($lblMode, $comboMode, $grpCustom, $btnPanel))
    $form.Controls.Add($layout)
    $form.ShowDialog($parentForm)
}

# --- Cookie Jar Window ---
