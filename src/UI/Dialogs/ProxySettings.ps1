function Show-ProxySettings {
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
