function Show-MonitorEmailSettings {
    param($parentForm)
    $form = New-Object System.Windows.Forms.Form -Property @{ Text="Email Alert Configuration"; Size=New-Object System.Drawing.Size(700, 750); StartPosition="CenterParent" }
    $layout = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; FlowDirection='TopDown'; Padding=[System.Windows.Forms.Padding]::new(15); WrapContents=$false; AutoScroll=$true }
    
    $layout.Controls.Add((New-Label -Text "SMTP Server:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,5,0,0) }))
    $txtServer = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpServer; Width=500; Height=25 }
    $layout.Controls.Add($txtServer)

    $layout.Controls.Add((New-Label -Text "SMTP Port:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtPort = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpPort; Width=150; Height=25 }
    $layout.Controls.Add($txtPort)

    $layout.Controls.Add((New-Label -Text "Auth Method:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $comboAuth = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle='DropDownList'; Width=200; Height=25 }
    $comboAuth.Items.AddRange(@("Basic", "OAuth2"))
    $comboAuth.SelectedItem = if ($script:settings.MonitorSmtpAuthMethod) { $script:settings.MonitorSmtpAuthMethod } else { "Basic" }
    $layout.Controls.Add($comboAuth)

    $chkSsl = New-Object System.Windows.Forms.CheckBox -Property @{ Text="Use SSL"; Checked=$script:settings.MonitorSmtpUseSsl; AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }
    $layout.Controls.Add($chkSsl)

    $layout.Controls.Add((New-Label -Text "From Address:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtFrom = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpFrom; Width=500; Height=25 }
    $layout.Controls.Add($txtFrom)

    $layout.Controls.Add((New-Label -Text "Username (Optional):" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtUser = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpUser; Width=500; Height=25 }
    $layout.Controls.Add($txtUser)

    $lblPass = New-Label -Text "Password:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }
    $layout.Controls.Add($lblPass)
    $txtPass = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpPass; Width=500; Height=25; UseSystemPasswordChar=$true }
    $layout.Controls.Add($txtPass)

    # OAuth2 Specific Fields
    $panelOAuth = New-Object System.Windows.Forms.Panel -Property @{ AutoSize=$true; Visible=$false }
    $layoutOAuth = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; FlowDirection='TopDown'; AutoSize=$true; WrapContents=$false; Padding=[System.Windows.Forms.Padding]::new(0,10,0,0) }
    
    $layoutOAuth.Controls.Add((New-Label -Text "Client ID:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,5,0,0) }))
    $txtClientId = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpClientId; Width=500; Height=25 }
    $layoutOAuth.Controls.Add($txtClientId)

    $layoutOAuth.Controls.Add((New-Label -Text "Client Secret:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtClientSecret = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpClientSecret; Width=500; Height=25; UseSystemPasswordChar=$true }
    $layoutOAuth.Controls.Add($txtClientSecret)

    $layoutOAuth.Controls.Add((New-Label -Text "Token Endpoint:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtTokenEndpoint = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpTokenEndpoint; Width=500; Height=25 }
    $layoutOAuth.Controls.Add($txtTokenEndpoint)

    $layoutOAuth.Controls.Add((New-Label -Text "Refresh Token:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) }))
    $txtRefreshToken = New-TextBox -Property @{ Text=$script:settings.MonitorSmtpRefreshToken; Width=500; Height=25; UseSystemPasswordChar=$true }
    $layoutOAuth.Controls.Add($txtRefreshToken)
    
    $btnRefresh = New-Button -Text "Refresh Token Now" -Property @{ Width=180; Height=30; Margin=[System.Windows.Forms.Padding]::new(0,10,0,5) } -OnClick {
        $script:settings.MonitorSmtpClientId = $txtClientId.Text
        $script:settings.MonitorSmtpClientSecret = $txtClientSecret.Text
        $script:settings.MonitorSmtpRefreshToken = $txtRefreshToken.Text
        $script:settings.MonitorSmtpTokenEndpoint = $txtTokenEndpoint.Text
        
        try {
            Refresh-SmtpToken
            $txtPass.Text = $script:settings.MonitorSmtpPass
            [System.Windows.Forms.MessageBox]::Show("Token refreshed successfully!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to refresh token:`n$($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
    $layoutOAuth.Controls.Add($btnRefresh)

    $panelOAuth.Controls.Add($layoutOAuth)
    $layout.Controls.Add($panelOAuth)

    $comboAuth.Add_SelectedIndexChanged({
        if ($comboAuth.SelectedItem -eq "OAuth2") { $lblPass.Text = "Access Token:"; $panelOAuth.Visible = $true } else { $lblPass.Text = "Password:"; $panelOAuth.Visible = $false }
    })
    if ($comboAuth.SelectedItem -eq "OAuth2") { $lblPass.Text = "Access Token:"; $panelOAuth.Visible = $true }

    # Alert Email Template
    $grpTemplate = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Alert Email Template"; AutoSize=$true; Width=600; Margin=[System.Windows.Forms.Padding]::new(0,15,0,0) }
    $tmplLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=2; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(5) }
    $tmplLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $tmplLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null

    $lblAlertSubject = New-Label -Text "Subject:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,8,0) }
    $txtAlertSubject = New-TextBox -Property @{ Text=$script:settings.MonitorAlertSubjectTemplate; Dock='Fill'; Height=25 }

    $lblAlertBody = New-Label -Text "Body:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,8,0) }
    $txtAlertBody = New-TextBox -Multiline $true -Property @{ Text=$script:settings.MonitorAlertBodyTemplate; Dock='Fill'; Height=120; ScrollBars='Vertical' }

    $checkForceHtml = New-Object System.Windows.Forms.CheckBox -Property @{
        Text = "Force HTML email body"
        Checked = $script:settings.MonitorAlertBodyForceHtml
        AutoSize = $true
        Margin = [System.Windows.Forms.Padding]::new(0,6,0,0)
    }
    $lblAlertHint = New-Label -Text "Placeholders: {MonitorName} {Status} {StatusCode} {Url} {TimeMs} {Message} {Timestamp}" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,8,0,0) }

    $tmplLayout.Controls.Add($lblAlertSubject, 0, 0); $tmplLayout.Controls.Add($txtAlertSubject, 1, 0)
    $tmplLayout.Controls.Add($lblAlertBody, 0, 1); $tmplLayout.Controls.Add($txtAlertBody, 1, 1)
    $tmplLayout.Controls.Add($checkForceHtml, 0, 2); $tmplLayout.SetColumnSpan($checkForceHtml, 2)
    $tmplLayout.Controls.Add($lblAlertHint, 0, 3); $tmplLayout.SetColumnSpan($lblAlertHint, 2)

    $grpTemplate.Controls.Add($tmplLayout)
    $layout.Controls.Add($grpTemplate)

    $grpActions = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Actions"; AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,15,0,0); Width=600 }
    $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize=$true; FlowDirection='LeftToRight'; Padding=[System.Windows.Forms.Padding]::new(5); WrapContents=$false }

    $btnSave = New-Button -Text "Save Settings" -Property @{ Width=140; Height=35; Margin=[System.Windows.Forms.Padding]::new(0,0,10,0) } -OnClick {
        # ... (keep existing save logic) ...
        $script:settings.MonitorSmtpServer = $txtServer.Text
        $script:settings.MonitorSmtpPort = [int]$txtPort.Text
        $script:settings.MonitorSmtpUseSsl = $chkSsl.Checked
        $script:settings.MonitorSmtpFrom = $txtFrom.Text
        $script:settings.MonitorSmtpUser = $txtUser.Text
        $script:settings.MonitorSmtpPass = $txtPass.Text
        $script:settings.MonitorSmtpAuthMethod = $comboAuth.SelectedItem
        $script:settings.MonitorSmtpClientId = $txtClientId.Text
        $script:settings.MonitorSmtpClientSecret = $txtClientSecret.Text
        $script:settings.MonitorSmtpTokenEndpoint = $txtTokenEndpoint.Text
        $script:settings.MonitorSmtpRefreshToken = $txtRefreshToken.Text
        $script:settings.MonitorAlertSubjectTemplate = $txtAlertSubject.Text
        $script:settings.MonitorAlertBodyTemplate = $txtAlertBody.Text
        $script:settings.MonitorAlertBodyForceHtml = $checkForceHtml.Checked
        Save-Settings
        $form.Close()
    }

    # FIX: Increased width to 160 to show full text
    $btnTest = New-Button -Text "Test Connection" -Property @{ Width=160; Height=35; Margin=[System.Windows.Forms.Padding]::new(10,0,0,0) } -OnClick {
        # ... (keep existing test logic) ...
         $server = $txtServer.Text
        $port = [int]$txtPort.Text
        $ssl = $chkSsl.Checked
        $from = $txtFrom.Text
        $user = $txtUser.Text
        $pass = $txtPass.Text
        $authMethod = $comboAuth.SelectedItem

        if (-not $server -or -not $from) {
            [System.Windows.Forms.MessageBox]::Show("Please enter SMTP Server and From Address.", "Missing Info", "OK", "Warning")
            return
        }

        $to = [Microsoft.VisualBasic.Interaction]::InputBox("Enter recipient email address for test:", "Test Email", $from)
        if (-not $to) { return }

        try {
            if ($authMethod -eq "OAuth2") {
                Send-SmtpOAuth2 -Server $server -Port $port -UseSsl $ssl -From $from -To $to -Subject "API Tester SMTP Test" -Body "This is a test email (OAuth2)." -User $user -AccessToken $pass -IsHtml:$false
            } else {
                $smtpParams = @{ SmtpServer=$server; Port=$port; UseSsl=$ssl; From=$from; To=$to; Subject="API Tester SMTP Test"; Body="This is a test email (Basic)."; IsBodyHtml = $false }
                if ($user) {
                    $securePass = $pass | ConvertTo-SecureString -AsPlainText -Force
                    $smtpParams.Credential = New-Object System.Management.Automation.PSCredential($user, $securePass)
                }
                Send-MailMessage @smtpParams -ErrorAction Stop
            }
            [System.Windows.Forms.MessageBox]::Show("Test email sent successfully to $to!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to send test email:`n$($_.Exception.Message)", "Test Failed", "OK", "Error")
        }
    }

    $btnPanel.Controls.AddRange(@($btnSave, $btnTest))
    $grpActions.Controls.Add($btnPanel)
    $layout.Controls.Add($grpActions)
    $form.Controls.Add($layout)
    $form.ShowDialog($parentForm)
    #FIX: Corrected function call
}

# --- Monitor Chart Window ---
