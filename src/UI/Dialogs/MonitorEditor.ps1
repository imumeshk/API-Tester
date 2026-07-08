function Show-MonitorEditor {
    param($Monitor)
    $form = New-Object System.Windows.Forms.Form -Property @{
        Text          = "Edit Monitor"
        Size          = New-Object System.Drawing.Size(800, 850)
        MinimumSize   = New-Object System.Drawing.Size(750, 800)
        StartPosition = "CenterParent"
        BackColor     = $script:Theme.FormBackground
        Padding       = [System.Windows.Forms.Padding]::new(10)
        AutoScroll    = $false
    }

    # Main layout
    $mainLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{
        Dock        = 'Top'
        ColumnCount = 1
        AutoScroll  = $false
        AutoSize    = $true
    }
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $mainLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    # --- General Settings Group ---
    $grpGeneral = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "General"; Dock = 'Fill'; AutoSize = $true; Padding = [System.Windows.Forms.Padding]::new(10); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
    $tblGeneral = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; AutoSize = $true }
    $tblGeneral.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $tblGeneral.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $lblName = New-Label -Text "Monitor Name:" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 3, 10, 3) }
    $txtName = New-TextBox -Property @{ Text = $Monitor.Name; Dock = 'Fill' }

    $lblInterval = New-Label -Text "Interval (seconds):" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 3, 10, 3) }
    $numInterval = New-Object System.Windows.Forms.NumericUpDown -Property @{ Width = 100; Minimum = 10; Maximum = 86400; Value = $Monitor.IntervalSeconds; Anchor = 'Left' }

    $tblGeneral.Controls.Add($lblName, 0, 0); $tblGeneral.Controls.Add($txtName, 1, 0)
    $tblGeneral.Controls.Add($lblInterval, 0, 1); $tblGeneral.Controls.Add($numInterval, 1, 1)
    $grpGeneral.Controls.Add($tblGeneral)

    # --- Request Details Group (Refactored) ---
    $grpReq = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Request Details"; Dock = 'Fill'; AutoSize = $false; Height = 320; Padding = [System.Windows.Forms.Padding]::new(10); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
    $requestTabControl = New-Object System.Windows.Forms.TabControl -Property @{ Dock = 'Fill'; Height = 300; MinimumSize = New-Object System.Drawing.Size(200, 280); Margin = [System.Windows.Forms.Padding]::new(0) }

    # Request > General Tab
    $tabReqGeneral = New-Object System.Windows.Forms.TabPage -Property @{ Text = "General" }
    $tblReqGeneral = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; AutoSize = $true }
    $tblReqGeneral.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $tblReqGeneral.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $lblReqMethod = New-Label -Text "Method:" -Property @{ Anchor = 'Left'; TextAlign = 'MiddleLeft' }
    $comboReqMethod = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Dock = 'Fill' }
    $comboReqMethod.Items.AddRange(@("GET", "POST", "PUT", "DELETE", "PATCH"))
    $comboReqMethod.SelectedItem = $Monitor.Request.Method
    $lblReqUrl = New-Label -Text "URL:" -Property @{ Anchor = 'Left'; TextAlign = 'MiddleLeft' }
    $txtReqUrl = New-TextBox -Property @{ Text = $Monitor.Request.Url; Dock = 'Fill' }
    $lblReqTimeout = New-Label -Text "Timeout (seconds):" -Property @{ Anchor = 'Left'; TextAlign = 'MiddleLeft' }
    $numReqTimeout = New-Object System.Windows.Forms.NumericUpDown -Property @{ Width = 100; Minimum = 1; Maximum = 300; Value = $Monitor.Request.RequestTimeoutSeconds }
    $btnImport = New-Button -Text "Import from Main Window" -Property @{ AutoSize = $true; MinimumSize = New-Object System.Drawing.Size(180, 26); Anchor = 'Left'; Margin = [System.Windows.Forms.Padding]::new(0, 6, 0, 0) } -OnClick {
        $comboReqMethod.SelectedItem = $script:comboMethod.SelectedItem
        $txtReqUrl.Text = $script:textUrl.Text
        $txtReqHeaders.Text = $script:textHeaders.Text
        $txtReqBody.Text = $script:textBody.Text
        $comboReqBodyType.SelectedItem = $script:comboBodyType.SelectedItem

        # Import Authentication settings
        $mainFormAuthData = (& $script:authPanel.GetAuthData)
        $editorAuthPanel = $authPanel
        $editorAuthPanel.ComboAuthType.SelectedItem = $mainFormAuthData.Type
        & $editorAuthPanel.SwitchPanel
        switch ($mainFormAuthData.Type) {
            "API Key"      { $editorAuthPanel.TextApiKeyName.Text = $mainFormAuthData.Key; $editorAuthPanel.TextApiKeyValue.Text = $mainFormAuthData.Value; $editorAuthPanel.ComboApiKeyAddTo.SelectedItem = $mainFormAuthData.AddTo }
            "Bearer Token" { $editorAuthPanel.TextBearerToken.Text = $mainFormAuthData.Token }
            "Basic Auth"   { $editorAuthPanel.TextBasicUser.Text = $mainFormAuthData.Username; $editorAuthPanel.TextBasicPass.Text = $mainFormAuthData.Password }
            "Auth2"        {
                $editorAuthPanel.TextAuth2ClientId.Text = $mainFormAuthData.ClientId; $editorAuthPanel.TextAuth2ClientSecret.Text = $mainFormAuthData.ClientSecret; $editorAuthPanel.TextAuth2AuthEndpoint.Text = $mainFormAuthData.AuthEndpoint; $editorAuthPanel.TextAuth2RedirectUri.Text = $mainFormAuthData.RedirectUri; $editorAuthPanel.TextAuth2TokenEndpoint.Text = $mainFormAuthData.TokenEndpoint; $editorAuthPanel.TextAuth2Scope.Text = $mainFormAuthData.Scope; $editorAuthPanel.TextAuth2AccessToken.Text = $mainFormAuthData.AccessToken; $editorAuthPanel.TextAuth2RefreshToken.Text = $mainFormAuthData.RefreshToken; $editorAuthPanel.TextAuth2ExpiresIn.Text = $mainFormAuthData.ExpiresIn; $editorAuthPanel.TextAuth2AccessToken.Tag = $mainFormAuthData.TokenExpiryTimestamp
            }
        }
        [System.Windows.Forms.MessageBox]::Show("Request details imported from main window.", "Import Complete", "OK", "Information")
    }
    $tblReqGeneral.Controls.Add($lblReqMethod, 0, 0); $tblReqGeneral.Controls.Add($comboReqMethod, 1, 0)
    $tblReqGeneral.Controls.Add($lblReqUrl, 0, 1); $tblReqGeneral.Controls.Add($txtReqUrl, 1, 1)
    $tblReqGeneral.Controls.Add($lblReqTimeout, 0, 2); $tblReqGeneral.Controls.Add($numReqTimeout, 1, 2)
    $tblReqGeneral.Controls.Add($btnImport, 0, 3); $tblReqGeneral.SetColumnSpan($btnImport, 2)
    $tabReqGeneral.Controls.Add($tblReqGeneral)

    # Request > Headers Tab
    $tabReqHeaders = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Headers" }
    $txtReqHeaders = New-TextBox -Multiline $true -Property @{ Text = $Monitor.Request.Headers; Dock = 'Fill'; Font = New-Object System.Drawing.Font("Courier New", 9) }
    $tabReqHeaders.Controls.Add($txtReqHeaders)

    # Request > Body Tab
    $tabReqBody = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Body" }
    $panelReqBodyType = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Top'; AutoSize = $true }
    $lblReqBodyType = New-Label -Text "Body Type:" -Property @{ AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0, 3, 0, 0) }
    $comboReqBodyType = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Width = 200 }
    $comboReqBodyType.Items.AddRange(@("multipart/form-data", "application/json", "application/xml", "text/plain", "application/x-www-form-urlencoded", "GraphQL"))
    $comboReqBodyType.SelectedItem = $Monitor.Request.BodyType
    $panelReqBodyType.Controls.AddRange(@($lblReqBodyType, $comboReqBodyType))
    $txtReqBody = New-TextBox -Multiline $true -Property @{ Text = $Monitor.Request.Body; Dock = 'Fill'; Font = New-Object System.Drawing.Font("Courier New", 9) }
    $tabReqBody.Controls.AddRange(@($txtReqBody, $panelReqBodyType))

    # Request > Auth Tab
    $authPanel = New-AuthPanel -AuthData $Monitor.Request.Authentication
    $tabReqAuth = $authPanel.Tab

    $requestTabControl.TabPages.AddRange(@($tabReqGeneral, $tabReqHeaders, $tabReqBody, $tabReqAuth))
    $grpReq.Controls.Add($requestTabControl)

    # --- Alerting Group ---
    $grpAlert = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Alerting"; Dock = 'Fill'; AutoSize = $true; Padding = [System.Windows.Forms.Padding]::new(10); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
    $tblAlert = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; AutoSize = $true }
    $tblAlert.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $tblAlert.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    $chkFail = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Alert on HTTP Failure (Status != 2xx)"; Checked = $Monitor.Alerts.OnFailure; AutoSize = $true }
    $chkSlow = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Alert on Slow Response"; Checked = $Monitor.Alerts.OnSlow; AutoSize = $true }
    $lblThresh = New-Label -Text "Threshold (ms):" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 0) }
    $numThresh = New-Object System.Windows.Forms.NumericUpDown -Property @{ Width = 80; Minimum = 1; Maximum = 60000; Anchor = 'Left' }
    try { $numThresh.Value = $Monitor.Alerts.ThresholdMs } catch { $numThresh.Value = 1000 }
    $chkEmail = New-Object System.Windows.Forms.CheckBox -Property @{ Text = "Send Email Alert"; Checked = $Monitor.Alerts.SendEmail; AutoSize = $true }
    $lblEmail = New-Label -Text "To:" -Property @{ AutoSize = $true; Anchor = 'Left'; TextAlign = 'MiddleLeft'; Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 0) }
    $txtEmail = New-TextBox -Property @{ Text = $Monitor.Alerts.EmailTo; Dock = 'Fill' }
    $btnSmtpConfig = New-Button -Text "Configure Email (Global)" -Property @{ Width = 250; Height = 35; Anchor = 'Left'; Margin = [System.Windows.Forms.Padding]::new(0, 5, 0, 0) } -OnClick { Show-MonitorEmailSettings -parentForm $form }

    $tblAlert.Controls.Add($chkFail, 0, 0); $tblAlert.SetColumnSpan($chkFail, 2)
    $tblAlert.Controls.Add($chkSlow, 0, 1); $tblAlert.SetColumnSpan($chkSlow, 2)
    $tblAlert.Controls.Add($lblThresh, 0, 2); $tblAlert.Controls.Add($numThresh, 1, 2)
    $tblAlert.Controls.Add($chkEmail, 0, 3); $tblAlert.SetColumnSpan($chkEmail, 2)
    $tblAlert.Controls.Add($lblEmail, 0, 4); $tblAlert.Controls.Add($txtEmail, 1, 4)
    $tblAlert.Controls.Add($btnSmtpConfig, 0, 5); $tblAlert.SetColumnSpan($btnSmtpConfig, 2)
    $grpAlert.Controls.Add($tblAlert)

    # --- Analytics Group ---
    $grpAnalytics = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Analytics Integration (Webhook URL)"; Dock = 'Fill'; AutoSize = $false; Height = 70; Padding = [System.Windows.Forms.Padding]::new(10); Margin = [System.Windows.Forms.Padding]::new(0, 0, 0, 10) }
    $txtWebhook = New-TextBox -Property @{ Text = $Monitor.AnalyticsUrl; Dock = 'Top'; Height = 25 }
    $grpAnalytics.Controls.Add($txtWebhook)

    $mainLayout.Controls.Add($grpGeneral, 0, 0)
    $mainLayout.Controls.Add($grpReq, 0, 1)
    $mainLayout.Controls.Add($grpAlert, 0, 2)
    $mainLayout.Controls.Add($grpAnalytics, 0, 3)

    # --- Bottom Button Panel ---
    $btnPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Bottom'; Height = 55; ColumnCount = 4; Padding = [System.Windows.Forms.Padding]::new(5) }
    $btnPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) # Spacer
    $btnPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) # Test
    $btnPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) # Save
    $btnPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) # Cancel

    $btnSave = New-Button -Text "Save" -Style 'Primary' -Property @{ Width = 100; Height = 35; Anchor = 'None' } -OnClick {
        # Validation
        if ([string]::IsNullOrWhiteSpace($txtName.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Monitor Name cannot be empty.", "Validation Error", "OK", "Warning")
            return
        }
        if ([string]::IsNullOrWhiteSpace($txtReqUrl.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Request URL cannot be empty.", "Validation Error", "OK", "Warning")
            return
        }

        $Monitor.Name = $txtName.Text
        $Monitor.IntervalSeconds = $numInterval.Value
        $Monitor.Request.Method = $comboReqMethod.SelectedItem
        $Monitor.Request.Url = $txtReqUrl.Text
        $Monitor.Request.RequestTimeoutSeconds = $numReqTimeout.Value
        $Monitor.Request.Headers = $txtReqHeaders.Text
        $Monitor.Request.BodyType = $comboReqBodyType.SelectedItem
        $Monitor.Request.Body = $txtReqBody.Text
        $Monitor.Request.Authentication = & $authPanel.GetAuthData
        $Monitor.Alerts.OnFailure = $chkFail.Checked
        $Monitor.Alerts.OnSlow = $chkSlow.Checked
        $Monitor.Alerts.ThresholdMs = $numThresh.Value
        $Monitor.Alerts.SendEmail = $chkEmail.Checked
        $Monitor.Alerts.EmailTo = $txtEmail.Text
        $Monitor.AnalyticsUrl = $txtWebhook.Text
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    }
    $btnCancel = New-Button -Text "Cancel" -Property @{ Width = 100; Height = 35; Anchor = 'None' } -OnClick { $form.Close() }
    $btnTest = New-Button -Text "Test Request" -Property @{ Width = 140; Height = 35; Anchor = 'None' } -OnClick {
        try {
            $req = [System.Net.HttpWebRequest]::Create($txtReqUrl.Text)
            $req.Method = $comboReqMethod.SelectedItem
            $req.Timeout = $numReqTimeout.Value * 1000
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $resp = $req.GetResponse()
            $sw.Stop()
            [System.Windows.Forms.MessageBox]::Show("Success!`nStatus: $([int]$resp.StatusCode)`nTime: $($sw.ElapsedMilliseconds)ms", "Test Result", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed!`nError: $($_.Exception.Message)", "Test Result", "OK", "Error")
        }
    }

    $btnPanel.Controls.Add($btnTest, 1, 0)
    $btnPanel.Controls.Add($btnSave, 2, 0)
    $btnPanel.Controls.Add($btnCancel, 3, 0)

    $scrollPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill'; AutoScroll = $true }
    $scrollPanel.Controls.Add($mainLayout)

    $form.Controls.AddRange(@($scrollPanel, $btnPanel))
    return $form.ShowDialog()
}

# --- Monitor Manager Window ---
