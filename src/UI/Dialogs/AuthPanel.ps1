function New-AuthPanel {
    param (
        [object]$AuthData # Pre-populate with this data
    )

    $tabAuth = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Authentication"; Padding = [System.Windows.Forms.Padding]::new(5) }

    # Main Layout: Changed Column 0 to Fixed 140px to match inner tables
    $authLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Fill'; ColumnCount = 2; RowCount = 2 }
    [void]$authLayout.ColumnStyles.Add( (New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)) )
    [void]$authLayout.ColumnStyles.Add( (New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)) )
    [void]$authLayout.RowStyles.Add(    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)) )
    [void]$authLayout.RowStyles.Add(    (New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)) )

    # Updated Label Properties for better vertical alignment (Top Margin 5)
    $lblProp = @{ AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(3,5,5,0) }

    $labelAuthType = New-Label -Text "Type:" -Property $lblProp
    
    # Panel to hold ComboBox and Clear button
    $panelAuthType = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock = 'Fill'; FlowDirection = 'LeftToRight'; AutoSize = $true; Margin = [System.Windows.Forms.Padding]::new(0); Padding = [System.Windows.Forms.Padding]::new(0) }

    $script:comboAuthType = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; Width = 200 }
    $script:comboAuthType.Items.AddRange(@("No Auth", "API Key", "Bearer Token", "Basic Auth", "Auth2", "Client Certificate"))

    # Clear Button
    $btnClearAuth = New-Button -Text "Clear" -Style 'Secondary' -Property @{ Width = 80; Height = $script:comboAuthType.Height + 4; Margin = [System.Windows.Forms.Padding]::new(5,0,0,0) } -OnClick {
        switch ($script:comboAuthType.SelectedItem) {
            "API Key"      { $script:textApiKeyName.Text = ""; $script:textApiKeyValue.Text = "" }
            "Bearer Token" { $script:textBearerToken.Text = "" }
            "Basic Auth"   { $script:textBasicUser.Text = ""; $script:textBasicPass.Text = "" }
            "Auth2"        {
                $script:textAuth2ClientId.Text = ""
                $script:textAuth2ClientSecret.Text = ""
                $script:textAuth2AuthEndpoint.Text = ""
                $script:textAuth2RedirectUri.Text = ""
                $script:textAuth2TokenEndpoint.Text = ""
                $script:textAuth2Scope.Text = ""
                $script:textAuth2AccessToken.Text = ""
                $script:textAuth2RefreshToken.Text = ""
                $script:textAuth2ExpiresIn.Text = ""
                $script:textAuth2AccessToken.Tag = $null
            }
            "Client Certificate" {
                $script:textCertPath.Text = ""
                $script:textCertPass.Text = ""
                $script:textCertThumb.Text = ""
            }
        }
    }
    $panelAuthType.Controls.AddRange(@($script:comboAuthType, $btnClearAuth))

    $script:panelAuthDetails = New-Object System.Windows.Forms.Panel -Property @{ Dock = 'Fill'; AutoScroll = $true; Padding = [System.Windows.Forms.Padding]::new(0, 5, 0, 0) }

    $authLayout.Controls.AddRange(@($labelAuthType, $panelAuthType))
    $authLayout.Controls.Add($script:panelAuthDetails, 0, 1); $authLayout.SetColumnSpan($script:panelAuthDetails, 2)

    # --- Bearer Token Panel ---
    $script:bearerTable = New-AuthDetailTable
    $script:textBearerToken = New-TextBox -Property @{ Dock = 'Fill' }
    
    [void]$script:bearerTable.Controls.Add((New-Label -Text "Token:" -Property $lblProp), 0, 0)
    [void]$script:bearerTable.Controls.Add($script:textBearerToken, 1, 0)

    # --- Basic Auth Panel ---
    $script:basicTable = New-AuthDetailTable
    $script:textBasicUser = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textBasicPass = New-TextBox -Property @{ Dock = 'Fill'; UseSystemPasswordChar = $true }
    
    [void]$script:basicTable.Controls.Add((New-Label -Text "Username:" -Property $lblProp), 0, 0)
    [void]$script:basicTable.Controls.Add($script:textBasicUser, 1, 0)
    [void]$script:basicTable.Controls.Add((New-Label -Text "Password:" -Property $lblProp), 0, 1)
    [void]$script:basicTable.Controls.Add($script:textBasicPass, 1, 1)

    # --- API Key Panel ---
    $script:apiKeyTable = New-AuthDetailTable
    $script:textApiKeyName  = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textApiKeyValue = New-TextBox -Property @{ Dock = 'Fill' }
    $script:comboApiKeyAddTo = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; Dock = 'Fill' }
    $script:comboApiKeyAddTo.Items.AddRange(@("Header", "Query Parameter"))
    
    [void]$script:apiKeyTable.Controls.Add((New-Label -Text "Key Name:" -Property $lblProp), 0, 0)
    [void]$script:apiKeyTable.Controls.Add($script:textApiKeyName, 1, 0)
    [void]$script:apiKeyTable.Controls.Add((New-Label -Text "Key Value:" -Property $lblProp), 0, 1)
    [void]$script:apiKeyTable.Controls.Add($script:textApiKeyValue, 1, 1)
    [void]$script:apiKeyTable.Controls.Add((New-Label -Text "Add to:" -Property $lblProp), 0, 2)
    [void]$script:apiKeyTable.Controls.Add($script:comboApiKeyAddTo, 1, 2)

    # --- Auth2 Panel ---
    $script:auth2Table = New-AuthDetailTable
    $script:textAuth2ClientId = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textAuth2ClientSecret = New-TextBox -Property @{ Dock = 'Fill'; UseSystemPasswordChar = $true }
    $script:textAuth2AuthEndpoint = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textAuth2RedirectUri = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textAuth2TokenEndpoint = New-TextBox -Property @{ Dock = 'Fill' }
    $script:textAuth2Scope = New-TextBox -Property @{ Dock = 'Fill' }
    
    $script:btnGetAuth2Token = New-Button -Text "Get Token" -Property @{ Dock = 'Fill'; Height = 25 } -OnClick {
        $clientId = $script:textAuth2ClientId.Text
        $clientSecret = $script:textAuth2ClientSecret.Text
        $tokenEndpoint = $script:textAuth2TokenEndpoint.Text
        $scope = $script:textAuth2Scope.Text

        if ([string]::IsNullOrWhiteSpace($clientId) -or [string]::IsNullOrWhiteSpace($clientSecret) -or [string]::IsNullOrWhiteSpace($tokenEndpoint)) {
            [System.Windows.Forms.MessageBox]::Show("Client ID, Client Secret, and Token Endpoint are required.", "Missing Info", "OK", "Warning")
            return
        }

        try {
            Write-Log "Attempting to get Auth2 token from $tokenEndpoint" -Level Info
            $body = @{ grant_type="client_credentials"; client_id=$clientId; client_secret=$clientSecret }
            if ($scope) { $body.scope = $scope }

            $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop

            $script:textAuth2AccessToken.Text = $tokenResponse.access_token
            $script:textAuth2RefreshToken.Text = $tokenResponse.refresh_token
            $script:textAuth2ExpiresIn.Text = if ($tokenResponse.expires_in) { "$($tokenResponse.expires_in) seconds" } else { "N/A" }
            if ($tokenResponse.expires_in) { $script:textAuth2AccessToken.Tag = ([DateTime]::UtcNow).AddSeconds([int]$tokenResponse.expires_in) }
            [System.Windows.Forms.MessageBox]::Show("Access Token obtained!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to get token: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }

    $script:btnGetAuth2CodeToken = New-Button -Text "Get Token (Browser)" -Property @{ Dock = 'Fill'; Height = 25 } -OnClick {
        $authEndpoint = $script:textAuth2AuthEndpoint.Text
        $clientId = $script:textAuth2ClientId.Text
        $redirectUri = $script:textAuth2RedirectUri.Text
        $scope = $script:textAuth2Scope.Text
        $state = [Guid]::NewGuid().ToString()

        if (-not $authEndpoint -or -not $clientId -or -not $redirectUri) {
             [System.Windows.Forms.MessageBox]::Show("Auth Endpoint, Client ID, and Redirect URI required.", "Missing Info", "OK", "Warning")
             return
        }
        $sep = if ($authEndpoint -match '\?') { '&' } else { '?' }
        $authUrl = "$authEndpoint${sep}response_type=code&client_id=$clientId&redirect_uri=$redirectUri&scope=$scope&state=$state"

        $browserForm = New-Object System.Windows.Forms.Form -Property @{ Width=1000; Height=700; Text="Authenticate"; StartPosition="CenterParent" }
        $wb = New-Object System.Windows.Forms.WebBrowser -Property @{ Dock='Fill'; ScriptErrorsSuppressed=$true }
        $browserForm.Controls.Add($wb)
        
        $wb.Add_Navigated({
            if ($wb.Url.AbsoluteUri.StartsWith($redirectUri)) {
                if ($wb.Url.Query -match 'code=([^&]+)') {
                    $code = $matches[1]
                    $browserForm.Close()
                    try {
                        $tokenEndpoint = $script:textAuth2TokenEndpoint.Text
                        $clientSecret = $script:textAuth2ClientSecret.Text
                        $body = @{ grant_type="authorization_code"; code=$code; redirect_uri=$redirectUri; client_id=$clientId; client_secret=$clientSecret }
                        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                        
                        $script:textAuth2AccessToken.Text = $tokenResponse.access_token
                        $script:textAuth2RefreshToken.Text = $tokenResponse.refresh_token
                        $script:textAuth2ExpiresIn.Text = if ($tokenResponse.expires_in) { "$($tokenResponse.expires_in) seconds" } else { "N/A" }
                        if ($tokenResponse.expires_in) { $script:textAuth2AccessToken.Tag = ([DateTime]::UtcNow).AddSeconds([int]$tokenResponse.expires_in) }
                        [System.Windows.Forms.MessageBox]::Show("Access Token obtained!", "Success", "OK", "Information")
                    } catch { [System.Windows.Forms.MessageBox]::Show("Failed to exchange code: $($_.Exception.Message)", "Error", "OK", "Error") }
                }
            }
        })
        $wb.Navigate($authUrl)
        $browserForm.ShowDialog()
    }

    $script:textAuth2AccessToken = New-TextBox -Property @{ Dock = 'Fill'; ReadOnly = $true }
    $script:textAuth2RefreshToken = New-TextBox -Property @{ Dock = 'Fill'; ReadOnly = $true }
    $script:textAuth2ExpiresIn = New-TextBox -Property @{ Dock = 'Fill'; ReadOnly = $true }
    
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Client ID:" -Property $lblProp), 0, 0)
    [void]$script:auth2Table.Controls.Add($script:textAuth2ClientId, 1, 0)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Client Secret:" -Property $lblProp), 0, 1)
    [void]$script:auth2Table.Controls.Add($script:textAuth2ClientSecret, 1, 1)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Auth Endpoint:" -Property $lblProp), 0, 2)
    [void]$script:auth2Table.Controls.Add($script:textAuth2AuthEndpoint, 1, 2)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Token Endpoint:" -Property $lblProp), 0, 3)
    [void]$script:auth2Table.Controls.Add($script:textAuth2TokenEndpoint, 1, 3)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Redirect URI:" -Property $lblProp), 0, 4)
    [void]$script:auth2Table.Controls.Add($script:textAuth2RedirectUri, 1, 4)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Scope:" -Property $lblProp), 0, 5)
    [void]$script:auth2Table.Controls.Add($script:textAuth2Scope, 1, 5)
    
    $btnPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true }
    $script:btnGetAuth2Token.Width = 100; $script:btnGetAuth2CodeToken.Width = 140
    $btnPanel.Controls.Add($script:btnGetAuth2Token); $btnPanel.Controls.Add($script:btnGetAuth2CodeToken)
    [void]$script:auth2Table.Controls.Add($btnPanel, 1, 6)

    [void]$script:auth2Table.Controls.Add((New-Label -Text "Access Token:" -Property $lblProp), 0, 7)
    [void]$script:auth2Table.Controls.Add($script:textAuth2AccessToken, 1, 7)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Refresh Token:" -Property $lblProp), 0, 8)
    [void]$script:auth2Table.Controls.Add($script:textAuth2RefreshToken, 1, 8)
    [void]$script:auth2Table.Controls.Add((New-Label -Text "Expires In:" -Property $lblProp), 0, 9)
    [void]$script:auth2Table.Controls.Add($script:textAuth2ExpiresIn, 1, 9)

    # --- Client Certificate Panel ---
    $script:certTable = New-AuthDetailTable
    $script:comboCertSource = New-Object System.Windows.Forms.ComboBox -Property @{ DropDownStyle = 'DropDownList'; Dock = 'Fill' }
    $script:comboCertSource.Items.AddRange(@("PFX File", "User Store"))
    $script:comboCertSource.SelectedIndex = 0
    
    $script:panelCertFile = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true; FlowDirection='LeftToRight'; Margin=[System.Windows.Forms.Padding]::new(0) }
    $script:textCertPath = New-TextBox -Property @{ Width=200 }
    $script:btnBrowseCert = New-Button -Text "..." -Style 'Secondary' -Property @{ Width=30; Height=23; Margin=[System.Windows.Forms.Padding]::new(3,0,0,0) } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter="PFX Files (*.pfx;*.p12)|*.pfx;*.p12|All Files (*.*)|*.*" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $script:textCertPath.Text = $ofd.FileName }
    }
    $script:panelCertFile.Controls.AddRange(@($script:textCertPath, $script:btnBrowseCert))
    
    $script:textCertPass = New-TextBox -Property @{ Dock='Fill'; UseSystemPasswordChar=$true }
    
    $script:panelCertStore = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Fill'; AutoSize=$true; FlowDirection='LeftToRight'; Margin=[System.Windows.Forms.Padding]::new(0) }
    $script:textCertThumb = New-TextBox -Property @{ Width=200; ReadOnly=$false; PlaceholderText="Thumbprint" }
    $script:btnSelectCert = New-Button -Text "Select" -Style 'Secondary' -Property @{ Width=60; Height=23; Margin=[System.Windows.Forms.Padding]::new(3,0,0,0) } -OnClick {
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
            $store.Open("ReadOnly")
            $certs = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection($store.Certificates, "Select Certificate", "Choose a client certificate for mTLS", "SingleSelection")
            if ($certs.Count -gt 0) { $script:textCertThumb.Text = $certs[0].Thumbprint }
            $store.Close()
        } catch { [System.Windows.Forms.MessageBox]::Show("Error accessing certificate store: $($_.Exception.Message)", "Error", "OK", "Error") }
    }
    $script:panelCertStore.Controls.AddRange(@($script:textCertThumb, $script:btnSelectCert))

    [void]$script:certTable.Controls.Add((New-Label -Text "Source:" -Property $lblProp), 0, 0)
    [void]$script:certTable.Controls.Add($script:comboCertSource, 1, 0)
    
    $script:lblCertPath = New-Label -Text "Path:" -Property $lblProp
    $script:lblCertPass = New-Label -Text "Password:" -Property $lblProp
    $script:lblCertThumb = New-Label -Text "Thumbprint:" -Property $lblProp

    [void]$script:certTable.Controls.Add($script:lblCertPath, 0, 1); [void]$script:certTable.Controls.Add($script:panelCertFile, 1, 1)
    [void]$script:certTable.Controls.Add($script:lblCertPass, 0, 2); [void]$script:certTable.Controls.Add($script:textCertPass, 1, 2)
    [void]$script:certTable.Controls.Add($script:lblCertThumb, 0, 3); [void]$script:certTable.Controls.Add($script:panelCertStore, 1, 3)

    $script:comboCertSource.Add_SelectedIndexChanged({
        $isPfx = ($script:comboCertSource.SelectedItem -eq "PFX File")
        $script:lblCertPath.Visible = $isPfx; $script:panelCertFile.Visible = $isPfx; $script:lblCertPass.Visible = $isPfx; $script:textCertPass.Visible = $isPfx
        $script:lblCertThumb.Visible = (-not $isPfx); $script:panelCertStore.Visible = (-not $isPfx)
    })
    # Trigger initial visibility
    $script:comboCertSource.SelectedIndex = 0; $script:lblCertThumb.Visible = $false; $script:panelCertStore.Visible = $false

    # Populate Data if Exists
    if ($AuthData) {
        $script:comboAuthType.SelectedItem = $AuthData.Type
        switch ($AuthData.Type) {
            "API Key"      { $script:textApiKeyName.Text = $AuthData.Key; $script:textApiKeyValue.Text = $AuthData.Value; $script:comboApiKeyAddTo.SelectedItem = $AuthData.AddTo }
            "Bearer Token" { $script:textBearerToken.Text = $AuthData.Token }
            "Basic Auth"   { $script:textBasicUser.Text = $AuthData.Username; $script:textBasicPass.Text = $AuthData.Password }
            "Auth2"        {
                $script:textAuth2ClientId.Text = $AuthData.ClientId
                $script:textAuth2ClientSecret.Text = $AuthData.ClientSecret
                $script:textAuth2AuthEndpoint.Text = $AuthData.AuthEndpoint
                $script:textAuth2RedirectUri.Text = $AuthData.RedirectUri
                $script:textAuth2TokenEndpoint.Text = $AuthData.TokenEndpoint
                $script:textAuth2Scope.Text = $AuthData.Scope
                $script:textAuth2AccessToken.Text = $AuthData.AccessToken
                $script:textAuth2RefreshToken.Text = $AuthData.RefreshToken
                $script:textAuth2ExpiresIn.Text = $AuthData.ExpiresIn
                $script:textAuth2AccessToken.Tag = $AuthData.TokenExpiryTimestamp
            }
            "Client Certificate" {
                $script:comboCertSource.SelectedItem = $AuthData.Source
                $script:textCertPath.Text = $AuthData.Path
                $script:textCertPass.Text = $AuthData.Password
                $script:textCertThumb.Text = $AuthData.Thumbprint
            }
        }
    } else {
        $script:comboAuthType.SelectedIndex = 0
    }

    # Switch Logic
    $switchPanel = {
        $script:panelAuthDetails.Controls.Clear()
        switch ($script:comboAuthType.SelectedItem) {
            "API Key"      { $script:panelAuthDetails.Controls.Add($script:apiKeyTable) }
            "Bearer Token" { $script:panelAuthDetails.Controls.Add($script:bearerTable) }
            "Basic Auth"   { $script:panelAuthDetails.Controls.Add($script:basicTable) }
            "Auth2"        { $script:panelAuthDetails.Controls.Add($script:auth2Table) }
            "Client Certificate" { $script:panelAuthDetails.Controls.Add($script:certTable) }
        }
    }
    $script:comboAuthType.Add_SelectedIndexChanged($switchPanel)
    $tabAuth.Controls.Add($authLayout)

    & $switchPanel # Initial render

    $getAuthData = {
        $details = @{ Type = $script:comboAuthType.SelectedItem }
        switch ($details.Type) {
            "API Key"      { $details.Key = $script:textApiKeyName.Text; $details.Value = $script:textApiKeyValue.Text; $details.AddTo = $script:comboApiKeyAddTo.SelectedItem }
            "Bearer Token" { $details.Token = $script:textBearerToken.Text }
            "Basic Auth"   { $details.Username = $script:textBasicUser.Text; $details.Password = $script:textBasicPass.Text }
            "Auth2"        {
                $details.ClientId = $script:textAuth2ClientId.Text; $details.ClientSecret = $script:textAuth2ClientSecret.Text
                $details.AuthEndpoint = $script:textAuth2AuthEndpoint.Text; $details.RedirectUri = $script:textAuth2RedirectUri.Text
                $details.TokenEndpoint = $script:textAuth2TokenEndpoint.Text; $details.Scope = $script:textAuth2Scope.Text
                $details.AccessToken = $script:textAuth2AccessToken.Text; $details.RefreshToken = $script:textAuth2RefreshToken.Text; $details.ExpiresIn = $script:textAuth2ExpiresIn.Text; $details.TokenExpiryTimestamp = $script:textAuth2AccessToken.Tag
            }
            "Client Certificate" {
                $details.Source = $script:comboCertSource.SelectedItem; $details.Path = $script:textCertPath.Text; $details.Password = $script:textCertPass.Text; $details.Thumbprint = $script:textCertThumb.Text
            }
        }
        return $details
    }

    [PSCustomObject]@{
        Tab              = $tabAuth
        GetAuthData      = $getAuthData
        SwitchPanel      = $switchPanel
        ComboAuthType    = $script:comboAuthType
        TextApiKeyName   = $script:textApiKeyName
        TextApiKeyValue  = $script:textApiKeyValue
        ComboApiKeyAddTo = $script:comboApiKeyAddTo
        TextBearerToken  = $script:textBearerToken
        TextBasicUser    = $script:textBasicUser
        TextBasicPass    = $script:textBasicPass
        TextAuth2TokenEndpoint = $script:textAuth2TokenEndpoint
        TextAuth2AuthEndpoint = $script:textAuth2AuthEndpoint
        TextAuth2RedirectUri = $script:textAuth2RedirectUri
        TextAuth2Scope = $script:textAuth2Scope
        TextAuth2AccessToken = $script:textAuth2AccessToken
        TextAuth2RefreshToken = $script:textAuth2RefreshToken
        TextAuth2ExpiresIn = $script:textAuth2ExpiresIn
        TextAuth2ClientId = $script:textAuth2ClientId
        TextAuth2ClientSecret = $script:textAuth2ClientSecret
        TextCertPath = $script:textCertPath
        TextCertPass = $script:textCertPass
        TextCertThumb = $script:textCertThumb
        ComboCertSource = $script:comboCertSource
    }
}
# --- Monitor Email Settings Window ---
