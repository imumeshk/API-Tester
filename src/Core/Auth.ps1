function Substitute-Variables {
    param ([string]$InputString)
    
    $activeEnvVars = $null
    if ($script:activeEnvironment -ne "No Environment" -and $script:environments.ContainsKey($script:activeEnvironment)) {
        $envData = $script:environments[$script:activeEnvironment]
        if ($envData -is [hashtable] -and $envData.ContainsKey('Variables')) { $activeEnvVars = $envData.Variables }
        elseif ($envData.PSObject.Properties.Name -contains 'Variables') { $activeEnvVars = $envData.Variables }
        else { $activeEnvVars = $envData }
    }

    $maxDepth = 5
    $currentString = $InputString

    for ($i = 0; $i -lt $maxDepth; $i++) {
        $previousString = $currentString
        $evaluator = {
            param($match)
            $varName = $match.Groups[1].Value
            if ($activeEnvVars -and $activeEnvVars.ContainsKey($varName)) { return $activeEnvVars[$varName] }
            if ($script:activeCollectionVariables) {
                if ($script:activeCollectionVariables -is [hashtable] -and $script:activeCollectionVariables.ContainsKey($varName)) { return $script:activeCollectionVariables[$varName] }
                if ($script:activeCollectionVariables.PSObject.Properties.Name -contains $varName) { return $script:activeCollectionVariables.$varName }
            }
            if ($script:globals -and $script:globals.ContainsKey($varName)) { return $script:globals[$varName] }
            
            switch ($varName) {
                '$guid'      { return [Guid]::NewGuid().ToString() }
                '$timestamp' { return [int64](Get-Date -UFormat %s) }
                '$randomInt' { return (Get-Random -Minimum 1 -Maximum 10000).ToString() }
                default      { return $match.Value }
            }
        }
        $currentString = [regex]::Replace($currentString, '\{\{([^{}]+?)\}\}', $evaluator)
        if ($currentString -eq $previousString) { break }
    }
    return $currentString
}

# Replaces {Placeholders} in alert templates with actual values.
function Format-AlertTemplate {
    param(
        [string]$Template,
        [hashtable]$Data
    )
    if ([string]::IsNullOrWhiteSpace($Template)) { return "" }
    $result = $Template
    foreach ($key in $Data.Keys) {
        $token = "\{$key\}"
        $result = $result -replace $token, [string]$Data[$key]
    }
    return $result
}

# Simple heuristic to detect HTML content in email body.
function New-AuthDetailTable {
    $table = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock = 'Top'; ColumnCount = 2; AutoSize = $true; AutoSizeMode = 'GrowAndShrink' }
    $table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    return $table
}

# --- Encryption Helpers (DPAPI) ---
function Send-SmtpOAuth2 {
    param($Server, $Port, $UseSsl, $From, $To, $Subject, $Body, $User, $AccessToken, [bool]$IsHtml = $false)
    
    try {
        $client = New-Object System.Net.Sockets.TcpClient($Server, $Port)
        $stream = $client.GetStream()
        if ($UseSsl) {
            $sslStream = New-Object System.Net.Security.SslStream($stream)
            $sslStream.AuthenticateAsClient($Server)
            $stream = $sslStream
        }
        
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true
        
        function Read-Response { return $reader.ReadLine() }
        function Send-Command { param($cmd) $writer.WriteLine($cmd) }
        
        Read-Response | Out-Null # Banner
        Send-Command "EHLO localhost"
        while($line = Read-Response) { if($line -match "^\d+ ") { break } }
        
        # Auth XOAUTH2 construction: user=EMAIL^Aauth=Bearer TOKEN^A^A
        $authStr = "user=$User`x01auth=Bearer $AccessToken`x01`x01"
        $authBytes = [System.Text.Encoding]::ASCII.GetBytes($authStr)
        $authBase64 = [Convert]::ToBase64String($authBytes)
        
        Send-Command "AUTH XOAUTH2 $authBase64"
        $res = Read-Response
        if ($res -notmatch "^235") { throw "SMTP Auth Failed: $res" }
        
        Send-Command "MAIL FROM: <$From>"; Read-Response | Out-Null
        Send-Command "RCPT TO: <$To>"; Read-Response | Out-Null
        Send-Command "DATA"; Read-Response | Out-Null
        
        $contentType = if ($IsHtml) { "text/html; charset=utf-8" } else { "text/plain; charset=utf-8" }
        $headers = "Subject: $Subject`r`nFrom: $From`r`nTo: $To`r`nMIME-Version: 1.0`r`nContent-Type: $contentType`r`n"
        Send-Command "$headers`r`n$Body`r`n."
        Read-Response | Out-Null
        Send-Command "QUIT"
        $client.Close()
    } catch { throw $_ }
}

function Refresh-SmtpToken {
    if (-not $script:settings.MonitorSmtpRefreshToken -or -not $script:settings.MonitorSmtpTokenEndpoint) { return }
    try {
        Write-Log "Refreshing SMTP OAuth2 Token..." -Level Info
        $body = @{
            grant_type    = "refresh_token"
            refresh_token = $script:settings.MonitorSmtpRefreshToken
            client_id     = $script:settings.MonitorSmtpClientId
            client_secret = $script:settings.MonitorSmtpClientSecret
        }
        $response = Invoke-RestMethod -Uri $script:settings.MonitorSmtpTokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        
        $script:settings.MonitorSmtpPass = $response.access_token
        if ($response.refresh_token) { $script:settings.MonitorSmtpRefreshToken = $response.refresh_token }
        if ($response.expires_in) { $script:settings.MonitorSmtpTokenExpiry = ([DateTime]::UtcNow).AddSeconds([int]$response.expires_in).ToString("o") }
        Save-Settings
        Write-Log "SMTP Token Refreshed." -Level Info
    } catch {
        Write-Log "SMTP Token Refresh Failed: $($_.Exception.Message)" -Level Info
        throw $_
    }
}

#endregion

#region UI Windows (Settings, Main Form)

# --- Simple Variables Editor (key=value) ---
