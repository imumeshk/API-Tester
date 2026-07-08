function Show-JwtTool {
    $jwtForm = New-Object System.Windows.Forms.Form -Property @{ Text = "JWT Utility"; Size = New-Object System.Drawing.Size(950, 700); StartPosition = "CenterParent"; BackColor = $script:Theme.FormBackground }
    $tabs = New-Object System.Windows.Forms.TabControl -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Segoe UI", 10) }
    
    # Decoder Tab
    $tabDecode = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Decoder"; Padding = [System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.FormBackground }
    $split = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock = 'Fill'; Orientation = 'Horizontal'; SplitterDistance = 280; BackColor = $script:Theme.FormBackground }
    
    $inputGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "JWT Input"; Dock = 'Fill'; Padding = [System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.GroupBackground }
    $inputLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=1; RowCount=2 }
    $inputLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $inputLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $txtJwtInput = New-RichTextBox -Property @{ Dock = 'Fill'; Text = "Paste JWT here..."; BorderStyle = 'FixedSingle'; BackColor = 'White'; Font = New-Object System.Drawing.Font("Consolas", 9) }
    $txtJwtOutput = New-RichTextBox -ReadOnly $true -Property @{ Dock = 'Fill'; Font = New-Object System.Drawing.Font("Consolas", 9); BorderStyle = 'FixedSingle'; BackColor = 'White' }

    $actionRow = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=3; AutoSize=$true }
    $actionRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $actionRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $actionRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $lblVerifySecret = New-Label -Text "Secret:" -Property @{ AutoSize=$true; Anchor='Left'; Margin=[System.Windows.Forms.Padding]::new(0,6,6,0) }
    $txtVerifySecret = New-TextBox -Property @{ Dock='Fill'; Margin=[System.Windows.Forms.Padding]::new(0,3,8,0); UseSystemPasswordChar = $true }

    $actionButtons = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ AutoSize=$true; FlowDirection='LeftToRight'; WrapContents=$false; Margin=[System.Windows.Forms.Padding]::new(0); Padding=[System.Windows.Forms.Padding]::new(0) }

    $btnClear = New-Button -Text "Clear" -Style 'Secondary' -Property @{ Width=90; Height=32; Margin=[System.Windows.Forms.Padding]::new(0) } -OnClick {
        $txtJwtInput.Clear()
        $txtJwtOutput.Clear()
    }

    $btnDecode = New-Button -Text "Decode" -Style 'Primary' -Property @{ Width=100; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,0,6,0) } -OnClick {
        $token = $txtJwtInput.Text.Trim()
        if ($token -match '^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$') {
            $parts = $token.Split('.')
            try {
                function FromB64Url($s) { 
                    $s=$s.Replace('-','+').Replace('_','/'); switch($s.Length%4){2{$s+='=='}3{$s+='='}}; 
                    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) 
                }
                $header = FromB64Url $parts[0] | ConvertFrom-Json | ConvertTo-Json
                $payload = FromB64Url $parts[1] | ConvertFrom-Json | ConvertTo-Json
                $txtJwtOutput.Text = "HEADER:`n$header`n`nPAYLOAD:`n$payload`n`nSIGNATURE:`n$($parts[2])"
            } catch { $txtJwtOutput.Text = "Error decoding JWT: $($_.Exception.Message)" }
        } else { $txtJwtOutput.Text = "Invalid JWT format." }
    }

    $btnVerify = New-Button -Text "Verify Sig" -Style 'Secondary' -Property @{ Width=110; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,0,6,0) } -OnClick {
        $token = $txtJwtInput.Text.Trim()
        $secret = $txtVerifySecret.Text
        if (-not $token -or -not $secret) { [System.Windows.Forms.MessageBox]::Show("Please enter JWT and Secret.", "Info", "OK", "Warning"); return }
        if ($token -match '^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$') {
            $parts = $token.Split('.')
            try {
                $hStr = $parts[0].Replace('-','+').Replace('_','/'); switch($hStr.Length%4){2{$hStr+='=='}3{$hStr+='='}}
                $headerJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($hStr))
                if (($headerJson | ConvertFrom-Json).alg -ne 'HS256') { [System.Windows.Forms.MessageBox]::Show("Only HS256 supported.", "Info", "OK", "Warning"); return }

                $hmac = New-Object System.Security.Cryptography.HMACSHA256(,[System.Text.Encoding]::UTF8.GetBytes($secret))
                $calcSig = [Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$($parts[0]).$($parts[1])"))).Replace('+','-').Replace('/','_').TrimEnd('=')

                if ($calcSig -eq $parts[2]) { [System.Windows.Forms.MessageBox]::Show("Signature Verified!", "Success", "OK", "Information") }
                else { [System.Windows.Forms.MessageBox]::Show("Verification Failed!", "Error", "OK", "Error") }
            } catch { [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", "OK", "Error") }
        }
    }

    $actionButtons.Controls.AddRange(@($btnVerify, $btnDecode, $btnClear))
    $actionRow.Controls.Add($lblVerifySecret, 0, 0)
    $actionRow.Controls.Add($txtVerifySecret, 1, 0)
    $actionRow.Controls.Add($actionButtons, 2, 0)

    $inputLayout.Controls.Add($txtJwtInput, 0, 0)
    $inputLayout.Controls.Add($actionRow, 0, 1)
    $inputGroup.Controls.Add($inputLayout)

    $outputGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Decoded Output"; Dock = 'Fill'; Padding = [System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.GroupBackground }
    $outputGroup.Controls.Add($txtJwtOutput)

    $split.Panel1.Controls.Add($inputGroup)
    $split.Panel2.Controls.Add($outputGroup)
    $tabDecode.Controls.Add($split)
    
    # Generator Tab (Simple HMAC)
    $tabGen = New-Object System.Windows.Forms.TabPage -Property @{ Text = "Generator (HS256)"; Padding = [System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.FormBackground }
    $genLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=1; RowCount=4 }
    $genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 55))) | Out-Null
    $genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $genLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 45))) | Out-Null

    $txtPayload = New-TextBox -Multiline $true -Property @{ Dock='Fill'; Height=150; Text='{ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 }'; Font=New-Object System.Drawing.Font("Consolas", 9); ScrollBars='Vertical' }
    $txtSecret = New-TextBox -Property @{ Dock='Fill'; Text='secret'; Height=25; Margin=[System.Windows.Forms.Padding]::new(0,4,0,0) }
    $txtJwtResult = New-TextBox -Multiline $true -Property @{ Dock='Fill'; ReadOnly=$true; Font=New-Object System.Drawing.Font("Consolas", 9); ScrollBars='Vertical' }

    $payloadGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Payload (JSON)"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.GroupBackground }
    $payloadGroup.Controls.Add($txtPayload)

    $secretRow = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Top'; ColumnCount=2; AutoSize=$true }
    $secretRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $secretRow.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $secretRow.Controls.Add((New-Label -Text "Secret:" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(0,6,6,0) }), 0, 0)
    $secretRow.Controls.Add($txtSecret, 1, 0)

    $btnGen = New-Button -Text "Generate JWT" -Style 'Primary' -Property @{ Height=35; Width=140; Margin=[System.Windows.Forms.Padding]::new(0,8,0,8) } -OnClick {
        try {
            $header = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}')).Replace('+','-').Replace('/','_').TrimEnd('=')
            $payloadJson = $txtPayload.Text; $null = $payloadJson | ConvertFrom-Json # Validate
            $payload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson)).Replace('+','-').Replace('/','_').TrimEnd('=')
            $secret = [System.Text.Encoding]::UTF8.GetBytes($txtSecret.Text)
            $toSign = [System.Text.Encoding]::UTF8.GetBytes("$header.$payload")
            $hmac = New-Object System.Security.Cryptography.HMACSHA256(,$secret); $sigBytes = $hmac.ComputeHash($toSign)
            $sig = [Convert]::ToBase64String($sigBytes).Replace('+','-').Replace('/','_').TrimEnd('=')
            $txtJwtResult.Text = "$header.$payload.$sig"
        } catch { $txtJwtResult.Text = "Error: $($_.Exception.Message)" }
    }
    $resultGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text = "Generated JWT"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor = $script:Theme.GroupBackground }
    $resultGroup.Controls.Add($txtJwtResult)

    $genLayout.Controls.Add($payloadGroup, 0, 0)
    $genLayout.Controls.Add($secretRow, 0, 1)
    $genLayout.Controls.Add($btnGen, 0, 2)
    $genLayout.Controls.Add($resultGroup, 0, 3)
    $tabGen.Controls.Add($genLayout)

    $tabs.TabPages.AddRange(@($tabDecode, $tabGen))
    $jwtForm.Controls.Add($tabs)
    $jwtForm.ShowDialog()
}

# --- REFACTORED: Environment Manager Window (now uses the top-level editor) ---
