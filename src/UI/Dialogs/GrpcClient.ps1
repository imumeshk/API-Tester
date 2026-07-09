function Show-GrpcClient {
    param($parentForm)
    Load-GrpcHistory

    $grpcForm = New-Object System.Windows.Forms.Form -Property @{ Text="gRPC Client (via grpcurl)"; Size=New-Object System.Drawing.Size(1100, 750); StartPosition="CenterParent"; BackColor=$script:Theme.FormBackground }
    
    $mainSplit = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock='Fill'; Orientation='Vertical'; SplitterDistance=280; BackColor=$script:Theme.FormBackground }

    # --- History Panel (Left) ---
    $historyGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text="History"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor=$script:Theme.GroupBackground }
    $historyLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=1; RowCount=2 }
    $historyLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $historyLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null

    $listHistory = New-Object System.Windows.Forms.ListBox -Property @{ Dock='Fill' }
    $btnClearHistory = New-Button -Text "Clear History" -Style 'Secondary' -Property @{ Dock='Fill'; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,8,0,0) } -OnClick {
        if ([System.Windows.Forms.MessageBox]::Show("Clear gRPC history?", "Confirm", "YesNo") -eq "Yes") {
            $script:grpcHistory = @()
            $listHistory.Items.Clear()
            Save-GrpcHistory
        }
    }
    $historyLayout.Controls.Add($listHistory, 0, 0)
    $historyLayout.Controls.Add($btnClearHistory, 0, 1)
    $historyGroup.Controls.Add($historyLayout)
    $mainSplit.Panel1.Controls.Add($historyGroup)

    # Populate History List
    foreach ($item in $script:grpcHistory) {
        $ts = Get-Date
        if ($item.Timestamp) {
            $tsStr = if ($item.Timestamp -is [PSCustomObject]) { $item.Timestamp.DateTime } else { $item.Timestamp }
            if (-not [DateTime]::TryParse($tsStr, [ref]$ts)) {
                 [void][DateTime]::TryParse($tsStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$ts)
            }
        }
        $listHistory.Items.Add("$($ts.ToString('HH:mm:ss')) | $($item.Method)")
    }

    # --- Client Panel (Right) ---
    $split = New-Object System.Windows.Forms.SplitContainer -Property @{ Dock='Fill'; Orientation='Horizontal'; SplitterDistance=330; BackColor=$script:Theme.FormBackground }
    
    # Input Panel
    $inputPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=2; RowCount=7; Padding=[System.Windows.Forms.Padding]::new(8) }
    $inputPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 30)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 70)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $inputPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    
    $txtHost = New-TextBox -Property @{ Dock='Fill'; Text='localhost:50051' }

    $protoPanel = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=2; RowCount=1; Margin=[System.Windows.Forms.Padding]::new(0) }
    $protoPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $protoPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $txtProtoFile = New-TextBox -Property @{ Dock='Fill'; PlaceholderText='Optional: Path to .proto file' }
    $btnBrowseProto = New-Button -Text "Browse" -Property @{ Width=70 } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter="Proto Files (*.proto)|*.proto|All Files (*.*)|*.*" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $txtProtoFile.Text = $ofd.FileName }
    }
    $protoPanel.Controls.Add($txtProtoFile, 0, 0); $protoPanel.Controls.Add($btnBrowseProto, 1, 0)

    $txtMethod = New-TextBox -Property @{ Dock='Fill'; Text='MyService/SayHello' }
    $txtHeaders = New-TextBox -Multiline $true -Property @{ Dock='Fill'; Text=''; Font=New-Object System.Drawing.Font("Courier New", 9); ScrollBars='Vertical' }
    $txtBody = New-TextBox -Multiline $true -Property @{ Dock='Fill'; Height=150; Text='{ "name": "World" }'; Font=New-Object System.Drawing.Font("Courier New", 9); ScrollBars='Vertical' }
    $chkPlaintext = New-Object System.Windows.Forms.CheckBox -Property @{ Text="Plaintext (-plaintext)"; AutoSize=$true; Checked=$true; Margin=[System.Windows.Forms.Padding]::new(0,8,0,0) }
    
    $inputPanel.Controls.Add((New-Label -Text "Host:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 0); $inputPanel.Controls.Add($txtHost, 1, 0)
    $inputPanel.Controls.Add((New-Label -Text "Proto File:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 1); $inputPanel.Controls.Add($protoPanel, 1, 1)
    $inputPanel.Controls.Add((New-Label -Text "Method:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 2); $inputPanel.Controls.Add($txtMethod, 1, 2)
    $inputPanel.Controls.Add((New-Label -Text "Headers:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 3); $inputPanel.Controls.Add($txtHeaders, 1, 3)
    $inputPanel.Controls.Add((New-Label -Text "JSON Body:" -Property @{AutoSize=$true; Anchor='Left'; TextAlign='MiddleLeft'}), 0, 4); $inputPanel.Controls.Add($txtBody, 1, 4)
    $inputPanel.Controls.Add($chkPlaintext, 0, 5); $inputPanel.SetColumnSpan($chkPlaintext, 2)
    
    $btnExecute = New-Button -Text "Execute gRPC" -Style 'Primary' -Property @{ Height=38; Dock='Fill'; Margin=[System.Windows.Forms.Padding]::new(0,10,0,0) } -OnClick {
        $txtOutput.Text = "Executing..."
        $hostAddr = $txtHost.Text
        $method = $txtMethod.Text
        $json = $txtBody.Text.Replace('"', '\"') # Simple escape for cmd line
        
        # Save to History
        $historyItem = [PSCustomObject]@{
            Timestamp = Get-Date
            Host = $hostAddr
            Method = $method
            Headers = $txtHeaders.Text
            Body = $txtBody.Text
            Plaintext = $chkPlaintext.Checked
        }
        $script:grpcHistory = @($historyItem) + $script:grpcHistory
        if ($script:grpcHistory.Count -gt 50) { $script:grpcHistory = $script:grpcHistory[0..49] }
        Save-GrpcHistory
        
        $listHistory.Items.Insert(0, "$($historyItem.Timestamp.ToString('HH:mm:ss')) | $($historyItem.Method)")
        if ($listHistory.Items.Count -gt 50) { $listHistory.Items.RemoveAt(50) }

        $argsList = @()
        if ($chkPlaintext.Checked) { $argsList += "-plaintext" }

        if (-not [string]::IsNullOrWhiteSpace($txtProtoFile.Text) -and (Test-Path $txtProtoFile.Text)) {
            $protoDir = Split-Path $txtProtoFile.Text
            $protoName = Split-Path $txtProtoFile.Text -Leaf
            $argsList += "-import-path", "`"$protoDir`"", "-proto", "`"$protoName`""
        }
        
        # Add Headers
        if (-not [string]::IsNullOrWhiteSpace($txtHeaders.Text)) {
            foreach ($line in $txtHeaders.Text -split "`n") {
                if ($line -match "^\s*(.+?):\s*(.+)$") {
                    $argsList += "-H", "`"$($matches[1]): $($matches[2])`""
                }
            }
        }

        $argsList += "-d", "`"$json`"", $hostAddr, $method
        
        # Resolve grpcurl path (check script dir first, then PATH)
        $grpCurlPath = "grpcurl"
        $localPath = Join-Path $scriptRoot "grpcurl.exe"
        if (Test-Path $localPath) {
            $grpCurlPath = $localPath
        } elseif (-not (Get-Command "grpcurl" -ErrorAction SilentlyContinue -CommandType Application)) {
            $txtOutput.Text = "Error: 'grpcurl' executable not found.`r`nPlease download it and place 'grpcurl.exe' in:`r`n$scriptRoot`r`nOr add it to your system PATH."
            return
        }

        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $grpCurlPath
            $psi.Arguments = $argsList -join " "
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            
            $p = [System.Diagnostics.Process]::Start($psi)
            $p.WaitForExit()
            $out = $p.StandardOutput.ReadToEnd()
            $err = $p.StandardError.ReadToEnd()
            $txtOutput.Text = if ($err) { "STDERR:`r`n$err`r`nSTDOUT:`r`n$out" } else { $out }
        } catch {
            $txtOutput.Text = "Error executing grpcurl. Ensure 'grpcurl' is installed and in your PATH.`r`nError: $($_.Exception.Message)"
        }
    }
    $inputPanel.Controls.Add($btnExecute, 0, 5)
    $inputPanel.SetColumnSpan($btnExecute, 2)
    
    $outputTools = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Top'; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(0); Margin=[System.Windows.Forms.Padding]::new(0); FlowDirection='LeftToRight'; WrapContents=$false }
    $btnBeautify = New-Button -Text "Beautify JSON" -Style 'Secondary' -Property @{ Width=140; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,0,8,0) } -OnClick {
        if ([string]::IsNullOrWhiteSpace($txtOutput.Text)) { return }
        try {
            $json = $txtOutput.Text | ConvertFrom-Json
            $txtOutput.Text = $json | ConvertTo-Json -Depth 10
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Invalid JSON: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
    $btnDownload = New-Button -Text "Download grpcurl" -Style 'Secondary' -Property @{ Width=160; Height=32; Margin=[System.Windows.Forms.Padding]::new(0,0,8,0) } -OnClick {
        try {
            $txtOutput.Text = "Checking for latest grpcurl release..."
            [System.Windows.Forms.Application]::DoEvents()
            
            $latest = Invoke-RestMethod "https://api.github.com/repos/fullstorydev/grpcurl/releases/latest"
            $asset = $latest.assets | Where-Object { $_.name -match "windows_x86_64.zip" } | Select-Object -First 1
            
            if (-not $asset) { throw "Could not find Windows x64 asset in latest release." }
            
            $zipPath = Join-Path $env:TEMP $asset.name
            $txtOutput.Text += "`r`nDownloading $($asset.browser_download_url)..."
            [System.Windows.Forms.Application]::DoEvents()
            
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
            
            $txtOutput.Text += "`r`nExtracting..."
            [System.Windows.Forms.Application]::DoEvents()
            
            Expand-Archive -Path $zipPath -DestinationPath $scriptRoot -Force
            
            $txtOutput.Text += "`r`nDone! 'grpcurl.exe' installed to $scriptRoot."
            Remove-Item $zipPath -ErrorAction SilentlyContinue
        } catch {
            $txtOutput.Text += "`r`nError: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show("Failed to download grpcurl: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
    $outputTools.Controls.Add($btnBeautify)
    $outputTools.Controls.Add($btnDownload)

    $txtOutput = New-RichTextBox -ReadOnly $true -Property @{ Dock='Fill'; Font=New-Object System.Drawing.Font("Courier New", 9); BackColor='White'; BorderStyle='FixedSingle' }
    
    $inputGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Request"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor=$script:Theme.GroupBackground }
    $inputGroup.Controls.Add($inputPanel)

    $outputGroup = New-Object System.Windows.Forms.GroupBox -Property @{ Text="Response"; Dock='Fill'; Padding=[System.Windows.Forms.Padding]::new(10); BackColor=$script:Theme.GroupBackground }
    $outputLayout = New-Object System.Windows.Forms.TableLayoutPanel -Property @{ Dock='Fill'; ColumnCount=1; RowCount=2 }
    $outputLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
    $outputLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $outputLayout.Controls.Add($outputTools, 0, 0)
    $outputLayout.Controls.Add($txtOutput, 0, 1)
    $outputGroup.Controls.Add($outputLayout)
    
    $split.Panel1.Controls.Add($inputGroup)
    $split.Panel2.Controls.Add($outputGroup)
    
    $mainSplit.Panel2.Controls.Add($split)

    # History Selection Event
    $listHistory.Add_SelectedIndexChanged({
        if ($listHistory.SelectedIndex -ne -1) {
            $item = $script:grpcHistory[$listHistory.SelectedIndex]
            $txtHost.Text = $item.Host
            $txtMethod.Text = $item.Method
            $txtHeaders.Text = $item.Headers
            $txtBody.Text = $item.Body
            $chkPlaintext.Checked = $item.Plaintext
        }
    })

    $grpcForm.Controls.Add($mainSplit)
    $grpcForm.ShowDialog($parentForm)
}

# --- Monitoring Dashboard Window ---
