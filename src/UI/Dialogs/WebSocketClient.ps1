function Show-WebSocketClient {
    param($parentForm)
    $wsForm = New-Object System.Windows.Forms.Form -Property @{ Text="WebSocket Client"; Size=New-Object System.Drawing.Size(750, 600); StartPosition="CenterParent"; BackColor = $script:Theme.FormBackground }
    
    $topPanel = New-Object System.Windows.Forms.FlowLayoutPanel -Property @{ Dock='Top'; AutoSize=$true; Padding=[System.Windows.Forms.Padding]::new(8); WrapContents=$false }
    $lblUrl = New-Label -Text "URL:" -Property @{ AutoSize=$true; TextAlign='MiddleLeft'; Margin=[System.Windows.Forms.Padding]::new(0,6,0,0) }
    $txtUrl = New-TextBox -Property @{ Width=320; Text="wss://echo.websocket.org" }
    $btnConnect = New-Button -Text "Connect" -Style 'Primary' -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(6,3,3,3) }
    $btnDisconnect = New-Button -Text "Disconnect" -Property @{ AutoSize=$true; Enabled=$false; Margin=[System.Windows.Forms.Padding]::new(3) }
    
    $btnSaveLog = New-Button -Text "Save Log" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(12,3,3,3) } -OnClick {
        $sfd = New-Object System.Windows.Forms.SaveFileDialog -Property @{ Filter="Text Files (*.txt)|*.txt"; FileName="websocket_log.txt" }
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $logBox.Text | Set-Content -Path $sfd.FileName }
    }
    $btnLoadLog = New-Button -Text "Load Log" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(3) } -OnClick {
        $ofd = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Filter="Text Files (*.txt)|*.txt" }
        if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $logBox.Text = Get-Content -Path $ofd.FileName -Raw }
    }
    $btnClearLog = New-Button -Text "Clear Log" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(3) } -OnClick {
        if ([System.Windows.Forms.MessageBox]::Show("Clear WebSocket log?", "Confirm", "YesNo") -eq "Yes") {
            $logBox.Clear()
        }
    }

    $lblStatus = New-Label -Text "Status: Disconnected" -Property @{ AutoSize=$true; Margin=[System.Windows.Forms.Padding]::new(10,6,0,0); ForeColor = [System.Drawing.Color]::DarkRed }
    $topPanel.Controls.AddRange(@($lblUrl, $txtUrl, $btnConnect, $btnDisconnect, $btnSaveLog, $btnLoadLog, $btnClearLog, $lblStatus))

    $logBox = New-RichTextBox -ReadOnly $true -Property @{ Dock='Fill'; BackColor='White'; Font=New-Object System.Drawing.Font("Consolas", 9); BorderStyle='None' }
    
    $bottomPanel = New-Object System.Windows.Forms.Panel -Property @{ Dock='Bottom'; Height=40; Padding=[System.Windows.Forms.Padding]::new(5) }
    $txtMsg = New-TextBox -Property @{ Dock='Fill' }
    $btnSend = New-Button -Text "Send" -Style 'Primary' -Property @{ Dock='Right'; Width=90; Enabled=$false }
    $bottomPanel.Controls.AddRange(@($btnSend, $txtMsg))

    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $buffer = New-Object byte[] 4096
    $timer = New-Object System.Windows.Forms.Timer -Property @{ Interval=100 }
    $script:wsTask = $null

    $btnConnect.Add_Click({
        try {
            if ($ws.State -ne 'None' -and $ws.State -ne 'Closed') { $ws = New-Object System.Net.WebSockets.ClientWebSocket }
            $uri = New-Object System.Uri($txtUrl.Text)
            $task = $ws.ConnectAsync($uri, [System.Threading.CancellationToken]::None)
            $task.Wait()
            if ($ws.State -eq 'Open') {
                $logBox.AppendText("[$([DateTime]::Now.ToString('HH:mm:ss'))] Connected to $($uri)`n")
                $btnConnect.Enabled = $false; $btnDisconnect.Enabled = $true; $btnSend.Enabled = $true
                $lblStatus.Text = "Status: Connected"
                $lblStatus.ForeColor = [System.Drawing.Color]::DarkGreen
                $timer.Start()
            }
        } catch { $logBox.AppendText("Error connecting: $($_.Exception.Message)`n") }
    })

    $btnDisconnect.Add_Click({
        if ($ws.State -eq 'Open') {
            $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "User Disconnect", [System.Threading.CancellationToken]::None) | Out-Null
            $logBox.AppendText("[$([DateTime]::Now.ToString('HH:mm:ss'))] Disconnected`n")
            $btnConnect.Enabled = $true; $btnDisconnect.Enabled = $false; $btnSend.Enabled = $false
            $lblStatus.Text = "Status: Disconnected"
            $lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
            $timer.Stop()
        }
    })

    $btnSend.Add_Click({
        if ($ws.State -eq 'Open' -and $txtMsg.Text) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($txtMsg.Text)
            $segment = New-Object System.ArraySegment[byte] -ArgumentList $bytes
            $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [System.Threading.CancellationToken]::None) | Out-Null
            $logBox.SelectionColor = 'Blue'
            $logBox.AppendText("[$([DateTime]::Now.ToString('HH:mm:ss'))] Sent: $($txtMsg.Text)`n")
            $txtMsg.Text = ""
        }
    })

    $timer.Add_Tick({
        if ($ws.State -eq 'Open') {
            if ($script:wsTask -eq $null) {
                $seg = New-Object System.ArraySegment[byte] -ArgumentList $buffer
                $script:wsTask = $ws.ReceiveAsync($seg, [System.Threading.CancellationToken]::None)
            } elseif ($script:wsTask.IsCompleted) {
                try {
                    $res = $script:wsTask.Result
                    if ($res.MessageType -eq 'Close') { 
                        $btnDisconnect.PerformClick() 
                    } else {
                        $msg = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $res.Count)
                        $logBox.SelectionColor = 'Green'
                        $logBox.AppendText("[$([DateTime]::Now.ToString('HH:mm:ss'))] Received: $msg`n")
                    }
                } catch { $logBox.AppendText("Error receiving: $($_.Exception.Message)`n") }
                $script:wsTask = $null
            }
        }
    })

    $wsForm.Controls.AddRange(@($logBox, $bottomPanel, $topPanel))
    $wsForm.ShowDialog($parentForm)
    if ($ws) { $ws.Dispose() }
}

# --- gRPC Client Window (Wrapper for grpcurl) ---
