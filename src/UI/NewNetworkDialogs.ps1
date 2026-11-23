#region XAML network dialogs (WebSocket, gRPC, Load tester)

# Status colours that stay readable on both themes: the dark theme uses lighter shades of the same colours.
function ConvertTo-ThemeColor {
    param([string]$Color)
    if ($script:settings.AppTheme -ne 'Dark') { return $Color }
    $lighter = @{ '#15803D' = '#4ADE80'; '#2563EB' = '#60A5FA'; '#B91C1C' = '#F87171'; '#B45309' = '#FBBF24'; '#D93025' = '#F87171'; '#107C10' = '#4ADE80' }
    if ($lighter.ContainsKey($Color.ToUpperInvariant())) { return $lighter[$Color.ToUpperInvariant()] }
    return $Color
}

function Add-RichTextLine {
    param($Box, [string]$Text, [string]$Color = '')
    $paragraph = New-Object System.Windows.Documents.Paragraph
    $paragraph.Margin = [System.Windows.Thickness]::new(0)
    $run = New-Object System.Windows.Documents.Run($Text)
    if ($Color) { $run.Foreground = ConvertTo-WpfBrush (ConvertTo-ThemeColor $Color) }
    [void]$paragraph.Inlines.Add($run)
    [void]$Box.Document.Blocks.Add($paragraph)
    $Box.ScrollToEnd()
}

function Get-RichTextContent {
    param($Box)
    return (New-Object System.Windows.Documents.TextRange($Box.Document.ContentStart, $Box.Document.ContentEnd)).Text
}

# ------------------------------------------------------------------------------------------------
# WebSocket client
# ------------------------------------------------------------------------------------------------

function Show-WebSocketDialog {
    $body = @'
  <Grid Margin="18,16,18,16">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Grid>
      <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <TextBlock Text="URL" VerticalAlignment="Center" FontWeight="SemiBold" Margin="0,0,10,0"/>
      <TextBox x:Name="WsUrlBox" Grid.Column="1" Height="34" VerticalContentAlignment="Center" Text="wss://echo.websocket.org"/>
      <Button x:Name="ConnectButton" Grid.Column="2" Style="{StaticResource PrimaryButton}" Width="112" Height="34" Margin="10,0,0,0" Content="Connect"/>
      <Button x:Name="DisconnectButton" Grid.Column="3" Width="112" Height="34" Margin="8,0,0,0" Content="Disconnect" IsEnabled="False"/>
    </Grid>
    <DockPanel Grid.Row="1" Margin="0,12,0,8">
      <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
        <Button x:Name="SaveLogButton" Width="100" Height="30" Margin="0,0,6,0" Content="Save log"/>
        <Button x:Name="LoadLogButton" Width="100" Height="30" Margin="0,0,6,0" Content="Load log"/>
        <Button x:Name="ClearLogButton" Width="100" Height="30" Content="Clear log"/>
      </StackPanel>
      <Border Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="13" Padding="12,4" HorizontalAlignment="Left" VerticalAlignment="Center">
        <TextBlock x:Name="WsStatusText" FontWeight="SemiBold" Text="&#x25CF; Disconnected"/>
      </Border>
    </DockPanel>
    <RichTextBox x:Name="WsLogBox" Grid.Row="2" IsReadOnly="True" FontFamily="Consolas" FontSize="12" VerticalScrollBarVisibility="Auto"/>
    <Grid Grid.Row="3" Margin="0,10,0,0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <TextBox x:Name="WsMessageBox" Height="34" VerticalContentAlignment="Center" ToolTip="Message to send - Enter sends"/>
      <Button x:Name="SendButton" Grid.Column="1" Style="{StaticResource PrimaryButton}" Width="112" Height="34" Margin="10,0,0,0" Content="Send" IsEnabled="False"/>
    </Grid>
  </Grid>
'@
    $names = 'WsUrlBox', 'ConnectButton', 'DisconnectButton', 'SaveLogButton', 'LoadLogButton', 'ClearLogButton', 'WsStatusText', 'WsLogBox', 'SendButton', 'WsMessageBox'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'WebSocket client' -Width 820 -Height 620
    $window = $dialog.Window; $controls = $dialog.Controls
    $script:ws = New-Object System.Net.WebSockets.ClientWebSocket
    $script:wsBuffer = New-Object byte[] 8192
    $script:wsReceiveTask = $null
    $script:wsConnectTask = $null
    $script:wsMessage = New-Object System.Text.StringBuilder
    $stamp = { Get-Date -Format 'HH:mm:ss' }

    $setConnected = {
        param([bool]$Connected)
        $controls['ConnectButton'].IsEnabled = -not $Connected; $controls['DisconnectButton'].IsEnabled = $Connected; $controls['SendButton'].IsEnabled = $Connected
        $controls['WsStatusText'].Text = if ($Connected) { "$([char]0x25CF) Connected" } else { "$([char]0x25CF) Disconnected" }
        $controls['WsStatusText'].Foreground = ConvertTo-WpfBrush (ConvertTo-ThemeColor $(if ($Connected) { '#15803D' } else { '#B91C1C' }))
    }
    $disconnect = {
        try { if ($script:ws.State -eq 'Open') { [void]$script:ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'User disconnect', [System.Threading.CancellationToken]::None) } } catch { }
        $script:wsReceiveTask = $null
        Add-RichTextLine -Box $controls['WsLogBox'] -Text "[$(& $stamp)] Disconnected"
        & $setConnected $false
    }

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(100)
    $timer.Add_Tick({
        if ($script:wsConnectTask) {
            if (-not $script:wsConnectTask.IsCompleted) { return }
            $connectTask = $script:wsConnectTask; $script:wsConnectTask = $null
            if ($connectTask.IsFaulted -or $script:ws.State -ne 'Open') {
                $reason = if ($connectTask.IsFaulted) { $connectTask.Exception.GetBaseException().Message } else { 'The connection was not opened.' }
                Add-RichTextLine -Box $controls['WsLogBox'] -Text "[$(& $stamp)] Error connecting: $reason" -Color '#B91C1C'
                & $setConnected $false
            } else {
                Add-RichTextLine -Box $controls['WsLogBox'] -Text "[$(& $stamp)] Connected to $($controls['WsUrlBox'].Text)"
                & $setConnected $true
            }
            return
        }
        if ($script:ws.State -ne 'Open') { return }
        if (-not $script:wsReceiveTask) {
            $script:wsReceiveTask = $script:ws.ReceiveAsync([System.ArraySegment[byte]]::new($script:wsBuffer), [System.Threading.CancellationToken]::None)
        } elseif ($script:wsReceiveTask.IsCompleted) {
            $receiveTask = $script:wsReceiveTask; $script:wsReceiveTask = $null
            if ($receiveTask.IsFaulted) { Add-RichTextLine -Box $controls['WsLogBox'] -Text "[$(& $stamp)] Error receiving: $($receiveTask.Exception.GetBaseException().Message)" -Color '#B91C1C'; & $disconnect; return }
            $received = $receiveTask.Result
            if ($received.MessageType -eq 'Close') { & $disconnect; return }
            [void]$script:wsMessage.Append([System.Text.Encoding]::UTF8.GetString($script:wsBuffer, 0, $received.Count))
            if ($received.EndOfMessage) {
                Add-RichTextLine -Box $controls['WsLogBox'] -Text "[$(& $stamp)] Received: $($script:wsMessage.ToString())" -Color '#15803D'
                [void]$script:wsMessage.Clear()
            }
        }
    })
    $timer.Start()

    $controls['ConnectButton'].Add_Click({
        try {
            if ($script:ws.State -ne 'None') { $script:ws.Dispose(); $script:ws = New-Object System.Net.WebSockets.ClientWebSocket }
            $script:wsConnectTask = $script:ws.ConnectAsync((New-Object System.Uri($controls['WsUrlBox'].Text)), [System.Threading.CancellationToken]::None)
            $controls['WsStatusText'].Text = "$([char]0x25CF) Connecting..."; $controls['WsStatusText'].Foreground = ConvertTo-WpfBrush (ConvertTo-ThemeColor '#B45309')
            $controls['ConnectButton'].IsEnabled = $false
        } catch { Add-RichTextLine -Box $controls['WsLogBox'] -Text "Error connecting: $($_.Exception.Message)" -Color '#B91C1C'; $controls['ConnectButton'].IsEnabled = $true }
    })
    $controls['DisconnectButton'].Add_Click({ & $disconnect })
    $send = {
        if ($script:ws.State -ne 'Open' -or -not $controls['WsMessageBox'].Text) { return }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($controls['WsMessageBox'].Text)
        [void]$script:ws.SendAsync([System.ArraySegment[byte]]::new($bytes), [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [System.Threading.CancellationToken]::None)
        Add-RichTextLine -Box $controls['WsLogBox'] -Text "[$(& $stamp)] Sent: $($controls['WsMessageBox'].Text)" -Color '#2563EB'
        $controls['WsMessageBox'].Text = ''
    }
    $controls['SendButton'].Add_Click($send)
    $controls['WsMessageBox'].Add_KeyDown({ param($sender, $keyArgs) if ($keyArgs.Key -eq [System.Windows.Input.Key]::Return) { & $send; $keyArgs.Handled = $true } })
    $controls['SaveLogButton'].Add_Click({
        $picker = New-Object Microsoft.Win32.SaveFileDialog; $picker.Filter = 'Text files (*.txt)|*.txt'; $picker.FileName = 'websocket_log.txt'
        if ($picker.ShowDialog($window) -eq $true) { Get-RichTextContent -Box $controls['WsLogBox'] | Set-Content -Path $picker.FileName }
    })
    $controls['LoadLogButton'].Add_Click({
        $picker = New-Object Microsoft.Win32.OpenFileDialog; $picker.Filter = 'Text files (*.txt)|*.txt'
        if ($picker.ShowDialog($window) -ne $true) { return }
        $controls['WsLogBox'].Document.Blocks.Clear()
        foreach ($line in (Get-Content -Path $picker.FileName)) { Add-RichTextLine -Box $controls['WsLogBox'] -Text $line }
    })
    $controls['ClearLogButton'].Add_Click({
        if ([System.Windows.MessageBox]::Show($window, 'Clear the WebSocket log?', 'Confirm', 'YesNo', 'Question') -eq 'Yes') { $controls['WsLogBox'].Document.Blocks.Clear() }
    })
    $window.Add_Closing({ $timer.Stop(); try { $script:ws.Dispose() } catch { } })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

# ------------------------------------------------------------------------------------------------
# gRPC client (wraps grpcurl)
# ------------------------------------------------------------------------------------------------

function Show-GrpcDialog {
    Import-GrpcHistory
    $body = @'
  <Grid Margin="16,14,16,14">
    <Grid.ColumnDefinitions><ColumnDefinition Width="260"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <Grid>
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
      <TextBlock Style="{StaticResource SectionLabel}" Text="HISTORY"/>
      <ListBox x:Name="GrpcHistoryList" Grid.Row="1" Margin="0,6,0,8"/>
      <Button x:Name="GrpcClearHistoryButton" Grid.Row="2" Padding="12,5" Content="Clear history"/>
    </Grid>
    <Grid Grid.Column="2">
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="1*"/><RowDefinition Height="1.4*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="1.6*"/></Grid.RowDefinitions>
      <Grid.ColumnDefinitions><ColumnDefinition Width="90"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <TextBlock Text="Host" VerticalAlignment="Center"/><TextBox x:Name="GrpcHostBox" Grid.Column="1" Height="28" VerticalContentAlignment="Center" Margin="0,3" Text="localhost:50051"/>
      <TextBlock Grid.Row="1" Text="Proto file" VerticalAlignment="Center"/>
      <DockPanel Grid.Row="1" Grid.Column="1" Margin="0,3"><Button x:Name="GrpcBrowseProtoButton" DockPanel.Dock="Right" Margin="6,0,0,0" Padding="12,3" Content="Browse"/><TextBox x:Name="GrpcProtoBox" Height="28" VerticalContentAlignment="Center" ToolTip="Optional: path to a .proto file"/></DockPanel>
      <TextBlock Grid.Row="2" Text="Method" VerticalAlignment="Center"/><TextBox x:Name="GrpcMethodBox" Grid.Row="2" Grid.Column="1" Height="28" VerticalContentAlignment="Center" Margin="0,3" Text="MyService/SayHello"/>
      <TextBlock Grid.Row="3" Text="Headers" Margin="0,6,0,0"/><TextBox x:Name="GrpcHeadersBox" Grid.Row="3" Grid.Column="1" Margin="0,3" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto" ToolTip="Name: value, one per line"/>
      <TextBlock Grid.Row="4" Text="JSON body" Margin="0,6,0,0"/><TextBox x:Name="GrpcBodyBox" Grid.Row="4" Grid.Column="1" Margin="0,3" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/>
      <CheckBox x:Name="GrpcPlaintextBox" Grid.Row="5" Grid.Column="1" Content="Use plaintext (no TLS)" IsChecked="True" Margin="0,6"/>
      <WrapPanel Grid.Row="6" Grid.ColumnSpan="2" Margin="0,4,0,6">
        <Button x:Name="GrpcExecuteButton" Style="{StaticResource PrimaryButton}" Padding="18,6" Margin="0,0,8,0" Content="Execute gRPC"/>
        <Button x:Name="GrpcBeautifyButton" Padding="14,6" Margin="0,0,8,0" Content="Beautify JSON"/>
        <Button x:Name="GrpcDownloadButton" Padding="14,6" Content="Download grpcurl"/>
      </WrapPanel>
      <TextBox x:Name="GrpcOutputBox" Grid.Row="7" Grid.ColumnSpan="2" IsReadOnly="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
    </Grid>
  </Grid>
'@
    $names = 'GrpcHistoryList', 'GrpcClearHistoryButton', 'GrpcHostBox', 'GrpcBrowseProtoButton', 'GrpcProtoBox', 'GrpcMethodBox', 'GrpcHeadersBox', 'GrpcBodyBox', 'GrpcPlaintextBox', 'GrpcExecuteButton', 'GrpcBeautifyButton', 'GrpcDownloadButton', 'GrpcOutputBox'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'gRPC client (via grpcurl)' -Width 1100 -Height 760
    $window = $dialog.Window; $controls = $dialog.Controls
    $controls['GrpcBodyBox'].Text = '{ "name": "World" }'

    $refreshHistory = {
        $controls['GrpcHistoryList'].Items.Clear()
        foreach ($entry in @($script:grpcHistory | Where-Object { $_ })) {
            $time = ConvertTo-HistoryTime -Timestamp $entry.Timestamp
            $item = New-Object System.Windows.Controls.ListBoxItem
            $item.Content = "$(if ($time) { $time.ToString('HH:mm:ss') } else { '??:??:??' }) | $($entry.Method)"
            $item.Tag = $entry
            [void]$controls['GrpcHistoryList'].Items.Add($item)
        }
    }
    & $refreshHistory
    $controls['GrpcHistoryList'].Add_SelectionChanged({
        $selected = $controls['GrpcHistoryList'].SelectedItem
        if (-not $selected) { return }
        $entry = $selected.Tag
        $controls['GrpcHostBox'].Text = [string]$entry.Host; $controls['GrpcMethodBox'].Text = [string]$entry.Method
        $controls['GrpcHeadersBox'].Text = [string]$entry.Headers; $controls['GrpcBodyBox'].Text = [string]$entry.Body; $controls['GrpcPlaintextBox'].IsChecked = [bool]$entry.Plaintext
    })
    $controls['GrpcClearHistoryButton'].Add_Click({
        if ([System.Windows.MessageBox]::Show($window, 'Clear gRPC history?', 'Confirm', 'YesNo', 'Question') -ne 'Yes') { return }
        $script:grpcHistory = @(); Save-GrpcHistory; & $refreshHistory
    })
    $controls['GrpcBrowseProtoButton'].Add_Click({
        $picker = New-Object Microsoft.Win32.OpenFileDialog; $picker.Filter = 'Proto files (*.proto)|*.proto|All files (*.*)|*.*'
        if ($picker.ShowDialog($window) -eq $true) { $controls['GrpcProtoBox'].Text = $picker.FileName }
    })
    $controls['GrpcBeautifyButton'].Add_Click({
        if ([string]::IsNullOrWhiteSpace($controls['GrpcOutputBox'].Text)) { return }
        try { $controls['GrpcOutputBox'].Text = Format-JsonText -Text $controls['GrpcOutputBox'].Text } catch { $controls['GrpcOutputBox'].Text += "`r`nInvalid JSON: $($_.Exception.Message)" }
    })

    $controls['GrpcDownloadButton'].Add_Click({
        try {
            $controls['GrpcOutputBox'].Text = 'Checking for the latest grpcurl release...'; Update-UiNow
            $latest = Invoke-RestMethod 'https://api.github.com/repos/fullstorydev/grpcurl/releases/latest'
            $asset = $latest.assets | Where-Object { $_.name -match 'windows_x86_64.zip' } | Select-Object -First 1
            if (-not $asset) { throw 'Could not find a Windows x64 asset in the latest release.' }
            $zipPath = Join-Path $env:TEMP $asset.name
            $controls['GrpcOutputBox'].AppendText("`r`nDownloading $($asset.browser_download_url)..."); Update-UiNow
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
            Expand-Archive -Path $zipPath -DestinationPath $scriptRoot -Force
            Remove-Item $zipPath -ErrorAction SilentlyContinue
            $controls['GrpcOutputBox'].AppendText("`r`nDone. grpcurl.exe was installed to $scriptRoot.")
        } catch { $controls['GrpcOutputBox'].AppendText("`r`nError: $($_.Exception.Message)") }
    })

    # Runs grpcurl without blocking the window: a timer waits for the process and its output readers.
    $script:grpcProcess = $null
    $grpcTimer = New-Object System.Windows.Threading.DispatcherTimer
    $grpcTimer.Interval = [TimeSpan]::FromMilliseconds(150)
    $grpcTimer.Add_Tick({
        if (-not $script:grpcProcess -or -not $script:grpcProcess.Process.HasExited) { return }
        $grpcTimer.Stop()
        $out = $script:grpcProcess.StdOut.Result; $err = $script:grpcProcess.StdErr.Result
        $script:grpcProcess = $null
        $controls['GrpcOutputBox'].Text = if ($err) { "STDERR:`r`n$err`r`nSTDOUT:`r`n$out" } else { $out }
        $controls['GrpcExecuteButton'].IsEnabled = $true
    })
    $controls['GrpcExecuteButton'].Add_Click({
        $hostAddress = $controls['GrpcHostBox'].Text; $method = $controls['GrpcMethodBox'].Text
        $historyItem = [PSCustomObject]@{ Timestamp = Get-Date; Host = $hostAddress; Method = $method; Headers = $controls['GrpcHeadersBox'].Text; Body = $controls['GrpcBodyBox'].Text; Plaintext = [bool]$controls['GrpcPlaintextBox'].IsChecked }
        $script:grpcHistory = @($historyItem) + @($script:grpcHistory | Where-Object { $_ })
        if ($script:grpcHistory.Count -gt 50) { $script:grpcHistory = @($script:grpcHistory[0..49]) }
        Save-GrpcHistory; & $refreshHistory

        $arguments = @()
        if ($controls['GrpcPlaintextBox'].IsChecked) { $arguments += '-plaintext' }
        $protoPath = $controls['GrpcProtoBox'].Text
        if (-not [string]::IsNullOrWhiteSpace($protoPath) -and (Test-Path $protoPath)) { $arguments += '-import-path', "`"$(Split-Path $protoPath)`"", '-proto', "`"$(Split-Path $protoPath -Leaf)`"" }
        foreach ($line in ($controls['GrpcHeadersBox'].Text -split "`r?`n")) { if ($line -match '^\s*(.+?):\s*(.+)$') { $arguments += '-H', "`"$($Matches[1]): $($Matches[2])`"" } }
        $arguments += '-d', "`"$($controls['GrpcBodyBox'].Text.Replace('"', '\"'))`"", $hostAddress, $method

        $executable = 'grpcurl'
        $localPath = Join-Path $scriptRoot 'grpcurl.exe'
        if (Test-Path $localPath) { $executable = $localPath }
        elseif (-not (Get-Command 'grpcurl' -ErrorAction SilentlyContinue -CommandType Application)) {
            $controls['GrpcOutputBox'].Text = "Error: 'grpcurl' was not found.`r`nUse 'Download grpcurl', or place grpcurl.exe in:`r`n$scriptRoot`r`nor add it to your PATH."
            return
        }
        try {
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $executable; $startInfo.Arguments = $arguments -join ' '
            $startInfo.RedirectStandardOutput = $true; $startInfo.RedirectStandardError = $true; $startInfo.UseShellExecute = $false; $startInfo.CreateNoWindow = $true
            $process = [System.Diagnostics.Process]::Start($startInfo)
            $script:grpcProcess = @{ Process = $process; StdOut = $process.StandardOutput.ReadToEndAsync(); StdErr = $process.StandardError.ReadToEndAsync() }
            $controls['GrpcOutputBox'].Text = 'Executing...'; $controls['GrpcExecuteButton'].IsEnabled = $false
            $grpcTimer.Start()
        } catch { $controls['GrpcOutputBox'].Text = "Error executing grpcurl: $($_.Exception.Message)" }
    })
    $window.Add_Closing({ $grpcTimer.Stop() })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}

# ------------------------------------------------------------------------------------------------
# Load tester (concurrent async requests driven by a UI timer - no runspaces needed)
# ------------------------------------------------------------------------------------------------

function Show-LoadTestDialog {
    param($RequestObject = $null)
    $body = @'
  <Grid Margin="16,14,16,14">
    <Grid.ColumnDefinitions><ColumnDefinition Width="300"/><ColumnDefinition Width="14"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel>
      <TextBlock Style="{StaticResource SectionLabel}" Text="URL"/><TextBox x:Name="LtUrlBox" Height="28" Margin="0,4,0,8" VerticalContentAlignment="Center"/>
      <TextBlock Style="{StaticResource SectionLabel}" Text="METHOD"/><ComboBox x:Name="LtMethodBox" Height="28" Margin="0,4,0,8" VerticalContentAlignment="Center"/>
      <TextBlock Style="{StaticResource SectionLabel}" Text="HEADERS"/><TextBox x:Name="LtHeadersBox" Height="70" Margin="0,4,0,8" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/>
      <TextBlock Style="{StaticResource SectionLabel}" Text="BODY"/><TextBox x:Name="LtBodyBox" Height="70" Margin="0,4,0,8" AcceptsReturn="True" FontFamily="Consolas" VerticalScrollBarVisibility="Auto"/>
      <TextBlock Style="{StaticResource SectionLabel}" Text="CONCURRENT THREADS (1-100)"/><TextBox x:Name="LtThreadsBox" Height="28" Margin="0,4,0,8" VerticalContentAlignment="Center" Text="10"/>
      <TextBlock Style="{StaticResource SectionLabel}" Text="DURATION (SECONDS)"/><TextBox x:Name="LtDurationBox" Height="28" Margin="0,4,0,12" VerticalContentAlignment="Center" Text="5"/>
      <TextBlock x:Name="LtRequestsText" Text="Requests: 0"/><TextBlock x:Name="LtSuccessText" Text="Success: 0"/><TextBlock x:Name="LtFailedText" Text="Failed: 0"/><TextBlock x:Name="LtLatencyText" Text="Avg latency: 0 ms"/><TextBlock x:Name="LtMessageText" Margin="0,6,0,0" Foreground="#B91C1C" TextWrapping="Wrap"/>
    </StackPanel></ScrollViewer>
    <Border Grid.Column="2" Background="{StaticResource Surface}" BorderBrush="{StaticResource Border}" BorderThickness="1" CornerRadius="6"><Canvas x:Name="LtChart" ClipToBounds="True"/></Border>
    <StackPanel Grid.Row="1" Grid.ColumnSpan="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="LtStartButton" Style="{StaticResource PrimaryButton}" Width="120" Content="Start test"/>
      <Button x:Name="LtStopButton" Width="100" Margin="8,0,0,0" Content="Stop" IsEnabled="False"/>
      <Button x:Name="LtCloseButton" IsCancel="True" Width="90" Margin="8,0,0,0" Content="Close"/>
    </StackPanel>
  </Grid>
'@
    $names = 'LtUrlBox', 'LtMethodBox', 'LtHeadersBox', 'LtBodyBox', 'LtThreadsBox', 'LtDurationBox', 'LtRequestsText', 'LtSuccessText', 'LtFailedText', 'LtLatencyText', 'LtMessageText', 'LtChart', 'LtStartButton', 'LtStopButton', 'LtCloseButton'
    $dialog = New-DialogWindow -BodyXaml $body -ControlNames $names -Title 'Load tester' -Width 1000 -Height 640
    $window = $dialog.Window; $controls = $dialog.Controls
    foreach ($method in @('GET', 'POST', 'PUT', 'DELETE', 'PATCH')) { [void]$controls['LtMethodBox'].Items.Add($method) }
    $controls['LtUrlBox'].Text = if ($RequestObject -and $RequestObject.Url) { [string]$RequestObject.Url } else { 'https://httpbin.org/get' }
    $controls['LtMethodBox'].SelectedItem = if ($RequestObject -and $RequestObject.Method -and $controls['LtMethodBox'].Items.Contains([string]$RequestObject.Method)) { [string]$RequestObject.Method } else { 'GET' }
    if ($RequestObject -and $RequestObject.Headers) {
        $controls['LtHeadersBox'].Text = if ($RequestObject.Headers -is [string]) { $RequestObject.Headers } else { (@($RequestObject.Headers.GetEnumerator() | ForEach-Object { "$($_.Name): $($_.Value)" }) -join "`r`n") }
    }
    if ($RequestObject -and $RequestObject.Body) { $controls['LtBodyBox'].Text = [string]$RequestObject.Body }
    $controls['LtChart'].SetResourceReference([System.Windows.Controls.Panel]::BackgroundProperty, 'Surface')

    $script:loadTest = @{ Running = $false; Client = $null; InFlight = (New-Object System.Collections.ArrayList); Total = 0; Success = 0; Failed = 0; LatencySum = 0.0
        Start = $null; End = $null; Threads = 10; LastSample = [datetime]::MinValue; X = (New-Object System.Collections.ArrayList); Rps = (New-Object System.Collections.ArrayList); Lat = (New-Object System.Collections.ArrayList) }

    $drawChart = {
        Update-LineChart -Canvas $controls['LtChart'] -Series @(
            @{ Name = 'Requests/sec'; Color = '#3659C9'; X = @($script:loadTest.X); Y = @($script:loadTest.Rps); Axis = 'Left' },
            @{ Name = 'Latency (ms)'; Color = '#F97316'; X = @($script:loadTest.X); Y = @($script:loadTest.Lat); Axis = 'Right' }) -LeftTitle 'Requests/sec' -RightTitle 'Latency (ms)' -EmptyText 'Start a test to see throughput and latency.'
    }
    $controls['LtChart'].Add_SizeChanged({ & $drawChart })

    $newMessage = {
        $message = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::new($script:loadTest.Method), $script:loadTest.Url)
        $content = $null
        if ($script:loadTest.Body -and $script:loadTest.Method -in @('POST', 'PUT', 'PATCH', 'DELETE')) {
            $contentType = 'application/json'
            foreach ($entry in $script:loadTest.Headers) { if ($entry.Name -ieq 'Content-Type') { $contentType = ($entry.Value -split ';')[0].Trim() } }
            try { $content = New-Object System.Net.Http.StringContent($script:loadTest.Body, [System.Text.Encoding]::UTF8, $contentType) } catch { $content = New-Object System.Net.Http.StringContent($script:loadTest.Body) }
            $message.Content = $content
        }
        foreach ($entry in $script:loadTest.Headers) {
            if ($entry.Name -ieq 'Content-Type') { continue }
            if (-not $message.Headers.TryAddWithoutValidation($entry.Name, $entry.Value) -and $content) { [void]$content.Headers.TryAddWithoutValidation($entry.Name, $entry.Value) }
        }
        return $message
    }
    $updateStats = {
        $test = $script:loadTest
        $average = if ($test.Total -gt 0) { [Math]::Round($test.LatencySum / $test.Total, 2) } else { 0 }
        $controls['LtRequestsText'].Text = "Requests: $($test.Total)"; $controls['LtSuccessText'].Text = "Success: $($test.Success)"; $controls['LtFailedText'].Text = "Failed: $($test.Failed)"; $controls['LtLatencyText'].Text = "Avg latency: $average ms"
        return $average
    }
    $finish = {
        $script:loadTestTimer.Stop()
        foreach ($flight in $script:loadTest.InFlight) { try { $flight.Message.Dispose() } catch { } }
        $script:loadTest.InFlight.Clear()
        try { if ($script:loadTest.Client) { $script:loadTest.Client.Dispose() } } catch { }
        $script:loadTest.Running = $false
        $controls['LtStartButton'].IsEnabled = $true; $controls['LtStopButton'].IsEnabled = $false
        & $drawChart
    }

    $script:loadTestTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:loadTestTimer.Interval = [TimeSpan]::FromMilliseconds(40)
    $script:loadTestTimer.Add_Tick({
        $test = $script:loadTest
        if (-not $test.Running) { return }
        foreach ($flight in @($test.InFlight)) {
            if (-not $flight.Task.IsCompleted) { continue }
            [void]$test.InFlight.Remove($flight)
            $flight.Stopwatch.Stop()
            $test.Total++; $test.LatencySum += $flight.Stopwatch.ElapsedMilliseconds
            if (-not $flight.Task.IsFaulted -and -not $flight.Task.IsCanceled -and $flight.Task.Result.IsSuccessStatusCode) { $test.Success++ } else { $test.Failed++ }
            try { if ($flight.Task.Status -eq 'RanToCompletion') { $flight.Task.Result.Dispose() }; $flight.Message.Dispose() } catch { }
        }
        $now = [datetime]::Now
        if ($now -lt $test.End) {
            while ($test.InFlight.Count -lt $test.Threads) {
                $message = & $newMessage
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                [void]$test.InFlight.Add(@{ Task = $test.Client.SendAsync($message); Message = $message; Stopwatch = $stopwatch })
            }
        }
        if (($now - $test.LastSample).TotalSeconds -ge 1) {
            $test.LastSample = $now
            $average = & $updateStats
            $elapsed = ($now - $test.Start).TotalSeconds
            [void]$test.X.Add($elapsed); [void]$test.Rps.Add($(if ($elapsed -gt 0) { [Math]::Round($test.Total / $elapsed, 2) } else { 0 })); [void]$test.Lat.Add($average)
            & $drawChart
        }
        if ($now -ge $test.End -and $test.InFlight.Count -eq 0) { [void](& $updateStats); & $finish }
    })

    $controls['LtStartButton'].Add_Click({
        $threads = 0; $duration = 0
        if (-not [int]::TryParse($controls['LtThreadsBox'].Text, [ref]$threads) -or $threads -lt 1 -or $threads -gt 100) { $controls['LtMessageText'].Text = 'Threads must be 1-100.'; return }
        if (-not [int]::TryParse($controls['LtDurationBox'].Text, [ref]$duration) -or $duration -lt 1 -or $duration -gt 3600) { $controls['LtMessageText'].Text = 'Duration must be 1-3600 seconds.'; return }
        if ([string]::IsNullOrWhiteSpace($controls['LtUrlBox'].Text)) { $controls['LtMessageText'].Text = 'Enter a URL.'; return }
        $controls['LtMessageText'].Text = ''
        Add-Type -AssemblyName System.Net.Http
        if ($script:settings.IgnoreSslErrors) { Enable-TrustAllCertificates }
        $client = New-Object System.Net.Http.HttpClient((New-Object System.Net.Http.HttpClientHandler))
        $client.Timeout = [TimeSpan]::FromSeconds(30)
        $url = (Expand-Variables -InputString $controls['LtUrlBox'].Text).Trim()
        if ($url -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') { $url = "https://$url" }
        $script:loadTest = @{ Running = $true; Client = $client; InFlight = (New-Object System.Collections.ArrayList); Total = 0; Success = 0; Failed = 0; LatencySum = 0.0
            Start = [datetime]::Now; End = [datetime]::Now.AddSeconds($duration); Threads = $threads; LastSample = [datetime]::Now; X = (New-Object System.Collections.ArrayList)
            Rps = (New-Object System.Collections.ArrayList); Lat = (New-Object System.Collections.ArrayList); Url = $url; Method = [string]$controls['LtMethodBox'].SelectedItem
            Headers = @(ConvertFrom-HeaderText -HeaderText (Expand-Variables -InputString $controls['LtHeadersBox'].Text)); Body = (Expand-Variables -InputString $controls['LtBodyBox'].Text) }
        $controls['LtStartButton'].IsEnabled = $false; $controls['LtStopButton'].IsEnabled = $true
        $script:loadTestTimer.Start()
    })
    # Stop: no new requests are started; the test finishes when the in-flight ones complete.
    $controls['LtStopButton'].Add_Click({ if ($script:loadTest.Running) { $script:loadTest.End = [datetime]::Now.AddSeconds(-1) } })
    $window.Add_Closing({ try { $script:loadTestTimer.Stop(); if ($script:loadTest.Client) { $script:loadTest.Client.Dispose() } } catch { } })
    [void](Show-WpfDialog -Window $window -OwnerForm (Get-MainWindow))
}
#endregion
